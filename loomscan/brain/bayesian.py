# v4.9: TODO — Wire into orchestrator. This module is written but not yet
# connected to the pipeline. See v4.9 plan for BayesianSecondOpinion wiring.


"""Bayesian Belief Network — second-opinion aggregator over the FIS output.

The FIS produces a (decision, confidence_interval) pair deterministically.
The BBN treats that as one noisy sensor and combines it with other signals:
  - confidence:           detector-reported confidence (0..1)
  - exploitability:       how directly attacker-triggered (0..1)
  - reliability:          historical layer precision/recall (0..1)
  - fp_history:           rule's historical FP rate (0..1, higher = more FP)
  - corroboration:        how many independent layers reported this (0..1)
  - test_exclusion:       is the finding excluded by tests/baselines? (0..1)

The network is a small fixed-structure BBN with hand-coded CPTs (conditional
probability tables). Output is a posterior P(block | evidence) along with a
human-readable decision trace.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from ..models import Decision


# =============================================================================
# Evidence & result dataclasses
# =============================================================================

@dataclass
class BBNEvidence:
    """Soft evidence (each in [0,1]) about a single finding."""
    confidence: float = 0.5         # detector-reported confidence
    exploitability: float = 0.5     # attacker-reachability
    reliability: float = 0.5        # source-layer historical reliability
    fp_history: float = 0.0         # historical false-positive rate (higher = more FP)
    corroboration: float = 0.0      # 0=single source, 1=many sources
    test_exclusion: float = 0.0     # 0=not excluded, 1=excluded by tests/baseline
    fis_score: float = 0.5          # the FIS defuzzified output (0..1)


@dataclass
class BBNResult:
    """Posterior over the decision variable + contributing factors."""
    p_block: float
    p_warn: float
    p_pass: float
    decision: Decision
    confidence: float               # P(decision) — highest posterior
    evidence_summary: Dict[str, float] = field(default_factory=dict)


@dataclass
class DecisionTrace:
    """Human-readable explanation of how the BBN reached its decision."""
    decision: Decision
    confidence: float
    posterior: Dict[str, float]              # {block, warn, pass}
    signal_contributions: Dict[str, float] = field(default_factory=dict)
    top_evidence: List[Tuple[str, float]] = field(default_factory=list)
    reasoning: str = ""

    def to_dict(self) -> dict:
        return {
            "decision": self.decision.value,
            "confidence": round(self.confidence, 3),
            "posterior": {k: round(v, 3) for k, v in self.posterior.items()},
            "signal_contributions": {k: round(v, 3) for k, v in self.signal_contributions.items()},
            "top_evidence": [(k, round(v, 3)) for k, v in self.top_evidence],
            "reasoning": self.reasoning,
        }


# =============================================================================
# CPTs (Conditional Probability Tables) — hand-coded
# =============================================================================
#
# Hidden node: severity ∈ {high, medium, low}
#   We treat severity as a latent variable inferred from the FIS score and
#   exploitability.
#
# Hidden node: trustworthy ∈ {yes, no}
#   Inferred from reliability, fp_history, and corroboration.
#
# Observed node: decision ∈ {block, warn, pass}
#   P(decision | severity, trustworthy) is a CPT.
#
# All probabilities are normalized by hand.

# P(severity | fis_score, exploitability) — discrete
def _p_severity(fis_score: float, exploitability: float) -> Dict[str, float]:
    """Infer latent severity distribution from FIS + exploitability."""
    # blend the two signals
    s = 0.6 * fis_score + 0.4 * exploitability
    if s >= 0.7:
        return {"high": 0.8, "medium": 0.18, "low": 0.02}
    if s >= 0.45:
        return {"high": 0.3, "medium": 0.6, "low": 0.1}
    if s >= 0.25:
        return {"high": 0.05, "medium": 0.5, "low": 0.45}
    return {"high": 0.0, "medium": 0.2, "low": 0.8}


# P(trustworthy | reliability, fp_history, corroboration)
def _p_trustworthy(reliability: float, fp_history: float,
                    corroboration: float) -> Dict[str, float]:
    """Infer latent trustworthiness."""
    # higher reliability & corroboration ⇒ trustworthy; higher fp_history ⇒ not
    score = 0.5 * reliability + 0.3 * corroboration - 0.4 * fp_history + 0.2
    score = max(0.0, min(1.0, score))
    return {"yes": score, "no": 1.0 - score}


# P(decision | severity, trustworthy) — table
# decision order: block, warn, pass
_CPT: Dict[Tuple[str, str], Tuple[float, float, float]] = {
    # (severity, trustworthy) → (P_block, P_warn, P_pass)
    ("high", "yes"):   (0.85, 0.13, 0.02),
    ("high", "no"):    (0.55, 0.30, 0.15),
    ("medium", "yes"): (0.30, 0.55, 0.15),
    ("medium", "no"):  (0.10, 0.50, 0.40),
    ("low", "yes"):    (0.05, 0.25, 0.70),
    ("low", "no"):     (0.02, 0.15, 0.83),
}


# Multipliers applied to evidence (each shifts P(block) up or down)
# Multipliers are 1.0 by default; values <1.0 *decrease* the block posterior.
_MULTIPLIERS: Dict[str, float] = {
    "confidence":      1.0,   # replaced per-finding by an exponential
    "exploitability":  1.0,
    "reliability":     1.0,
    "fp_history":      1.0,   # decreasing — higher FP history reduces block
    "corroboration":   1.0,
    "test_exclusion":  1.0,   # high test_exclusion strongly reduces block
}


def _multiplier(name: str, value: float) -> float:
    """Convert a 0..1 evidence value to a multiplier on P(block).

    For positive evidence (confidence, exploitability, reliability,
    corroboration): multiplier grows from ~0.5 (value=0) to ~1.5 (value=1).
    For negative evidence (fp_history, test_exclusion): multiplier shrinks
    from 1.0 (value=0) to ~0.1 (value=1).
    """
    if name in {"fp_history", "test_exclusion"}:
        # negative: high value reduces block probability
        return 1.0 - 0.9 * value
    # positive: high value increases block probability
    return 0.5 + value


# =============================================================================
# BayesianSecondOpinion
# =============================================================================

class BayesianSecondOpinion:
    """Compute a posterior decision over a finding's evidence."""

    def __init__(self) -> None:
        pass

    def evaluate(self, evidence: BBNEvidence) -> BBNResult:
        # marginalize over latent severity × trustworthy
        p_sev = _p_severity(evidence.fis_score, evidence.exploitability)
        p_trust = _p_trustworthy(evidence.reliability, evidence.fp_history,
                                  evidence.corroboration)
        p_block = 0.0
        p_warn = 0.0
        p_pass = 0.0
        for sev, ps in p_sev.items():
            for trust, pt in p_trust.items():
                w = ps * pt
                if w == 0:
                    continue
                b, wn, p = _CPT[(sev, trust)]
                p_block += w * b
                p_warn += w * wn
                p_pass += w * p
        # apply evidence multipliers (multiplicative on P(block))
        # v4.10: Fixed dead-branch bug AND the inversion. v4.9 fixed the
        # dead branch but inverted the logic for fp_history/test_exclusion.
        # _multiplier returns LOW values for high FP history (untrustworthy).
        # So for fp_history/test_exclusion: high value → low m → should
        # INCREASE pass (mult_pass *= (2.0 - m)) and DECREASE block.
        # For other signals: high value → high m → should INCREASE block
        # (mult_block *= m) and DECREASE pass.
        mult_block = 1.0
        mult_pass = 1.0
        for name in ("confidence", "exploitability", "reliability",
                      "fp_history", "corroboration", "test_exclusion"):
            value = getattr(evidence, name)
            m = _multiplier(name, value)
            if name in {"fp_history", "test_exclusion"}:
                # High FP/exclusion → low m → boost pass, reduce block
                mult_pass *= (2.0 - m)  # inverse: low m → high boost
                mult_block *= m           # low m → reduce block
            else:
                # High confidence/exploitability → high m → boost block, reduce pass
                mult_block *= m
                mult_pass *= (2.0 - m)  # inverse
        # apply test_exclusion very strongly
        if evidence.test_exclusion > 0.5:
            mult_block *= (1.0 - evidence.test_exclusion)
        p_block *= mult_block
        p_pass *= mult_pass  # v4.9: use the actual mult_pass, not derived from mult_block
        # renormalize
        total = p_block + p_warn + p_pass
        if total == 0:
            p_block = p_warn = p_pass = 1.0 / 3.0
        else:
            p_block /= total
            p_warn /= total
            p_pass /= total
        # pick decision
        posterior = {"block": p_block, "warn": p_warn, "pass": p_pass}
        best = max(posterior, key=posterior.get)
        decision = {"block": Decision.BLOCK, "warn": Decision.WARN,
                     "pass": Decision.PASS}[best]
        return BBNResult(
            p_block=p_block, p_warn=p_warn, p_pass=p_pass,
            decision=decision, confidence=posterior[best],
            evidence_summary={
                "fis_score": evidence.fis_score,
                "confidence": evidence.confidence,
                "exploitability": evidence.exploitability,
                "reliability": evidence.reliability,
                "fp_history": evidence.fp_history,
                "corroboration": evidence.corroboration,
                "test_exclusion": evidence.test_exclusion,
            })

    def explain(self, evidence: BBNEvidence) -> DecisionTrace:
        result = self.evaluate(evidence)
        # signal contributions: how much each shifted P(block) from a 0.33 baseline
        baseline = 0.33
        contributions: Dict[str, float] = {}
        for name in ("confidence", "exploitability", "reliability",
                      "fp_history", "corroboration", "test_exclusion"):
            value = getattr(evidence, name)
            m = _multiplier(name, value)
            if name in {"fp_history", "test_exclusion"}:
                contributions[name] = baseline * (m - 1.0)
            else:
                contributions[name] = baseline * (m - 1.0)
        # top evidence: sorted by absolute contribution
        top = sorted(contributions.items(), key=lambda kv: abs(kv[1]), reverse=True)[:3]
        reasoning_parts = [
            f"BBN posterior P(block)={result.p_block:.2f}, P(warn)={result.p_warn:.2f}, "
            f"P(pass)={result.p_pass:.2f} → {result.decision.value}",
            f"FIS score {evidence.fis_score:.2f} + exploitability {evidence.exploitability:.2f} "
            f"determined latent severity.",
            f"Top contributing evidence: {', '.join(f'{k}={v:+.2f}' for k, v in top)}.",
        ]
        return DecisionTrace(
            decision=result.decision,
            confidence=result.confidence,
            posterior={"block": result.p_block, "warn": result.p_warn, "pass": result.p_pass},
            signal_contributions=contributions,
            top_evidence=top,
            reasoning=" ".join(reasoning_parts),
        )


# =============================================================================
# ExplainableAggregator — combines FIS + BBN + counterfactual
# =============================================================================

@dataclass
class AggregatedSecondOpinion:
    decision: Decision
    confidence: float
    fis_decision: str
    bbn_decision: Decision
    counterfactual_verified: bool
    reasoning: str
    trace: Dict[str, any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "decision": self.decision.value,
            "confidence": round(self.confidence, 3),
            "fis_decision": self.fis_decision,
            "bbn_decision": self.bbn_decision.value,
            "counterfactual_verified": self.counterfactual_verified,
            "reasoning": self.reasoning,
            "trace": self.trace,
        }


class ExplainableAggregator:
    """Combine FIS, BBN, and counterfactual evidence into one decision.

    Pipeline:
      1. FIS produces a deterministic (decision, score) from the 5 input signals.
      2. BBN produces a posterior P(decision | evidence) including the FIS score.
      3. Counterfactual verification (if provided) can downgrade a BLOCK to WARN
         if the detector still fires after a fix-mutation.
      4. Final decision = majority vote between FIS and BBN, with the
         counterfactual as a tie-breaker.
    """

    def __init__(self) -> None:
        self.bbn = BayesianSecondOpinion()

    def aggregate(self, fis_score: float, fis_decision: str,
                   evidence: BBNEvidence,
                   counterfactual_verified: Optional[bool] = None) -> AggregatedSecondOpinion:
        # set FIS score in evidence
        evidence.fis_score = fis_score
        bbn_result = self.bbn.evaluate(evidence)
        bbn_decision = bbn_result.decision
        # majority: FIS vs BBN
        fis_dec = Decision(fis_decision) if fis_decision in Decision._value2member_map_ else Decision.WARN
        votes = [fis_dec, bbn_decision]
        # tie-break: counterfactual
        cf = counterfactual_verified if counterfactual_verified is not None else None
        if votes.count(fis_dec) >= 2:
            decision = fis_dec
        elif votes.count(bbn_decision) >= 2:
            decision = bbn_decision
        else:
            # tie → use counterfactual as tie-breaker if available, else WARN
            if cf is True:
                decision = fis_dec  # verified true positive → trust FIS
            elif cf is False:
                decision = Decision.PASS  # verified false positive → pass
            else:
                decision = Decision.WARN  # uncertain → warn
        # if counterfactual explicitly verified as FP, downgrade BLOCK → WARN
        if cf is False and decision == Decision.BLOCK:
            decision = Decision.WARN
        confidence = bbn_result.confidence
        reasoning = (f"FIS={fis_dec.value}, BBN={bbn_decision.value} (P={bbn_result.confidence:.2f}), "
                     f"CF={'verified' if cf else 'unverified' if cf is None else 'refuted'} → {decision.value}")
        return AggregatedSecondOpinion(
            decision=decision,
            confidence=confidence,
            fis_decision=fis_decision,
            bbn_decision=bbn_decision,
            counterfactual_verified=bool(cf) if cf is not None else False,
            reasoning=reasoning,
            trace={"bbn_posterior": {"block": bbn_result.p_block,
                                       "warn": bbn_result.p_warn,
                                       "pass": bbn_result.p_pass}},
        )
