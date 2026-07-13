"""Interval Type-2 Fuzzy Inference System engine.

Implements the standard IT2-FIS inference pipeline:
  1. Fuzzification: convert crisp inputs to IT2 membership values
  2. Rule evaluation: apply rules using t-norm (min) for AND, t-conorm (max) for OR
  3. Type reduction: Karnik-Mendel algorithm to reduce IT2 output to interval [yl, yu]
  4. Defuzzification: average of (yl, yu) → crisp decision

This is the deterministic "brain" of the pipeline. No ML runtime, no LLM,
no GPU. ~150 lines of math.
"""
from __future__ import annotations

from typing import Dict, Tuple, List
import math

from .membership import (
    IT2Membership, SeverityMF, ConfidenceMF, BlastRadiusMF,
    ExploitabilityMF, SourceReliabilityMF, DecisionMF,
    encode_blast_radius,
)
from .rules import FuzzyRule, get_rules


class IT2FIS:
    """Interval Type-2 Fuzzy Inference System."""

    def __init__(self, rules: List[FuzzyRule] = None):
        self.rules = rules or get_rules()
        self.severity_mf = SeverityMF()
        self.confidence_mf = ConfidenceMF()
        self.blast_mf = BlastRadiusMF()
        self.exploit_mf = ExploitabilityMF()
        self.reliability_mf = SourceReliabilityMF()
        self.decision_mf = DecisionMF()

    def evaluate(self, severity_score: float, confidence: float,
                 blast_radius: str, exploitability: float,
                 source_reliability: float) -> Tuple[IT2Membership, str]:
        """Run the FIS on a single finding's signals.

        Args:
            severity_score: 0..1 (use Finding.severity_score())
            confidence: 0..1
            blast_radius: 'function' | 'module' | 'system'
            exploitability: 0..1
            source_reliability: 0..1 (from LayerStats.reliability_score)

        Returns:
            (output_membership, dominant_rule_comment)
            output_membership is an IT2Membership over the decision variable
            (0=pass, 0.5=warn, 1=block). Use .midpoint for crisp decision.
        """
        # Step 1: fuzzify inputs
        sev_vals = self.severity_mf.evaluate(severity_score)
        conf_vals = self.confidence_mf.evaluate(confidence)
        blast_vals = self.blast_mf.evaluate(encode_blast_radius(blast_radius))
        exploit_vals = self.exploit_mf.evaluate(exploitability)
        rel_vals = self.reliability_mf.evaluate(source_reliability)

        # Step 2: evaluate rules
        # Each rule contributes an IT2 output membership. The output of a rule
        # is the AND (min) of its premises, applied as a "firing strength"
        # interval. We aggregate by OR (max) over rules with the same decision.
        decision_outputs: Dict[str, IT2Membership] = {
            "pass": IT2Membership(0, 0),
            "warn": IT2Membership(0, 0),
            "block": IT2Membership(0, 0),
        }
        dominant_rule_strength = 0.0
        dominant_rule_comment = ""

        for rule in self.rules:
            firing = self._evaluate_rule_premise(
                rule, sev_vals, conf_vals, blast_vals, exploit_vals, rel_vals
            )
            if firing.midpoint > 0:
                # aggregate into the rule's decision
                current = decision_outputs[rule.decision]
                decision_outputs[rule.decision] = current | firing
                if firing.midpoint > dominant_rule_strength:
                    dominant_rule_strength = firing.midpoint
                    dominant_rule_comment = rule.comment

        # Step 3: convert decision memberships to a single output interval
        # Each decision has a centroid: pass=0.0, warn=0.5, block=1.0
        # (extreme values so a single firing rule dominates)
        decision_centroids = {"pass": 0.0, "warn": 0.5, "block": 1.0}

        # Weighted average (type-reduction approximation)
        # For each decision, weight = firing strength interval
        # Output: y = Σ(w_i * c_i) / Σ(w_i) — but w_i is an interval, so y is an interval
        num_lower = 0.0
        num_upper = 0.0
        den_lower = 0.0
        den_upper = 0.0
        for decision, weight in decision_outputs.items():
            c = decision_centroids[decision]
            if weight.upper > 0:
                # upper output: use upper weights with centroid
                num_upper += weight.upper * c
                den_upper += weight.upper
                # lower output: use lower weights with centroid
                num_lower += weight.lower * c
                den_lower += weight.lower

        if den_upper == 0:
            return IT2Membership(0.5, 0.5), "no rules fired — defaulting to warn"

        # The interval is [num_lower/den_upper, num_upper/den_lower]
        # (Karnik-Mendel simplification: lower bound uses lower weights with
        # upper normalization, and vice versa)
        y_lower = num_lower / den_upper if den_upper > 0 else 0.5
        y_upper = num_upper / den_lower if den_lower > 0 else 0.5

        # Ensure y_lower <= y_upper (mathematically guaranteed, but float rounding...)
        if y_lower > y_upper:
            y_lower, y_upper = y_upper, y_lower

        return IT2Membership(y_lower, y_upper), dominant_rule_comment

    def _evaluate_rule_premise(self, rule: FuzzyRule,
                                sev: dict, conf: dict, blast: dict,
                                exploit: dict, rel: dict) -> IT2Membership:
        """Evaluate the AND of all non-None premises in a rule.

        Returns the firing strength as an IT2Membership.
        AND = t-norm = min for IT2.
        """
        terms: List[IT2Membership] = []
        if rule.severity:
            terms.append(sev.get(rule.severity, IT2Membership(0, 0)))
        if rule.confidence:
            terms.append(conf.get(rule.confidence, IT2Membership(0, 0)))
        if rule.blast_radius:
            terms.append(blast.get(rule.blast_radius, IT2Membership(0, 0)))
        if rule.exploitability:
            terms.append(exploit.get(rule.exploitability, IT2Membership(0, 0)))
        if rule.source_reliability:
            terms.append(rel.get(rule.source_reliability, IT2Membership(0, 0)))

        if not terms:
            # rule with no premises — always fires at full strength
            return IT2Membership(1.0, 1.0)

        result = terms[0]
        for t in terms[1:]:
            result = result & t
        return result


def decision_from_score(score: float) -> str:
    """Map a defuzzified decision score (0..1) to a decision label."""
    if score < 0.30:
        return "pass"
    if score < 0.70:
        return "warn"
    return "block"
