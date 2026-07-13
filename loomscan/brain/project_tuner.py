# v4.10+: Wired into the orchestrator feedback loop (orchestrator.py:144-155).
# confidence tuning that the current per-layer tuner.py cannot provide.


"""Per-project FIS tuning via feedback.

The global FIS uses hand-tuned membership functions that work reasonably
across all projects. This module lets each project adapt the FIS to its own
feedback history: which rules produce FPs, which rules miss real bugs, and
therefore how much each rule's confidence should be up- or down-weighted.

Two convenience functions cover the 80% use case:
  - record_feedback(rule_id, kind):  record a TP/FP label
  - get_confidence_multiplier(rule_id): read the multiplier the FIS should
    apply to that rule's confidence score
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# =============================================================================
# Data model
# =============================================================================

@dataclass
class FeedbackEntry:
    """A single human-labeled finding."""
    rule_id: str
    finding_key: str            # fingerprint
    kind: str                   # 'tp' | 'fp' | 'fn'
    file: str = ""
    line: int = 0
    labeler: str = ""
    labeled_at: str = ""
    note: str = ""


@dataclass
class RuleStats:
    """Aggregated stats for one rule."""
    rule_id: str
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0

    @property
    def total(self) -> int:
        return self.true_positives + self.false_positives

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom else 0.5

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom else 0.5

    @property
    def fp_rate(self) -> float:
        """False-positive rate (0..1, higher = worse)."""
        denom = self.true_positives + self.false_positives
        return self.false_positives / denom if denom else 0.0

    @property
    def confidence_multiplier(self) -> float:
        """Multiplier in [0..1.5] applied to a rule's self-reported confidence.

        - rule with 0 labels → 1.0 (neutral)
        - rule with 100% precision → 1.5 (upweight)
        - rule with 0% precision   → 0.1 (effectively suppress)
        """
        if self.total == 0:
            return 1.0
        # Sigmoid centered on precision=0.7 (a "good" rule)
        # maps precision 0 → ~0.07, 0.5 → ~0.45, 0.7 → ~0.75, 1.0 → ~0.95
        # then scales into [0.1, 1.5]
        import math
        z = 6 * (self.precision - 0.7)
        sig = 1.0 / (1.0 + math.exp(-z))
        return round(0.1 + 1.4 * sig, 3)

    @property
    def suppressed(self) -> bool:
        """True if the rule should be auto-suppressed (very high FP rate)."""
        return self.total >= 5 and self.precision < 0.2

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "tp": self.true_positives,
            "fp": self.false_positives,
            "fn": self.false_negatives,
            "precision": round(self.precision, 3),
            "recall": round(self.recall, 3),
            "confidence_multiplier": self.confidence_multiplier,
            "suppressed": self.suppressed,
        }


# =============================================================================
# Persistent feedback store
# =============================================================================

class FeedbackStore:
    """JSON-backed persistent store for per-project feedback."""

    def __init__(self, store_path: Path) -> None:
        self.store_path = store_path
        self.entries: List[FeedbackEntry] = []
        self._load()

    def _load(self) -> None:
        if not self.store_path.exists():
            return
        try:
            data = json.loads(self.store_path.read_text(encoding="utf-8"))
            for e in data.get("entries", []):
                self.entries.append(FeedbackEntry(**e))
        except Exception:
            self.entries = []

    def _save(self) -> None:
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            payload = {
                "version": 1,
                "updated": datetime.now().isoformat(),
                "entries": [asdict(e) for e in self.entries],
            }
            self.store_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        except Exception:
            pass

    def add(self, entry: FeedbackEntry) -> None:
        if not entry.labeled_at:
            entry.labeled_at = datetime.now().isoformat()
        self.entries.append(entry)
        self._save()

    def record(self, rule_id: str, kind: str, finding_key: str = "",
                file: str = "", line: int = 0, labeler: str = "",
                note: str = "") -> None:
        if kind not in {"tp", "fp", "fn"}:
            raise ValueError(f"kind must be tp/fp/fn, got {kind}")
        self.add(FeedbackEntry(
            rule_id=rule_id, finding_key=finding_key, kind=kind,
            file=file, line=line, labeler=labeler, note=note))

    def rule_stats(self) -> Dict[str, RuleStats]:
        out: Dict[str, RuleStats] = {}
        for e in self.entries:
            s = out.setdefault(e.rule_id, RuleStats(rule_id=e.rule_id))
            if e.kind == "tp": s.true_positives += 1
            elif e.kind == "fp": s.false_positives += 1
            elif e.kind == "fn": s.false_negatives += 1
        return out

    def summary(self) -> Dict[str, dict]:
        return {rid: s.to_dict() for rid, s in self.rule_stats().items()}


# =============================================================================
# Per-project FIS tuner
# =============================================================================

class ProjectTuner:
    """Compute per-rule confidence multipliers and auto-suppress high-FP rules.

    Usage:
        tuner = ProjectTuner(FeedbackStore(repo_root / ".loomscan" / "feedback.json"))
        multiplier = tuner.get_confidence_multiplier("CRYPTO-PY-MD5")
        if tuner.is_suppressed("CQ-PRINT-LOG"):
            # skip this rule
    """

    def __init__(self, store: FeedbackStore) -> None:
        self.store = store
        self._stats: Dict[str, RuleStats] = store.rule_stats()

    def refresh(self) -> None:
        self._stats = self.store.rule_stats()

    def get_confidence_multiplier(self, rule_id: str) -> float:
        s = self._stats.get(rule_id)
        return s.confidence_multiplier if s else 1.0

    def is_suppressed(self, rule_id: str) -> bool:
        s = self._stats.get(rule_id)
        return bool(s and s.suppressed)

    def suppressed_rules(self) -> List[str]:
        return [rid for rid, s in self._stats.items() if s.suppressed]

    def top_problem_rules(self, top_k: int = 10) -> List[Tuple[str, RuleStats]]:
        """Rules with the worst precision (most FPs)."""
        scored = [(rid, s) for rid, s in self._stats.items() if s.total >= 3]
        scored.sort(key=lambda x: x[1].precision)
        return scored[:top_k]

    def top_reliable_rules(self, top_k: int = 10) -> List[Tuple[str, RuleStats]]:
        """Rules with the best precision (most trustworthy)."""
        scored = [(rid, s) for rid, s in self._stats.items() if s.total >= 3]
        scored.sort(key=lambda x: x[1].precision, reverse=True)
        return scored[:top_k]

    def export_tuning_config(self) -> dict:
        """Export per-rule multipliers in a format the FIS can consume."""
        return {
            "version": 1,
            "generated_at": datetime.now().isoformat(),
            "multipliers": {rid: s.confidence_multiplier for rid, s in self._stats.items()},
            "suppressed": self.suppressed_rules(),
            "rule_stats": {rid: s.to_dict() for rid, s in self._stats.items()},
        }


# =============================================================================
# Convenience functions (singleton-style)
# =============================================================================

_DEFAULT_STORE_PATH: Optional[Path] = None
_DEFAULT_STORE: Optional[FeedbackStore] = None


def _get_default_store() -> FeedbackStore:
    global _DEFAULT_STORE, _DEFAULT_STORE_PATH
    if _DEFAULT_STORE is None:
        if _DEFAULT_STORE_PATH is None:
            _DEFAULT_STORE_PATH = Path.cwd() / ".loomscan" / "feedback.json"
        _DEFAULT_STORE = FeedbackStore(_DEFAULT_STORE_PATH)
    return _DEFAULT_STORE


def set_default_store_path(path: Path) -> None:
    """Set the path used by the convenience functions. Resets any cache."""
    global _DEFAULT_STORE, _DEFAULT_STORE_PATH
    _DEFAULT_STORE_PATH = path
    _DEFAULT_STORE = None


def record_feedback(rule_id: str, kind: str, finding_key: str = "",
                     file: str = "", line: int = 0,
                     labeler: str = "", note: str = "") -> None:
    """Record a TP/FP/FN label for a finding."""
    store = _get_default_store()
    store.record(rule_id, kind, finding_key, file, line, labeler, note)


def get_confidence_multiplier(rule_id: str) -> float:
    """Get the FIS confidence multiplier for a rule (1.0 = neutral)."""
    store = _get_default_store()
    stats = store.rule_stats().get(rule_id)
    return stats.confidence_multiplier if stats else 1.0


def is_rule_suppressed(rule_id: str) -> bool:
    """True if the rule should be auto-suppressed due to high FP rate."""
    store = _get_default_store()
    stats = store.rule_stats().get(rule_id)
    return bool(stats and stats.suppressed)
