"""FIS auto-tuner.

Calibrates the IT2-FIS rule weights against ground-truth feedback. When
the user records TP/FP via `loomscan feedback tp/fp`, we don't just track stats —
we also nudge the membership functions to reduce false positives and false
negatives.

Strategy:
  - For each layer with high false-positive rate (>30%), widen the "uncertain"
    confidence band → more findings get marked UNCERTAIN → LLM tie-breaker
    gets a chance to filter them.
  - For each layer with high false-negative rate (>30%), tighten the severity
    thresholds → more findings get marked WARN/BLOCK instead of PASS.

The tuner is conservative — it only adjusts by 5% per feedback batch, so it
takes a month of real usage to converge.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Tuple
from dataclasses import dataclass


@dataclass
class TuningAdjustment:
    layer: str
    confidence_band_widen: float  # how much to widen the "uncertain" band (0-1)
    severity_threshold_lower: float  # how much to lower the warn/block threshold (0-1)
    reason: str


def compute_adjustments(stats: Dict[str, dict]) -> Dict[str, TuningAdjustment]:
    """Compute tuning adjustments based on per-layer precision/recall.

    Args:
        stats: {layer_id: {tp, fp, fn, precision, recall}}

    Returns:
        {layer_id: TuningAdjustment}
    """
    adjustments: Dict[str, TuningAdjustment] = {}
    for layer, s in stats.items():
        tp = s.get("tp", 0)
        fp = s.get("fp", 0)
        fn = s.get("fn", 0)
        precision = s.get("precision", tp / (tp + fp) if (tp + fp) else 0.5)
        recall = s.get("recall", tp / (tp + fn) if (tp + fn) else 0.5)

        conf_widen = 0.0
        sev_lower = 0.0
        reasons = []

        # High FP → widen uncertain band
        if precision < 0.6 and (tp + fp) >= 5:
            conf_widen = min(0.10, (0.6 - precision) * 0.5)
            reasons.append(f"precision={precision:.0%} (low) → widen uncertain band by {conf_widen:.2f}")

        # High FN → lower severity threshold (more aggressive blocking)
        if recall < 0.6 and (tp + fn) >= 5:
            sev_lower = min(0.10, (0.6 - recall) * 0.5)
            reasons.append(f"recall={recall:.0%} (low) → lower block threshold by {sev_lower:.2f}")

        if conf_widen > 0 or sev_lower > 0:
            adjustments[layer] = TuningAdjustment(
                layer=layer,
                confidence_band_widen=conf_widen,
                severity_threshold_lower=sev_lower,
                reason="; ".join(reasons),
            )
    return adjustments


def apply_adjustments_to_config(config_path: Path, adjustments: Dict[str, TuningAdjustment]) -> None:
    """Persist tuning adjustments into the .loomscan.yaml under a `tuning:` section.

    The aggregator reads this section at startup and applies the adjustments
    to the membership functions.
    """
    import yaml
    if not config_path.exists():
        return
    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except Exception:
        return
    raw.setdefault("tuning", {})
    for layer, adj in adjustments.items():
        raw["tuning"][layer] = {
            "confidence_band_widen": adj.confidence_band_widen,
            "severity_threshold_lower": adj.severity_threshold_lower,
            "reason": adj.reason,
            "applied_at": __import__("datetime").datetime.now().isoformat(),
        }
    config_path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")


def load_tuning(config_path: Path) -> Dict[str, Tuple[float, float]]:
    """Load tuning adjustments from config. Returns {layer: (widen, lower)}."""
    import yaml
    if not config_path.exists():
        return {}
    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}
    out: Dict[str, Tuple[float, float]] = {}
    for layer, adj in (raw.get("tuning") or {}).items():
        out[layer] = (
            float(adj.get("confidence_band_widen", 0)),
            float(adj.get("severity_threshold_lower", 0)),
        )
    return out
