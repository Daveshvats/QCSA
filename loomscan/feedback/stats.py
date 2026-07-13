"""Per-layer precision/recall tracking.

Feeds into the IT2-FIS as the 'source_reliability' signal. Layers that
historically produce false positives get downweighted; layers that catch
real bugs get upweighted.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict
from datetime import datetime

from ..models import LayerStats


class StatsTracker:
    def __init__(self, stats_path: Path):
        self.stats_path = stats_path
        self.layers: Dict[str, LayerStats] = {}
        self.load()

    def load(self) -> None:
        if not self.stats_path.exists():
            return
        try:
            data = json.loads(self.stats_path.read_text(encoding="utf-8"))
            for layer_id, s in data.get("layers", {}).items():
                self.layers[layer_id] = LayerStats(
                    layer=layer_id,
                    true_positives=s.get("tp", 0),
                    false_positives=s.get("fp", 0),
                    bugs_missed=s.get("fn", 0),
                )
        except Exception:
            pass

    def save(self) -> None:
        data = {
            "version": 1,
            "updated": datetime.now().isoformat(),
            "layers": {
                lid: {"tp": s.true_positives, "fp": s.false_positives,
                      "fn": s.bugs_missed,
                      "precision": s.precision, "recall": s.recall}
                for lid, s in self.layers.items()
            },
        }
        self.stats_path.parent.mkdir(parents=True, exist_ok=True)
        self.stats_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def record_true_positive(self, layer_id: str) -> None:
        if layer_id not in self.layers:
            self.layers[layer_id] = LayerStats(layer=layer_id)
        self.layers[layer_id].true_positives += 1
        self.save()

    def record_false_positive(self, layer_id: str) -> None:
        if layer_id not in self.layers:
            self.layers[layer_id] = LayerStats(layer=layer_id)
        self.layers[layer_id].false_positives += 1
        self.save()

    def record_escaped_bug(self, layer_id: str) -> None:
        if layer_id not in self.layers:
            self.layers[layer_id] = LayerStats(layer=layer_id)
        self.layers[layer_id].bugs_missed += 1
        self.save()

    def reliability(self, layer_id: str) -> float:
        s = self.layers.get(layer_id)
        return s.reliability_score if s else 0.5

    def summary(self) -> Dict:
        return {
            lid: {"precision": s.precision, "recall": s.recall,
                  "tp": s.true_positives, "fp": s.false_positives, "fn": s.bugs_missed}
            for lid, s in self.layers.items()
        }
