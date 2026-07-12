"""Baseline system — only flag NEW issues.

Inspired by detekt's baseline feature. The #1 adoption blocker for static
analysis tools is that they flood users with hundreds of findings on legacy
code. The baseline solves this:

  1. `stca baseline create` — runs STCA on the current codebase, saves ALL
     finding fingerprints to .stca-baseline.json
  2. `stca check --baseline` — only flags findings whose fingerprint is NOT
     in the baseline (i.e., new issues)
  3. `stca baseline update` — adds current findings to the baseline (after
     you've reviewed/acknowledged them)

This enables incremental improvement: you don't have to fix 500 legacy issues
before STCA is useful. You baseline them, then STCA only blocks NEW issues.

The baseline is per-file-path + per-rule, so:
  - If you fix a baseline issue, it stays "resolved" (good)
  - If you reintroduce it, it becomes "new" again (good)
  - If you move code, the fingerprint changes (acceptable tradeoff)
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional


BASELINE_FILE = ".stca-baseline.json"


@dataclass
class BaselineEntry:
    """A single baselined finding."""
    fingerprint: str
    rule_id: str
    file: str
    line: int
    severity: str
    first_seen: str
    last_seen: str = ""


class Baseline:
    """Manages the baseline of known/accepted issues."""

    def __init__(self, repo_root: Path):
        self.repo_root = repo_root
        self.baseline_file = repo_root / BASELINE_FILE
        self.entries: Dict[str, BaselineEntry] = {}  # fingerprint → entry
        self._load()

    def _load(self) -> None:
        if not self.baseline_file.exists():
            return
        try:
            data = json.loads(self.baseline_file.read_text(encoding="utf-8"))
            for e_dict in data.get("entries", []):
                entry = BaselineEntry(**e_dict)
                self.entries[entry.fingerprint] = entry
        except Exception:
            pass

    def _save(self) -> None:
        data = {
            "version": 1,
            "created_at": datetime.now().isoformat(),
            "entry_count": len(self.entries),
            "entries": [
                {**e.__dict__} for e in self.entries.values()
            ],
        }
        self.baseline_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def create(self, findings: List) -> int:
        """Create a baseline from current findings. Returns count baselined."""
        now = datetime.now().isoformat()
        self.entries.clear()
        for f in findings:
            self.entries[f.fingerprint] = BaselineEntry(
                fingerprint=f.fingerprint,
                rule_id=f.rule_id,
                file=f.file,
                line=f.start_line,
                severity=f.severity.value,
                first_seen=now,
                last_seen=now,
            )
        self._save()
        return len(self.entries)

    def update(self, findings: List) -> Tuple[int, int]:
        """Add new findings to the baseline without removing existing ones.

        Returns (added_count, total_count).
        """
        now = datetime.now().isoformat()
        added = 0
        for f in findings:
            if f.fingerprint not in self.entries:
                self.entries[f.fingerprint] = BaselineEntry(
                    fingerprint=f.fingerprint,
                    rule_id=f.rule_id,
                    file=f.file,
                    line=f.start_line,
                    severity=f.severity.value,
                    first_seen=now,
                    last_seen=now,
                )
                added += 1
            else:
                self.entries[f.fingerprint].last_seen = now
        self._save()
        return added, len(self.entries)

    def filter_new(self, findings: List) -> Tuple[List, List]:
        """Filter findings, returning (new_findings, baselined_findings).

        New findings are those NOT in the baseline.
        """
        new = []
        baselined = []
        for f in findings:
            if f.fingerprint in self.entries:
                baselined.append(f)
            else:
                new.append(f)
        return new, baselined

    def remove_resolved(self, current_fingerprints: Set[str]) -> int:
        """Remove baseline entries that no longer exist in current findings.

        This happens when you fix a baselined issue — it should be removed
        from the baseline so if it reappears, it's flagged as new.

        Returns count removed.
        """
        to_remove = [fp for fp in self.entries if fp not in current_fingerprints]
        for fp in to_remove:
            del self.entries[fp]
        if to_remove:
            self._save()
        return len(to_remove)

    def stats(self) -> dict:
        """Return baseline statistics."""
        from collections import Counter
        by_severity = Counter(e.severity for e in self.entries.values())
        by_rule = Counter(e.rule_id for e in self.entries.values())
        return {
            "total_entries": len(self.entries),
            "by_severity": dict(by_severity),
            "top_rules": dict(by_rule.most_common(10)),
            "baseline_file": str(self.baseline_file),
        }

    def exists(self) -> bool:
        """Check if a baseline has been created."""
        return len(self.entries) > 0
