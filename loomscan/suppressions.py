"""Inline suppression mechanism.

Allows developers to suppress findings with comments:
    # loomscan: ignore
    eval(user_input)  # loomscan: ignore[L0.sast.mini:py-eval]
    # loomscan: ignore L0.sast.mini:py-eval  (rule-specific)

Suppressions are tracked and reported in the output (not silently dropped)
so reviewers can see what was suppressed and audit it.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import List, Set, Tuple, Optional
from dataclasses import dataclass


@dataclass
class Suppression:
    file: str
    line: int
    rule_id: Optional[str]  # None = all rules
    reason: Optional[str]
    raw: str


SUPPRESSION_PATTERNS = [
    # loomscan: ignore  (suppresses everything on this line)
    re.compile(r"loomscan:\s*ignore\b(?:\s*\[([^\]]+)\])?(?:\s*--\s*(.*))?$", re.IGNORECASE),
    # noqa: loomscan=L0.sast.mini:py-eval  (PEP-8 compatible)
    re.compile(r"noqa:\s*loomscan=([^\s]+)", re.IGNORECASE),
    # pylint-style: # pylint: disable=loomscan-L0.sast.mini:py-eval
    re.compile(r"pylint:\s*disable=loomscan-([^\s]+)", re.IGNORECASE),
]


def find_suppressions(file_path: Path, repo_root: Path = None) -> List[Suppression]:
    """Find all inline suppressions in a file.

    v4.14 BUG #3 FIX: Store RELATIVE path (not absolute) so it matches
    finding.file which is relative to repo_root. Previously stored
    str(file_path) (absolute) but findings use relative paths, so
    is_suppressed() never matched — every # loomscan: ignore was silently
    skipped.
    """
    if not file_path.exists():
        return []
    try:
        lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return []

    # v4.14: Store relative path if repo_root is available, else absolute
    if repo_root:
        try:
            rel_path = str(file_path.relative_to(repo_root))
        except ValueError:
            rel_path = str(file_path)
    else:
        rel_path = str(file_path)

    suppressions: List[Suppression] = []
    for i, line in enumerate(lines, start=1):
        for pat in SUPPRESSION_PATTERNS:
            m = pat.search(line)
            if m:
                rule_id = m.group(1) if m.lastindex and m.lastindex >= 1 else None
                reason = m.group(2) if m.lastindex and m.lastindex >= 2 else None
                suppressions.append(Suppression(
                    file=rel_path,
                    line=i,
                    rule_id=rule_id,
                    reason=reason,
                    raw=line.strip(),
                ))
                break
    return suppressions


def is_suppressed(finding_file: str, finding_line: int, finding_rule_id: str,
                  suppressions: List[Suppression]) -> Tuple[bool, Optional[Suppression]]:
    """Check if a finding is suppressed by an inline comment.

    A suppression on line N suppresses findings on:
      - line N (same line)
      - line N+1 (comment on the line above the finding)
    """
    for sup in suppressions:
        if sup.file != finding_file:
            # v4.8: Require full path equality, not just basename.
            # Previously, frontend/utils/auth.py matched backend/admin/auth.py
            # because basenames were equal. This caused cross-module suppression.
            continue
        if sup.line == finding_line or sup.line == finding_line - 1:
            if sup.rule_id is None:
                return True, sup
            if sup.rule_id == finding_rule_id:
                return True, sup
            # also check prefix match (e.g., "L0.sast.mini" matches "L0.sast.mini:py-eval")
            if finding_rule_id.startswith(sup.rule_id):
                return True, sup
    return False, None


def filter_suppressed(findings: list, repo_root: Path) -> Tuple[list, list]:
    """Filter findings, returning (kept, suppressed)."""
    # collect suppressions per file
    sup_by_file: dict = {}
    for f in findings:
        file_path = repo_root / f.file
        if str(file_path) not in sup_by_file and file_path.exists():
            sup_by_file[str(file_path)] = find_suppressions(file_path, repo_root)

    kept = []
    suppressed = []
    for f in findings:
        file_path = repo_root / f.file
        sups = sup_by_file.get(str(file_path), [])
        is_sup, sup = is_suppressed(f.file, f.start_line, f.rule_id, sups)
        if is_sup:
            suppressed.append((f, sup))
        else:
            kept.append(f)
    return kept, suppressed
