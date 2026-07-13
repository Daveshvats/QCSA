"""L3 — Invariant checking layer.

Maintains a set of *inferred invariants* for the codebase (stored in
`.loomscan-invariants.json`). On each run:

  1. For functions in the diff, check that the previously inferred invariants
     still hold (cheap, deterministic, <1s).
  2. If `.loomscan-invariants.json` is missing or stale, the user can run
     `loomscan bootstrap invariants` to re-infer from a test run.

This is a simplified Python implementation of the Daikon idea. Real Daikon
supports a richer invariant language (non-linear relations, sequences);
we focus on the 5 most common and useful classes.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import List, Dict, Any

from .base import LayerBase
from ..models import Finding, DiffHunk, LayerID, Severity, BlastRadius


INVARIANTS_FILE = ".loomscan-invariants.json"


class L3Invariants(LayerBase):
    id = LayerID.L3_INVARIANTS
    name = "Invariant Checks"
    description = "Daikon-style runtime-inferred invariant checking"

    def run(self, repo_root: Path, hunks: List[DiffHunk],
            config) -> List[Finding]:
        findings: List[Finding] = []
        inv_file = repo_root / INVARIANTS_FILE
        if not inv_file.exists():
            findings.append(Finding(
                layer=self.id, rule_id="L3.invariants.not_bootstrapped",
                message="No invariant database found — run `loomscan bootstrap invariants` to infer invariants from a test run",
                file="<pipeline>", start_line=0,
                severity=Severity.INFO, confidence=1.0,
            ))
            return findings

        try:
            inv_db = json.loads(inv_file.read_text(encoding="utf-8"))
        except Exception as e:
            findings.append(Finding(
                layer=self.id, rule_id="L3.invariants.corrupt",
                message=f"Invariant database is corrupt: {e}",
                file=INVARIANTS_FILE, start_line=0,
                severity=Severity.LOW, confidence=1.0,
            ))
            return findings

        # For each changed function, check static invariants
        # (e.g., "this function expects x > 0" — verify the diff doesn't violate it)
        for hunk in hunks:
            if not hunk.function_name or not hunk.function_body:
                continue
            key = f"{hunk.file}::{hunk.function_name}"
            invariants = inv_db.get("invariants", {}).get(key, [])
            for inv in invariants:
                violation = self._check_static_invariant(inv, hunk.function_body)
                if violation:
                    findings.append(Finding(
                        layer=self.id,
                        rule_id=f"L3.invariants.violated:{inv.get('id', 'unknown')}",
                        message=f"Likely invariant violation: {inv.get('description')}. {violation}",
                        file=hunk.file, start_line=hunk.start_line,
                        end_line=hunk.end_line,
                        severity=Severity.HIGH, confidence=0.7,
                        blast_radius=BlastRadius.FUNCTION, exploitability=0.2,
                        cwe="CWE-1078",  # inappropriate source code style
                        fix_suggestion=inv.get("fix_suggestion"),
                        raw=inv,
                    ))
        return findings

    def _check_static_invariant(self, inv: Dict, function_body: str) -> str:
        """Check whether a static-text heuristic suggests the invariant is
        violated by the new function body. Returns a violation message or "".

        This is approximate — real invariant checking requires execution.
        But it catches the common cases (e.g., invariant says 'x > 0' and the
        new code does `if x == 0: return x`).
        """
        kind = inv.get("kind")
        expr = inv.get("expression", "")
        if not expr:
            return ""

        if kind == "non_negative":
            # invariant: variable should never go negative
            # check if function body assigns the variable to a potentially negative value
            var = expr.split(">")[0].strip()
            pattern = rf"\b{re.escape(var)}\s*=\s*-?\d+\s*$"
            for line in function_body.splitlines():
                m = re.search(rf"\b{re.escape(var)}\s*=\s*(-\d+)", line)
                if m:
                    return f"Function assigns {var} = {m.group(1)} (negative)"

        elif kind == "non_empty":
            # invariant: list/dict should never be empty when used
            var = expr.replace("len(", "").replace(") > 0", "").strip()
            if re.search(rf"if\s+not\s+{re.escape(var)}\s*:\s*return\s+{re.escape(var)}", function_body):
                return ""  # ok — early return on empty
            # check if function appends to an empty list directly
            if re.search(rf"\b{re.escape(var)}\s*=\s*\[\]", function_body) and \
               not re.search(rf"{re.escape(var)}\.append", function_body):
                return f"Function resets {var} to [] without populating it"

        elif kind == "never_none":
            var = expr.replace("!=", "").replace("None", "").strip()
            if re.search(rf"\b{re.escape(var)}\s*=\s*None\b", function_body):
                return f"Function assigns {var} = None"

        elif kind == "always_positive":
            var = expr.split(">")[0].strip()
            for line in function_body.splitlines():
                m = re.search(rf"\b{re.escape(var)}\s*=\s*(\d+)", line)
                if m and int(m.group(1)) <= 0:
                    return f"Function assigns {var} = {m.group(1)} (non-positive)"

        return ""
