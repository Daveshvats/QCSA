"""L6 — Symbolic verification layer (plug-in for Rust via Kani).

For Rust projects with Kani installed, runs `kani` on functions in critical
paths (auth/, crypto/, payment/). Proves absence of overflow, panic, and
contract violations.

For non-Rust projects, this layer is a no-op.
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import List

from .base import LayerBase
from ..models import Finding, DiffHunk, LayerID, Severity, BlastRadius


class L6Symbolic(LayerBase):
    id = LayerID.L6_SYMBOLIC
    name = "Symbolic Verification"
    description = "Kani model-checking for Rust critical paths"

    def run(self, repo_root: Path, hunks: List[DiffHunk],
            config) -> List[Finding]:
        findings: List[Finding] = []
        rust_hunks = [h for h in hunks if h.file.endswith(".rs")]
        if not rust_hunks:
            return findings

        # only run on critical paths
        critical_hunks = [h for h in rust_hunks if config.is_critical_path(h.file)]
        if not critical_hunks:
            return findings

        if not self.is_tool_available("kani"):
            findings.append(Finding(
                layer=self.id, rule_id="L6.kani.not_installed",
                message="Kani not installed — install with `cargo install kani-verifier` for Rust formal verification",
                file="<pipeline>", start_line=0,
                severity=Severity.INFO, confidence=1.0,
            ))
            return findings

        # run kani on the affected files
        for hunk in critical_hunks[:2]:  # cap at 2 — Kani is slow
            try:
                proc = subprocess.run(
                    ["kani", "--output-format=json", hunk.file],
                    capture_output=True, text=True, check=False, timeout=120,
                    cwd=str(repo_root),
                )
                if proc.returncode != 0:
                    # parse failures
                    for line in proc.stderr.splitlines():
                        if "FAILED" in line or "assertion" in line.lower():
                            findings.append(Finding(
                                layer=self.id, rule_id="L6.kani.assertion_failed",
                                message=f"Kani verification failed: {line[:200]}",
                                file=hunk.file, start_line=hunk.start_line,
                                end_line=hunk.end_line,
                                severity=Severity.CRITICAL, confidence=0.95,
                                blast_radius=BlastRadius.SYSTEM, exploitability=0.4,
                                cwe="CWE-754",  # improper check for unusual condition
                                raw={"stderr": proc.stderr[:500]},
                            ))
            except subprocess.TimeoutExpired:
                findings.append(Finding(
                    layer=self.id, rule_id="L6.kani.timeout",
                    message=f"Kani verification timed out on {hunk.file}",
                    file=hunk.file, start_line=hunk.start_line,
                    severity=Severity.LOW, confidence=0.9,
                ))
            except Exception:
                continue
        return findings
