"""L1 — Property-based testing layer.

Runs Hypothesis property tests on changed functions. Property tests express
*what must always be true* — they catch semantic bugs that example-based
tests miss (off-by-one, edge cases, algebraic violations).

This layer runs the existing test suite filtered to tests covering changed
functions. If Hypothesis isn't installed, the layer is a no-op (with an INFO
finding telling the user to install it).
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import List

from .base import LayerBase
from ..models import Finding, DiffHunk, LayerID, Severity, BlastRadius


class L1Property(LayerBase):
    id = LayerID.L1_PROPERTY
    name = "Property Tests"
    description = "Hypothesis property test runner on changed functions"

    def run(self, repo_root: Path, hunks: List[DiffHunk],
            config) -> List[Finding]:
        findings: List[Finding] = []
        changed_files = {h.file for h in hunks if h.file.endswith(".py")}
        if not changed_files:
            return findings

        # try importing hypothesis
        try:
            import hypothesis  # noqa
        except ImportError:
            findings.append(Finding(
                layer=self.id, rule_id="L1.hypothesis.not_installed",
                message="hypothesis not installed — install with `pip install hypothesis` for property testing",
                file="<pipeline>", start_line=0,
                severity=Severity.INFO, confidence=1.0,
            ))
            return findings

        # find test files for the changed source files
        test_targets: List[str] = []
        for src in changed_files:
            # app/foo.py → tests/test_foo.py
            stem = Path(src).stem
            for candidate in [f"tests/test_{stem}.py", f"test/test_{stem}.py",
                              f"tests/{stem}_test.py"]:
                if (repo_root / candidate).exists():
                    test_targets.append(candidate)

        if not test_targets:
            return findings

        # run pytest with hypothesis
        try:
            proc = subprocess.run(
                [sys.executable, "-m", "pytest", *test_targets,
                 "--hypothesis-show-statistics", "-q",
                 "--no-header", "--tb=line"],
                capture_output=True, text=True, check=False, timeout=60,
                cwd=str(repo_root),
            )
        except subprocess.TimeoutExpired:
            findings.append(Finding(
                layer=self.id, rule_id="L1.hypothesis.timeout",
                message="Property test run timed out (>60s)",
                file="<pipeline>", start_line=0,
                severity=Severity.MEDIUM, confidence=0.9,
            ))
            return findings
        except Exception as e:
            findings.append(Finding(
                layer=self.id, rule_id="L1.hypothesis.run_error",
                message=f"Failed to run property tests: {e}",
                file="<pipeline>", start_line=0,
                severity=Severity.LOW, confidence=0.8,
            ))
            return findings

        # parse output for failures
        if proc.returncode != 0:
            for line in (proc.stdout + proc.stderr).splitlines():
                if "FAILED" in line or "Falsifying example" in line:
                    # extract file:line if possible
                    parts = line.split("::")[0].strip()
                    file = parts.split("/")[-1] if parts else "<unknown>"
                    findings.append(Finding(
                        layer=self.id, rule_id="L1.hypothesis.failure",
                        message=f"Property test failure: {line.strip()[:200]}",
                        file=file, start_line=0,
                        severity=Severity.HIGH, confidence=0.85,
                        blast_radius=BlastRadius.FUNCTION, exploitability=0.3,
                        cwe="CWE-838",  # representative: improper neutralization
                        raw={"stdout_excerpt": line},
                    ))
        return findings
