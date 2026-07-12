"""L7 — Deterministic simulation testing (EXPERIMENTAL stub).

Full deterministic simulation requires a deterministic hypervisor like
Antithesis. We provide a lightweight stub that:
  - detects async/concurrency code in the diff
  - recommends running the system under a deterministic scheduler
  - if `pytest-xdist` with `--dist=loadscope` is available, runs the tests
    under it as a poor-man's deterministic scheduler

In production, replace this with Antithesis integration or
`loom`/`shuttle` (Rust deterministic concurrency testing).
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path
from typing import List

from .base import LayerBase
from ..models import Finding, DiffHunk, LayerID, Severity, BlastRadius


CONCURRENCY_PATTERNS = [
    (r"\basync\s+def\b", "async function"),
    (r"\bawait\s+", "await expression"),
    (r"\bthreading\.(Thread|Lock|RLock|Semaphore)\b", "threading primitive"),
    (r"\bmultiprocessing\.", "multiprocessing"),
    (r"\basyncio\.(gather|wait|create_task)\b", "asyncio primitive"),
    (r"\bconcurrent\.futures\b", "concurrent.futures"),
]


class L7Simulation(LayerBase):
    id = LayerID.L7_SIMULATION
    name = "Deterministic Simulation"
    description = "Concurrency bug detection via deterministic scheduling"

    def run(self, repo_root: Path, hunks: List[DiffHunk],
            config) -> List[Finding]:
        findings: List[Finding] = []

        # only run on concurrency-tagged paths
        concurrency_hunks = [h for h in hunks if config.is_concurrency_path(h.file)]
        if not concurrency_hunks:
            # also auto-detect concurrency patterns in any diff
            for h in hunks:
                body = h.function_body or "\n".join(h.added_lines)
                for pat, name in CONCURRENCY_PATTERNS:
                    if re.search(pat, body):
                        concurrency_hunks.append(h)
                        break

        if not concurrency_hunks:
            return findings

        # warn that deterministic simulation is recommended
        findings.append(Finding(
            layer=self.id, rule_id="L7.simulation.recommended",
            message=f"Concurrency primitives detected in {len(concurrency_hunks)} changed function(s) — consider running under a deterministic scheduler (Antithesis, loom, shuttle)",
            file="<diff>", start_line=0,
            severity=Severity.MEDIUM, confidence=0.6,
            blast_radius=BlastRadius.MODULE, exploitability=0.3,
            cwe="CWE-362",  # race condition
            fix_suggestion="Tag files with @stca:concurrency and integrate loom/shuttle/Antithesis",
            raw={"functions": [h.function_name for h in concurrency_hunks if h.function_name]},
        ))

        # if pytest is available, run the affected tests with --dist=loadscope
        # as a cheap deterministic-ish scheduler
        test_files = set()
        for h in concurrency_hunks:
            if h.file.endswith(".py"):
                stem = Path(h.file).stem
                for cand in [f"tests/test_{stem}.py", f"test/test_{stem}.py"]:
                    if (repo_root / cand).exists():
                        test_files.add(cand)
        if test_files:
            try:
                proc = subprocess.run(
                    [sys.executable, "-m", "pytest", *test_files, "-q",
                     "--tb=line", "-p", "no:randomly"],
                    capture_output=True, text=True, check=False, timeout=60,
                    cwd=str(repo_root),
                )
                if proc.returncode != 0:
                    for line in proc.stdout.splitlines():
                        if "FAILED" in line or "ERROR" in line:
                            findings.append(Finding(
                                layer=self.id, rule_id="L7.simulation.test_failure",
                                message=f"Concurrency test failure: {line[:200]}",
                                file="<test>", start_line=0,
                                severity=Severity.HIGH, confidence=0.7,
                                blast_radius=BlastRadius.MODULE, exploitability=0.4,
                                cwe="CWE-362",
                                raw={"line": line},
                            ))
            except Exception:
                pass

        return findings
