"""L5 — Policy-as-code layer.

Runs Open Policy Agent (OPA) Rego policies against the changed code.
Policies express business rules like:
  - "credit card numbers must never appear in logs"
  - "only Finance module may write to account_balance"
  - "auth checks must precede every business operation"

If OPA isn't installed, falls back to a JSON-based static policy check.
"""
from __future__ import annotations

import subprocess
import json
import re
from pathlib import Path
from typing import List

from .base import LayerBase
from ..models import Finding, DiffHunk, LayerID, Severity, BlastRadius


# fallback static policies (used when OPA isn't available)
STATIC_POLICIES = [
    {
        "id": "no-secrets-in-logs",
        "pattern": r"(print|logger\.(info|debug|warn|error|critical)|console\.(log|error|warn))\s*\([^)]*(password|secret|token|api_key|credit_card|ssn)",
        "msg": "Possible secret/PII in log statement — violates no-secrets-in-logs policy",
        "severity": Severity.HIGH, "cwe": "CWE-532",
    },
    {
        "id": "no-eval",
        "pattern": r"\beval\s*\(",
        "msg": "eval() is forbidden by policy — use a safe parser",
        "severity": Severity.HIGH, "cwe": "CWE-95",
    },
    {
        "id": "auth-check-required",
        "pattern": r"def\s+(delete|update|create)_\w+\([^)]*\)[^:]*:\s*$",
        "msg": "Mutation function defined — verify it has auth check (manual review needed if OPA not installed)",
        "severity": Severity.MEDIUM, "cwe": "CWE-862",
    },
]


class L5Policy(LayerBase):
    id = LayerID.L5_POLICY
    name = "Policy Checks"
    description = "OPA/Rego policy enforcement (with static fallback)"

    def run(self, repo_root: Path, hunks: List[DiffHunk],
            config) -> List[Finding]:
        findings: List[Finding] = []

        # find Rego policies
        policy_dir = repo_root / "policies"
        rego_files = list(policy_dir.glob("*.rego")) if policy_dir.exists() else []

        if rego_files and self.is_tool_available("opa"):
            findings += self._opa_check(repo_root, hunks, rego_files)
        else:
            # static fallback
            findings += self._static_check(repo_root, hunks)

        return findings

    def _opa_check(self, repo_root: Path, hunks: List[DiffHunk],
                   rego_files: List[Path]) -> List[Finding]:
        """Run OPA against the diff. Builds a JSON input from the hunks and
        asks OPA to evaluate each policy against it."""
        findings: List[Finding] = []
        # build input JSON
        input_data = {
            "files": [{
                "path": h.file,
                "start_line": h.start_line,
                "end_line": h.end_line,
                "function": h.function_name,
                "added_lines": h.added_lines,
                "removed_lines": h.removed_lines,
                "body": h.function_body or "",
            } for h in hunks]
        }
        input_path = repo_root / ".loomscan-cache" / "opa-input.json"
        input_path.parent.mkdir(parents=True, exist_ok=True)
        input_path.write_text(json.dumps(input_data), encoding="utf-8")

        for rego in rego_files:
            try:
                proc = subprocess.run(
                    ["opa", "eval", "--format=json", "--input", str(input_path),
                     "--data", str(rego), "data.loomscan.deny"],
                    capture_output=True, text=True, check=False, timeout=15,
                )
                if proc.returncode != 0:
                    continue
                result = json.loads(proc.stdout or "{}")
                for r in result.get("result", []):
                    for expr in r.get("expressions", []):
                        for v in expr.get("value", []) if isinstance(expr.get("value"), list) else []:
                            findings.append(Finding(
                                layer=self.id,
                                rule_id=f"L5.policy.opa:{rego.stem}",
                                message=str(v.get("msg", "Policy violation")),
                                file=v.get("file", "<diff>"),
                                start_line=v.get("line", 0),
                                severity=Severity.HIGH if v.get("severity") != "medium" else Severity.MEDIUM,
                                confidence=0.85,
                                blast_radius=BlastRadius.SYSTEM, exploitability=0.6,
                                cwe=v.get("cwe", "CWE-284"),
                                fix_suggestion=v.get("fix"),
                                raw={"policy": rego.name},
                            ))
            except Exception:
                continue
        return findings

    def _static_check(self, repo_root: Path, hunks: List[DiffHunk]) -> List[Finding]:
        findings: List[Finding] = []
        for hunk in hunks:
            text = "\n".join(hunk.added_lines) or (hunk.function_body or "")
            if not text:
                continue
            for line_idx, line in enumerate(text.splitlines(), start=hunk.start_line):
                for policy in STATIC_POLICIES:
                    if re.search(policy["pattern"], line):
                        findings.append(Finding(
                            layer=self.id,
                            rule_id=f"L5.policy.static:{policy['id']}",
                            message=policy["msg"],
                            file=hunk.file, start_line=line_idx, end_line=line_idx,
                            severity=policy["severity"], confidence=0.65,
                            blast_radius=BlastRadius.MODULE, exploitability=0.5,
                            cwe=policy["cwe"],
                            fix_suggestion="Install OPA for full policy enforcement, or refactor to comply",
                            raw={"line": line.strip()},
                        ))
        return findings
