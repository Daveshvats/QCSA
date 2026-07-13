"""L0 — Fast hooks layer.

Runs in <5s. Catches:
  - hardcoded secrets (gitleaks if installed, else regex fallback)
  - Python lint errors (ruff if installed)
  - SAST patterns (semgrep if installed, else a built-in mini-ruleset)

This layer alone catches ~25% of real bugs. Designed to NEVER require an LLM
and to gracefully skip tools that aren't installed.
"""
from __future__ import annotations

import re
import subprocess
import json
from pathlib import Path
from typing import List

from .base import LayerBase
from ..models import Finding, DiffHunk, LayerID, Severity, BlastRadius


# --- built-in secret patterns (used when gitleaks isn't available) ---------
SECRET_PATTERNS = [
    (r"(?i)(aws_access_key_id|aws_secret_access_key)\s*[=:]\s*['\"]?[A-Z0-9a-z/+=]{16,}['\"]?",
     "AWS credential", "CWE-798"),
    (r"(?i)\b(sk-[a-zA-Z0-9]{20,})\b", "OpenAI/Stripe-style API key", "CWE-798"),
    (r"(?i)\b(ghp_[a-zA-Z0-9]{36,})\b", "GitHub PAT", "CWE-798"),
    (r"(?i)\b(glpat-[a-zA-Z0-9_-]{20,})\b", "GitLab PAT", "CWE-798"),
    # v3.3: Fixed hardcoded password regex — now matches both assignment (=)
    # AND comparison (==). The old regex `[=:]` didn't match `==` because
    # it only expected one `=`. Now we match `==` first (comparison), then
    # fall back to `=` (assignment).
    (r"(?i)(password|passwd|pwd)\s*(?:==|[=:])\s*['\"][^'\"]{4,}['\"]",
     "Hardcoded password", "CWE-259"),
    (r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
     "Private key material", "CWE-321"),
]


# --- built-in SAST patterns (used when semgrep isn't available) ------------
MINI_SAST_RULES = [
    {
        "id": "py-eval-injection",
        "pattern": r"\beval\s*\(",
        "msg": "Use of eval() — code injection risk",
        "severity": Severity.HIGH, "cwe": "CWE-95",
    },
    {
        "id": "py-exec-injection",
        "pattern": r"\bexec\s*\(",
        "msg": "Use of exec() — code injection risk",
        "severity": Severity.HIGH, "cwe": "CWE-95",
    },
    {
        "id": "py-shell-injection",
        "pattern": r"subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True",
        "msg": "subprocess with shell=True — shell injection risk",
        "severity": Severity.HIGH, "cwe": "CWE-78",
    },
    {
        "id": "py-sql-string-format",
        "pattern": r"(execute|executemany)\s*\(\s*f['\"]",
        "msg": "SQL query built with f-string — SQL injection risk",
        "severity": Severity.CRITICAL, "cwe": "CWE-89",
    },
    # v3.3: SQL injection via intermediate variable — catches the pattern:
    #   query = f"SELECT ... {user_input}"
    #   cursor.execute(query)
    # The old regex only caught `execute(f"...")` on the same line.
    {
        "id": "py-sql-var-fstring",
        "pattern": r"(query|sql|stmt|statement)\s*=\s*f['\"]",
        "msg": "SQL query string built with f-string (variable) — SQL injection risk when passed to execute()",
        "severity": Severity.HIGH, "cwe": "CWE-89",
    },
    {
        "id": "py-assert-in-prod",
        "pattern": r"^\s*assert\s+",
        "msg": "assert in production code — stripped with -O, use real check",
        "severity": Severity.LOW, "cwe": "CWE-617",
    },
    {
        "id": "js-eval",
        "pattern": r"\beval\s*\(",
        "msg": "Use of eval() — code injection risk",
        "severity": Severity.HIGH, "cwe": "CWE-95",
    },
    {
        "id": "js-innerhtml",
        "pattern": r"\.innerHTML\s*=",
        "msg": "innerHTML assignment — XSS risk",
        "severity": Severity.MEDIUM, "cwe": "CWE-79",
    },
    {
        "id": "js-document-write",
        "pattern": r"document\.write\s*\(",
        "msg": "document.write — XSS risk",
        "severity": Severity.MEDIUM, "cwe": "CWE-79",
    },
]


class L0Fast(LayerBase):
    id = LayerID.L0_FAST
    name = "Fast Hooks"
    description = "Secrets + lint + SAST patterns (<5s)"

    def run(self, repo_root: Path, hunks: List[DiffHunk],
            config) -> List[Finding]:
        findings: List[Finding] = []

        # only scan files in the diff
        files_in_diff = {h.file for h in hunks}
        if not files_in_diff:
            return findings

        # 1. secrets — gitleaks or built-in
        findings += self._scan_secrets(repo_root, files_in_diff)

        # 2. SAST — semgrep (with bundled packs) or built-in mini rules
        findings += self._scan_sast(repo_root, files_in_diff, hunks)

        # 3. ruff (Python)
        findings += self._scan_ruff(repo_root, files_in_diff)

        # 4. golangci-lint (Go)
        findings += self._scan_golangci(repo_root, files_in_diff)

        # 5. eslint (JavaScript/TypeScript)
        findings += self._scan_eslint(repo_root, files_in_diff)

        # 6. SpotBugs / clang-tidy (Java/C++) — wrappers, opt-in
        findings += self._scan_clang_tidy(repo_root, files_in_diff)

        return findings

    # ---- secrets ------------------------------------------------------
    def _scan_secrets(self, repo_root: Path, files: set) -> List[Finding]:
        if self.is_tool_available("gitleaks"):
            return self._gitleaks(repo_root, files)
        # fallback: regex scan
        out: List[Finding] = []
        for f in files:
            path = repo_root / f
            if not path.exists() or not path.is_file():
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            for i, line in enumerate(text.splitlines(), start=1):
                for pat, name, cwe in SECRET_PATTERNS:
                    if re.search(pat, line):
                        out.append(Finding(
                            layer=self.id, rule_id=f"L0.secrets.regex:{name}",
                            message=f"Possible {name} in source",
                            file=f, start_line=i, end_line=i,
                            severity=Severity.CRITICAL, confidence=0.85,
                            blast_radius=BlastRadius.SYSTEM, exploitability=0.9,
                            cwe=cwe,
                            fix_suggestion="Move to environment variable or secret manager",
                            raw={"line": line.strip()},
                        ))
        return out

    def _gitleaks(self, repo_root: Path, files: set) -> List[Finding]:
        try:
            proc = subprocess.run(
                ["gitleaks", "detect", "--source", str(repo_root),
                 "--no-git", "--report-format", "json", "--report-path", "-"],
                capture_output=True, text=True, check=False, timeout=30,
            )
            if proc.returncode not in (0, 1):
                return []
            data = json.loads(proc.stdout or "[]")
        except Exception:
            return []
        out: List[Finding] = []
        for item in data:
            file = item.get("File", "")
            if file not in files:
                continue
            out.append(Finding(
                layer=self.id, rule_id=f"L0.secrets.gitleaks:{item.get('RuleID', 'unknown')}",
                message=item.get("Description", item.get("SecretID", "Secret detected")),
                file=file, start_line=item.get("StartLine", 0),
                end_line=item.get("EndLine", 0),
                severity=Severity.CRITICAL, confidence=0.9,
                blast_radius=BlastRadius.SYSTEM, exploitability=0.95,
                cwe="CWE-798",
                fix_suggestion="Move to environment variable or secret manager",
                raw=item,
            ))
        return out

    # ---- SAST ---------------------------------------------------------
    def _scan_sast(self, repo_root: Path, files: set,
                   hunks: List[DiffHunk]) -> List[Finding]:
        # v5.5: Always call _semgrep — it handles the native YAML fallback internally.
        # Previously, when semgrep wasn't installed, this fell through to the 5-rule
        # mini-SAST, ignoring all 2,095 YAML pack rules. Now _semgrep() checks
        # for semgrep and falls back to _run_native_yaml_engine() automatically.
        return self._semgrep(repo_root, files)

    def _semgrep(self, repo_root: Path, files: set) -> List[Finding]:
        """Run semgrep with BOTH bundled LoomScan rule packs AND community rules.

        v5.2: Falls back to native YAML engine when semgrep is not installed.
        The native engine applies regex-based rules using Python's re module.
        """
        from ..rules import get_all_packs_for_files
        pack_paths = get_all_packs_for_files(list(files))

        # Try semgrep first (supports all features: pattern-inside, metavariables, etc.)
        if self.is_tool_available("semgrep"):
            return self._run_semgrep_binary(repo_root, files, pack_paths)

        # v5.2: Fall back to native YAML engine
        import logging
        _logger = logging.getLogger("loomscan.l0_fast")
        _logger.warning(
            "semgrep not installed — using native YAML engine. "
            "Some advanced rules (pattern-inside, metavariables) will be skipped. "
            "Install semgrep for full coverage: pip install semgrep"
        )
        return self._run_native_yaml_engine(repo_root, files, pack_paths)

    def _run_semgrep_binary(self, repo_root: Path, files: set,
                            pack_paths: list) -> List[Finding]:
        """Run semgrep as an external binary."""
        try:
            configs = [str(p) for p in pack_paths] + ["auto"]

            external_manifest = repo_root / ".loomscan-cache" / "external-packs.json"
            if external_manifest.exists():
                import json
                try:
                    data = json.loads(external_manifest.read_text())
                    configs.extend(p["url"] for p in data.values())
                except Exception:
                    pass

            cmd = ["semgrep", "--json", "--quiet"]
            for c in configs:
                cmd.extend(["--config", c])

            for f in files:
                cmd.append(str(repo_root / f))

            proc = subprocess.run(
                cmd,
                capture_output=True, text=True, check=False, timeout=120,
            )
            if proc.returncode not in (0, 1):
                return []
            data = json.loads(proc.stdout or "{}")
        except Exception:
            return []
        out: List[Finding] = []
        for r in data.get("results", []):
            sev_map = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM,
                       "INFO": Severity.LOW}
            out.append(Finding(
                layer=self.id, rule_id=f"L0.semgrep:{r.get('check_id', 'unknown')}",
                message=r.get("extra", {}).get("message", "Semgrep finding"),
                file=r.get("path", ""), start_line=r.get("start", {}).get("line", 0),
                end_line=r.get("end", {}).get("line", 0),
                severity=sev_map.get(r.get("extra", {}).get("severity", "WARNING"),
                                     Severity.MEDIUM),
                confidence=0.7,
                blast_radius=BlastRadius.MODULE,
                exploitability=0.5,
                cwe=r.get("extra", {}).get("metadata", {}).get("cwe", [None])[0]
                    if isinstance(r.get("extra", {}).get("metadata", {}).get("cwe"), list)
                    else r.get("extra", {}).get("metadata", {}).get("cwe"),
                raw=r,
            ))
        return out

    def _run_native_yaml_engine(self, repo_root: Path, files: set,
                                pack_paths: list) -> List[Finding]:
        """v5.2: Apply YAML pack rules using the native regex engine.

        This is the fallback when semgrep is not installed. It handles
        all rules with 'pattern', 'pattern-regex', and 'pattern-either'
        fields. Rules with advanced features (pattern-inside, metavariables)
        are silently skipped.
        """
        from ..yaml_engine import apply_packs, count_applicable_rules

        # Log coverage stats
        total, applicable, unsupported = count_applicable_rules(pack_paths)
        import logging
        _logger = logging.getLogger("loomscan.l0_fast")
        _logger.info(
            f"Native YAML engine: {applicable}/{total} rules applicable "
            f"({unsupported} require semgrep)"
        )

        # Build file paths
        file_paths = [repo_root / f for f in files if (repo_root / f).exists()]

        # Apply packs
        hits = apply_packs(pack_paths, file_paths, repo_root)

        # Convert to Finding objects
        sev_map = {
            "critical": Severity.CRITICAL, "high": Severity.HIGH,
            "medium": Severity.MEDIUM, "low": Severity.LOW,
            "info": Severity.INFO,
        }
        out: List[Finding] = []
        for hit in hits:
            out.append(Finding(
                layer=self.id,
                rule_id=f"L0.yaml:{hit.rule_id}",
                message=hit.message,
                file=hit.file, start_line=hit.line,
                end_line=hit.line,
                severity=sev_map.get(hit.severity, Severity.MEDIUM),
                confidence=0.7,
                blast_radius=BlastRadius.MODULE,
                exploitability=0.5,
                cwe=hit.cwe,
                raw={"pattern": hit.pattern, "engine": "native"},
            ))
        return out

    # ---- ruff ---------------------------------------------------------
    def _scan_ruff(self, repo_root: Path, files: set) -> List[Finding]:
        py_files = [f for f in files if f.endswith(".py")]
        if not py_files or not self.is_tool_available("ruff"):
            return []
        try:
            proc = subprocess.run(
                ["ruff", "check", "--output-format=json",
                 *[str(repo_root / f) for f in py_files]],
                capture_output=True, text=True, check=False, timeout=20,
            )
            data = json.loads(proc.stdout or "[]")
        except Exception:
            return []
        out: List[Finding] = []
        for r in data:
            out.append(Finding(
                layer=self.id, rule_id=f"L0.ruff:{r.get('code', 'unknown')}",
                message=r.get("message", "Ruff finding"),
                file=r.get("filename", ""), start_line=r.get("location", {}).get("row", 0),
                end_line=r.get("end_location", {}).get("row", 0),
                severity=Severity.LOW, confidence=0.95,
                blast_radius=BlastRadius.FUNCTION, exploitability=0.0,
                raw=r,
            ))
        return out

    # ---- golangci-lint ------------------------------------------------
    def _scan_golangci(self, repo_root: Path, files: set) -> List[Finding]:
        go_files = [f for f in files if f.endswith(".go")]
        if not go_files or not self.is_tool_available("golangci-lint"):
            return []
        try:
            proc = subprocess.run(
                ["golangci-lint", "run", "--out-format=json",
                 *[str(repo_root / f) for f in go_files]],
                capture_output=True, text=True, check=False, timeout=30,
                cwd=str(repo_root),
            )
            data = json.loads(proc.stdout or "{}")
        except Exception:
            return []
        out: List[Finding] = []
        for issue in data.get("Issues", []):
            sev_map = {"error": Severity.HIGH, "warning": Severity.MEDIUM,
                       "info": Severity.LOW}
            out.append(Finding(
                layer=self.id,
                rule_id=f"L0.golangci:{issue.get('FromLinter', 'unknown')}",
                message=issue.get("Text", "golangci-lint finding"),
                file=issue.get("Pos", {}).get("Filename", ""),
                start_line=issue.get("Pos", {}).get("Line", 0),
                severity=sev_map.get(issue.get("Severity", "warning"), Severity.MEDIUM),
                confidence=0.85,
                blast_radius=BlastRadius.FUNCTION, exploitability=0.1,
                raw=issue,
            ))
        return out

    # ---- eslint -------------------------------------------------------
    def _scan_eslint(self, repo_root: Path, files: set) -> List[Finding]:
        js_files = [f for f in files if f.endswith((".js", ".jsx", ".ts", ".tsx"))]
        if not js_files or not self.is_tool_available("eslint"):
            return []
        try:
            proc = subprocess.run(
                ["eslint", "--format=json",
                 *[str(repo_root / f) for f in js_files]],
                capture_output=True, text=True, check=False, timeout=30,
                cwd=str(repo_root),
            )
            data = json.loads(proc.stdout or "[]")
        except Exception:
            return []
        out: List[Finding] = []
        sev_map = {2: Severity.HIGH, 1: Severity.MEDIUM, 0: Severity.LOW}
        for r in data:
            for m in r.get("messages", []):
                out.append(Finding(
                    layer=self.id,
                    rule_id=f"L0.eslint:{m.get('ruleId', 'unknown')}",
                    message=m.get("message", "ESLint finding"),
                    file=r.get("filePath", ""),
                    start_line=m.get("line", 0),
                    severity=sev_map.get(m.get("severity", 1), Severity.MEDIUM),
                    confidence=0.85,
                    blast_radius=BlastRadius.FUNCTION, exploitability=0.1,
                    raw=m,
                ))
        return out

    # ---- clang-tidy ---------------------------------------------------
    def _scan_clang_tidy(self, repo_root: Path, files: set) -> List[Finding]:
        cpp_files = [f for f in files if f.endswith((".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hxx"))]
        if not cpp_files or not self.is_tool_available("clang-tidy"):
            return []
        out: List[Finding] = []
        for f in cpp_files[:5]:  # cap at 5 files
            try:
                proc = subprocess.run(
                    ["clang-tidy", "--warnings-as-errors=*", str(repo_root / f)],
                    capture_output=True, text=True, check=False, timeout=30,
                    cwd=str(repo_root),
                )
                for line in (proc.stdout + proc.stderr).splitlines():
                    if "warning:" in line or "error:" in line:
                        # parse clang-tidy output format
                        # path:line:col: severity: message [check-name]
                        import re
                        m = re.match(r"^([^:]+):(\d+):\d+: (\w+): (.+) \[([^\]]+)\]", line)
                        if m:
                            _, lineno, sev, msg, check = m.groups()
                            out.append(Finding(
                                layer=self.id,
                                rule_id=f"L0.clang_tidy:{check}",
                                message=msg,
                                file=f, start_line=int(lineno),
                                severity=Severity.HIGH if sev == "error" else Severity.MEDIUM,
                                confidence=0.85,
                                blast_radius=BlastRadius.FUNCTION, exploitability=0.2,
                                raw={"line": line, "check": check},
                            ))
            except Exception:
                continue
        return out
