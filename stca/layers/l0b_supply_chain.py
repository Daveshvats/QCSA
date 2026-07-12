"""L0b — Supply Chain vulnerability layer.

Detects known CVEs in:
  - Python dependencies (pip-audit, osv-scanner)
  - Node.js dependencies (npm audit, osv-scanner)
  - Go dependencies (govulncheck, osv-scanner)
  - Rust dependencies (cargo audit)
  - Java dependencies (osv-scanner)

Also detects:
  - EOL Python versions (3.7, 3.8 are EOL)
  - EOL Node.js versions
  - Known typosquatted package names

This layer is critical because the L0 SAST rules scan *your* code, but most
real-world breaches come from vulnerable *dependencies*.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import List, Dict

from .base import LayerBase
from ..models import Finding, DiffHunk, LayerID, Severity, BlastRadius


# EOL Python versions (as of 2026) — anything below 3.10 is EOL
EOL_PYTHON = {"3.7", "3.8", "3.9"}
# EOL Node.js versions (as of 2026) — Node 16, 18 are EOL
EOL_NODE = {"v16", "v18", "v14", "v12", "v10"}

# Common typosquats (well-known examples)
TYPOSQUATS = {
    "reqeusts": "requests",
    "python-dateitme": "python-dateutil",
    "pymsql": "pymysql",
    "djang": "django",
    "cryptograpyh": "cryptography",
    "boto": "boto3",  # boto is deprecated, use boto3
    "openai-api": "openai",  # unofficial package, often malicious
}


class L0bSupplyChain(LayerBase):
    """Note: this layer doesn't have a LayerID in the enum yet — we use a
    string identifier. The orchestrator handles it as an 'extra' layer.
    """
    id = LayerID.L0B_SUPPLY_CHAIN  # v4.11: use own LayerID
    name = "Supply Chain"
    description = "Dependency CVE scanning + EOL language detection + typosquat detection"

    # Override the id for finding attribution
    LAYER_TAG = "L0b_supply"

    def run(self, repo_root: Path, hunks: List[DiffHunk],
            config) -> List[Finding]:
        findings: List[Finding] = []

        # 1. Python dependency audit
        findings += self._audit_python(repo_root)
        # 2. Node.js dependency audit
        findings += self._audit_nodejs(repo_root)
        # 3. Go dependency audit
        findings += self._audit_go(repo_root)
        # 4. Rust dependency audit
        findings += self._audit_rust(repo_root)
        # 5. Multi-language via osv-scanner
        findings += self._audit_osv(repo_root)
        # 6. EOL language version detection
        findings += self._check_eol_versions(repo_root)
        # 7. Typosquat detection
        findings += self._check_typosquats(repo_root)

        # Rewrite the layer tag for all findings
        for f in findings:
            f.layer = self.id  # keep enum valid
            # use the rule_id prefix to indicate this is L0b
            if not f.rule_id.startswith("L0b"):
                f.rule_id = f"L0b.{f.rule_id}"

        return findings

    def _audit_python(self, repo_root: Path) -> List[Finding]:
        """Run pip-audit on requirements files."""
        findings: List[Finding] = []
        req_files = list(repo_root.glob("requirements*.txt")) + \
                    list(repo_root.glob("pyproject.toml")) + \
                    list(repo_root.glob("Pipfile*"))
        if not req_files:
            return findings

        if not self.is_tool_available("pip-audit"):
            findings.append(Finding(
                layer=self.id, rule_id="L0b.pip_audit.not_installed",
                message="pip-audit not installed — run `stca install-tools` to enable Python dependency CVE scanning",
                file="<pipeline>", start_line=0,
                severity=Severity.INFO, confidence=1.0,
            ))
            return findings

        for req in req_files[:3]:  # cap at 3 files
            try:
                proc = subprocess.run(
                    ["pip-audit", "-r" if req.suffix == ".txt" else "--requirement",
                     str(req), "--format=json", "--no-deps"],
                    capture_output=True, text=True, check=False, timeout=60,
                )
                if proc.returncode not in (0, 1):
                    continue
                data = json.loads(proc.stdout or "{}")
                for dep in data.get("dependencies", []):
                    for vuln in dep.get("vulns", []):
                        findings.append(Finding(
                            layer=self.id,
                            rule_id=f"L0b.pip_audit.{vuln.get('id', 'unknown')}",
                            message=f"Vulnerable dependency: {dep['name']}=={dep['version']} — {vuln.get('description', vuln.get('id', ''))[:150]}",
                            file=str(req.relative_to(repo_root)),
                            start_line=1,
                            severity=Severity.HIGH if vuln.get("fix_versions") else Severity.MEDIUM,
                            confidence=0.95,
                            blast_radius=BlastRadius.SYSTEM, exploitability=0.7,
                            cwe="CWE-1104",  # use of unmaintained third party components
                            fix_suggestion=f"Upgrade {dep['name']} to {vuln.get('fix_versions', ['latest'])[0]}",
                            raw={"package": dep["name"], "version": dep["version"],
                                 "vuln_id": vuln.get("id"), "fix": vuln.get("fix_versions")},
                        ))
            except Exception:
                continue
        return findings

    def _audit_nodejs(self, repo_root: Path) -> List[Finding]:
        """Run npm audit on package-lock.json."""
        findings: List[Finding] = []
        if not (repo_root / "package-lock.json").exists():
            return findings

        if not self.is_tool_available("npm"):
            # v4.8: Surface missing tool as a warning instead of silent zero
            findings.append(Finding(
                layer=self.id, rule_id="L0b.npm_audit.tool_missing",
                message="npm not installed — Node.js dependency vulnerabilities not checked. Install Node.js to enable npm audit.",
                file="package-lock.json", start_line=1,
                severity=Severity.INFO, confidence=1.0,
            ))
            return findings

        try:
            proc = subprocess.run(
                ["npm", "audit", "--json"],
                capture_output=True, text=True, check=False, timeout=60,
                cwd=str(repo_root),
            )
            data = json.loads(proc.stdout or "{}")
            for vuln_id, vuln in data.get("vulnerabilities", {}).items():
                findings.append(Finding(
                    layer=self.id,
                    rule_id=f"L0b.npm_audit.{vuln_id}",
                    message=f"npm vulnerability: {vuln_id} — {vuln.get('name', '')} severity={vuln.get('severity', 'unknown')}",
                    file="package-lock.json", start_line=1,
                    severity={"critical": Severity.CRITICAL, "high": Severity.HIGH,
                              "moderate": Severity.MEDIUM, "low": Severity.LOW}
                              .get(vuln.get("severity"), Severity.MEDIUM),
                    confidence=0.9,
                    blast_radius=BlastRadius.SYSTEM, exploitability=0.7,
                    cwe="CWE-1104",
                    fix_suggestion=f"Run `npm audit fix` to update {vuln_id}",
                    raw=vuln,
                ))
        except Exception:
            pass
        return findings

    def _audit_go(self, repo_root: Path) -> List[Finding]:
        """Run govulncheck on Go projects."""
        findings: List[Finding] = []
        if not (repo_root / "go.mod").exists():
            return findings
        if not self.is_tool_available("govulncheck"):
            findings.append(Finding(
                layer=self.id, rule_id="L0b.govulncheck.tool_missing",
                message="govulncheck not installed — Go dependency vulnerabilities not checked. Install with: go install golang.org/x/vuln/cmd/govulncheck@latest",
                file="go.mod", start_line=1,
                severity=Severity.INFO, confidence=1.0,
            ))
            return findings

        try:
            proc = subprocess.run(
                ["govulncheck", "-json", "./..."],
                capture_output=True, text=True, check=False, timeout=120,
                cwd=str(repo_root),
            )
            for line in proc.stdout.splitlines():
                if not line.strip():
                    continue
                try:
                    obj = json.loads(line)
                    if obj.get("osv"):
                        findings.append(Finding(
                            layer=self.id,
                            rule_id=f"L0b.govulncheck.{obj['osv']['id']}",
                            message=f"Go vulnerability: {obj['osv']['id']} — {obj['osv'].get('summary', '')[:150]}",
                            file="go.mod", start_line=1,
                            severity=Severity.HIGH, confidence=0.9,
                            blast_radius=BlastRadius.SYSTEM, exploitability=0.6,
                            cwe="CWE-1104",
                            raw=obj,
                        ))
                except json.JSONDecodeError:
                    continue
        except Exception:
            pass
        return findings

    def _audit_rust(self, repo_root: Path) -> List[Finding]:
        """Run cargo audit on Rust projects."""
        findings: List[Finding] = []
        if not (repo_root / "Cargo.lock").exists():
            return findings
        if not self.is_tool_available("cargo-audit"):
            # try `cargo audit` (without hyphen)
            if not self.is_tool_available("cargo"):
                findings.append(Finding(
                    layer=self.id, rule_id="L0b.cargo_audit.tool_missing",
                    message="cargo-audit not installed — Rust dependency vulnerabilities not checked. Install with: cargo install cargo-audit",
                    file="Cargo.lock", start_line=1,
                    severity=Severity.INFO, confidence=1.0,
                ))
                return findings

        try:
            cmd = ["cargo", "audit", "--json"] if self.is_tool_available("cargo-audit") \
                  else ["cargo", "audit", "--json"]
            proc = subprocess.run(
                cmd, capture_output=True, text=True, check=False, timeout=60,
                cwd=str(repo_root),
            )
            data = json.loads(proc.stdout or "{}")
            for vuln in data.get("vulnerabilities", {}).get("list", []):
                findings.append(Finding(
                    layer=self.id,
                    rule_id=f"L0b.cargo_audit.{vuln.get('advisory', {}).get('id', 'unknown')}",
                    message=f"Rust vulnerability: {vuln.get('advisory', {}).get('id')} — {vuln.get('advisory', {}).get('title', '')[:150]}",
                    file="Cargo.lock", start_line=1,
                    severity=Severity.HIGH, confidence=0.95,
                    blast_radius=BlastRadius.SYSTEM, exploitability=0.7,
                    cwe="CWE-1104",
                    fix_suggestion=f"Update {vuln.get('package', {}).get('name')} to patched version",
                    raw=vuln,
                ))
        except Exception:
            pass
        return findings

    def _audit_osv(self, repo_root: Path) -> List[Finding]:
        """Run osv-scanner — covers Python, Node, Go, Rust, Java, Maven."""
        findings: List[Finding] = []
        if not self.is_tool_available("osv-scanner"):
            findings.append(Finding(
                layer=self.id, rule_id="L0b.osv_scanner.tool_missing",
                message="osv-scanner not installed — multi-language dependency vulnerabilities not checked. Install from: https://github.com/google/osv-scanner",
                file="<pipeline>", start_line=1,
                severity=Severity.INFO, confidence=1.0,
            ))
            return findings

        try:
            proc = subprocess.run(
                ["osv-scanner", "--json", "-r", str(repo_root)],
                capture_output=True, text=True, check=False, timeout=120,
                cwd=str(repo_root),
            )
            data = json.loads(proc.stdout or "{}")
            for result in data.get("results", []):
                for pkg in result.get("packages", []):
                    for vuln in pkg.get("vulnerabilities", []):
                        findings.append(Finding(
                            layer=self.id,
                            rule_id=f"L0b.osv.{vuln.get('id', 'unknown')}",
                            message=f"OSV: {vuln.get('id')} in {pkg.get('package', {}).get('name', 'unknown')}@{pkg.get('package', {}).get('version', '?')} — {vuln.get('summary', '')[:150]}",
                            file=str(result.get("source", {}).get("path", "")),
                            start_line=1,
                            severity=Severity.HIGH, confidence=0.95,
                            blast_radius=BlastRadius.SYSTEM, exploitability=0.7,
                            cwe="CWE-1104",
                            fix_suggestion=f"Update {pkg.get('package', {}).get('name')} to a fixed version",
                            raw=vuln,
                        ))
        except Exception:
            pass
        return findings

    def _check_eol_versions(self, repo_root: Path) -> List[Finding]:
        """Detect EOL Python/Node versions in CI configs, Dockerfiles, etc."""
        findings: List[Finding] = []

        # Check Python version from various sources
        python_version = f"{sys.version_info.major}.{sys.version_info.minor}"
        if python_version in EOL_PYTHON:
            findings.append(Finding(
                layer=self.id,
                rule_id=f"L0b.eol.python_{python_version}",
                message=f"Python {python_version} is EOL — security patches no longer backported",
                file="<runtime>", start_line=0,
                severity=Severity.HIGH, confidence=1.0,
                blast_radius=BlastRadius.SYSTEM, exploitability=0.5,
                cwe="CWE-1104",
                fix_suggestion="Upgrade to Python 3.10 or newer",
            ))

        # Check Dockerfiles for EOL base images
        for dockerfile in list(repo_root.glob("**/Dockerfile*"))[:5]:
            try:
                text = dockerfile.read_text(encoding="utf-8", errors="replace")
                for i, line in enumerate(text.splitlines(), 1):
                    line_lower = line.lower()
                    if line_lower.startswith("from"):
                        # check for python:3.7, python:3.8, node:16, etc.
                        if re.search(r"python:3\.[789]", line):
                            findings.append(Finding(
                                layer=self.id,
                                rule_id="L0b.eol.docker_python",
                                message=f"Dockerfile uses EOL Python base image: {line.strip()}",
                                file=str(dockerfile.relative_to(repo_root)),
                                start_line=i,
                                severity=Severity.HIGH, confidence=0.9,
                                blast_radius=BlastRadius.SYSTEM, exploitability=0.5,
                                cwe="CWE-1104",
                                fix_suggestion="Use python:3.12-slim or newer",
                                raw={"line": line},
                            ))
                        if re.search(r"node:(16|18|14|12|10)", line):
                            findings.append(Finding(
                                layer=self.id,
                                rule_id="L0b.eol.docker_node",
                                message=f"Dockerfile uses EOL Node.js base image: {line.strip()}",
                                file=str(dockerfile.relative_to(repo_root)),
                                start_line=i,
                                severity=Severity.HIGH, confidence=0.9,
                                blast_radius=BlastRadius.SYSTEM, exploitability=0.5,
                                cwe="CWE-1104",
                                fix_suggestion="Use node:20-slim or newer",
                                raw={"line": line},
                            ))
            except Exception:
                continue

        # Check .python-version file
        py_version_file = repo_root / ".python-version"
        if py_version_file.exists():
            ver = py_version_file.read_text(encoding="utf-8").strip()
            if any(ver.startswith(eol) for eol in EOL_PYTHON):
                findings.append(Finding(
                    layer=self.id,
                    rule_id=f"L0b.eol.python_version_file",
                    message=f".python-version specifies EOL Python {ver}",
                    file=".python-version", start_line=1,
                    severity=Severity.HIGH, confidence=1.0,
                    blast_radius=BlastRadius.SYSTEM, exploitability=0.5,
                    cwe="CWE-1104",
                    fix_suggestion=f"Upgrade to 3.10+",
                ))

        # Check .nvmrc file
        nvmrc = repo_root / ".nvmrc"
        if nvmrc.exists():
            ver = nvmrc.read_text(encoding="utf-8").strip()
            if any(ver.startswith(eol) for eol in EOL_NODE):
                findings.append(Finding(
                    layer=self.id,
                    rule_id="L0b.eol.nvmrc",
                    message=f".nvmrc specifies EOL Node.js {ver}",
                    file=".nvmrc", start_line=1,
                    severity=Severity.HIGH, confidence=1.0,
                    blast_radius=BlastRadius.SYSTEM, exploitability=0.5,
                    cwe="CWE-1104",
                    fix_suggestion="Upgrade to Node 20 LTS or newer",
                ))

        return findings

    def _check_typosquats(self, repo_root: Path) -> List[Finding]:
        """Detect common typosquatted package names in requirements files."""
        findings: List[Finding] = []
        for req_file in list(repo_root.glob("requirements*.txt"))[:3]:
            try:
                for i, line in enumerate(req_file.read_text(encoding="utf-8").splitlines(), 1):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    pkg_name = re.split(r"[=<>!\[]", line, 1)[0].strip().lower()
                    if pkg_name in TYPOSQUATS:
                        findings.append(Finding(
                            layer=self.id,
                            rule_id=f"L0b.typosquat.{pkg_name}",
                            message=f"Possible typosquatted package: '{pkg_name}' — did you mean '{TYPOSQUATS[pkg_name]}'?",
                            file=str(req_file.relative_to(repo_root)),
                            start_line=i,
                            severity=Severity.CRITICAL, confidence=0.7,
                            blast_radius=BlastRadius.SYSTEM, exploitability=0.9,
                            cwe="CWE-1357",  # reliance on third-party component
                            fix_suggestion=f"Replace '{pkg_name}' with '{TYPOSQUATS[pkg_name]}'",
                            raw={"typo": pkg_name, "correct": TYPOSQUATS[pkg_name]},
                        ))
            except Exception:
                continue

        # check package.json
        pkg_json = repo_root / "package.json"
        if pkg_json.exists():
            try:
                data = json.loads(pkg_json.read_text())
                for section in ("dependencies", "devDependencies"):
                    for dep in data.get(section, {}):
                        if dep in TYPOSQUATS:
                            findings.append(Finding(
                                layer=self.id,
                                rule_id=f"L0b.typosquat.{dep}",
                                message=f"Possible typosquatted npm package: '{dep}' — did you mean '{TYPOSQUATS[dep]}'?",
                                file="package.json", start_line=1,
                                severity=Severity.CRITICAL, confidence=0.7,
                                blast_radius=BlastRadius.SYSTEM, exploitability=0.9,
                                cwe="CWE-1357",
                                fix_suggestion=f"Replace '{dep}' with '{TYPOSQUATS[dep]}'",
                            ))
            except Exception:
                pass

        return findings
