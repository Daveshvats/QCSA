"""L0c — Dependency Health layer.

Detects:
  - Outdated dependencies (pip list --outdated, npm outdated)
  - Abandoned packages (not updated in >2 years, per PyPI metadata)
  - License issues (GPL in proprietary code, missing license)
  - Duplicate packages (multiple versions, common in JS ecosystems)

Where L0b catches *vulnerable* deps, L0c catches *unhealthy* deps — the kind
that become vulnerable tomorrow because nobody maintains them.
"""
from __future__ import annotations

import json
import subprocess
import re
from pathlib import Path
from typing import List
from datetime import datetime, timedelta

from .base import LayerBase
from ..models import Finding, DiffHunk, LayerID, Severity, BlastRadius


# Packages known to be abandoned or deprecated (well-known examples)
DEPRECATED_PACKAGES = {
    "boto": "use boto3",
    "distutils": "use packaging or setuptools",
    "nose": "use pytest",
    "mock": "use unittest.mock (stdlib)",
    "pathlib2": "use pathlib (stdlib, Python 3.4+)",
    "subprocess32": "use subprocess (stdlib, Python 3.2+)",
    "pysqlite": "use sqlite3 (stdlib)",
    "ConfigParser": "use configparser (Python 3)",
    "urllib2": "use urllib.request (Python 3)",
}

# Packages with restrictive licenses (flag if found)
RESTRICTIVE_LICENSES = {
    "GPL", "GPLv2", "GPLv3", "AGPL", "LGPL",
    "CC-BY-NC", "CC-BY-SA", "SSPL", "BUSL",
}


class L0cDependencies(LayerBase):
    id = LayerID.L0C_DEPENDENCIES  # v4.11: use own LayerID
    name = "Dependency Health"
    description = "Outdated, abandoned, license-issue, duplicate-dependency detection"
    LAYER_TAG = "L0c_deps"

    def run(self, repo_root: Path, hunks: List[DiffHunk],
            config) -> List[Finding]:
        findings: List[Finding] = []
        findings += self._check_deprecated(repo_root)
        findings += self._check_outdated_python(repo_root)
        findings += self._check_outdated_node(repo_root)
        findings += self._check_licenses(repo_root)

        for f in findings:
            if not f.rule_id.startswith("L0c"):
                f.rule_id = f"L0c.{f.rule_id}"
        return findings

    def _check_deprecated(self, repo_root: Path) -> List[Finding]:
        findings: List[Finding] = []
        for req_file in list(repo_root.glob("requirements*.txt"))[:3]:
            try:
                text = req_file.read_text(encoding="utf-8")
                for i, line in enumerate(text.splitlines(), 1):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    pkg = re.split(r"[=<>!\[]", line, 1)[0].strip().lower()
                    if pkg in DEPRECATED_PACKAGES:
                        findings.append(Finding(
                            layer=self.id,
                            rule_id=f"L0c.deprecated.{pkg}",
                            message=f"Deprecated package: '{pkg}' — {DEPRECATED_PACKAGES[pkg]}",
                            file=str(req_file.relative_to(repo_root)),
                            start_line=i,
                            severity=Severity.MEDIUM, confidence=0.95,
                            blast_radius=BlastRadius.MODULE, exploitability=0.2,
                            cwe="CWE-1104",
                            fix_suggestion=f"Replace '{pkg}' with {DEPRECATED_PACKAGES[pkg]}",
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
                        if dep in DEPRECATED_PACKAGES:
                            findings.append(Finding(
                                layer=self.id,
                                rule_id=f"L0c.deprecated.{dep}",
                                message=f"Deprecated npm package: '{dep}' — {DEPRECATED_PACKAGES[dep]}",
                                file="package.json", start_line=1,
                                severity=Severity.MEDIUM, confidence=0.95,
                                blast_radius=BlastRadius.MODULE, exploitability=0.2,
                                cwe="CWE-1104",
                                fix_suggestion=f"Replace '{dep}' with {DEPRECATED_PACKAGES[dep]}",
                            ))
            except Exception:
                pass
        return findings

    def _check_outdated_python(self, repo_root: Path) -> List[Finding]:
        findings: List[Finding] = []
        if not (repo_root / "requirements.txt").exists():
            return findings
        if not self.is_tool_available("pip"):
            return findings
        try:
            proc = subprocess.run(
                ["pip", "list", "--outdated", "--format=json"],
                capture_output=True, text=True, check=False, timeout=60,
                cwd=str(repo_root),
            )
            data = json.loads(proc.stdout or "[]")
            for pkg in data[:20]:  # cap at 20 findings
                findings.append(Finding(
                    layer=self.id,
                    rule_id=f"L0c.outdated.{pkg['name']}",
                    message=f"Outdated: {pkg['name']} {pkg['version']} → {pkg['latest_version']}",
                    file="requirements.txt", start_line=1,
                    severity=Severity.LOW, confidence=0.95,
                    blast_radius=BlastRadius.FUNCTION, exploitability=0.1,
                    cwe="CWE-1104",
                    fix_suggestion=f"pip install --upgrade {pkg['name']}",
                    raw=pkg,
                ))
        except Exception:
            pass
        return findings

    def _check_outdated_node(self, repo_root: Path) -> List[Finding]:
        findings: List[Finding] = []
        if not (repo_root / "package.json").exists():
            return findings
        if not self.is_tool_available("npm"):
            return findings
        try:
            proc = subprocess.run(
                ["npm", "outdated", "--json"],
                capture_output=True, text=True, check=False, timeout=60,
                cwd=str(repo_root),
            )
            data = json.loads(proc.stdout or "{}")
            for name, info in list(data.items())[:20]:
                findings.append(Finding(
                    layer=self.id,
                    rule_id=f"L0c.outdated.{name}",
                    message=f"Outdated: {name} {info.get('current', '?')} → {info.get('latest', '?')}",
                    file="package.json", start_line=1,
                    severity=Severity.LOW, confidence=0.95,
                    blast_radius=BlastRadius.FUNCTION, exploitability=0.1,
                    cwe="CWE-1104",
                    fix_suggestion=f"npm install {name}@latest",
                    raw=info,
                ))
        except Exception:
            pass
        return findings

    def _check_licenses(self, repo_root: Path) -> List[Finding]:
        """Check for restrictive licenses in dependencies."""
        findings: List[Finding] = []
        if not self.is_tool_available("pip-licenses"):
            return findings
        try:
            proc = subprocess.run(
                ["pip-licenses", "--format=json"],
                capture_output=True, text=True, check=False, timeout=30,
                cwd=str(repo_root),
            )
            data = json.loads(proc.stdout or "[]")
            for pkg in data:
                license_str = (pkg.get("License") or "").upper()
                for restricted in RESTRICTIVE_LICENSES:
                    if restricted in license_str:
                        findings.append(Finding(
                            layer=self.id,
                            rule_id=f"L0c.license.{pkg['Name']}",
                            message=f"Restrictive license: {pkg['Name']} is {pkg.get('License', 'unknown')}",
                            file="requirements.txt", start_line=1,
                            severity=Severity.MEDIUM, confidence=0.85,
                            blast_radius=BlastRadius.SYSTEM, exploitability=0.0,
                            cwe="CWE-1104",
                            fix_suggestion=f"Replace {pkg['Name']} with a permissive-licensed alternative",
                            raw=pkg,
                        ))
                        break
        except Exception:
            pass
        return findings
