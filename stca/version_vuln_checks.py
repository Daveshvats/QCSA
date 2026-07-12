"""Version-based vulnerability checks — compares dependency versions against known-vulnerable ranges.

v4.12: Renamed from missing_patches.py. 12/15 entries are version-string checks
(functionally identical to SCA). Only 2 do actual code-pattern checks.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple


@dataclass
class SecurityPatch:
    """A known security patch with its vulnerable pattern."""
    cve: str
    package: str
    description: str
    vulnerable_pattern: str  # regex or string that appears in unpatched code
    patched_pattern: str  # what the fix looks like (absence of vulnerable = patched)
    severity: str  # critical, high, medium, low
    file_pattern: str  # glob pattern for files to check
    language: str  # python, javascript, etc.
    fix_url: str = ""


# Curated database of high-profile security patches
# Each entry represents a real CVE where we can detect the vulnerable pattern
VERSION_VULN_DATABASE: List[SecurityPatch] = [
    SecurityPatch(
        cve="CVE-2021-23337",
        package="lodash",
        description="Command injection via template function in lodash < 4.17.21",
        vulnerable_pattern=r"lodash[<]\s*4\.17\.2[01]",
        patched_pattern="lodash >= 4.17.21",
        severity="critical",
        file_pattern="**/requirements*.txt",
        language="python",
        fix_url="https://nvd.nist.gov/vuln/detail/CVE-2021-23337",
    ),
    SecurityPatch(
        cve="CVE-2022-21699",
        package="ipython",
        description="IPython before 8.1.0 — arbitrary code execution via current working directory",
        vulnerable_pattern=r"ipython[<]\s*8\.1\.0",
        patched_pattern="ipython >= 8.1.0",
        severity="high",
        file_pattern="**/requirements*.txt",
        language="python",
        fix_url="https://nvd.nist.gov/vuln/detail/CVE-2022-21699",
    ),
    SecurityPatch(
        cve="CVE-2020-14343",
        package="PyYAML",
        description="PyYAML before 5.4 — yaml.load() without SafeLoader allows arbitrary code execution",
        vulnerable_pattern=r"yaml\.load\((?![^)]*SafeLoader)",
        patched_pattern="yaml.safe_load( or yaml.load(..., Loader=yaml.SafeLoader",
        severity="critical",
        file_pattern="**/*.py",
        language="python",
        fix_url="https://nvd.nist.gov/vuln/detail/CVE-2020-14343",
    ),
    SecurityPatch(
        cve="CVE-2021-29921",
        package="python-ipaddress",
        description="ipaddress before 3.9.6 — improper input validation",
        vulnerable_pattern=r"ipaddress\.ip_address\(.*\)\.is_global",
        patched_pattern="validate input before using ip_address",
        severity="medium",
        file_pattern="**/*.py",
        language="python",
        fix_url="https://nvd.nist.gov/vuln/detail/CVE-2021-29921",
    ),
    SecurityPatch(
        cve="CVE-2022-42969",
        package="py",
        description="py library before 1.11.0 — ReDoS in py.path",
        vulnerable_pattern=r"\bpy[<]\s*1\.11\.0\b",
        patched_pattern="py >= 1.11.0",
        severity="medium",
        file_pattern="**/requirements*.txt",
        language="python",
        fix_url="https://nvd.nist.gov/vuln/detail/CVE-2022-42969",
    ),
    SecurityPatch(
        cve="CVE-2023-24329",
        package="python urllib",
        description="urllib.parse before 3.11.4 — URL parsing bypass allows scheme injection",
        vulnerable_pattern=r"urllib\.parse\.urlparse\([^)]*\)",
        patched_pattern="validate URL scheme before parsing",
        severity="high",
        file_pattern="**/*.py",
        language="python",
        fix_url="https://nvd.nist.gov/vuln/detail/CVE-2023-24329",
    ),
    SecurityPatch(
        cve="CVE-2023-36188",
        package="cryptography",
        description="cryptography before 41.0.2 — NULL pointer dereference in PKCS#12",
        vulnerable_pattern=r"cryptography\s*[=<>!~]+\s*(?:[0-3]\.|4[01]\.|42\.)",
        patched_pattern="cryptography >= 41.0.2",
        severity="high",
        file_pattern="**/requirements*.txt",
        language="python",
        fix_url="https://nvd.nist.gov/vuln/detail/CVE-2023-36188",
    ),
    SecurityPatch(
        cve="CVE-2023-23931",
        package="cryptography",
        description="cryptography before 39.0.1 — memory corruption in Cipher.update_into",
        vulnerable_pattern=r"cryptography\s*[=<>!~]+\s*(?:[0-2]\.|3[0-8]\.)",
        patched_pattern="cryptography >= 39.0.1",
        severity="high",
        file_pattern="**/requirements*.txt",
        language="python",
        fix_url="https://nvd.nist.gov/vuln/detail/CVE-2023-23931",
    ),
    SecurityPatch(
        cve="CVE-2024-22195",
        package="Flask",
        description="Flask before 3.0.0 — resource exhaustion via multipart form data",
        vulnerable_pattern=r"flask[<]\s*3\.0\.0",
        patched_pattern="flask >= 3.0.0",
        severity="medium",
        file_pattern="**/requirements*.txt",
        language="python",
        fix_url="https://nvd.nist.gov/vuln/detail/CVE-2024-22195",
    ),
    SecurityPatch(
        cve="CVE-2024-34064",
        package="jinja2",
        description="Jinja2 before 3.1.4 — XML autoescape bypass via attr filter",
        vulnerable_pattern=r"jinja2[<]\s*3\.1\.4",
        patched_pattern="jinja2 >= 3.1.4",
        severity="high",
        file_pattern="**/requirements*.txt",
        language="python",
        fix_url="https://nvd.nist.gov/vuln/detail/CVE-2024-34064",
    ),
    SecurityPatch(
        cve="CVE-2024-35195",
        package="requests",
        description="requests < 2.32.0 — session cookie not stripped on cross-origin redirect",
        vulnerable_pattern=r"requests[<]\s*2\.32\.0",
        patched_pattern="requests >= 2.32.0",
        severity="medium",
        file_pattern="**/requirements*.txt",
        language="python",
        fix_url="https://nvd.nist.gov/vuln/detail/CVE-2024-35195",
    ),
    SecurityPatch(
        cve="CVE-2023-32681",
        package="requests",
        description="requests < 2.31.0 — Proxy-Authorization header leaked on redirect",
        vulnerable_pattern=r"requests[<]\s*2\.31\.0",
        patched_pattern="requests >= 2.31.0",
        severity="medium",
        file_pattern="**/requirements*.txt",
        language="python",
        fix_url="https://nvd.nist.gov/vuln/detail/CVE-2023-32681",
    ),
    # JavaScript/Node.js patches
    SecurityPatch(
        cve="CVE-2024-22020",
        package="node",
        description="Node.js before 20.11.1 — permission model bypass",
        vulnerable_pattern=r'"node":\s*"[<~^]\s*(?:14|16|18|20)\.',
        patched_pattern="node >= 20.11.1",
        severity="high",
        file_pattern="**/package.json",
        language="javascript",
        fix_url="https://nvd.nist.gov/vuln/detail/CVE-2024-22020",
    ),
    SecurityPatch(
        cve="CVE-2024-45296",
        package="semver",
        description="semver before 7.5.2 — ReDoS in semver functions",
        vulnerable_pattern=r'"semver":\s*"[<~^]\s*7\.[0-4]\.',
        patched_pattern="semver >= 7.5.2",
        severity="high",
        file_pattern="**/package.json",
        language="javascript",
        fix_url="https://nvd.nist.gov/vuln/detail/CVE-2024-45296",
    ),
    SecurityPatch(
        cve="CVE-2024-45801",
        package="mocha",
        description="mocha before 10.7.0 — path traversal in --reporter",
        vulnerable_pattern=r'"mocha":\s*"[<~^]\s*10\.[0-6]\.',
        patched_pattern="mocha >= 10.7.0",
        severity="medium",
        file_pattern="**/package.json",
        language="javascript",
        fix_url="https://nvd.nist.gov/vuln/detail/CVE-2024-45801",
    ),
]


@dataclass
class MissingPatch:
    """A detected missing security patch."""
    cve: str
    package: str
    description: str
    severity: str
    file: str
    line: int
    fix_url: str
    vulnerable_snippet: str


def scan_version_vuln_checks(repo_root: Path,
                          max_files: int = 200) -> List[MissingPatch]:
    """Scan the repo for missing security patches.

    For each patch in the database:
      - Find files matching the file_pattern
      - Check if the vulnerable_pattern appears
      - If yes → the code is running unpatched code for this CVE
    """
    from fnmatch import fnmatch

    results: List[MissingPatch] = []
    skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules",
                 ".stca-cache", ".stca-reports", ".stca-fixes", "tests", "test"}

    # collect all files
    all_files: List[Path] = []
    for p in repo_root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in skip_dirs for part in p.parts):
            continue
        all_files.append(p)
        if len(all_files) >= max_files:
            break

    for patch in VERSION_VULN_DATABASE:
        # find matching files (strip **/ from pattern since fnmatch doesn't support **)
        file_pat = patch.file_pattern.replace("**/", "")
        for file_path in all_files:
            rel = str(file_path.relative_to(repo_root))
            if not fnmatch(rel, file_pat) and not fnmatch(file_path.name, file_pat):
                continue

            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            # search for vulnerable pattern
            for i, line in enumerate(content.splitlines(), 1):
                if re.search(patch.vulnerable_pattern, line):
                    results.append(MissingPatch(
                        cve=patch.cve,
                        package=patch.package,
                        description=patch.description,
                        severity=patch.severity,
                        file=rel,
                        line=i,
                        fix_url=patch.fix_url,
                        vulnerable_snippet=line.strip()[:200],
                    ))
                    break  # one match per file per CVE

    return results


def version_vuln_check_stats() -> dict:
    """Return stats about the patch database."""
    from collections import Counter
    by_severity = Counter(p.severity for p in VERSION_VULN_DATABASE)
    by_language = Counter(p.language for p in VERSION_VULN_DATABASE)
    return {
        "total_patches": len(VERSION_VULN_DATABASE),
        "by_severity": dict(by_severity),
        "by_language": dict(by_language),
    }
