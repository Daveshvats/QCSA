"""HTML/config security scanner — detects missing CSP, security headers, etc.

Inspired by the Uno Care audit finding CRIT-6 (missing CSP headers).
Scans:
  - index.html for missing CSP, X-Frame-Options, Referrer-Policy
  - .env files for hardcoded secrets
  - vite.config.js / webpack.config.js for security misconfigs
  - package.json for devtools in production
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import List


@dataclass
class HTMLSecurityIssue:
    """A security issue found in HTML/config files."""
    issue_type: str
    file: str
    line: int
    description: str
    severity: str  # 'critical', 'high', 'medium', 'low'
    fix: str = ""


def scan_html_config(repo_root: Path) -> List[HTMLSecurityIssue]:
    """Scan HTML and config files for security issues."""
    issues: List[HTMLSecurityIssue] = []
    skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules",
                 ".loomscan-cache", ".loomscan-reports", ".loomscan-fixes", "build", "dist"}

    # Scan index.html
    for pattern in ["index.html", "**/index.html"]:
        for p in repo_root.glob(pattern):
            if any(part in skip_dirs for part in p.parts):
                continue
            issues += _scan_html_file(p, repo_root)

    # Scan .env files
    for p in repo_root.glob(".env*"):
        if p.name == ".env.example" or p.name == ".env.template":
            continue
        issues += _scan_env_file(p, repo_root)

    # Scan vite.config.js / webpack.config.js
    for pattern in ["vite.config.*", "webpack.config.*"]:
        for p in repo_root.glob(pattern):
            issues += _scan_build_config(p, repo_root)

    # Scan package.json for devtools in production
    pkg_json = repo_root / "package.json"
    if pkg_json.exists():
        issues += _scan_package_json(pkg_json, repo_root)

    return issues


def _scan_html_file(file_path: Path, repo_root: Path) -> List[HTMLSecurityIssue]:
    """Scan an HTML file for missing security headers."""
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []

    rel = str(file_path.relative_to(repo_root))
    issues: List[HTMLSecurityIssue] = []

    # Check for CSP
    if "Content-Security-Policy" not in content:
        issues.append(HTMLSecurityIssue(
            issue_type="missing_csp", file=rel, line=1,
            description="Missing Content-Security-Policy header — no defense against XSS (CWE-693)",
            severity="critical",
            fix='Add: <meta http-equiv="Content-Security-Policy" content="default-src \'self\'; script-src \'self\'; ...">',
        ))

    # Check for X-Frame-Options
    if "X-Frame-Options" not in content:
        issues.append(HTMLSecurityIssue(
            issue_type="missing_xframe", file=rel, line=1,
            description="Missing X-Frame-Options — clickjacking risk (CWE-1021)",
            severity="high",
            fix='Add: <meta http-equiv="X-Frame-Options" content="DENY">',
        ))

    # Check for Referrer-Policy
    if "Referrer-Policy" not in content:
        issues.append(HTMLSecurityIssue(
            issue_type="missing_referrer_policy", file=rel, line=1,
            description="Missing Referrer-Policy — referrer leaked to third parties (CWE-200)",
            severity="medium",
            fix='Add: <meta name="referrer" content="strict-origin-when-cross-origin">',
        ))

    # Check for Permissions-Policy
    if "Permissions-Policy" not in content:
        issues.append(HTMLSecurityIssue(
            issue_type="missing_permissions_policy", file=rel, line=1,
            description="Missing Permissions-Policy — browser features not restricted (CWE-693)",
            severity="low",
            fix='Add: <meta http-equiv="Permissions-Policy" content="camera=(self), microphone=()">',
        ))

    return issues


def _scan_env_file(file_path: Path, repo_root: Path) -> List[HTMLSecurityIssue]:
    """Scan .env files for hardcoded secrets."""
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []

    rel = str(file_path.relative_to(repo_root))
    issues: List[HTMLSecurityIssue] = []

    secret_patterns = [
        (r'(?i)(API_KEY|SECRET|TOKEN|PASSWORD)\s*=\s*["\']?[A-Za-z0-9+/=]{16,}', "hardcoded_secret"),
        (r'(?i)AWS_ACCESS_KEY_ID\s*=\s*["\']?AKIA', "aws_key"),
        (r'(?i)JWT_SECRET\s*=\s*["\']?[A-Za-z0-9]{10,}', "jwt_secret"),
    ]

    for i, line in enumerate(content.splitlines(), 1):
        if line.strip().startswith("#"):
            continue
        for pattern, issue_type in secret_patterns:
            if re.search(pattern, line):
                issues.append(HTMLSecurityIssue(
                    issue_type=issue_type, file=rel, line=i,
                    description=f"Secret in .env file: {line.split('=')[0]}=*** (CWE-798)",
                    severity="high",
                    fix="Ensure .env is in .gitignore and secrets are managed via a secret manager",
                ))
                break

    return issues


def _scan_build_config(file_path: Path, repo_root: Path) -> List[HTMLSecurityIssue]:
    """Scan build config for security misconfigs."""
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []

    rel = str(file_path.relative_to(repo_root))
    issues: List[HTMLSecurityIssue] = []

    # Check for source maps in production
    if "sourcemap" in content and re.search(r'sourcemap\s*:\s*true', content):
        issues.append(HTMLSecurityIssue(
            issue_type="sourcemap_enabled", file=rel, line=1,
            description="Source maps enabled — may expose source code in production (CWE-540)",
            severity="medium",
            fix="Set sourcemap: false for production builds, or use hidden sourcemaps",
        ))

    return issues


def _scan_package_json(file_path: Path, repo_root: Path) -> List[HTMLSecurityIssue]:
    """Scan package.json for production issues."""
    import json
    try:
        data = json.loads(file_path.read_text(encoding="utf-8"))
    except Exception:
        return []

    rel = str(file_path.relative_to(repo_root))
    issues: List[HTMLSecurityIssue] = []

    # Check for devtools in dependencies (not devDependencies)
    deps = data.get("dependencies", {})
    devtools_packages = [
        "@tanstack/react-query-devtools",
        "redux-devtools",
        "@redux-devtools/extension",
    ]
    for pkg in devtools_packages:
        if pkg in deps:
            issues.append(HTMLSecurityIssue(
                issue_type="devtools_in_production", file=rel, line=1,
                description=f"{pkg} in dependencies — devtools ship in production bundle (CWE-489)",
                severity="medium",
                fix=f"Move {pkg} to devDependencies and conditionally import it",
            ))

    return issues
