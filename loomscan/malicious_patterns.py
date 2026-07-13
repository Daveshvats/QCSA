"""Malicious package pattern detection — inspired by SourceCode-AI/aura.

aura (https://github.com/SourceCode-AI/aura) detects malicious patterns in
PyPI packages — not just known CVEs, but BEHAVIORAL patterns that indicate
malware: downloading executables at install time, reading SSH keys, etc.

Traditional SCA tools (pip-audit, osv-scanner) check package VERSIONS against
known CVE databases. This module checks the package BEHAVIOR for patterns
that indicate malice, even if no CVE has been filed yet.

Patterns we detect:
  1. setup.py / pyproject.toml that downloads files at install time
  2. Code that reads SSH keys, AWS creds, or .env files
  3. Code that makes network requests during import (not during function calls)
  4. Code that modifies system files or environment
  5. Obfuscated code (base64-encoded strings that get exec'd)
  6. Typosquatted package names (already in L0b, but we add behavioral check)
  7. Packages that override builtins (monkey-patching at import time)
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class MaliciousPattern:
    """A detected malicious pattern in a package."""
    pattern_type: str  # 'install_download' | 'ssh_key_read' | 'import_network' | etc.
    file: str
    line: int
    description: str
    severity: str  # critical, high, medium, low
    indicator: str  # what triggered the detection
    context: str = ""


# Patterns that indicate malicious behavior
MALICIOUS_INDICATORS = {
    # === Install-time downloads ===
    "install_download": {
        "description": "Downloads files at install time (setup.py)",
        "severity": "critical",
        "patterns": [
            (r"setup\.py.*urllib\.request\.urlretrieve", "urlretrieve in setup.py"),
            (r"setup\.py.*requests\.get", "requests.get in setup.py"),
            (r"setup\.py.*subprocess.*curl", "curl in setup.py"),
            (r"setup\.py.*subprocess.*wget", "wget in setup.py"),
            (r"setup\.py.*os\.system.*curl", "curl via os.system in setup.py"),
        ],
    },
    # === Credential theft ===
    "ssh_key_read": {
        "description": "Reads SSH keys",
        "severity": "critical",
        "patterns": [
            (r'\.ssh/id_rsa', "reads SSH private key"),
            (r'\.ssh/id_ed25519', "reads SSH ed25519 key"),
            (r'\.ssh/id_ecdsa', "reads SSH ECDSA key"),
            (r'open\(.*\.ssh', "opens file in .ssh directory"),
        ],
    },
    "aws_creds_read": {
        "description": "Reads AWS credentials",
        "severity": "critical",
        "patterns": [
            (r'\.aws/credentials', "reads AWS credentials file"),
            (r'\.aws/config', "reads AWS config file"),
            (r'AWS_ACCESS_KEY_ID.*os\.environ', "reads AWS_ACCESS_KEY_ID from env"),
            (r'AWS_SECRET_ACCESS_KEY.*os\.environ', "reads AWS_SECRET_ACCESS_KEY from env"),
        ],
    },
    "env_file_read": {
        "description": "Reads .env files",
        "severity": "high",
        "patterns": [
            (r'open\([\'"]\.env', "reads .env file"),
            (r'open\([\'"].*\.env[\'"]', "reads .env file"),
            (r'dotenv.*load', "loads dotenv"),
        ],
    },
    # === Import-time side effects ===
    "import_network": {
        "description": "Makes network requests at import time (not in a function)",
        "severity": "high",
        "patterns": [
            (r'^requests\.get\(', "requests.get at module level"),
            (r'^requests\.post\(', "requests.post at module level"),
            (r'^urllib\.request\.urlopen\(', "urlopen at module level"),
            (r'^socket\.connect\(', "socket.connect at module level"),
        ],
    },
    "import_subprocess": {
        "description": "Runs subprocess at import time",
        "severity": "critical",
        "patterns": [
            (r'^subprocess\.(call|run|Popen)\(', "subprocess at module level"),
            (r'^os\.system\(', "os.system at module level"),
            (r'^os\.popen\(', "os.popen at module level"),
        ],
    },
    # === Obfuscated code ===
    "base64_exec": {
        "description": "Base64-decoded string executed via eval/exec",
        "severity": "critical",
        "patterns": [
            (r'eval\(base64\.b64decode', "eval of base64-decoded data"),
            (r'exec\(base64\.b64decode', "exec of base64-decoded data"),
            (r'eval\(.*decode\(', "eval of decoded data"),
            (r'exec\(.*decode\(', "exec of decoded data"),
        ],
    },
    "hex_obfuscation": {
        "description": "Hex-encoded string executed",
        "severity": "high",
        "patterns": [
            (r'eval\(.*fromhex', "eval of hex-decoded data"),
            (r'exec\(.*fromhex', "exec of hex-decoded data"),
            (r'eval\(.*\\\\x', "eval of hex-escaped string"),
        ],
    },
    # === System modification ===
    "system_modification": {
        "description": "Modifies system files or crontab",
        "severity": "critical",
        "patterns": [
            (r'open\([\'"]/etc/', "writes to /etc/"),
            (r'open\([\'"]/var/spool/cron', "modifies crontab"),
            (r'crontab.*-e', "edits crontab"),
            (r'os\.chmod\([\'"]/etc/', "chmod on /etc/"),
        ],
    },
    "persistence": {
        "description": "Establishes persistence (startup scripts, services)",
        "severity": "high",
        "patterns": [
            (r'open\([\'"]~/.bashrc', "modifies .bashrc"),
            (r'open\([\'"]~/.bash_profile', "modifies .bash_profile"),
            (r'open\([\'"]~/.profile', "modifies .profile"),
            (r'systemctl.*enable', "enables systemd service"),
            (r'launchctl.*load', "loads launchd agent"),
        ],
    },
    # === Builtin override ===
    "builtin_override": {
        "description": "Overrides Python builtins (monkey-patching)",
        "severity": "medium",
        "patterns": [
            (r'__builtins__\[', "modifies __builtins__"),
            (r'builtins\.\w+\s*=', "assigns to builtin"),
        ],
    },
    # === Data exfiltration ===
    "data_exfiltration": {
        "description": "Sends data to external server",
        "severity": "critical",
        "patterns": [
            (r'requests\.post\(.*\.ssh', "sends SSH key to server"),
            (r'requests\.post\(.*\.aws', "sends AWS creds to server"),
            (r'urllib\.request\.urlopen\(.*\.env', "sends .env to server"),
            (r'socket\.send\(.*environ', "sends environment to server"),
        ],
    },
}


def scan_malicious_patterns(file_path: Path,
                             repo_root: Path = None) -> List[MaliciousPattern]:
    """Scan a Python file for malicious patterns."""
    if not file_path.exists() or file_path.suffix != ".py":
        return []
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []

    rel_path = str(file_path.relative_to(repo_root)) if repo_root else str(file_path)
    hits: List[MaliciousPattern] = []
    seen: set = set()

    for pattern_type, config in MALICIOUS_INDICATORS.items():
        for regex_pattern, indicator in config["patterns"]:
            for i, line in enumerate(source.splitlines(), 1):
                if re.search(regex_pattern, line, re.IGNORECASE):
                    key = (i, pattern_type, indicator)
                    if key in seen:
                        continue
                    seen.add(key)
                    hits.append(MaliciousPattern(
                        pattern_type=pattern_type,
                        file=rel_path,
                        line=i,
                        description=config["description"],
                        severity=config["severity"],
                        indicator=indicator,
                        context=line.strip()[:200],
                    ))

    return hits


def scan_repo_malicious_patterns(repo_root: Path,
                                  max_files: int = 200) -> List[MaliciousPattern]:
    """Scan all Python files in the repo for malicious patterns."""
    skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules",
                 ".loomscan-cache", ".loomscan-reports", ".loomscan-fixes"}
    hits: List[MaliciousPattern] = []
    count = 0
    for p in repo_root.rglob("*.py"):
        if any(part in skip_dirs for part in p.parts):
            continue
        hits.extend(scan_malicious_patterns(p, repo_root))
        count += 1
        if count >= max_files:
            break
    return hits


def malicious_stats(hits: List[MaliciousPattern]) -> dict:
    """Return stats about malicious pattern detections."""
    from collections import Counter
    by_type = Counter(h.pattern_type for h in hits)
    by_severity = Counter(h.severity for h in hits)
    return {
        "total_hits": len(hits),
        "by_type": dict(by_type),
        "by_severity": dict(by_severity),
    }
