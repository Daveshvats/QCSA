"""Cryptographic correctness analyzer.

v4.15 HONESTY FIX: Docstring previously claimed Go/Java/C++ support.
Actually only Python and JS/TS are implemented (verified by suffix checks).
Go/Java/C/C++ rules are defined but the scan functions return [] for them.

Detects weak crypto in Python (hashlib, Crypto, cryptography) and JS/TS
(CryptoJS, jsonwebtoken, crypto). Also detects unsafe secret comparisons
(== on passwords/tokens), PBKDF2 without salt, and static IVs.

Note: `_is_secret_comparison` requires BOTH operands to be secret-named to
avoid false positives on `if user_input == expected`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

from .multi_lang import get_language


@dataclass
class CryptoIssue:
    file: str
    line: int
    rule_id: str
    severity: str
    description: str
    fix: str = ""
    cwe: str = ""
    confidence: float = 0.85
    language: str = ""


# =============================================================================
# Python crypto analyzer
# =============================================================================

_PY_RULES: List[Tuple[str, str, str, str, str, str, float]] = [
    ("CRYPTO-PY-MD5", r"\bhashlib\.md5\s*\(", "high",
     "MD5 cryptographically broken — collision attacks",
     "Use hashlib.sha256()", "CWE-327", 0.9),
    ("CRYPTO-PY-SHA1", r"\bhashlib\.sha1\s*\(", "high",
     "SHA1 cryptographically broken — collision attacks",
     "Use hashlib.sha256()", "CWE-327", 0.9),
    ("CRYPTO-PY-AES-ECB", r"\bMODE_ECB\b", "critical",
     "AES-ECB — identical plaintext blocks produce identical ciphertext",
     "Use MODE_GCM or MODE_CBC with random IV", "CWE-327", 0.95),
    ("CRYPTO-PY-CBC-NO-HMAC", r"\bMODE_CBC\b", "medium",
     "AES-CBC without HMAC — vulnerable to padding oracle (CBC malleability)",
     "Use AES-GCM (authenticated) or add HMAC-SHA256 over ciphertext", "CWE-327", 0.7),
    ("CRYPTO-PY-RSA-PKCS1", r"\bPKCS1_v1_5\.new\s*\(", "high",
     "RSA PKCS#1 v1.5 padding — Bleichenbacher attack",
     "Use PKCS1_OAEP.new()", "CWE-780", 0.85),
    ("CRYPTO-PY-RANDOM-SECURITY", r"\brandom\.(?:randint|choice|uniform|randrange|sample|random)\s*\(",
     "high", "random module is NOT cryptographically secure",
     "Use secrets module (e.g. secrets.token_bytes, secrets.choice)", "CWE-338", 0.85),
    ("CRYPTO-PY-PBKDF2-NO-SALT", r"hashlib\.pbkdf2_hmac\s*\([^)]*\)\s*$|"
     r"hashlib\.pbkdf2_hmac\s*\(\s*['\"][^'\"]+['\"]\s*,\s*[^,]+,\s*(?:None|b?['\"]['\"])\s*,",
     "critical", "PBKDF2 without salt — rainbow-table attack",
     "Generate a unique salt with os.urandom(16) per password", "CWE-327", 0.9),
    ("CRYPTO-PY-STATIC-IV", r"\b(?:iv|IV|nonce)\s*=\s*['\"][^'\"]{4,}['\"]",
     "critical", "Static IV/nonce — catastrophic for GCM/CBC",
     "Generate a fresh IV with os.urandom(12) for each encryption", "CWE-323", 0.9),
    ("CRYPTO-PY-HARDCODED-SECRET", r"\b(?:password|secret|api_?key|token)\s*=\s*['\"][^'\"]{4,}['\"]",
     "high", "Hardcoded secret in source",
     "Load from environment: os.environ['SECRET']", "CWE-798", 0.85),
]


class PythonCryptoAnalyzer:
    """Regex + small-AST analyzer for Python crypto issues."""

    def analyze_file(self, file_path: Path) -> List[CryptoIssue]:
        if not file_path.exists() or file_path.suffix != ".py":
            return []
        try:
            source = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return []
        out: List[CryptoIssue] = []
        file_str = str(file_path)
        lines = source.splitlines()
        for i, line in enumerate(lines, 1):
            for rule_id, pat, sev, desc, fix, cwe, conf in _PY_RULES:
                try:
                    if re.search(pat, line):
                        out.append(CryptoIssue(
                            file=file_str, line=i, rule_id=rule_id, severity=sev,
                            description=desc, fix=fix, cwe=cwe, confidence=conf,
                            language="python"))
                except re.error:
                    continue
        # multi-line: PBKDF2 across lines without explicit salt
        for m in re.finditer(r"hashlib\.pbkdf2_hmac\s*\(([^)]*)\)", source, re.DOTALL):
            args = m.group(1)
            if "None" in args or not re.search(r"salt", args, re.IGNORECASE):
                line_num = source[:m.start()].count("\n") + 1
                out.append(CryptoIssue(
                    file=file_str, line=line_num, rule_id="CRYPTO-PY-PBKDF2-NO-SALT",
                    severity="critical",
                    description="PBKDF2 called without explicit salt argument",
                    fix="Pass a unique per-password salt", cwe="CWE-327",
                    confidence=0.85, language="python"))
        # == on secrets: requires BOTH operands to look secret-named
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r"(\w+)\s*==\s*(\w+)", line):
                left, right = m.group(1), m.group(2)
                if self._is_secret_comparison(left, right):
                    out.append(CryptoIssue(
                        file=file_str, line=i, rule_id="CRYPTO-PY-SECRET-EQ",
                        severity="high",
                        description=f"Secret compared with == ('{left} == {right}') — timing attack",
                        fix="Use hmac.compare_digest(a, b)", cwe="CWE-208",
                        confidence=0.85, language="python"))
        return out

    @staticmethod
    def _is_secret_comparison(left: str, right: str) -> bool:
        """Return True only if BOTH operands look secret-named.

        This avoids flagging common patterns like `user_input == expected`.
        """
        secret_re = re.compile(
            r"(password|passwd|pwd|secret|token|api_?key|access_?key|"
            r"auth_?token|session_?id|refresh_?token|hash|signature|hmac)",
            re.IGNORECASE)
        return bool(secret_re.search(left) and secret_re.search(right))


# =============================================================================
# JS crypto analyzer
# =============================================================================

_JS_RULES: List[Tuple[str, str, str, str, str, str, float]] = [
    ("CRYPTO-JS-AES-ECB", r"\bCryptoJS\.mode\.ECB\b", "critical",
     "CryptoJS AES-ECB — deterministic, leaks patterns",
     "Use CryptoJS.mode.GCM or CBC with random IV", "CWE-327", 0.95),
    ("CRYPTO-JS-MD5", r"\bCryptoJS\.MD5\s*\(", "high",
     "CryptoJS.MD5 — broken",
     "Use CryptoJS.SHA256", "CWE-327", 0.9),
    ("CRYPTO-JS-SHA1", r"\bCryptoJS\.SHA1\s*\(", "high",
     "CryptoJS.SHA1 — broken",
     "Use CryptoJS.SHA256", "CWE-327", 0.9),
    ("CRYPTO-JS-MATH-RANDOM", r"\bMath\.random\s*\(\s*\)", "high",
     "Math.random() is NOT a CSPRNG",
     "Use window.crypto.getRandomValues() or require('crypto').randomBytes",
     "CWE-338", 0.85),
    ("CRYPTO-JS-WEAK-JWT-SECRET", r"jwt\.sign\s*\(\s*[^,]+,\s*['\"]([^'\"]{1,15})['\"]",
     "critical", "JWT signed with weak secret (<16 chars)",
     "Use a >=32-char secret from process.env", "CWE-326", 0.9),
    ("CRYPTO-JS-HARDCODED-SECRET", r"\b(?:password|secret|api_?key|token)\s*[:=]\s*['\"][^'\"]{4,}['\"]",
     "high", "Hardcoded secret in JS source",
     "Load from process.env", "CWE-798", 0.8),
    ("CRYPTO-JS-EVAL-DECRYPT", r"\beval\s*\(\s*\w+\.decrypt", "critical",
     "eval() of decrypted data — RCE if crypto is broken",
     "Parse with JSON.parse after validation", "CWE-95", 0.9),
]


class JSCryptoAnalyzer:
    """Regex-based analyzer for JS/TS crypto issues."""

    def analyze_file(self, file_path: Path) -> List[CryptoIssue]:
        if not file_path.exists() or file_path.suffix.lower() not in {".js", ".jsx", ".ts", ".tsx", ".mjs"}:
            return []
        try:
            source = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return []
        out: List[CryptoIssue] = []
        file_str = str(file_path)
        lines = source.splitlines()
        for i, line in enumerate(lines, 1):
            for rule_id, pat, sev, desc, fix, cwe, conf in _JS_RULES:
                try:
                    if re.search(pat, line):
                        out.append(CryptoIssue(
                            file=file_str, line=i, rule_id=rule_id, severity=sev,
                            description=desc, fix=fix, cwe=cwe, confidence=conf,
                            language="javascript"))
                except re.error:
                    continue
        return out


# =============================================================================
# Top-level
# =============================================================================

def analyze_crypto(file_path: Path) -> List[CryptoIssue]:
    """Dispatch to the right analyzer based on file extension."""
    lang = get_language(file_path)
    if lang == "python":
        return PythonCryptoAnalyzer().analyze_file(file_path)
    if lang == "javascript":
        return JSCryptoAnalyzer().analyze_file(file_path)
    return []


def analyze_repo_crypto(repo_root: Path) -> List[CryptoIssue]:
    out: List[CryptoIssue] = []
    skip = {"node_modules", ".git", "vendor", "__pycache__", "dist", "build"}
    for path in repo_root.rglob("*"):
        if not path.is_file():
            continue
        if any(s in str(path) for s in skip):
            continue
        if path.suffix.lower() in {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs"}:
            out.extend(analyze_crypto(path))
    return out
