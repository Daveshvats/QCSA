"""Dedicated JavaScript/TypeScript pattern scanner.

Semgrep has known issues matching pattern-regex in JSX/TSX files. This module
provides a fast, reliable regex-based scanner that runs INSTEAD of (or alongside)
semgrep for JS/TS files.

Each pattern is a regex that matches a specific vulnerability pattern in JS/JSX/TS/TSX.
This is the same approach ESLint security plugins use — simple, fast, reliable.

Patterns are organized by audit finding they address:
  - CRIT-1: Hardcoded AES key (Base64 pattern)
  - CRIT-2: Test URL in production code
  - CRIT-4: JWT in localStorage
  - CRIT-5: Hardcoded UUIDs/customer IDs
  - HIGH-4: AES-ECB mode
  - HIGH-6: Server error echoed to user
  - HIGH-7: Logout without server call
  - HIGH-10: JSON.parse at module level
  - HIGH-15: window.open without noopener
  - MED-4: console.log of sensitive data
  - MED-1: document.write
  - Plus 20+ additional React/JS patterns
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple


@dataclass
class JSPatternHit:
    """A pattern match in a JS/TS file."""
    rule_id: str
    file: str
    line: int
    message: str
    severity: str  # 'critical', 'high', 'medium', 'low', 'info'
    cwe: str
    fix: str
    context: str = ""


# All patterns: (rule_id, regex, message, severity, cwe, fix)
JS_PATTERNS: List[Tuple[str, str, str, str, str, str]] = [
    # === CRIT-1: Hardcoded AES/encryption key (Base64) ===
    (
        "js-hardcoded-crypto-key",
        r'(?:encodedKey|secretKey|encryptKey|aesKey|SECRET_KEY|ENCRYPTION_KEY)\s*=\s*["\']([A-Za-z0-9+/=]{16,})["\']',
        "Hardcoded encryption key (Base64) — key ships in client bundle, anyone can decrypt (CWE-321)",
        "critical", "CWE-321",
        "Delete this file. All encryption must happen server-side.",
    ),
    # === CRIT-2: Test URL in production code ===
    (
        "js-test-url-in-prod",
        r'(?:BASE_URL|API_URL|OFFSITE_BASE_URL)\s*=\s*["\']https?://(?:api)?test\.',
        "Hardcoded test API URL — production traffic goes to test environment (CWE-489)",
        "critical", "CWE-489",
        "Replace with import.meta.env.VITE_API_BASE_URL",
    ),
    (
        "js-apitest-url",
        r'https?://apitest\.',
        "Test backend URL (apitest.*) found in source — verify this is not used in production (CWE-489)",
        "high", "CWE-489",
        "Use environment variable instead of hardcoded URL",
    ),
    # === CRIT-4: JWT/token in localStorage ===
    (
        "js-jwt-in-localstorage",
        r'localStorage\.setItem\s*\(\s*["\'](?:AUTHHEADER|.*TOKEN|.*JWT|.*AUTH)',
        "JWT/token stored in localStorage — XSS can steal it (CWE-922). Use httpOnly cookies.",
        "critical", "CWE-922",
        "Migrate to httpOnly cookie + in-memory token pattern",
    ),
    (
        "js-jwt-from-localstorage",
        r'localStorage\.getItem\s*\(\s*["\'](?:AUTHHEADER|.*TOKEN|.*JWT|.*AUTH)',
        "JWT/token read from localStorage — accessible to XSS (CWE-922)",
        "high", "CWE-922",
        "Use httpOnly cookie with refresh token flow",
    ),
    # === CRIT-5: Hardcoded UUIDs (customer identifiers) ===
    (
        "js-hardcoded-uuid",
        r"['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]",
        "Hardcoded UUID — may leak customer identifiers (CWE-200). Move to backend config.",
        "medium", "CWE-200",
        "Fetch customer configuration from server instead of hardcoding",
    ),
    # === HIGH-4: AES-ECB mode ===
    (
        "js-aes-ecb",
        r'CryptoJS\.mode\.ECB|mode:\s*["\']ecb["\']|AES.*ECB',
        "AES-ECB mode — cryptographically broken (CWE-327). Identical blocks produce identical ciphertext.",
        "high", "CWE-327",
        "Use AES-GCM via WebCrypto API. Delete client-side crypto.",
    ),
    # === HIGH-4b: CryptoJS usage (client-side crypto is insecure) ===
    (
        "js-cryptojs-usage",
        r'CryptoJS\.',
        "CryptoJS usage — client-side crypto is insecure, keys are in the bundle (CWE-327)",
        "high", "CWE-327",
        "Use WebCrypto API (crypto.subtle) or move encryption server-side",
    ),
    # === HIGH-6: Server error message echoed ===
    (
        "js-error-echo",
        r'(?:enqueueSnackbar|toast|alert|setError|setError)\s*\(\s*`?\$\{.*?(?:error|err)\.?(?:response\.)?data\.message',
        "Raw server error displayed to user — may leak internal details (CWE-209)",
        "high", "CWE-209",
        "Use safe fallback: enqueueSnackbar(getApiErrorMessage(err, 'Something went wrong'))",
    ),
    # === HIGH-7: Logout without server call ===
    (
        "js-logout-no-server",
        r'logout(?:User)?\s*(?:=\s*)?(?:\([^)]*\)\s*=>|function)[^}]*localStorage\.removeItem',
        "Logout only clears localStorage — server token not invalidated (CWE-613)",
        "high", "CWE-613",
        "Add POST /auth/logout server call to revoke the token",
    ),
    # === HIGH-10: JSON.parse at module level ===
    (
        "js-json-parse-module-level",
        r'^(?:const|let|var)\s+\w+\s*=\s*JSON\.parse\s*\(\s*localStorage',
        "JSON.parse(localStorage) at module level — crashes entire bundle if malformed (CWE-754)",
        "high", "CWE-754",
        "Move inside a component with try/catch. Use safeJsonParse helper.",
    ),
    # === HIGH-15: window.open without noopener ===
    (
        "js-window-open-no-noopener",
        r'window\.open\s*\([^)]*["\']_blank["\']',
        "window.open(_blank) without noopener — tabnabbing + open redirect (CWE-1022)",
        "high", "CWE-1022",
        "Add 'noopener,noreferrer' as third argument",
    ),
    # === MED-1: document.write ===
    (
        "js-document-write",
        r'document\.write\s*\(',
        "document.write — XSS risk (CWE-79). Use DOM APIs instead.",
        "medium", "CWE-79",
        "Use document.createElement + textContent",
    ),
    # === MED-1b: innerHTML assignment ===
    (
        "js-innerhtml",
        r'\.innerHTML\s*=',
        "innerHTML assignment — XSS risk if value contains user data (CWE-79)",
        "medium", "CWE-79",
        "Use textContent or DOMPurify.sanitize()",
    ),
    # === MED-4: console.log of sensitive data ===
    (
        "js-console-log-sensitive",
        r'console\.log\s*\(.*(?:token|password|secret|JWT|auth|payload|credential|decodeToken)',
        "console.log of sensitive data (CWE-532) — remove or use debug logger",
        "medium", "CWE-532",
        "Remove the console.log or use a debug-only logger",
    ),
    # === dangerouslySetInnerHTML ===
    (
        "js-dangerously-set-inner-html",
        r'dangerouslySetInnerHTML',
        "dangerouslySetInnerHTML — XSS risk if value contains user data (CWE-79)",
        "high", "CWE-79",
        "Use DOMPurify.sanitize() before setting innerHTML",
    ),
    # === eval() ===
    (
        "js-eval",
        r'\beval\s*\(',
        "eval() — code injection risk (CWE-95)",
        "critical", "CWE-95",
        "Use JSON.parse() or Function() constructor instead",
    ),
    # === Template literal with HTML + interpolation (XSS) ===
    (
        "js-template-html-xss",
        r'`[^`]*<(?:td|div|span|p|h[1-6]|th|li|a|img|body|html)\b[^`]*\$\{',
        "Template literal with HTML tags and ${} interpolation — XSS risk (CWE-79)",
        "critical", "CWE-79",
        "HTML-escape all interpolated values. Use escape-html or DOMPurify.",
    ),
    # === Role/permission from localStorage (CWE-269) ===
    (
        "js-role-from-localstorage",
        r'localStorage\.getItem\s*\(\s*["\'].*(?:ROLE|PERMISSION|ACCESS)',
        "Role/permission read from localStorage — user-editable, not trustworthy (CWE-269)",
        "high", "CWE-269",
        "Read role from decoded JWT (server-signed), not localStorage",
    ),
    # === CorpId from localStorage (CWE-639) ===
    (
        "js-corpid-from-localstorage",
        r'localStorage\.getItem\s*\(\s*["\'].*(?:CORP|TENANT|ORG_ID|CAMP_ID)',
        "CorpId/tenantId from localStorage — user can substitute any org ID (CWE-639)",
        "high", "CWE-639",
        "Verify server-side that JWT corpId matches the requested corpId",
    ),
    # === Default-allow in switch (CWE-285) ===
    (
        "js-default-allow-switch",
        r'default\s*:\s*\n?\s*(?:permissions|access|role|visibility)\s*=\s*\{[^}]*true',
        "Default case grants access — should default to DENY (CWE-285)",
        "critical", "CWE-285",
        "Change default to: permissions = {} (nothing visible)",
    ),
    # === Fetch without auth header ===
    (
        "js-fetch-no-auth",
        r'\bfetch\s*\(',
        "fetch() call — verify Authorization header is included (CWE-862)",
        "info", "CWE-862",
        "Ensure fetch includes Authorization: Bearer <token> header",
    ),
    # === setInterval without cleanup ===
    (
        "js-setinterval-no-cleanup",
        r'setInterval\s*\(',
        "setInterval — verify clearInterval is called in useEffect cleanup (CWE-404)",
        "info", "CWE-404",
        "Return () => clearInterval(intervalId) from useEffect",
    ),
    # === CSP in request header (ineffective) ===
    (
        "js-csp-in-request",
        r"headers\s*[:{].*Content-Security-Policy",
        "CSP header set on REQUEST — browsers ignore it. CSP must be on RESPONSE (CWE-693)",
        "high", "CWE-693",
        "Set CSP via server response headers or meta tag in index.html",
    ),
    # === CORS wildcard ===
    (
        "js-cors-wildcard",
        r"Access-Control-Allow-Origin.*\*",
        "CORS wildcard — allows any origin (CWE-942)",
        "high", "CWE-942",
        "Set specific allowed origins instead of *",
    ),
    # === OTP without rate limiting ===
    (
        "js-otp-no-rate-limit",
        r'send(?:Offsite)?OTP|resendOTP',
        "OTP sending function — verify rate limiting and cooldown exist (CWE-307)",
        "info", "CWE-307",
        "Add 60s cooldown timer, max 3 attempts, CAPTCHA after 3 failures",
    ),
    # === JSON.parse without try/catch ===
    (
        "js-json-parse-no-try",
        r'JSON\.parse\s*\(',
        "JSON.parse — verify this is wrapped in try/catch (CWE-754)",
        "low", "CWE-754",
        "Wrap in try/catch or use safeJsonParse helper",
    ),
    # === POC directory reference ===
    (
        "js-poc-in-production",
        r'/poc/|hospitalLogo|signatureBase64|generatePDF',
        "POC/proof-of-concept file reference — should not ship in production (CWE-489)",
        "high", "CWE-489",
        "Delete the /poc/ directory from production builds",
    ),
    # === Missing route auth check (simplified) ===
    (
        "js-missing-route-auth",
        r'const\s+\w*(?:Auth|Protected|Secure)\w*(?:Layout|Route)\s*=',
        "Auth layout component — verify it checks token validity before rendering (CWE-862)",
        "warning", "CWE-862",
        "Check: if (!isJwtValid(token)) return <Navigate to='/login' />",
    ),
]


# === Per-pattern exclusions (fixes validator.js 41% FP rate) ===
PATTERN_EXTRAS: dict = {}

def _register_extras(rule_id: str, skip_paths: List[str] = None, skip_if_contains: List[str] = None):
    PATTERN_EXTRAS[rule_id] = {
        "skip_paths": skip_paths or [],
        "skip_if_contains": skip_if_contains or [],
    }

_register_extras("js-json-parse-no-try",
    skip_paths=["bench","benchmark","benchmarks","test","tests","fixtures","lib","vendor","third_party","examples"],
    skip_if_contains=["@benchmark","// benchmark","This is a benchmark","validator.js","* validations"])
_register_extras("js-fetch-no-auth",
    skip_paths=["bench","benchmark","benchmarks","examples","fixtures","test","tests","lib","vendor","third_party"],
    skip_if_contains=["polyfill","shim","@deprecated"])
_register_extras("js-json-parse-module-level",
    skip_paths=["bench","benchmark","benchmarks","test","tests","fixtures","examples"],
    skip_if_contains=["// fixture","test fixture"])
_register_extras("js-default-allow-switch",
    skip_paths=["bench","benchmark","benchmarks","test","tests","fixtures","examples"])
_register_extras("js-no-code-splitting",
    skip_paths=["bench","benchmark","benchmarks","test","tests","fixtures","examples","lib","vendor"])
_register_extras("js-setinterval-no-cleanup",
    skip_paths=["bench","benchmark","test","tests","fixtures"])
_register_extras("js-template-html-xss",
    skip_paths=["bench","benchmark","test","tests","fixtures","examples"])
_register_extras("js-csp-in-request",
    skip_paths=["bench","benchmark","test","tests","fixtures"])
_register_extras("js-missing-route-auth",
    skip_paths=["bench","benchmark","test","tests","fixtures","examples","docs"])


def scan_js_patterns(file_path: Path, repo_root: Path = None) -> List[JSPatternHit]:
    """Scan a JS/TS/JSX/TSX file for all vulnerability patterns."""
    if not file_path.exists():
        return []
    ext = file_path.suffix.lower()
    if ext not in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"):
        return []

    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []

    rel = str(file_path.relative_to(repo_root)) if repo_root and file_path.is_relative_to(repo_root) else str(file_path)

    # Pre-compute per-pattern suppression based on path/content for this file
    rel_path_lower = rel.lower()
    source_lower = source.lower()
    suppressed_by_pattern: set = set()
    for rule_id, extras in PATTERN_EXTRAS.items():
        skip_paths = extras.get("skip_paths", [])
        if any(part in rel_path_lower for part in [p.lower() for p in skip_paths]):
            suppressed_by_pattern.add(rule_id)
            continue
        skip_if_contains = extras.get("skip_if_contains", [])
        if any(marker.lower() in source_lower for marker in skip_if_contains):
            suppressed_by_pattern.add(rule_id)

    hits: List[JSPatternHit] = []
    seen: set = set()

    lines = source.splitlines()
    for i, line in enumerate(lines, 1):
        for rule_id, pattern, message, severity, cwe, fix in JS_PATTERNS:
            # Per-pattern path/content suppression
            if rule_id in suppressed_by_pattern:
                continue
            if re.search(pattern, line, re.IGNORECASE if rule_id.startswith("js-default") else 0):
                key = (rule_id, i, line.strip()[:100])
                if key in seen:
                    continue
                seen.add(key)
                hits.append(JSPatternHit(
                    rule_id=f"L0.jspattern.{rule_id}",
                    file=rel, line=i,
                    message=message,
                    severity=severity,
                    cwe=cwe,
                    fix=fix,
                    context=line.strip()[:200],
                ))

    # Multi-line patterns (default-allow switch)
    full_source = source
    for rule_id, pattern, message, severity, cwe, fix in JS_PATTERNS:
        if rule_id == "js-default-allow-switch":
            for m in re.finditer(pattern, full_source, re.MULTILINE | re.DOTALL):
                line_num = full_source[:m.start()].count("\n") + 1
                key = (rule_id, line_num, "")
                if key in seen:
                    continue
                seen.add(key)
                hits.append(JSPatternHit(
                    rule_id=f"L0.jspattern.{rule_id}",
                    file=rel, line=line_num,
                    message=message,
                    severity=severity,
                    cwe=cwe,
                    fix=fix,
                    context=full_source[m.start():m.end()][:200].replace("\n", " "),
                ))

    return hits


def scan_repo_js_patterns(repo_root: Path, max_files: int = 500) -> List[JSPatternHit]:
    """Scan all JS/TS files in the repo."""
    skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules",
                 ".stca-cache", ".stca-reports", ".stca-fixes", "build", "dist",
                 ".pytest_cache", "coverage"}
    js_extensions = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
    hits: List[JSPatternHit] = []
    count = 0
    for p in repo_root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in skip_dirs for part in p.parts):
            continue
        if p.suffix.lower() not in js_extensions:
            continue
        hits.extend(scan_js_patterns(p, repo_root))
        count += 1
        if count >= max_files:
            break
    return hits
