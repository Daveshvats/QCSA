from __future__ import annotations
from .v4_types import UnifiedFinding

import ast
import re
import os
import json
import subprocess
import sys
import textwrap
import tempfile
import logging
from pathlib import Path
from typing import List, Optional, Dict, Any, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict

try:
    from .normalized_ast import parse_file, get_language, is_supported, NormalizedNode, _HAS_TS, _TS_LANGUAGE_MODULES
except ImportError:
    _HAS_TS = False
    _TS_LANGUAGE_MODULES = {}

_v4_logger = logging.getLogger("stca.v4_restored")

def _log_v4_error(scanner_name: str, exc: BaseException) -> None:
    """Log a v4 scanner failure."""
    _v4_logger.warning("v4 scanner '%s' failed: %s: %s",
                       scanner_name, type(exc).__name__, exc)


# =============================================================================
# SHARED DATA TYPES
# =============================================================================

# v4.9: Define _detect_lang_by_ext — referenced at 4 call sites but was never
# defined, causing NameError when _HAS_TS is False (tree-sitter not installed).
# This is a simple extension-to-language mapper that doesn't require tree-sitter.
_EXT_TO_LANG = {
    ".py": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".go": "go",
    ".java": "java",
    ".c": "c", ".h": "c",
    ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp", ".hxx": "cpp",
    ".rs": "rust",
}

def _detect_lang_by_ext(file_path: Path) -> str:
    """Detect language from file extension without requiring tree-sitter."""
    return _EXT_TO_LANG.get(file_path.suffix.lower(), "unknown")


# =============================================================================
# 1. EXPANDED SECURITY RULES (JS: 32 rules, Java: 28 rules)
# =============================================================================

JS_EXPANDED_RULES: List[Tuple[str, str, str, str, str, str]] = [
    ("js-proto-pollution-assign", r'Object\.assign\s*\(\s*\{\s*\}\s*,', "Prototype pollution: Object.assign({}, userInput)", "critical", "CWE-1321", "Use Object.create(null)"),
    ("js-proto-pollution-merge", r'\b(?:merge|deepMerge|deepExtend|defaultsDeep)\s*\([^)]*(?:user|input|req|body|data)', "Prototype pollution: merge with user input", "high", "CWE-1321", "Block __proto__ keys"),
    ("js-proto-access", r'__proto__\s*[=:\[]', "Direct __proto__ manipulation", "critical", "CWE-1321", "Use Object.create(null)"),
    ("js-dom-xss-innerhtml", r'\.innerHTML\s*=\s*(?!["\']\s*["\'])', "DOM XSS: innerHTML with non-literal", "high", "CWE-79", "Use textContent or DOMPurify"),
    ("js-dom-xss-outerhtml", r'\.outerHTML\s*=\s*(?!["\']\s*["\'])', "DOM XSS: outerHTML with non-literal", "high", "CWE-79", "Use textContent"),
    ("js-dom-xss-insert-adjacent", r'\.insertAdjacentHTML\s*\([^)]*(?:user|input|req|data|location)', "DOM XSS: insertAdjacentHTML with user input", "high", "CWE-79", "Use DOMPurify"),
    ("js-dom-xss-document-write", r'document\.write\s*\([^)]*(?:user|input|req|data|location|cookie)', "DOM XSS: document.write with user input", "critical", "CWE-79", "Never use document.write with dynamic content"),
    ("js-dom-xss-href", r'\.href\s*=\s*(?:location|window\.location|document\.URL|location\.hash|location\.search)', "DOM XSS: href from location object", "high", "CWE-79", "Validate URL protocol"),
    ("js-postmessage-no-origin", r'addEventListener\s*\(\s*["\']message["\'][^)]*\)(?!.*origin)', "postMessage without origin check", "high", "CWE-346", "Check event.origin"),
    ("js-redos-nested", r'(?:\([^\)]*[+*][^\)]*\)[+*]|\[[^\]]*[+*][^\]]*\)[+*])', "ReDoS: nested quantifiers in regex", "high", "CWE-1333", "Use re2 or restructure"),
    ("js-insecure-deser-eval", r'eval\s*\(\s*(?:JSON\.parse|atob|Buffer)', "Insecure deserialization: eval(JSON.parse())", "critical", "CWE-913", "Never eval deserialized data"),
    ("js-function-constructor", r'new\s+Function\s*\(', "Code injection: new Function()", "critical", "CWE-95", "Avoid dynamic code generation"),
    ("js-open-redirect", r'(?:window\.location|location\.href)\s*=\s*(?:req|request|query|params|url|redirect|next|returnUrl)', "Open redirect: user input to location", "high", "CWE-601", "Validate against allowlist"),
    ("js-open-redirect-express", r'res\.redirect\s*\(\s*(?:req\.(?:query|params|body)\.|req\.get\()', "Open redirect: Express res.redirect with user input", "high", "CWE-601", "Validate target"),
    ("js-path-traversal-join", r'path\.(?:join|resolve)\s*\([^)]*(?:req|query|params|body|user|input)', "Path traversal: path.join with user input", "high", "CWE-22", "Validate path components"),
    ("js-path-traversal-readfile", r'(?:readFile|readFileSync|createReadStream)\s*\([^)]*(?:req|query|params|user|input)', "Path traversal: file read with user input", "high", "CWE-22", "Validate paths"),
    ("js-sql-injection-concat", r'(?:\.query|\.execute)\s*\(\s*(?:"[^"]*"\s*\+|`[^`]*\$\{)', "SQL injection: query with concatenation/template literal", "critical", "CWE-89", "Use parameterized queries"),
    ("js-ssrf-fetch", r'(?:fetch|axios|request|got)\s*\(\s*(?:req|query|params|body|user|url)\b', "SSRF: HTTP request with user URL", "high", "CWE-918", "Validate URL against allowlist"),
    ("js-insecure-cookie-no-httponly", r'(?:res\.cookie|document\.cookie)\s*\([^)]*(?!.*httpOnly)', "Insecure cookie: no httpOnly", "medium", "CWE-1004", "Add httpOnly: true"),
    ("js-insecure-cookie-no-secure", r'res\.cookie\s*\([^)]*(?!.*secure)(?!.*httpOnly)', "Insecure cookie: no secure flag", "medium", "CWE-614", "Add secure: true"),
    ("js-race-async", r'async\s+function\s+\w+[^{]*\{[^}]*if\s*\([^)]*\)[^{]*(?:await|fetch|setTimeout)', "Race condition: check-then-await", "medium", "CWE-362", "Use atomic operations"),
    ("js-unhandled-promise", r'\.(?:then|catch)\s*\(\s*(?:\(\)\s*=>\s*\{\s*\}|function\s*\(\)\s*\{\s*\})\s*\)', "Empty .catch() — rejection swallowed", "medium", "CWE-755", "Log the error"),
    ("js-session-fixation", r'(?:login|signin|authenticate)\w*\s*\([^)]*\)\s*\{(?!.*(?:regenerate|destroy|rotate))', "Session fixation: no session regeneration on login", "medium", "CWE-384", "Call req.session.regenerate()"),
    ("js-insecure-upload", r'(?:multer|formidable|busboy)\s*\(\s*\{[^}]*(?!.*fileFilter)', "Insecure upload: no file type filter", "high", "CWE-434", "Add fileFilter"),
    ("js-csrf-no-token", r'(?:fetch|axios|XMLHttpRequest)\s*\([^)]*(?!.*[Cc]srf|.*[Xx]-[Cc][Ss][Rr][Ff])', "Missing CSRF token", "medium", "CWE-352", "Add X-CSRF-Token header"),
    ("js-insecure-random", r'Math\.random\s*\(\s*\)', "Insecure random: Math.random()", "high", "CWE-330", "Use crypto.getRandomValues()"),
    ("js-hardcoded-api-key", r'(?:api[_-]?key|apikey|secret|token|auth)\s*[=:]\s*["\'][A-Za-z0-9_\-]{20,}["\']', "Hardcoded API key/secret", "critical", "CWE-798", "Move to env vars"),
    ("js-express-no-helmet", r'express\s*\(\s*\)(?!.*helmet)', "Express without Helmet — missing security headers", "low", "CWE-693", "Use helmet()"),
    ("js-cors-wildcard", r'cors\s*\(\s*\{\s*origin\s*:\s*["\']\*["\']', "CORS wildcard: all origins", "high", "CWE-942", "Restrict origins"),
    ("js-bl-missing-validation", r'req\.(?:body|query|params)\.\w+\s*(?!!|!==|typeof|instanceof)', "User input without validation", "low", "CWE-20", "Validate with joi/zod"),
    ("js-role-client-side", r'(?:role|admin|isAdmin|userType)\s*(?:===|==)\s*["\'](?:admin|superuser)["\']', "Client-side role check — bypassable", "high", "CWE-602", "Move auth to server"),
    ("js-bl-no-rate-limit", r'(?:login|signin|register|signup|reset|otp)\w*\s*(?:\(|route)', "Auth endpoint — verify rate limiting", "medium", "CWE-307", "Add rate limiter"),
]

JAVA_EXPANDED_RULES: List[Tuple[str, str, str, str, str, str]] = [
    ("java-spring-no-auth", r'@(?:GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)(?!.*@(?:PreAuthorize|PostAuthorize|Secured|RolesAllowed))', "Spring endpoint without @PreAuthorize", "high", "CWE-862", "Add @PreAuthorize"),
    ("java-spring-csrf-disabled", r'\.csrf\s*\(\s*\)\s*\.disable\s*\(\s*\)', "CSRF protection disabled", "high", "CWE-352", "Remove .csrf().disable()"),
    ("java-spring-permit-all", r'\.requestMatchers\s*\([^)]*\)\s*\.permitAll', "Spring Security permitAll — no auth", "medium", "CWE-862", "Use .authenticated()"),
    ("java-deserialization", r'ObjectInputStream[\s\S]*?\.readObject', "Insecure deserialization: readObject()", "critical", "CWE-502", "Use JSON or ObjectInputFilter"),
    ("java-xxe-docbuilder", r'DocumentBuilderFactory\.newInstance\s*\(\s*\)(?!.*setFeature\s*\(\s*["\']http://apache.org/xml/features/disallow-doctype-decl)', "XXE: DocumentBuilderFactory without entity restrictions", "critical", "CWE-611", "Disable external entities"),
    ("java-xxe-sax", r'SAXParserFactory\.newInstance\s*\(\s*\)(?!.*setFeature)', "XXE: SAXParserFactory without restrictions", "critical", "CWE-611", "Disable external entities"),
    ("java-sql-concat", r'(?:executeQuery|execute|executeUpdate)\s*\(\s*["\'](?:SELECT|INSERT|UPDATE|DELETE|DROP)[^"]*"\s*\+', "SQL injection: concatenated query", "critical", "CWE-89", "Use PreparedStatement"),
    ("java-sql-format", r'String\.format\s*\(\s*["\'](?:SELECT|INSERT|UPDATE|DELETE|DROP)', "SQL injection: String.format for SQL", "critical", "CWE-89", "Use PreparedStatement"),
    ("java-ssrf-url", r'(?:HttpURLConnection|URL)\s*\(\s*["\']https?://["\']\s*\+\s*(?:request|req|param|user)', "SSRF: HttpURLConnection with user URL", "high", "CWE-918", "Validate URL against allowlist"),
    ("java-ssrf-rest", r'(?:RestTemplate|WebClient|OkHttpClient)\s*\.\s*(?:getForObject|postForObject|exchange)\s*\(\s*(?:request|req|param|user)', "SSRF: HTTP client with user URL", "high", "CWE-918", "Validate URL"),
    ("java-ldap-injection", r'(?:LdapContext|DirContext)\s*\.\s*search\s*\([^)]*(?:\+|String\.format)', "LDAP injection: search with concatenation", "critical", "CWE-90", "Escape input"),
    ("java-path-traversal", r'new\s+File\s*\(\s*(?:request|req|param|user|input|getparameter)', "Path traversal: new File with user input", "high", "CWE-22", "Validate path"),
    ("java-path-paths", r'Paths\.get\s*\(\s*(?:request|req|param|user|input|getparameter)', "Path traversal: Paths.get with user input", "high", "CWE-22", "Validate path"),
    ("java-open-redirect", r'sendRedirect\s*\(\s*(?:request|req|param|getParameter|getAttribute)', "Open redirect: sendRedirect with user input", "high", "CWE-601", "Validate URL"),
    ("java-insecure-random", r'new\s+Random\s*\(\s*\)', "Insecure random: java.util.Random", "high", "CWE-330", "Use SecureRandom"),
    ("java-hardcoded-password", r'(?:password|passwd|secret|apiKey|api_key|token)\s*=\s*"[^"]{6,}"', "Hardcoded credential", "critical", "CWE-798", "Use env vars"),
    ("java-hardcoded-db-creds", r'(?:jdbc:|datasource).*password\s*=\s*[^"\'\s]+', "Hardcoded DB credentials", "critical", "CWE-798", "Use config server"),
    ("java-logging-sensitive", r'(?:log(?:ger)?|System\.out)\.\w+\s*\([^)]*(?:password|passwd|secret|token|apiKey|creditCard|ssn)', "Sensitive data in log", "high", "CWE-532", "Never log credentials"),
    ("java-missing-valid", r'@RequestBody\s+\w+\s+\w+\s*[),](?!.*@Valid)', "Missing @Valid on @RequestBody", "medium", "CWE-20", "Add @Valid"),
    ("java-catch-stacktrace", r'catch\s*\(\s*Exception\s+\w+\s*\)\s*\{[^}]*printStackTrace\s*\(\s*\)', "Stack trace leaked to user", "medium", "CWE-209", "Log server-side only"),
    ("java-nosql-injection", r'(?:BasicDBObject|Document|Bson)\s*\(\s*["\']\$\w+["\']', "NoSQL injection: MongoDB $ operator", "high", "CWE-943", "Sanitize input"),
    ("java-bl-missing-transactional", r'@(?:PostMapping|PutMapping|DeleteMapping)(?![^@]*@Transactional)[^{]*\{[^}]*(?:save|persist|update|delete|merge)', "DB write without @Transactional", "medium", "CWE-754", "Add @Transactional"),
    ("java-bl-optional-get", r'\.get\s*\(\s*\)(?!.*isPresent|.*orElse|.*orElseThrow)', "Optional.get() without isPresent()", "high", "CWE-690", "Use orElseThrow()"),
    ("java-insecure-trustmanager", r'TrustManager[\s\S]*?checkServerTrusted\s*\(\s*\)\s*\{\s*\}', "Insecure TrustManager: empty check", "critical", "CWE-295", "Implement proper validation"),
    ("java-insecure-hostname", r'HostnameVerifier[\s\S]*?return\s+true', "Insecure HostnameVerifier: always true", "critical", "CWE-295", "Implement validation"),
    ("java-redos", r'Pattern\.compile\s*\(\s*"[^"]*(?:\(.*[+*].*\)[+*]|\\d[+*]\\d[+*])', "ReDoS: nested quantifiers", "medium", "CWE-1333", "Simplify regex"),
    ("java-missing-rate-limit", r'@(?:PostMapping|GetMapping)(?![^@]*(?:RateLimit|Throttle|@Limit))[^{]*\{[^}]*(?:login|signin|register|otp|reset)', "Auth endpoint without rate limiting", "medium", "CWE-307", "Add rate limiter"),
    ("java-hql-injection", r'(?:createQuery|createSQLQuery)\s*\(\s*["\'][^"\']*\+', "HQL/SQL injection: query with concatenation", "critical", "CWE-89", "Use parameterized HQL"),
]

def scan_expanded_js(file_path) -> List[UnifiedFinding]:
    try:
        source = file_path.read_text(encoding="utf-8") if hasattr(file_path, 'read_text') else open(file_path).read()
    except Exception:
        return []
    findings = []
    for rule_id, pattern, message, severity, cwe, fix in JS_EXPANDED_RULES:
        for m in re.finditer(pattern, source, re.IGNORECASE):
            findings.append(UnifiedFinding(
                rule_id=f"EXP.{rule_id}", severity=severity, description=message,
                file=str(file_path), line=source[:m.start()].count('\n') + 1,
                language="javascript", category="security", suggestion=fix,
                evidence=m.group(0)[:100], cwe=cwe))
    return findings

def scan_expanded_java(file_path) -> List[UnifiedFinding]:
    try:
        source = file_path.read_text(encoding="utf-8") if hasattr(file_path, 'read_text') else open(file_path).read()
    except Exception:
        return []
    findings = []
    for rule_id, pattern, message, severity, cwe, fix in JAVA_EXPANDED_RULES:
        for m in re.finditer(pattern, source, re.IGNORECASE):
            findings.append(UnifiedFinding(
                rule_id=f"EXP.{rule_id}", severity=severity, description=message,
                file=str(file_path), line=source[:m.start()].count('\n') + 1,
                language="java", category="security", suggestion=fix,
                evidence=m.group(0)[:100], cwe=cwe))
    return findings

def scan_expanded_repo(repo_root: Path, max_files=200) -> List[UnifiedFinding]:
    skip = {".git", "__pycache__", ".venv", "venv", "node_modules", ".stca-cache", "build", "dist", "target"}
    findings = []
    count = 0
    for f in sorted(Path(repo_root).rglob("*")):
        if not f.is_file() or any(p in skip for p in f.parts) or count >= max_files:
            continue
        ext = f.suffix.lower()
        if ext in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"):
            count += 1
            findings.extend(scan_expanded_js(f))
        elif ext == ".java":
            count += 1
            findings.extend(scan_expanded_java(f))
    return findings


# =============================================================================
# 2. CODEBASE UNDERSTANDING (behavioral analysis, all languages)
# =============================================================================

