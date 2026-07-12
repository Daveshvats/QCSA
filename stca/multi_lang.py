"""Multi-language pattern framework — language-agnostic analyzers.

Provides regex-based pattern matching for Python, JS/TS, Go, Java, and C/C++.
Each v2 feature uses this to support all 5 languages without writing 5 AST parsers.

Languages supported: Python, JavaScript/TypeScript, Go, Java, C/C++
"""
from __future__ import annotations

import logging
_logger = logging.getLogger(__name__.replace('stca.', ''))

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple

PYTHON_EXTS = {".py"}
JS_TS_EXTS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
GO_EXTS = {".go"}
JAVA_EXTS = {".java"}
C_CPP_EXTS = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hxx"}
ALL_SOURCE_EXTS = PYTHON_EXTS | JS_TS_EXTS | GO_EXTS | JAVA_EXTS | C_CPP_EXTS


def get_language(file_path: Path) -> str:
    ext = file_path.suffix.lower()
    if ext in PYTHON_EXTS: return "python"
    if ext in JS_TS_EXTS: return "javascript"
    if ext in GO_EXTS: return "go"
    if ext in JAVA_EXTS: return "java"
    if ext in C_CPP_EXTS: return "cpp"
    return "unknown"


@dataclass
class LangFinding:
    file: str
    line: int
    rule_id: str
    severity: str
    description: str
    fix: str
    cwe: str
    confidence: float = 0.7
    language: str = ""


def run_patterns_per_language(file_path: Path, repo_root: Optional[Path] = None,
                                patterns_by_lang: Optional[Dict[str, List[Tuple]]] = None) -> List[LangFinding]:
    if not file_path.exists(): return []
    lang = get_language(file_path)
    if lang == "unknown" or not patterns_by_lang: return []
    patterns = patterns_by_lang.get(lang, [])
    if not patterns: return []
    rel = str(file_path.relative_to(repo_root)) if repo_root else str(file_path)
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []
    findings: List[LangFinding] = []
    lines = source.splitlines()
    for i, line in enumerate(lines, 1):
        for pat in patterns:
            if len(pat) < 7: continue
            rule_id, regex, severity, desc, fix, cwe, conf = pat[:7]
            try:
                if re.search(regex, line):
                    findings.append(LangFinding(file=rel, line=i, rule_id=rule_id,
                        severity=severity, description=desc, fix=fix, cwe=cwe,
                        confidence=conf, language=lang))
            except re.error:
                continue
    # JS multi-line scanners
    if lang == "javascript":
        findings += _scan_js_multiline_delete_via_wrapper(source, rel)
        findings += _scan_js_multiline_useeffect(source, rel)
        findings += _scan_js_axios_no_timeout(source, rel)
    if lang == "java":
        findings += _scan_java_refund_ownership(source, rel)
    return findings


def _scan_js_multiline_delete_via_wrapper(source, rel):
    findings = []
    lines = source.splitlines()
    delete_url_lines = [(i, l.strip()) for i, l in enumerate(lines, 1)
                        if re.search(r'[`"\'][^`"\']*(?:delete|remove|destroy|purge)[^`"\']*[`"\']', l, re.IGNORECASE)]
    wrapper_lines = [(i, l.strip()) for i, l in enumerate(lines, 1)
                     if re.search(r'\b(?:updateData|updateRecord|saveData|patchData|postData|createData|submitData)\s*\(', l)]
    for url_line, _ in delete_url_lines:
        for wrap_line, _ in wrapper_lines:
            if abs(wrap_line - url_line) <= 30 and wrap_line > url_line:
                findings.append(LangFinding(file=rel, line=wrap_line,
                    rule_id="HTTP-JS-DELETE-VIA-UPDATE-MULTI", severity="high",
                    description=f"DELETE via update wrapper (URL at L{url_line}, call at L{wrap_line}) — bypasses DELETE middleware",
                    fix="Use axios.delete(url)", cwe="CWE-358", confidence=0.7, language="javascript"))
                break
    return findings


def _scan_js_multiline_useeffect(source, rel):
    findings = []
    for m in re.finditer(r'useEffect\s*\(\s*\([^)]*\)\s*=>\s*\{', source):
        start = m.end()
        lookahead = source[start:start+500]
        no_deps = re.search(r'\}\s*\)\s*[,;]?\s*\n', lookahead)
        if no_deps:
            end_section = lookahead[no_deps.start():no_deps.end()+20]
            if not re.search(r'\}\s*,\s*\[', end_section) and not re.search(r'\}\s*\)\s*,\s*\[', end_section):
                line_num = source[:m.start()].count("\n") + 1
                findings.append(LangFinding(file=rel, line=line_num,
                    rule_id="REACT-USEEffect-NO-DEPS", severity="medium",
                    description="useEffect without dependency array — runs every render",
                    fix="Add: useEffect(fn, [deps])", cwe="CWE-1333", confidence=0.6, language="javascript"))
    for m in re.finditer(r'useEffect\s*\([^}]*\{[^}]*\}\s*,\s*\[([^\]]+)\]', source, re.DOTALL):
        deps = m.group(1)
        if re.search(r'\w+\.\w+|\{[^}]+\}|\[[^\]]+\]', deps):
            line_num = source[:m.start()].count("\n") + 1
            findings.append(LangFinding(file=rel, line=line_num,
                rule_id="REACT-USEEffect-OBJ-DEP", severity="low",
                description=f"useEffect with object/array dep '{deps.strip()[:30]}' — re-run loop risk",
                fix="Use primitive deps or useMemo", cwe="CWE-1333", confidence=0.5, language="javascript"))
    return findings


def _scan_js_axios_no_timeout(source, rel):
    findings = []
    lines = source.splitlines()
    for i, line in enumerate(lines, 1):
        if re.search(r'\baxios\.(?:get|post|put|delete|patch)\s*\(', line):
            lookahead = "\n".join(lines[i-1:min(i+5, len(lines))])
            if 'timeout' not in lookahead:
                findings.append(LangFinding(file=rel, line=i,
                    rule_id="AXIOS-JS-NO-TIMEOUT", severity="low",
                    description="axios call without timeout", fix="Add timeout: {timeout: 10000}",
                    cwe="CWE-400", confidence=0.4, language="javascript"))
    for i, line in enumerate(lines, 1):
        if re.search(r'\baxios\.(?:post|put|patch)\s*\([^,]+,\s*[^,]+,\s*\{[^}]*\}\s*,\s*\{', line):
            findings.append(LangFinding(file=rel, line=i,
                rule_id="AXIOS-JS-4TH-ARG-IGNORED", severity="medium",
                description="axios.post(url, data, config, extra) — 4th arg IGNORED (timeout in wrong position)",
                fix="Merge into 3rd arg: {headers, timeout}", cwe="CWE-400", confidence=0.85, language="javascript"))
    return findings


def _scan_java_refund_ownership(source, rel):
    findings = []
    lines = source.splitlines()
    refund_re = re.compile(r'\b(?:public|private)\s+\w+\s+(?:initiate|process|create|issue|handle|do)?(?:Refund|refund)\w*\s*\(')
    for i, line in enumerate(lines, 1):
        if not refund_re.search(line): continue
        body = "\n".join(lines[i:min(i+50, len(lines))])
        has_find = bool(re.search(r'(?:paymentRepository|paymentRepo|repo)\.findById\s*\(', body))
        has_ownership = any(p in body for p in
            ['getUserId().equals','belongsTo','verifyOwnership','checkOwnership','isOwner',
             'canAccess','@PreAuthorize','getCurrentUser','SecurityContextHolder'])
        if has_find and not has_ownership:
            findings.append(LangFinding(file=rel, line=i,
                rule_id="REFUND-JAVA-NO-OWNERSHIP-CHECK", severity="high",
                description="Refund method calls findById without ownership check — any user can refund any payment",
                fix="Add: if (!payment.getUserId().equals(currentUser.getId())) throw new ForbiddenException()",
                cwe="CWE-602", confidence=0.8, language="java"))
    return findings


# === CRYPTO_PATTERNS ===
CRYPTO_PATTERNS: Dict[str, List[Tuple]] = {
    "python": [
        ("CRYPTO-MD5", r"\bhashlib\.md5\s*\(", "high", "MD5 cryptographically broken", "Use sha256()", "CWE-327", 0.85),
        ("CRYPTO-SHA1", r"\bhashlib\.sha1\s*\(", "high", "SHA1 cryptographically broken", "Use sha256()", "CWE-327", 0.85),
        ("CRYPTO-AES-ECB", r"\bMODE_ECB\b", "critical", "AES-ECB — identical blocks produce identical ciphertext", "Use MODE_GCM", "CWE-327", 0.95),
        ("CRYPTO-NON-CSPRNG", r"\brandom\.(?:randint|choice|uniform|randrange|sample)\s*\(", "high", "random module NOT cryptographically secure", "Use secrets module", "CWE-338", 0.85),
        ("CRYPTO-RSA-PKCS1", r"\bPKCS1_v1_5\.new\s*\(", "high", "RSA PKCS#1 v1.5 — Bleichenbacher attack", "Use PKCS1_OAEP.new()", "CWE-780", 0.85),
        ("CRYPTO-STATIC-IV", r"\b(?:iv|IV|nonce)\s*=\s*['\"][^'\"]+['\"]", "critical", "Static IV/nonce — catastrophic for GCM", "Use os.urandom(12)", "CWE-323", 0.9),
    ],
    "javascript": [
        ("CRYPTO-JS-AES-ECB", r"\bCryptoJS\.mode\.ECB\b", "critical", "CryptoJS AES-ECB", "Use mode.GCM", "CWE-327", 0.95),
        ("CRYPTO-JS-INSECURE-HASH", r"\bCryptoJS\.(?:MD5|SHA1)\s*\(", "high", "Insecure hash", "Use SHA256", "CWE-327", 0.85),
        ("CRYPTO-JS-MATH-RANDOM", r"\bMath\.random\s*\(\s*\)", "high", "Math.random NOT CSPRNG", "Use crypto.getRandomValues()", "CWE-338", 0.85),
        ("CRYPTO-JS-WEAK-JWT-SECRET", r'jwt\.sign\s*\([^,]+,\s*["\']([^"\']{1,15})["\']', "critical", "JWT weak secret", "Use >=32 chars from env", "CWE-326", 0.9),
    ],
    "go": [
        ("CRYPTO-GO-MD5", r"\bmd5\.New\s*\(", "high", "MD5 broken", "Use sha256.New()", "CWE-327", 0.85),
        ("CRYPTO-GO-SHA1", r"\bsha1\.New\s*\(", "high", "SHA1 broken", "Use sha256.New()", "CWE-327", 0.85),
        ("CRYPTO-GO-DES", r"\bdes\.NewCipher\s*\(", "high", "DES insecure", "Use aes.NewCipher()", "CWE-327", 0.85),
        ("CRYPTO-GO-MATH-RAND", r"\bmath/rand\.(?:Intn|Read|Float|Int)\s*\(", "high", "math/rand NOT CSPRNG", "Use crypto/rand", "CWE-338", 0.85),
    ],
    "java": [
        ("CRYPTO-JAVA-MD5", r'\bMessageDigest\.getInstance\s*\(\s*["\']MD5["\']', "high", "MD5 broken", "Use SHA-256", "CWE-327", 0.85),
        ("CRYPTO-JAVA-SHA1", r'\bMessageDigest\.getInstance\s*\(\s*["\']SHA-?1["\']', "high", "SHA1 broken", "Use SHA-256", "CWE-327", 0.85),
        ("CRYPTO-JAVA-AES-ECB", r'\bCipher\.getInstance\s*\(\s*["\']AES/ECB', "critical", "AES-ECB", "Use AES/GCM/NoPadding", "CWE-327", 0.95),
        ("CRYPTO-JAVA-RSA-PKCS1", r'\bCipher\.getInstance\s*\(\s*["\']RSA/ECB/PKCS1', "high", "RSA PKCS#1 v1.5", "Use OAEPWithSHA-256AndMGF1", "CWE-780", 0.85),
        ("CRYPTO-JAVA-RANDOM", r'\bnew\s+Random\s*\(', "high", "java.util.Random NOT CSPRNG", "Use SecureRandom", "CWE-338", 0.85),
        ("CRYPTO-JAVA-JWT-HS256-WEAK", r'SignatureAlgorithm\.HS256.*["\'][^"\']{1,15}["\']', "high", "JWT HS256 weak secret", "Use >=32 chars from env", "CWE-326", 0.85),
    ],
    "cpp": [
        ("CRYPTO-CPP-MD5", r"\bMD5\s*\(", "high", "MD5 broken", "Use SHA256", "CWE-327", 0.85),
        ("CRYPTO-CPP-SHA1", r"\bSHA1\s*\(", "high", "SHA1 broken", "Use SHA256", "CWE-327", 0.85),
        ("CRYPTO-CPP-STRCPY", r'\bstrcpy\s*\(', "high", "strcpy — buffer overflow", "Use strncpy/strlcpy", "CWE-120", 0.85),
        ("CRYPTO-CPP-GETS", r'\bgets\s*\(', "critical", "gets — always vulnerable", "Use fgets()", "CWE-242", 0.95),
        ("CRYPTO-CPP-SPRINTF", r'\bsprintf\s*\(', "high", "sprintf — buffer overflow", "Use snprintf()", "CWE-120", 0.85),
        ("CRYPTO-CPP-RAND", r'\brand\s*\(\s*\)|srand\s*\(', "high", "rand() NOT CSPRNG", "Use RAND_bytes()", "CWE-338", 0.85),
        ("CRYPTO-CPP-SCANF", r'\bscanf\s*\(', "high", "scanf — buffer overflow", "Use fgets()+sscanf()", "CWE-120", 0.85),
    ],
}

CONCURRENCY_PATTERNS: Dict[str, List[Tuple]] = {
    "python": [
        ("CONC-PY-GATHER-NO-EXC", r"\basyncio\.gather\s*\(", "medium", "asyncio.gather without try/except", "Wrap or use return_exceptions=True", "CWE-754", 0.7),
        ("CONC-PY-CREATE-TASK-NOSTORE", r"\basyncio\.create_task\s*\(", "high", "create_task result not stored — GC risk", "Assign and await", "CWE-404", 0.8),
        ("CONC-PY-LOCK-NO-RELEASE", r"\bthreading\.Lock\s*\(\s*\)", "medium", "Lock without release — deadlock risk", "Use `with lock:`", "CWE-667", 0.6),
    ],
    "javascript": [
        ("CONC-JS-PROMISE-NO-CATCH", r"\bnew\s+Promise\s*\(", "medium", "Promise without .catch()", "Add .catch()", "CWE-755", 0.5),
        ("CONC-JS-ASYNC-NO-TRY", r"\basync\s+(?:function|\w+\s*\()", "info", "async function — verify try/catch", "Wrap await in try/catch", "CWE-755", 0.4),
        ("CONC-JS-PROMISE-ALL-NO-HANDLE", r"\bPromise\.all\s*\(", "high", "Promise.all without try/catch", "Use Promise.allSettled or try/catch", "CWE-755", 0.7),
        ("CONC-JS-SETINTERVAL-NO-CLEAN", r"\bsetInterval\s*\(", "medium", "setInterval without cleanup", "clearInterval in useEffect", "CWE-404", 0.6),
    ],
    "go": [
        ("CONC-GO-GOROUTINE-LEAK", r"\bgo\s+(?:func|\w+\s*\()", "medium", "Goroutine without WaitGroup/context", "Use sync.WaitGroup", "CWE-404", 0.5),
        ("CONC-GO-RECV-NO-SEND", r"<-\s*\w+", "high", "Receive without sender — deadlock", "Use select with default", "CWE-667", 0.4),
    ],
    "java": [
        ("CONC-JAVA-SYNCHRONIZED-THIS", r"synchronized\s*\(\s*this\s*\)", "medium", "synchronized(this) — exposes lock", "Use private final lock", "CWE-667", 0.5),
        ("CONC-JAVA-NEW-THREAD", r"new\s+Thread\s*\(", "medium", "new Thread() — no pool", "Use ExecutorService", "CWE-404", 0.6),
    ],
    "cpp": [
        ("CONC-CPP-PTHREAD-NO-JOIN", r"\bpthread_create\s*\(", "high", "pthread_create without join", "Call pthread_join()", "CWE-404", 0.7),
        ("CONC-CPP-MUTEX-NO-UNLOCK", r"\bpthread_mutex_lock\s*\(", "high", "pthread_mutex_lock without unlock", "Use std::lock_guard", "CWE-667", 0.7),
    ],
}

AUTH_PATTERNS: Dict[str, List[Tuple]] = {
    "python": [
        ("AUTH-PY-DECORATOR", r"@(?:login_required|permission_required|requires_role)", "info", "Auth decorator found", "Verify applied to all sensitive endpoints", "CWE-862", 0.3),
    ],
    "javascript": [
        ("AUTH-JS-USEGUARDS", r"@UseGuards\s*\(", "info", "NestJS auth guard", "Verify on all endpoints", "CWE-862", 0.3),
        ("AUTH-JS-NO-AUTH-ROUTE", r'(?:router|app)\.(?:post|put|delete|patch)\s*\(\s*["\'](?:/api/)?(?:admin|user|delete|payment)', "high", "Sensitive route without auth check", "Add @UseGuards", "CWE-862", 0.6),
        ("AUTH-JS-FETCH-NO-AUTH", r"\bfetch\s*\([^)]+\)(?!\s*\.then.*auth|.*headers.*Auth)", "medium", "fetch() — verify Authorization header", "Add Authorization header", "CWE-306", 0.4),
    ],
    "go": [
        ("AUTH-GO-NO-AUTH-MIDDLEWARE", r'\bhttp\.HandleFunc\s*\(\s*["\']/(?:admin|api/)', "medium", "HTTP handler — verify auth middleware", "Add authMiddleware()", "CWE-862", 0.5),
        ("AUTH-GO-SQL-INJECTION", r'(?:fmt\.Sprintf|".*"\s*\+)\s*SELECT', "critical", "SQL injection via concatenation", "Use db.Query(sql, args...)", "CWE-89", 0.9),
        ("AUTH-GO-CMD-INJECTION", r'exec\.Command\s*\(\s*["\']sh["\']\s*,\s*["\']-c["\']', "critical", "Command injection", "Use explicit args", "CWE-78", 0.9),
        ("AUTH-GO-PATH-TRAVERSAL", r'filepath\.Join\s*\([^)]*\+', "high", "Path traversal", "Use filepath.Clean", "CWE-22", 0.7),
    ],
    "java": [
        ("AUTH-JAVA-PREAUTHORIZE", r"@PreAuthorize\s*\(", "info", "Spring @PreAuthorize", "Verify on all methods", "CWE-862", 0.3),
        ("AUTH-JAVA-HASROLE", r'\bhasRole\s*\(', "info", "hasRole() check", "Verify covers all actions", "CWE-862", 0.3),
        ("AUTH-JAVA-NO-AUTH-REQUEST", r"\b@(?:GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)", "medium", "Spring MVC mapping — verify @PreAuthorize", "Add @PreAuthorize", "CWE-862", 0.5),
        ("AUTH-JAVA-SQL-NO-PARAM", r'\bStatement\s*\+.*\+.*\bexecuteQuery', "critical", "SQL injection via concatenation", "Use PreparedStatement", "CWE-89", 0.9),
        ("AUTH-JAVA-SQL-FORMAT", r'String\.format\s*\(\s*["\']SELECT', "critical", "SQL via String.format", "Use PreparedStatement", "CWE-89", 0.9),
        ("AUTH-JAVA-JPA-QUERY-CONCAT", r'@Query\s*\(\s*["\'].*\+\s*\w+', "high", "@Query with concatenation — JPQL injection", "Use @Param and :paramName", "CWE-89", 0.8),
        ("AUTH-JAVA-CMD-INJECTION", r'Runtime\.getRuntime\(\)\.exec\s*\(\s*[^)]*\+', "critical", "Command injection", "Use ProcessBuilder", "CWE-78", 0.9),
        ("AUTH-JAVA-PATH-TRAVERSAL", r'new\s+File\s*\([^)]*\+', "high", "Path traversal via concatenation", "Validate paths", "CWE-22", 0.7),
        ("AUTH-JAVA-HARDCODED-PATH", r'new\s+File\s*\(\s*["\']/(?:Users|home|var|tmp|etc|opt|root)/', "medium", "Hardcoded absolute file path", "Use config-based paths", "CWE-547", 0.7),
        ("AUTH-JAVA-OPEN-REDIRECT", r'response\.sendRedirect\s*\(\s*request\.getParameter', "medium", "Open redirect", "Validate URL", "CWE-601", 0.6),
        ("AUTH-JAVA-XSS", r'response\.getWriter\(\)\.print\s*\(\s*request\.getParameter', "high", "XSS — user input to response", "Escape output", "CWE-79", 0.8),
        ("AUTH-JAVA-XXE", r'DocumentBuilderFactory\.newInstance\(\)', "medium", "XXE — verify external entities disabled", "Set disallow-doctype-decl", "CWE-611", 0.6),
        ("AUTH-JAVA-AUTOWIRED-FIELD", r'@Autowired\s+private', "medium", "@Autowired field injection", "Use constructor injection", "CWE-1078", 0.6),
        ("AUTH-JAVA-TRANSACTIONAL-NO-ROLLBACK", r'@Transactional\s*(?!\([^)]*rollback)', "low", "@Transactional without rollbackFor", "Add rollbackFor=Exception.class", "", 0.4),
        ("AUTH-JAVA-DESERIALIZATION", r'new\s+ObjectInputStream\s*\(', "high", "Deserialization RCE risk", "Use JSON or whitelist", "CWE-502", 0.85),
        ("AUTH-JAVA-REFLECTION", r'Class\.forName\s*\(', "medium", "Reflection — access control bypass", "Avoid reflection", "CWE-470", 0.5),
        ("AUTH-JAVA-URL-OPEN-STREAM", r'\.openStream\s*\(\s*\)', "medium", "URL.openStream — no timeout, SSRF", "Use HttpURLConnection with timeout", "CWE-400", 0.5),
        ("UPLOAD-JAVA-CONTENT-TYPE-TRUST", r'\.getContentType\s*\(\s*\)', "high", "getContentType() client-controlled — Stored XSS risk", "Use magic-byte sniffing", "CWE-434", 0.85),
        ("COUPON-JAVA-NO-RATE-LIMIT", r'@(?:GetMapping|PostMapping|RequestMapping)\s*\(\s*(?:value\s*=\s*)?["\'][^"\']*coupon', "medium", "Coupon endpoint — verify rate limiting", "Add @RateLimit", "CWE-799", 0.6),
        ("REFUND-JAVA-METHOD", r'\b(?:public|private)\s+\w+\s+(?:initiate|process|create|issue)?Refund\w*\s*\(', "medium", "Refund method — verify ownership check", "Check user owns payment", "CWE-602", 0.5),
    ],
    "cpp": [],
}

MODERN_ATTACK_PATTERNS: Dict[str, List[Tuple]] = {
    "python": [
        ("LLM-PROMPT-INJECTION", r'(?:system|prompt|instruction)\s*(?:\+|\.format|f["\'])\s*(?:user_input|request\.\w+)', "high", "Prompt injection risk", "Sanitize input", "CWE-20", 0.7),
        ("LLM-PICKLE-LOAD", r'\b(?:pickle|torch|joblib)\.load\s*\(', "critical", "Untrusted pickle load — RCE", "Use safetensors", "CWE-502", 0.85),
        ("LLM-OUTPUT-TO-EXEC", r'(?:exec|eval|subprocess\.call|os\.system)\s*\(.*(?:llm_response|completion)', "critical", "LLM output to exec — RCE", "Parse JSON, validate", "CWE-913", 0.9),
    ],
    "javascript": [
        ("LLM-JS-PROMPT-INJECTION", r'(?:systemPrompt|prompt)\s*(?:\+|`|\$\{)', "high", "Prompt injection", "Sanitize input", "CWE-20", 0.7),
        ("WS-NO-ORIGIN", r'(?:WebSocketServer|new\s+WebSocket\.Server)', "medium", "WebSocket — verify origin check", "Check origin", "CWE-346", 0.5),
        ("WS-NO-AUTH-CONNECT", r'wss?\.on\s*\(\s*["\']connection["\']', "high", "WebSocket — verify auth", "Verify token", "CWE-306", 0.6),
        ("GQL-INTROSPECTION", r'introspection\s*[:=]\s*true', "medium", "GraphQL introspection enabled", "Disable in prod", "CWE-200", 0.7),
        ("GRPC-INSECURE", r'grpc\.credentials\.createInsecure\s*\(', "medium", "gRPC insecure — plaintext", "Use createSsl", "CWE-319", 0.7),
    ],
    "go": [
        ("WS-GO-NO-AUTH", r'\bwebsocket\.Upgrader\s*\{', "medium", "WebSocket upgrader — verify auth", "Set CheckOrigin, verify token", "CWE-306", 0.5),
    ],
    "java": [
        ("LLM-JAVA-PICKLE-LOAD", r'ObjectInputStream\s*\(\s*new\s+FileInputStream', "critical", "Untrusted deserialization — RCE", "Use JSON or ObjectInputFilter", "CWE-502", 0.85),
        ("SPRING-CSRF-DISABLED", r'csrf\(\)\.disable\(\)', "high", "CSRF disabled", "Enable CSRF", "CWE-352", 0.8),
        ("SPRING-CORS-WILDCARD", r'allowedOrigins\s*\(\s*["\']\*["\']', "medium", "CORS wildcard", "Restrict origins", "CWE-942", 0.7),
        ("SPRING-H2-CONSOLE", r'spring\.h2\.console\.enabled\s*=\s*true', "medium", "H2 console enabled", "Disable in prod", "CWE-489", 0.6),
        ("SPRING-ACTUATOR-EXPOSE", r'management\.endpoints\.web\.exposure\.include\s*=\s*\*', "high", "Actuator all endpoints exposed", "Restrict to health,info", "CWE-200", 0.8),
        ("SPRING-DEVTOOLS-PROD", r'spring-boot-devtools', "medium", "DevTools in production", "Mark optional", "CWE-489", 0.7),
    ],
    "cpp": [],
}

IDOR_PATTERNS: Dict[str, List[Tuple]] = {
    "javascript": [
        ("IDOR-JS-AXIOS-ID-PATH", r'\baxios\.(?:get|put|delete|patch)\s*\(\s*[`"\'].*\$\{(?:id|userId|employeeId|patientId|accountId)\}', "high", "API call with ID in URL — verify authz", "Verify server checks access", "CWE-639", 0.6),
        ("IDOR-JS-FETCH-ID-PATH", r'\bfetch\s*\(\s*[`"\'].*\$\{(?:id|userId|employeeId|patientId)\}', "high", "fetch() with ID in URL", "Verify server authz", "CWE-639", 0.6),
        ("IDOR-JS-LOCALSTORAGE-ID", r'localStorage\.getItem\s*\(\s*["\'](?:CORP_ID|CAMP_ID|USER_ID|TENANT_ID|ORG_ID)', "high", "Tenant ID from localStorage — IDOR", "Get from server-side JWT", "CWE-639", 0.7),
        ("HTTP-JS-DELETE-VIA-PATCH", r'axios\.patch\s*\(\s*[`"\'][^`"\']*(?:delete|remove|destroy|purge)', "high", "DELETE via PATCH", "Use axios.delete()", "CWE-358", 0.7),
        ("HTTP-JS-DELETE-VIA-POST", r'axios\.post\s*\(\s*[`"\'][^`"\']*(?:delete|remove|destroy|purge)', "medium", "DELETE via POST", "Use axios.delete()", "CWE-358", 0.6),
        ("REACT-DEVTOOLS-PROD", r'<ReactQueryDevtools', "medium", "ReactQueryDevtools in production", "Conditionally render", "CWE-489", 0.7),
    ],
    "python": [
        ("IDOR-PY-FLASK-ID-PATH", r'@app\.route\s*\(\s*[`"\'][^`"\']*<int:(?:id|user_id|employee_id)', "medium", "Flask route with ID — verify authz", "Check access in handler", "CWE-639", 0.5),
        ("IDOR-PY-DJANGO-ID-PATH", r'path\s*\(\s*[`"\'][^`"\']*<(?:int:)?(?:id|user_id|employee_id)', "medium", "Django route with ID — verify authz", "Check access in view", "CWE-639", 0.5),
    ],
    "go": [
        ("IDOR-GO-ID-PATH", r'(?:http\.HandleFunc|mux\.HandleFunc)\s*\(\s*[`"\'][^`"\']*\{(?:id|user_id|userId)\}', "medium", "HTTP route with ID", "Check access in handler", "CWE-639", 0.5),
    ],
    "java": [
        ("IDOR-JAVA-PATHVARIABLE", r'@PathVariable\s*(?:\([^)]*\))?\s*(?:Long|String|Integer|UUID)\s+(?:userId|employeeId|patientId|accountId|orderId|serviceId|corpId|invoiceId|voucherId|id)\b', "medium", "@PathVariable with sensitive ID — verify authz", "Check user has access", "CWE-639", 0.6),
        ("IDOR-JAVA-ID-PATH", r'@(?:GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping)\s*\(\s*["\'][^"\']*\{(?:id|userId|employeeId|patientId|accountId|orderId|serviceId|corpId|invoiceId|voucherId)\}', "medium", "Spring route with ID — verify authz", "Check access via @PreAuthorize", "CWE-639", 0.5),
    ],
    "cpp": [],
}

STATE_MACHINE_PATTERNS: Dict[str, List[Tuple]] = {
    "python": [
        ("SM-PY-FILE-NO-CLOSE", r'\bopen\s*\([^)]+\)(?![^)]*with\b)', "medium", "File opened without `with`", "Use `with open()`", "CWE-775", 0.6),
        ("SM-PY-DB-NO-COMMIT", r'\bcursor\.execute\s*\([^)]+\)(?![^)]*commit)', "medium", "DB execute without commit", "Call conn.commit()", "CWE-754", 0.5),
    ],
    "javascript": [
        ("SM-JS-FS-NO-CLOSE", r'\bfs\.open\s*\((?![^)]*\.close)', "medium", "fs.open without close", "Use fs.promises or close()", "CWE-775", 0.6),
        ("SM-JS-EVENT-NO-REMOVE", r'\baddEventListener\s*\((?![^)]*removeEventListener)', "low", "addEventListener without remove", "Remove in cleanup", "CWE-404", 0.4),
    ],
    "go": [
        ("SM-GO-FILE-NO-CLOSE", r'\bos\.Open\s*\((?![^)]*defer.*Close)', "medium", "os.Open without defer Close", "Add defer f.Close()", "CWE-775", 0.7),
        ("SM-GO-DB-NO-CLOSE", r'\bsql\.Open\s*\((?![^)]*defer.*Close)', "medium", "sql.Open without defer Close", "Add defer db.Close()", "CWE-775", 0.7),
    ],
    "java": [
        ("SM-JAVA-STREAM-NO-CLOSE", r'\bnew\s+(?:FileInputStream|FileOutputStream|BufferedReader)\s*\(', "medium", "Stream without close — resource leak", "Use try-with-resources", "CWE-775", 0.6),
        ("SM-JAVA-CONN-NO-CLOSE", r'\.getConnection\s*\(', "medium", "DB connection without close", "Use try-with-resources", "CWE-775", 0.6),
    ],
    "cpp": [
        ("SM-CPP-MALLOC-NO-FREE", r'\bmalloc\s*\((?![^)]*free)', "high", "malloc without free — memory leak", "Use RAII: std::unique_ptr", "CWE-401", 0.7),
        ("SM-CPP-NEW-NO-DELETE", r'\bnew\s+\w+(?![^;]*delete)', "high", "new without delete — memory leak", "Use std::make_unique", "CWE-401", 0.7),
        ("SM-CPP-FOPEN-NO-FCLOSE", r'\bfopen\s*\((?![^)]*fclose)', "high", "fopen without fclose", "Use RAII wrapper", "CWE-775", 0.7),
    ],
}


def scan_crypto_multi(file_path, repo_root=None):
    return run_patterns_per_language(file_path, repo_root, CRYPTO_PATTERNS)
def scan_concurrency_multi(file_path, repo_root=None):
    return run_patterns_per_language(file_path, repo_root, CONCURRENCY_PATTERNS)
def scan_auth_multi(file_path, repo_root=None):
    return run_patterns_per_language(file_path, repo_root, AUTH_PATTERNS)
def scan_modern_multi(file_path, repo_root=None):
    return run_patterns_per_language(file_path, repo_root, MODERN_ATTACK_PATTERNS)
def scan_idor_multi(file_path, repo_root=None):
    return run_patterns_per_language(file_path, repo_root, IDOR_PATTERNS)
def scan_state_machine_multi(file_path, repo_root=None):
    return run_patterns_per_language(file_path, repo_root, STATE_MACHINE_PATTERNS)

# Merge extra rules for comprehensive coverage
try:
    from .extra_rules import merge_patterns, EXTRA_CRYPTO, EXTRA_AUTH, EXTRA_MODERN, EXTRA_IDOR
    CRYPTO_PATTERNS = merge_patterns(CRYPTO_PATTERNS, EXTRA_CRYPTO)
    AUTH_PATTERNS = merge_patterns(AUTH_PATTERNS, EXTRA_AUTH)
    MODERN_ATTACK_PATTERNS = merge_patterns(MODERN_ATTACK_PATTERNS, EXTRA_MODERN)
    IDOR_PATTERNS = merge_patterns(IDOR_PATTERNS, EXTRA_IDOR)
except Exception:
    pass

def scan_repo_multi(repo_root, scanner, max_files=600):
    findings = []
    skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules", ".stca-cache", "build", "dist"}
    count = 0
    for p in repo_root.rglob("*"):
        if not p.is_file() or any(part in skip_dirs for part in p.parts): continue
        if p.suffix.lower() in ALL_SOURCE_EXTS:
            try: findings += scanner(p, repo_root)
            except Exception: pass  # v4.5: suppressed — add logging
            count += 1
            if count >= max_files: break
    return findings
