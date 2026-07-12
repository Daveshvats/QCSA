"""Expanded security rules — supplements multi_lang.py with additional patterns.

This module adds rules that were lost during recovery and ensures comprehensive
coverage across all 5 languages. It's imported by multi_lang.py at runtime.
"""
from __future__ import annotations
from typing import Dict, List, Tuple

# Additional crypto rules
EXTRA_CRYPTO: Dict[str, List[Tuple]] = {
    "python": [
        ("CRYPTO-PY-CBC-NO-HMAC", r'\bMODE_CBC\b', "high", "AES-CBC without HMAC — padding oracle", "Use AES-GCM", "CWE-327", 0.7),
        ("CRYPTO-PY-NO-SALT", r'(?:pbkdf2_hmac|scrypt)\s*\([^)]*(?!.*salt)', "critical", "Key derivation without salt — rainbow table risk", "Use os.urandom(16)", "CWE-916", 0.85),
        ("CRYPTO-PY-STRING-KEY", r'(?:AES|DES)\.new\s*\(\s*["\'][^"\']+["\']', "high", "String key for cipher — should be bytes", "Use key derivation", "CWE-321", 0.7),
    ],
    "javascript": [
        ("CRYPTO-JS-BCRYPT-LOW", r"bcrypt\.(?:hashSync|hash)\s*\([^,]+,\s*(\d{1,2})\b", "medium", "BCrypt low rounds", "Use >= 10 rounds", "CWE-916", 0.7),
        ("CRYPTO-JS-INNER-HTML", r'\.innerHTML\s*=', "high", "innerHTML — XSS risk", "Use textContent/DOMPurify", "CWE-79", 0.85),
        ("CRYPTO-JS-DOCUMENT-WRITE", r'\bdocument\.write\s*\(', "high", "document.write — XSS", "Use DOM methods", "CWE-79", 0.9),
    ],
    "go": [
        ("CRYPTO-GO-RC4", r'\brc4\.NewCipher\s*\(', "high", "RC4 broken", "Use AES-GCM", "CWE-327", 0.85),
        ("CRYPTO-GO-WEAK-AES", r'aes\.NewCipher.*\n.*\.Encrypt\s*\(', "high", "AES without GCM — likely ECB", "Use cipher.NewGCM()", "CWE-327", 0.7),
    ],
    "java": [
        ("CRYPTO-JAVA-DES", r'\bCipher\.getInstance\s*\(\s*["\']DES["\']', "high", "DES insecure — 56-bit key", "Use AES/GCM", "CWE-327", 0.85),
        ("CRYPTO-JAVA-JWT-NOVERIFY", r'Jwts\.parser\(\)\.setSigningKey\s*\(\s*["\']', "high", "JWT parser with hardcoded key", "Load from secure config", "CWE-321", 0.8),
        ("CRYPTO-JAVA-JWT-URL", r'getParameter\s*\([^)]*token["\']\s*\)', "medium", "JWT in URL parameter — leakage", "Use Authorization header", "CWE-598", 0.7),
    ],
    "cpp": [
        ("CRYPTO-CPP-STRCAT", r'\bstrcat\s*\(', "high", "strcat — buffer overflow", "Use strncat()", "CWE-120", 0.85),
        ("CRYPTO-CPP-STRNCPY-NO-TERM", r'\bstrncpy\s*\([^)]*\)\s*;\s*$', "medium", "strncpy may not null-terminate", "Manually terminate", "CWE-170", 0.5),
        ("CRYPTO-CPP-DES", r'\bDES_set_key|EVP_des_cbc|EVP_des_ecb\b', "high", "DES insecure", "Use EVP_aes_256_gcm()", "CWE-327", 0.85),
    ],
}

# Additional auth/business logic rules
EXTRA_AUTH: Dict[str, List[Tuple]] = {
    "python": [
        ("AUTH-PY-FLASK-NO-AUTH", r'@app\.route\s*\(\s*["\']/(?:admin|api/)', "medium", "Flask route — verify auth decorator", "Add @login_required", "CWE-862", 0.5),
        ("AUTH-PY-DJANGO-NO-AUTH", r'path\s*\(\s*[`"\']/(?:admin|api/)', "medium", "Django route — verify auth", "Add login_required", "CWE-862", 0.5),
        ("AUTH-PY-SQL-INJECTION", r'(?:execute|cursor)\s*\(\s*["\'].*%s.*["\']\s*%', "critical", "SQL injection via string formatting", "Use parameterized queries", "CWE-89", 0.9),
        ("AUTH-PY-CMD-INJECTION", r'os\.system\s*\(\s*[^)]*\+', "critical", "Command injection via concatenation", "Use subprocess with list args", "CWE-78", 0.9),
        ("AUTH-PY-PATH-TRAVERSAL", r'open\s*\(\s*[^)]*\+', "high", "Path traversal via concatenation", "Validate and sanitize paths", "CWE-22", 0.7),
    ],
    "javascript": [
        ("AUTH-JS-AXIOS-NO-AUTH", r'\baxios\.(?:get|post|put|delete|patch)\s*\([^)]+\)(?!.*headers.*Auth)', "medium", "axios call — verify auth header", "Add Authorization header", "CWE-306", 0.4),
        ("AUTH-JS-ROLES", r'@Roles\s*\(', "info", "NestJS role decorator", "Verify role check", "CWE-862", 0.3),
        ("AUTH-JS-NO-AUTH-ROUTE", r'(?:router|app)\.(?:post|put|delete|patch)\s*\(\s*["\'](?:/api/)?(?:admin|user|delete|payment)', "high", "Sensitive route without auth check", "Add @UseGuards", "CWE-862", 0.6),
        # Missing rules restored from gap analysis
        ("CRYPTO-JS-NOT-CONSTANT-TIME", r'\b\w*(?:password|token|secret|jwt|bearer|csrf|apiKey|apikey|api_key|hmac|signature|otp|mfa|totp)\w*\s*===?\s*\w*(?:password|token|secret|jwt|bearer|csrf|apiKey|apikey|api_key|hmac|signature|otp|mfa|totp)\w*', "high", "Secret compared with == — vulnerable to timing attacks", "Use crypto.timingSafeEqual()", "CWE-208", 0.85),
        ("js-cross-portal-token", r'(?:detectPortal|portal)\s*(?:===?|!==?)\s*(?:["\'](?:camp|reporting|feedback|attendance|offsite)["\'])', "medium", "Cross-portal token confusion — interceptor uses page URL", "Verify token belongs to current portal", "CWE-863", 0.6),
        ("js-pii-to-user-email", r'(?:sendToMail|sendEmail|email)\s*\(\s*[^)]*(?:empId|employeeId|patientId|userEmail|emailId)', "critical", "PII/employee data sent to user-controlled email — no validation (CWE-200)", "Verify email against allowlist", "CWE-200", 0.85),
    ],
    "go": [
        ("AUTH-GO-JWT-NO-VERIFY", r'\bjwt\.Parse\s*\(', "medium", "JWT parse — verify signature", "Use jwt.ParseWithClaims", "CWE-347", 0.5),
        ("AUTH-GO-OPEN-REDIRECT", r'http\.Redirect\s*\(\s*[^,]+,\s*r\.URL\.Query\(\)', "medium", "Open redirect", "Validate URL", "CWE-601", 0.6),
    ],
    "java": [
        ("AUTH-JAVA-SECURED", r'@Secured\s*\(', "info", "Spring @Secured", "Verify on all methods", "CWE-862", 0.3),
        ("AUTH-JAVA-ROLES-ALLOWED", r'@RolesAllowed\s*\(', "info", "Jakarta @RolesAllowed", "Verify on all methods", "CWE-862", 0.3),
        ("AUTH-JAVA-HASAUTHORITY", r'\bhasAuthority\s*\(', "info", "hasAuthority() check", "Verify covers all actions", "CWE-862", 0.3),
        ("AUTH-JAVA-SQL-FORMAT", r'String\.format\s*\(\s*["\']SELECT', "critical", "SQL via String.format", "Use PreparedStatement", "CWE-89", 0.9),
        ("AUTH-JAVA-JPA-QUERY-CONCAT", r'@Query\s*\(\s*["\'].*\+\s*\w+', "high", "@Query with concatenation — JPQL injection", "Use @Param", "CWE-89", 0.8),
        ("AUTH-JAVA-CMD-INJECTION", r'Runtime\.getRuntime\(\)\.exec\s*\(\s*[^)]*\+', "critical", "Command injection", "Use ProcessBuilder", "CWE-78", 0.9),
        ("AUTH-JAVA-PATH-TRAVERSAL", r'new\s+File\s*\([^)]*\+', "high", "Path traversal", "Validate paths", "CWE-22", 0.7),
        ("AUTH-JAVA-HARDCODED-PATH", r'new\s+File\s*\(\s*["\']/(?:Users|home|var|tmp|etc|opt|root)/', "medium", "Hardcoded absolute path", "Use config paths", "CWE-547", 0.7),
        ("AUTH-JAVA-OPEN-REDIRECT", r'response\.sendRedirect\s*\(\s*request\.getParameter', "medium", "Open redirect", "Validate URL", "CWE-601", 0.6),
        ("AUTH-JAVA-XSS", r'response\.getWriter\(\)\.print\s*\(\s*request\.getParameter', "high", "XSS — user input to response", "Escape output", "CWE-79", 0.8),
        ("AUTH-JAVA-LDAP-INJECTION", r'searchControls\([^)]*\+', "high", "LDAP injection", "Use parameterized queries", "CWE-90", 0.7),
        ("AUTH-JAVA-XXE", r'DocumentBuilderFactory\.newInstance\(\)', "medium", "XXE — verify entities disabled", "Set disallow-doctype-decl", "CWE-611", 0.6),
        ("AUTH-JAVA-VALUE-HARDCODED", r'@Value\s*\(\s*["\'][^"$\{]*["\']\s*\)', "low", "@Value with hardcoded literal", "Use ${property}", "", 0.4),
        ("AUTH-JAVA-TRANSACTIONAL-NO-ROLLBACK", r'@Transactional\s*(?!\([^)]*rollback)', "low", "@Transactional without rollbackFor", "Add rollbackFor=Exception.class", "", 0.4),
        ("AUTH-JAVA-DESERIALIZATION", r'new\s+ObjectInputStream\s*\(', "high", "Deserialization RCE risk", "Use JSON or whitelist", "CWE-502", 0.85),
        ("AUTH-JAVA-REFLECTION", r'Class\.forName\s*\(', "medium", "Reflection — access control bypass", "Avoid reflection", "CWE-470", 0.5),
        ("AUTH-JAVA-URL-OPEN-STREAM", r'\.openStream\s*\(\s*\)', "medium", "URL.openStream — no timeout, SSRF", "Use HttpURLConnection with timeout", "CWE-400", 0.5),
        ("UPLOAD-JAVA-CONTENT-TYPE-TRUST", r'\.getContentType\s*\(\s*\)', "high", "getContentType() client-controlled — Stored XSS risk", "Use magic-byte sniffing", "CWE-434", 0.85),
        ("COUPON-JAVA-NO-RATE-LIMIT", r'@(?:GetMapping|PostMapping|RequestMapping)\s*\(\s*(?:value\s*=\s*)?["\'][^"\']*coupon', "medium", "Coupon endpoint — verify rate limiting", "Add @RateLimit", "CWE-799", 0.6),
        ("REFUND-JAVA-METHOD", r'\b(?:public|private)\s+\w+\s+(?:initiate|process|create|issue)?Refund\w*\s*\(', "medium", "Refund method — verify ownership check", "Check user owns payment", "CWE-602", 0.5),
        # Missing rules restored from gap analysis
        ("SPRING-SECURITY-DEBUG", r'debug\(true\)', "low", "Spring Security debug mode — leaks internals", "Disable in production", "CWE-489", 0.5),
        ("CRYPTO-JAVA-WEAK-KEY", r'\bSecretKeySpec\s*\(\s*[^,]+,\s*["\']AES["\']\s*\)', "medium", "Hardcoded AES key (verify length and source)", "Load key from secure storage", "CWE-321", 0.6),
    ],
    "cpp": [
        ("AUTH-CPP-SYSTEM", r'\bsystem\s*\(', "high", "system() — command injection", "Use execve/fork", "CWE-78", 0.9),
        ("CONC-CPP-ATOMIC-RELAXED", r"std::memory_order_relaxed", "medium", "Relaxed memory order — data race risk", "Use acquire/release", "CWE-362", 0.5),
    ],
}

# Additional modern attack rules
EXTRA_MODERN: Dict[str, List[Tuple]] = {
    "python": [
        ("LLM-NO-RATE-LIMIT", r'(?:openai|anthropic)\.completions\.create', "medium", "LLM API without rate limiting", "Add 10 req/min", "CWE-770", 0.5),
        ("WS-NO-AUTH-PY", r'\bwebsocket\s*\.(?:serve|connect)\s*\((?![^)]*(?:auth|token|verify))', "high", "WebSocket without auth", "Verify token", "CWE-306", 0.6),
    ],
    "javascript": [
        ("GQL-NO-DEPTH-LIMIT", r'(?:ApolloServer|graphqlhttp)\s*\((?![^)]*depthLimit)', "medium", "GraphQL without depth limit", "Add depthLimit: 10", "CWE-770", 0.5),
        ("GRPC-INSECURE", r'grpc\.credentials\.createInsecure\s*\(', "medium", "gRPC insecure — plaintext", "Use createSsl", "CWE-319", 0.7),
    ],
    "go": [
        ("GRPC-GO-INSECURE", r'grpc\.NewServer\s*\(\s*grpc\.(?:Insecure|creds\.NewServerTLSFromFile)', "high", "gRPC — verify TLS", "Use TLS creds", "CWE-319", 0.6),
    ],
    "java": [
        ("SPRING-DEVTOOLS-PROD", r'spring-boot-devtools', "medium", "DevTools in production", "Mark optional", "CWE-489", 0.7),
        ("SPRING-CSRF-DISABLED", r'csrf\(\)\.disable\(\)', "high", "CSRF disabled", "Enable CSRF", "CWE-352", 0.8),
        ("SPRING-CORS-WILDCARD", r'allowedOrigins\s*\(\s*["\']\*["\']', "medium", "CORS wildcard", "Restrict origins", "CWE-942", 0.7),
        ("SPRING-H2-CONSOLE", r'spring\.h2\.console\.enabled\s*=\s*true', "medium", "H2 console enabled", "Disable in prod", "CWE-489", 0.6),
        ("SPRING-ACTUATOR-EXPOSE", r'management\.endpoints\.web\.exposure\.include\s*=\s*\*', "high", "Actuator all endpoints", "Restrict", "CWE-200", 0.8),
        ("LLM-JAVA-PICKLE-LOAD", r'ObjectInputStream\s*\(\s*new\s+FileInputStream', "critical", "Untrusted deserialization — RCE", "Use JSON/ObjectInputFilter", "CWE-502", 0.85),
    ],
    "cpp": [],
}

# Additional IDOR rules
EXTRA_IDOR: Dict[str, List[Tuple]] = {
    "javascript": [
        ("IDOR-JS-LOCALSTORAGE-ID", r'localStorage\.getItem\s*\(\s*["\'](?:CORP_ID|CAMP_ID|USER_ID|TENANT_ID|ORG_ID)', "high", "Tenant ID from localStorage — IDOR", "Get from server-side JWT", "CWE-639", 0.7),
        ("HTTP-JS-DELETE-VIA-PATCH", r'axios\.patch\s*\(\s*[`"\'][^`"\']*(?:delete|remove|destroy|purge)', "high", "DELETE via PATCH", "Use axios.delete()", "CWE-358", 0.7),
        ("HTTP-JS-DELETE-VIA-POST", r'axios\.post\s*\(\s*[`"\'][^`"\']*(?:delete|remove|destroy|purge)', "medium", "DELETE via POST", "Use axios.delete()", "CWE-358", 0.6),
        ("REACT-DEVTOOLS-PROD", r'<ReactQueryDevtools', "medium", "ReactQueryDevtools in production", "Conditionally render", "CWE-489", 0.7),
        ("AXIOS-JS-4TH-ARG-IGNORED", r'\baxios\.(?:post|put|patch)\s*\([^,]+,\s*[^,]+,\s*\{[^}]*\}\s*,\s*\{', "medium", "axios 4th arg IGNORED (timeout wrong position)", "Merge into 3rd arg", "CWE-400", 0.85),
    ],
    "python": [
        ("IDOR-PY-FLASK-ID-PATH", r'@app\.route\s*\(\s*[`"\'][^`"\']*<int:(?:id|user_id|employee_id)', "medium", "Flask route with ID — verify authz", "Check access", "CWE-639", 0.5),
        ("IDOR-PY-DJANGO-ID-PATH", r'path\s*\(\s*[`"\'][^`"\']*<(?:int:)?(?:id|user_id|employee_id)', "medium", "Django route with ID — verify authz", "Check access", "CWE-639", 0.5),
    ],
    "go": [
        ("IDOR-GO-ID-PATH", r'(?:http\.HandleFunc|mux\.HandleFunc)\s*\(\s*[`"\'][^`"\']*\{(?:id|user_id|userId)\}', "medium", "HTTP route with ID", "Check access", "CWE-639", 0.5),
    ],
    "java": [
        ("IDOR-JAVA-PATHVARIABLE", r'@PathVariable\s*(?:\([^)]*\))?\s*(?:Long|String|Integer|UUID)\s+(?:userId|employeeId|patientId|accountId|orderId|serviceId|corpId|invoiceId|voucherId|id)\b', "medium", "@PathVariable with sensitive ID", "Check user access", "CWE-639", 0.6),
        ("IDOR-JAVA-ID-PATH", r'@(?:GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping)\s*\(\s*["\'][^"\']*\{(?:id|userId|employeeId|patientId|accountId|orderId|serviceId|corpId|invoiceId|voucherId)\}', "medium", "Spring route with ID", "Check via @PreAuthorize", "CWE-639", 0.5),
    ],
    "cpp": [],
}
