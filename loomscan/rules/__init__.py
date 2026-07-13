"""Rule registry — discover and pull rule packs.

A "rule pack" is a curated set of Semgrep or Rego rules. LoomScan bundles several
packs in loomscan/rules/packs/, and users can pull additional packs from URLs
into ~/.loomscan/rules/.
"""
from __future__ import annotations

import urllib.request
from pathlib import Path
from typing import List, Dict


# Built-in rule packs shipped with LoomScan
BUILTIN_PACKS = {
    # LoomScan original packs
    "python-security": {
        "path": "packs/python-security.yml",
        "language": "python",
        "rules": 26,
        "description": "OWASP Top 10 + Python-specific antipatterns",
    },
    "python-frameworks": {
        "path": "packs/python-frameworks.yml",
        "language": "python",
        "rules": 35,
        "description": "Django, Flask, FastAPI framework-specific rules",
    },
    "javascript-security": {
        "path": "packs/javascript-security.yml",
        "language": "javascript,typescript",
        "rules": 23,
        "description": "XSS, prototype pollution, SSRF, SQL injection",
    },
    "javascript-frameworks": {
        "path": "packs/javascript-frameworks.yml",
        "language": "javascript,typescript",
        "rules": 30,
        "description": "Express, React, Next.js, NestJS framework-specific rules",
    },
    "go-security": {
        "path": "packs/go-security.yml",
        "language": "go",
        "rules": 12,
        "description": "Crypto, SQL injection, TLS, path traversal",
    },
    "java-security": {
        "path": "packs/java-security.yml",
        "language": "java",
        "rules": 12,
        "description": "Deserialization, XXE, SQL injection",
    },
    "java-frameworks": {
        "path": "packs/java-frameworks.yml",
        "language": "java",
        "rules": 25,
        "description": "Spring, Hibernate, JPA framework-specific rules",
    },
    "cpp-security": {
        "path": "packs/cpp-security.yml",
        "language": "c,cpp",
        "rules": 12,
        "description": "Buffer overflows, format strings, use-after-free",
    },
    # v4.36: Renamed from "-ported" to "-inspired" to be honest about what
    # these are: concept adaptations from other tools, not literal ports.
    # The rules scan Python code (the source tools target Kotlin/Java/R/Lua).
    "detekt-inspired": {
        "path": "packs/detekt-inspired.yml",
        "language": "python",
        "rules": 26,
        "description": "Concepts inspired by detekt (Kotlin) adapted to Python: complexity, style, empty-blocks, exceptions, potential-bugs, naming, performance",
    },
    "spotbugs-inspired": {
        "path": "packs/spotbugs-inspired.yml",
        "language": "python",
        "rules": 19,
        "description": "Concepts inspired by SpotBugs (Java) adapted to Python: BAD_PRACTICE, CORRECTNESS, MALICIOUS_CODE, MULTI_THREADING, PERFORMANCE, STYLE",
    },
    "lintr-inspired": {
        "path": "packs/lintr-inspired.yml",
        "language": "python",
        "rules": 20,
        "description": "Concepts inspired by lintr (R) adapted to Python: assignment, braces, operators, quotes, semicolons, spaces, naming, deprecated",
    },
    "luacheck-inspired": {
        "path": "packs/luacheck-inspired.yml",
        "language": "python",
        "rules": 15,
        "description": "Concepts inspired by luacheck (Lua) adapted to Python: globals, read-only, unused, recursion, redefined, shadow, type, format",
    },
    "react-security": {
        "path": "packs/react-security.yml",
        "language": "javascript,typescript",
        "rules": 32,
        "description": "React/JS-specific: localStorage JWT, JSX XSS, AES-ECB, hardcoded keys, test URLs, auth guards, switch/default, fetch without auth, JSON.parse, setInterval, CryptoJS, template literal XSS",
    },
    # v4.30: New language packs (v4.34 expanded)
    "rust-security": {
        "path": "packs/rust-security.yml",
        "language": "rust",
        "rules": 61,
        "description": "Rust: unsafe, transmute, Command::new injection, unwrap panic, FFI, asm!, TLS, crypto",
    },
    "php-security": {
        "path": "packs/php-security.yml",
        "language": "php",
        "rules": 102,
        "description": "PHP: eval, unserialize, SQL injection, XSS, session fixation, RFI/LFI, XXE, crypto",
    },
    "ruby-security": {
        "path": "packs/ruby-security.yml",
        "language": "ruby",
        "rules": 79,
        "description": "Ruby: eval, Marshal.load, html_safe XSS, mass assignment, CSRF, Brakeman-inspired (constantize, send, render)",
    },
    # v4.34: New packs
    "csharp-security": {
        "path": "packs/csharp-security.yml",
        "language": "csharp",
        "rules": 51,
        "description": "C#/.NET: Process.Start, MD5/SHA1/DES, BinaryFormatter, XXE, SQL injection, async deadlocks",
    },
    "swift-security": {
        "path": "packs/swift-security.yml",
        "language": "swift",
        "rules": 30,
        "description": "Swift/iOS: force unwrap, Keychain misuse, MD5/SHA1, UserDefaults secrets, arc4random",
    },
    "scala-security": {
        "path": "packs/scala-security.yml",
        "language": "scala",
        "rules": 30,
        "description": "Scala: Runtime.exec, ObjectInputStream, XML XXE, SQL interpolation, null/NPE, Await.result",
    },
    # v4.35: 4 new packs
    "kotlin-security": {
        "path": "packs/kotlin-security.yml",
        "language": "kotlin",
        "rules": 50,
        "description": "Kotlin: Runtime.exec, ProcessBuilder, MD5/SHA1/DES, ECB, Random, JDBC templates, ObjectInputStream, XXE, coroutines, !!, lateinit",
    },
    "sql-security": {
        "path": "packs/sql-security.yml",
        "language": "sql",
        "rules": 51,
        "description": "SQL: SELECT *, UPDATE/DELETE without WHERE, DROP, GRANT ALL, xp_cmdshell, INTO OUTFILE, hardcoded passwords, LIKE %, ORDER BY RAND()",
    },
    "bash-security": {
        "path": "packs/bash-security.yml",
        "language": "bash",
        "rules": 51,
        "description": "Bash/Sh: eval, source var, rm -rf, curl|sh, wget --no-check-certificate, unquoted vars, chmod 777, sudo with var, iptables -F",
    },
    "dart-security": {
        "path": "packs/dart-security.yml",
        "language": "dart",
        "rules": 30,
        "description": "Dart/Flutter: Process.run, MD5/SHA1, AES-ECB, Random, SharedPreferences secrets, http (no HTTPS), rawQuery, FFI, Isolate",
    },
    # v4.36: 4 new packs
    "lua-security": {
        "path": "packs/lua-security.yml",
        "language": "lua",
        "rules": 35,
        "description": "Lua: loadstring, dofile, os.execute, io.popen, MD5/SHA1, math.random, hardcoded secrets, string.format with SQL",
    },
    "r-security": {
        "path": "packs/r-security.yml",
        "language": "r",
        "rules": 35,
        "description": "R: eval/parse, system/system2, source/load/readRDS user input, MD5/SHA1, sample/runif, dbGetQuery with paste/sprintf",
    },
    "haskell-security": {
        "path": "packs/haskell-security.yml",
        "language": "haskell",
        "rules": 30,
        "description": "Haskell: unsafePerformIO/unsafeCoerce, system/rawSystem, MD5/SHA1, System.Random, partial functions (head/tail/fromJust/error/undefined)",
    },
    "elixir-security": {
        "path": "packs/elixir-security.yml",
        "language": "elixir",
        "rules": 30,
        "description": "Elixir: Code.eval_string, System.cmd, :os.cmd, MD5/SHA1/DES/RC4, :rand.uniform, Ecto query/fragment interpolation, html_safe, String.to_atom",
    },
    # v4.37: 3 new deep packs
    "owasp-top-10": {
        "path": "packs/owasp-top-10.yml",
        "language": "multi",
        "rules": 124,
        "description": "OWASP Top 10 (2021) + CWE Top 25 + Semgrep community-inspired: A01 broken access, A02 crypto, A03 injection, A04 design, A05 misconfig, A06 components, A07 auth, A08 integrity, A09 logging, A10 SSRF",
    },
    "sql-stored-procedures": {
        "path": "packs/sql-stored-procedures.yml",
        "language": "sql",
        "rules": 40,
        "description": "SQL stored procedures deep: dynamic SQL, sp_executesql, EXECUTE AS, GRANT EXEC, triggers, cursors, sp_configure (xp_cmdshell, OLE, CLR, external scripts), sp_OACreate/Method, sp_send_dbmail",
    },
    "bash-deep": {
        "path": "packs/bash-deep.yml",
        "language": "bash",
        "rules": 41,
        "description": "Bash deep: IFS injection, source/mapfile/readarray user input, printf format string, eval set, declare/local/export/typeset user input, trap DEBUG/EXIT/ERR, SSH StrictHostKeyChecking, tar/unzip path traversal",
    },
    # v4.38: 5 new language packs
    "objectivec-security": {
        "path": "packs/objectivec-security.yml",
        "language": "objectivec",
        "rules": 30,
        "description": "Objective-C: NSLog/printf, sprintf/strcpy/gets, system/popen, NSSelectorFromString, Keychain, NSUserDefaults, SSL, ATS, CC_MD5/SHA1, force unwrap",
    },
    "groovy-security": {
        "path": "packs/groovy-security.yml",
        "language": "groovy",
        "rules": 30,
        "description": "Groovy: Eval.me/GroovyShell, GString SQL, String.execute(), Runtime.exec, MD5/SHA1, Random, render GString XSS, GORM find/where GString, Yaml.load, ObjectInputStream",
    },
    "julia-security": {
        "path": "packs/julia-security.yml",
        "language": "julia",
        "rules": 30,
        "description": "Julia: Meta.eval/parse, run with interpolation, shell cmd interpolation, include user path, MD5/SHA1, Random/MersenneTwister, unsafe_string/pointer, ccall, serialize/deserialize",
    },
    "perl-security": {
        "path": "packs/perl-security.yml",
        "language": "perl",
        "rules": 30,
        "description": "Perl: eval string, system/exec/backtick user input, open pipe/2-arg, require/do LFI, MD5/SHA1, rand, CGI param XSS/SQL/RCE, taint mode, Storable.retrieve",
    },
    "cobol-security": {
        "path": "packs/cobol-security.yml",
        "language": "cobol",
        "rules": 25,
        "description": "COBOL: ACCEPT without validation, hardcoded PASSWORD/SECRET, CALL 'SYSTEM'/'popen', DISPLAY of SSN/credit card, ALTER, file OPEN/READ/WRITE without status check",
    },
    # v4.39: Community deep pack
    "semgrep-community-deep": {
        "path": "packs/semgrep-community-deep.yml",
        "language": "multi",
        "rules": 188,
        "description": "Semgrep community-inspired deep rules: Python (subprocess/pickle/yaml/XML/tempfile/os), JS (require/child_process/eval/Function/vm/prototype pollution), Go (SQL/HTML/exec/HTTP/TLS), Java (Runtime/ProcessBuilder/SQL/ObjectInputStream/XML/Cipher/SSL/Spring), Ruby (send/constantize/eval/YAML/Marshal/open/ERB/system), PHP (eval/assert/preg/system/unserialize/include/SQL/header/cURL/extract), Docker/K8s/Terraform IaC, secrets",
    },
    # v4.40: Language-specific deep packs
    "python-deep": {
        "path": "packs/python-deep.yml",
        "language": "python",
        "rules": 188,
        "description": "Python deep: Django (DEBUG, SECRET_KEY, ALLOWED_HOSTS, CSRF, sessions, raw SQL, mark_safe), Flask (debug, secret_key, CORS, send_file, render_template_string, Markup), FastAPI (CORS, JWT, docs, Passlib), general Python (eval/exec, subprocess, pickle/yaml/marshal, XML XXE, hashlib, random, requests, paramiko, FTP/SMTP/telnet, ctypes, importlib)",
    },
    "javascript-deep": {
        "path": "packs/javascript-deep.yml",
        "language": "javascript,typescript",
        "rules": 159,
        "description": "JS/TS deep: Express (helmet, CORS, body limit, static, sendFile, redirect, render, session, CSRF, Multer, JWT), Node.js (require/import, child_process, eval, Function, vm, prototype pollution, fs, crypto, PBKDF2, AWS SDK), React/Next.js (dangerouslySetInnerHTML, innerHTML, eval, document.write, localStorage, window.open, href, CryptoJS, fetch HTTP, redirect, image), general JS (eval, setTimeout string, innerHTML, document.write, localStorage, window.location, prototype, crypto MD5/ECB/DES, SQL injection, CORS, postMessage, WebSocket)",
    },
    "java-deep": {
        "path": "packs/java-deep.yml",
        "language": "java",
        "rules": 158,
        "description": "Java/Spring deep: Spring (auth, redirect, forward, Thymeleaf, JdbcTemplate, @Query, CORS, CSRF, actuator, H2 console, SpEL, @ModelAttribute, multipart, JWT, password encoders, session), general Java (Runtime.exec, ProcessBuilder, ScriptEngine, Class.forName, SQL, ObjectInputStream, XML XXE, MessageDigest, Cipher DES/ECB/RC4, SSL TrustManager, System.exit, Thread.sleep, JNDI injection, Log4Shell, Jackson default typing, Velocity/FreeMarker SSTI, File path traversal, ReDoS, BeanUtils mass assignment, Struts OGNL, gRPC plaintext, AWS S3/RDS/EC2)",
    },
    "no-secrets-in-logs": {
        "path": "../policies/no_secrets_in_logs.rego",
        "language": "rego",
        "rules": 4,
        "description": "Rego policy — no secrets/PII in log/print statements",
    },
    # v5.1: Framework-specific taint rules
    "framework-taint": {
        "path": "packs/framework-taint.yml",
        "language": "multi",
        "rules": 100,
        "description": "Framework taint: Flask (render_template_string, mark_safe, redirect, send_file), Django (mark_safe, raw SQL, .extra, redirect), Express (res.send/render/redirect/sendFile, CORS, session, CSRF), Spring (Thymeleaf utext, redirect, JdbcTemplate, @Query, SpEL, CORS, CSRF, actuator), React (dangerouslySetInnerHTML, innerHTML, eval, document.write, localStorage), SSRF (requests/urllib/http/fetch/axios/cURL), access control (missing auth decorators, JWT bypass, session fixation)",
    },
}


# Curated external rule packs (free, OSS)
EXTERNAL_PACKS = {
    "semgrep-community": {
        "url": "https://semgrep.dev/r/all",
        "language": "multi",
        "description": "Semgrep community rules — all languages",
    },
    "semgrep-owasp": {
        "url": "https://semgrep.dev/r/owasp-top-25",
        "language": "multi",
        "description": "OWASP Top 25 vulnerability patterns",
    },
    "semgrep-django": {
        "url": "https://semgrep.dev/r/django",
        "language": "python",
        "description": "Django-specific security rules",
    },
    "semgrep-flask": {
        "url": "https://semgrep.dev/r/flask",
        "language": "python",
        "description": "Flask-specific security rules",
    },
    "semgrep-react": {
        "url": "https://semgrep.dev/r/react",
        "language": "javascript,typescript",
        "description": "React-specific security rules",
    },
    "semgrep-express": {
        "url": "https://semgrep.dev/r/expressjs",
        "language": "javascript,typescript",
        "description": "Express.js security rules",
    },
    "semgrep-go": {
        "url": "https://semgrep.dev/r/golang",
        "language": "go",
        "description": "Go security rules",
    },
    "trailofbits": {
        "url": "https://github.com/Traho/semgrep-rules",
        "language": "multi",
        "description": "Trail of Bits security rules",
    },
}


def get_builtin_pack_path(name: str) -> Path:
    """Get the filesystem path to a built-in rule pack."""
    if name not in BUILTIN_PACKS:
        raise ValueError(f"Unknown pack: {name}")
    return Path(__file__).parent / BUILTIN_PACKS[name]["path"]


def list_builtin_packs() -> Dict:
    return BUILTIN_PACKS


def list_external_packs() -> Dict:
    return EXTERNAL_PACKS


def get_all_packs_for_files(files: List[str]) -> List[Path]:
    """Return all built-in rule pack paths applicable to the given files.

    Auto-selects packs based on file extensions.
    """
    from collections import defaultdict
    exts = defaultdict(int)
    for f in files:
        ext = Path(f).suffix.lower()
        exts[ext] += 1

    pack_paths: List[Path] = []
    if any(e in (".py",) for e in exts):
        pack_paths.append(get_builtin_pack_path("python-security"))
        pack_paths.append(get_builtin_pack_path("python-frameworks"))
        pack_paths.append(get_builtin_pack_path("python-deep"))  # v4.40
        # include inspired packs from detekt, spotbugs, lintr, luacheck
        pack_paths.append(get_builtin_pack_path("detekt-inspired"))
        pack_paths.append(get_builtin_pack_path("spotbugs-inspired"))
        pack_paths.append(get_builtin_pack_path("lintr-inspired"))
        pack_paths.append(get_builtin_pack_path("luacheck-inspired"))
    if any(e in (".js", ".jsx", ".ts", ".tsx") for e in exts):
        pack_paths.append(get_builtin_pack_path("javascript-security"))
        pack_paths.append(get_builtin_pack_path("javascript-frameworks"))
        pack_paths.append(get_builtin_pack_path("react-security"))
        pack_paths.append(get_builtin_pack_path("javascript-deep"))  # v4.40
    if any(e in (".go",) for e in exts):
        pack_paths.append(get_builtin_pack_path("go-security"))
    if any(e in (".java",) for e in exts):
        pack_paths.append(get_builtin_pack_path("java-security"))
        pack_paths.append(get_builtin_pack_path("java-frameworks"))
        pack_paths.append(get_builtin_pack_path("java-deep"))  # v4.40
    if any(e in (".c", ".cpp", ".cc", ".h", ".hpp") for e in exts):
        pack_paths.append(get_builtin_pack_path("cpp-security"))
    # v4.30: New language pack auto-selection
    if any(e in (".rs",) for e in exts):
        pack_paths.append(get_builtin_pack_path("rust-security"))
    if any(e in (".php", ".phtml") for e in exts):
        pack_paths.append(get_builtin_pack_path("php-security"))
    if any(e in (".rb", ".rake") for e in exts):
        pack_paths.append(get_builtin_pack_path("ruby-security"))
    # v4.34: New language packs
    if any(e in (".cs", ".vb") for e in exts):
        pack_paths.append(get_builtin_pack_path("csharp-security"))
    if any(e in (".swift",) for e in exts):
        pack_paths.append(get_builtin_pack_path("swift-security"))
    if any(e in (".scala", ".sc") for e in exts):
        pack_paths.append(get_builtin_pack_path("scala-security"))
    # v4.35: New language packs
    if any(e in (".kt", ".kts") for e in exts):
        pack_paths.append(get_builtin_pack_path("kotlin-security"))
    if any(e in (".sql", ".psql", ".mysql", ".ddl") for e in exts):
        pack_paths.append(get_builtin_pack_path("sql-security"))
    if any(e in (".sh", ".bash", ".zsh", ".ksh") for e in exts):
        pack_paths.append(get_builtin_pack_path("bash-security"))
    if any(e in (".dart",) for e in exts):
        pack_paths.append(get_builtin_pack_path("dart-security"))
    # v4.36: New language packs
    if any(e in (".lua",) for e in exts):
        pack_paths.append(get_builtin_pack_path("lua-security"))
    if any(e in (".r", ".R") for e in exts):
        pack_paths.append(get_builtin_pack_path("r-security"))
    if any(e in (".hs", ".lhs") for e in exts):
        pack_paths.append(get_builtin_pack_path("haskell-security"))
    if any(e in (".ex", ".exs") for e in exts):
        pack_paths.append(get_builtin_pack_path("elixir-security"))
    # v4.38: New language packs
    if any(e in (".m", ".mm") for e in exts):
        pack_paths.append(get_builtin_pack_path("objectivec-security"))
    if any(e in (".groovy", ".gradle", ".gvy", ".gy") for e in exts):
        pack_paths.append(get_builtin_pack_path("groovy-security"))
    if any(e in (".jl",) for e in exts):
        pack_paths.append(get_builtin_pack_path("julia-security"))
    if any(e in (".pl", ".pm", ".t", ".pod") for e in exts):
        pack_paths.append(get_builtin_pack_path("perl-security"))
    if any(e in (".cob", ".cbl", ".cpy", ".COB", ".CBL") for e in exts):
        pack_paths.append(get_builtin_pack_path("cobol-security"))
    # v4.37: Deep packs
    if any(e in (".sql", ".psql", ".mysql", ".ddl") for e in exts):
        pack_paths.append(get_builtin_pack_path("sql-stored-procedures"))
    if any(e in (".sh", ".bash", ".zsh", ".ksh") for e in exts):
        pack_paths.append(get_builtin_pack_path("bash-deep"))
    # v4.37: OWASP Top 10 is multi-language — always include
    pack_paths.append(get_builtin_pack_path("owasp-top-10"))
    # v4.39: Semgrep community deep is multi-language — always include
    pack_paths.append(get_builtin_pack_path("semgrep-community-deep"))
    # v5.1: Framework taint is multi-language — always include
    pack_paths.append(get_builtin_pack_path("framework-taint"))
    return pack_paths


def pull_external_pack(name: str, dest_dir: Path) -> Path:
    """Download an external rule pack into dest_dir.

    For Semgrep registry URLs (semgrep.dev/r/...), we don't actually download
    the file — semgrep's `--config <url>` handles that. We just record the URL
    in a manifest for the L0 layer to use.
    """
    if name not in EXTERNAL_PACKS:
        raise ValueError(f"Unknown external pack: {name}")
    url = EXTERNAL_PACKS[name]["url"]
    dest_dir.mkdir(parents=True, exist_ok=True)
    manifest = dest_dir / "external-packs.json"
    import json
    data = {}
    if manifest.exists():
        try:
            data = json.loads(manifest.read_text())
        except Exception:
            pass
    data[name] = {"url": url, **EXTERNAL_PACKS[name]}
    manifest.write_text(json.dumps(data, indent=2))
    return manifest
