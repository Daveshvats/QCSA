"""C/C++ dangerous function database — inspired by Flawfinder.

Flawfinder (https://github.com/david-a-wheeler/flawfinder) maintains a
curated database of C/C++ functions that are known to be dangerous,
each with a risk level (1-5) and explanation.

We implement the same concept: a curated database of dangerous C/C++
functions, each with:
  - Risk level (1=minor, 5=critical)
  - CWE
  - Explanation
  - Safer alternative

This is more precise than generic Semgrep rules because each entry has
a hit-level risk score that the FIS can use for aggregation.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple


@dataclass
class DangerousFunction:
    """A dangerous C/C++ function with risk assessment."""
    name: str
    risk_level: int  # 1 (minor) to 5 (critical)
    cwe: str
    explanation: str
    safer_alternative: str
    language: str = "c"  # c, cpp, both


# Curated database of dangerous C/C++ functions
# Based on Flawfinder's database + MITRE CWE entries
DANGEROUS_FUNCTIONS: Dict[str, DangerousFunction] = {
    # === Risk 5: Critical ===
    "gets": DangerousFunction(
        name="gets", risk_level=5, cwe="CWE-242",
        explanation="gets() is inherently unsafe — no bounds checking. Removed from C11.",
        safer_alternative="fgets(buf, sizeof(buf), stdin)",
    ),
    "strcpy": DangerousFunction(
        name="strcpy", risk_level=5, cwe="CWE-120",
        explanation="strcpy() performs no bounds checking — buffer overflow.",
        safer_alternative="strncpy(dst, src, sizeof(dst)-1) or strlcpy(dst, src, sizeof(dst))",
    ),
    "strcat": DangerousFunction(
        name="strcat", risk_level=5, cwe="CWE-120",
        explanation="strcat() performs no bounds checking — buffer overflow.",
        safer_alternative="strncat(dst, src, sizeof(dst)-strlen(dst)-1)",
    ),
    "sprintf": DangerousFunction(
        name="sprintf", risk_level=5, cwe="CWE-120",
        explanation="sprintf() has no bounds checking — buffer overflow.",
        safer_alternative="snprintf(buf, sizeof(buf), fmt, ...)",
    ),
    "vsprintf": DangerousFunction(
        name="vsprintf", risk_level=5, cwe="CWE-120",
        explanation="vsprintf() has no bounds checking — buffer overflow.",
        safer_alternative="vsnprintf(buf, sizeof(buf), fmt, ap)",
    ),
    "system": DangerousFunction(
        name="system", risk_level=5, cwe="CWE-78",
        explanation="system() passes the argument to a shell — command injection.",
        safer_alternative="execve() or fork()+exec() with proper argument array",
    ),
    "popen": DangerousFunction(
        name="popen", risk_level=5, cwe="CWE-78",
        explanation="popen() uses a shell to execute the command — command injection.",
        safer_alternative="pipe()+fork()+exec()",
    ),

    # === Risk 4: High ===
    "scanf": DangerousFunction(
        name="scanf", risk_level=4, cwe="CWE-120",
        explanation="scanf(%s) reads unbounded input — buffer overflow. Use width specifier.",
        safer_alternative="scanf(%99s, buf) or fgets()+sscanf()",
    ),
    "sscanf": DangerousFunction(
        name="sscanf", risk_level=4, cwe="CWE-120",
        explanation="sscanf(%s) can overflow if no width specified.",
        safer_alternative="sscanf(%99s, buf) with width specifier",
    ),
    "fscanf": DangerousFunction(
        name="fscanf", risk_level=4, cwe="CWE-120",
        explanation="fscanf(%s) reads unbounded input — buffer overflow.",
        safer_alternative="fscanf(%99s, buf) with width specifier",
    ),
    "alloca": DangerousFunction(
        name="alloca", risk_level=4, cwe="CWE-770",
        explanation="alloca() allocates on the stack — stack overflow if size is user-controlled.",
        safer_alternative="malloc()/free() or VLA with bounds checking",
    ),
    "realpath": DangerousFunction(
        name="realpath", risk_level=4, cwe="CWE-120",
        explanation="realpath() without allocated buffer can overflow. Use realpath(NULL, NULL) on POSIX.1-2008.",
        safer_alternative="realpath(path, NULL) (POSIX.1-2008, returns malloc'd buffer)",
    ),
    "tmpnam": DangerousFunction(
        name="tmpnam", risk_level=4, cwe="CWE-377",
        explanation="tmpnam() generates predictable filenames — race condition / symlink attack.",
        safer_alternative="mkstemp() or tmpfile()",
    ),
    "tempnam": DangerousFunction(
        name="tempnam", risk_level=4, cwe="CWE-377",
        explanation="tempnam() generates predictable filenames — race condition.",
        safer_alternative="mkstemp() or tmpfile()",
    ),
    "getenv": DangerousFunction(
        name="getenv", risk_level=4, cwe="CWE-807",
        explanation="getenv() returns environment variable — untrusted input. Validate before use.",
        safer_alternative="Validate the value; don't pass directly to system/exec",
    ),

    # === Risk 3: Medium ===
    "strncpy": DangerousFunction(
        name="strncpy", risk_level=3, cwe="CWE-170",
        explanation="strncpy() doesn't null-terminate if source >= count. Must manually null-terminate.",
        safer_alternative="strlcpy() (BSD) or manual null-termination: buf[sizeof(buf)-1] = '\\0';",
    ),
    "strncat": DangerousFunction(
        name="strncat", risk_level=3, cwe="CWE-193",
        explanation="strncat() count is the MAX to append, not buffer remaining. Easy to miscalculate.",
        safer_alternative="strlcat() (BSD) or careful size calculation",
    ),
    "atoi": DangerousFunction(
        name="atoi", risk_level=3, cwe="CWE-20",
        explanation="atoi() has no error handling — returns 0 on failure. Can't distinguish '0' from error.",
        safer_alternative="strtol() with errno checking",
    ),
    "atol": DangerousFunction(
        name="atol", risk_level=3, cwe="CWE-20",
        explanation="atol() has no error handling — returns 0 on failure.",
        safer_alternative="strtol() with errno checking",
    ),
    "atof": DangerousFunction(
        name="atof", risk_level=3, cwe="CWE-20",
        explanation="atof() has no error handling — returns 0.0 on failure.",
        safer_alternative="strtod() with errno checking",
    ),
    "malloc": DangerousFunction(
        name="malloc", risk_level=3, cwe="CWE-690",
        explanation="malloc() can return NULL — must check before use. NULL deref on OOM.",
        safer_alternative="Always check: ptr = malloc(n); if (!ptr) handle_error();",
    ),
    "realloc": DangerousFunction(
        name="realloc", risk_level=3, cwe="CWE-401",
        explanation="realloc() can return a new pointer — old pointer is invalid. Memory leak if you lose the old pointer.",
        safer_alternative="new_ptr = realloc(old_ptr, n); if (new_ptr) old_ptr = new_ptr;",
    ),
    "free": DangerousFunction(
        name="free", risk_level=3, cwe="CWE-416",
        explanation="free() followed by use of the pointer = use-after-free. Set pointer to NULL after free.",
        safer_alternative="free(ptr); ptr = NULL;",
    ),
    "memcpy": DangerousFunction(
        name="memcpy", risk_level=3, cwe="CWE-120",
        explanation="memcpy() has no bounds checking — verify destination is large enough.",
        safer_alternative="memcpy_s() (C11) or manual bounds check before call",
    ),
    "memmove": DangerousFunction(
        name="memmove", risk_level=3, cwe="CWE-120",
        explanation="memmove() has no bounds checking — verify destination is large enough.",
        safer_alternative="memmove_s() (C11) or manual bounds check",
    ),
    "fopen": DangerousFunction(
        name="fopen", risk_level=3, cwe="CWE-22",
        explanation="fopen() with user-controlled path — path traversal risk.",
        safer_alternative="Validate path components; use realpath() to canonicalize",
    ),
    "open": DangerousFunction(
        name="open", risk_level=3, cwe="CWE-22",
        explanation="open() with user-controlled path — path traversal risk.",
        safer_alternative="Validate path components; check against allowed directories",
    ),
    "access": DangerousFunction(
        name="access", risk_level=3, cwe="CWE-367",
        explanation="access() then open() = TOCTOU race condition. Don't use access() for security decisions.",
        safer_alternative="open() with O_CREAT|O_EXCL and check errno",
    ),

    # === Risk 2: Low ===
    "printf": DangerousFunction(
        name="printf", risk_level=2, cwe="CWE-134",
        explanation="printf() with user-controlled format string — format string attack.",
        safer_alternative="printf(\"%s\", user_str) — never pass user input as format",
    ),
    "fprintf": DangerousFunction(
        name="fprintf", risk_level=2, cwe="CWE-134",
        explanation="fprintf() with user-controlled format string — format string attack.",
        safer_alternative="fprintf(fp, \"%s\", user_str)",
    ),
    "syslog": DangerousFunction(
        name="syslog", risk_level=2, cwe="CWE-134",
        explanation="syslog() with user-controlled format string — format string attack.",
        safer_alternative="syslog(prio, \"%s\", user_str)",
    ),
    "chmod": DangerousFunction(
        name="chmod", risk_level=2, cwe="CWE-732",
        explanation="chmod() — verify the permission change is intentional and not overly permissive.",
        safer_alternative="Use restrictive permissions: 0600 for files, 0700 for dirs",
    ),
    "chown": DangerousFunction(
        name="chown", risk_level=2, cwe="CWE-732",
        explanation="chown() — verify ownership change is intentional.",
        safer_alternative="Document why ownership is changing; audit in code review",
    ),
    "setuid": DangerousFunction(
        name="setuid", risk_level=2, cwe="CWE-269",
        explanation="setuid() — privilege escalation if not done carefully. Check return value.",
        safer_alternative="Drop privileges permanently: setuid(getuid()) and verify return",
    ),
    "setgid": DangerousFunction(
        name="setgid", risk_level=2, cwe="CWE-269",
        explanation="setgid() — privilege escalation if not done carefully.",
        safer_alternative="Drop group privileges permanently; verify return value",
    ),
    "signal": DangerousFunction(
        name="signal", risk_level=2, cwe="CWE-828",
        explanation="signal() has undefined behavior in some cases. Use sigaction() instead.",
        safer_alternative="sigaction() with proper flags",
    ),

    # === Risk 1: Info ===
    "rand": DangerousFunction(
        name="rand", risk_level=1, cwe="CWE-338",
        explanation="rand() is not cryptographically secure. Don't use for security tokens.",
        safer_alternative="arc4random() (BSD) or /dev/urandom or getrandom()",
    ),
    "srand": DangerousFunction(
        name="srand", risk_level=1, cwe="CWE-338",
        explanation="srand() seeds rand() — not cryptographically secure.",
        safer_alternative="Use /dev/urandom or getrandom() for crypto",
    ),
    "time": DangerousFunction(
        name="time", risk_level=1, cwe="CWE-338",
        explanation="time() returns predictable value — don't use as random seed for security.",
        safer_alternative="Use /dev/urandom for security-sensitive randomness",
    ),
    "ctime": DangerousFunction(
        name="ctime", risk_level=1, cwe="CWE-805",
        explanation="ctime() returns pointer to static buffer — not thread-safe.",
        safer_alternative="ctime_r() (thread-safe version)",
    ),
    "gmtime": DangerousFunction(
        name="gmtime", risk_level=1, cwe="CWE-805",
        explanation="gmtime() returns pointer to static buffer — not thread-safe.",
        safer_alternative="gmtime_r() (thread-safe version)",
    ),
    "localtime": DangerousFunction(
        name="localtime", risk_level=1, cwe="CWE-805",
        explanation="localtime() returns pointer to static buffer — not thread-safe.",
        safer_alternative="localtime_r() (thread-safe version)",
    ),
    "getpwuid": DangerousFunction(
        name="getpwuid", risk_level=1, cwe="CWE-805",
        explanation="getpwuid() returns pointer to static buffer — not thread-safe.",
        safer_alternative="getpwuid_r() (thread-safe version)",
    ),
}


@dataclass
class DangerousFunctionHit:
    """A detected use of a dangerous function."""
    function: str
    file: str
    line: int
    risk_level: int  # 1-5
    cwe: str
    explanation: str
    safer_alternative: str
    context: str = ""


def scan_dangerous_functions(file_path: Path,
                              repo_root: Path = None) -> List[DangerousFunctionHit]:
    """Scan a C/C++ file for dangerous function usage."""
    if not file_path.exists():
        return []
    if file_path.suffix.lower() not in (".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hxx"):
        return []

    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []

    rel_path = str(file_path.relative_to(repo_root)) if repo_root else str(file_path)
    hits: List[DangerousFunctionHit] = []
    seen_lines: set = set()

    for i, line in enumerate(source.splitlines(), 1):
        for func_name, func_info in DANGEROUS_FUNCTIONS.items():
            # match the function call: func_name(
            # use word boundary to avoid matching substrings
            pattern = rf'\b{re.escape(func_name)}\s*\('
            if re.search(pattern, line):
                key = (i, func_name)
                if key in seen_lines:
                    continue
                seen_lines.add(key)
                hits.append(DangerousFunctionHit(
                    function=func_name,
                    file=rel_path,
                    line=i,
                    risk_level=func_info.risk_level,
                    cwe=func_info.cwe,
                    explanation=func_info.explanation,
                    safer_alternative=func_info.safer_alternative,
                    context=line.strip()[:200],
                ))

    return hits


def scan_repo_dangerous_functions(repo_root: Path,
                                   max_files: int = 200) -> List[DangerousFunctionHit]:
    """Scan all C/C++ files in the repo for dangerous functions."""
    skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules",
                 ".loomscan-cache", ".loomscan-reports", ".loomscan-fixes", "build", "dist"}
    hits: List[DangerousFunctionHit] = []
    count = 0
    for p in repo_root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in skip_dirs for part in p.parts):
            continue
        if p.suffix.lower() in (".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hxx"):
            hits.extend(scan_dangerous_functions(p, repo_root))
            count += 1
            if count >= max_files:
                break
    return hits


def database_stats() -> dict:
    """Return stats about the dangerous function database."""
    from collections import Counter
    by_risk = Counter(f.risk_level for f in DANGEROUS_FUNCTIONS.values())
    return {
        "total_functions": len(DANGEROUS_FUNCTIONS),
        "by_risk_level": {f"risk_{k}": v for k, v in sorted(by_risk.items())},
        "critical": by_risk.get(5, 0),
        "high": by_risk.get(4, 0),
        "medium": by_risk.get(3, 0),
        "low": by_risk.get(2, 0),
        "info": by_risk.get(1, 0),
    }
