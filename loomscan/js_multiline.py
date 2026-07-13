"""Multi-line pattern matcher for JS/TS files.

12 patterns that span multiple lines (and therefore can't be caught by
line-based scanners). All patterns use re.DOTALL so `.` matches newlines.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple


@dataclass
class MultilineFinding:
    file: str
    line: int
    rule_id: str
    severity: str
    description: str
    fix: str = ""
    cwe: str = ""
    confidence: float = 0.7


# Each pattern: (rule_id, regex, severity, description, fix, cwe, confidence)
# All regexes are compiled with re.DOTALL.

PATTERNS: List[Tuple[str, str, str, str, str, str, float]] = [
    ("ML-TOKEN-BEFORE-ROLE-CHECK",
     r"localStorage\.getItem\s*\(\s*['\"]token['\"][^;]*;(?:(?!\b(?:hasRole|checkRole|isAdmin|requireRole|role\s*===).*$){1,50})\.(?:delete|remove|update|admin)\w*\s*\(",
     "high",
     "Token retrieved from localStorage before role check is performed — token presence ≠ authorization",
     "Verify the user's role server-side before allowing sensitive actions",
     "CWE-862", 0.7),

    ("ML-LOGOUT-WITHOUT-SERVER",
     r"function\s+\w*[Ll]ogout\w*\s*\([^)]*\)\s*\{[^}]*(?:localStorage\.removeItem|sessionStorage\.clear|localStorage\.clear)[^}]*\}",
     "high",
     "Logout only clears client storage — server session remains valid",
     "Call a /logout endpoint to invalidate the session server-side",
     "CWE-613", 0.75),

    ("ML-AUTH-LAYOUT-NO-CHECK",
     r"<\s*(?:AuthenticatedLayout|ProtectedLayout|AppLayout|DashboardLayout)\b[^>]*>(?:(?!\b(?:useAuth|useUser|isAuthenticated|requireAuth|loading|isLoading|redirect|router\.push).*</?)(?:.|\n))*?(?:<\s*button|<\s*a\s+href|onClick\s*=)",
     "medium",
     "Auth layout doesn't gate on auth state before rendering actions",
     "Add `if (!user) return <Login />` at the top of the layout",
     "CWE-862", 0.6),

    ("ML-TOKEN-PRESENCE-ONLY",
     r"if\s*\(\s*(?:localStorage\.getItem\s*\(\s*['\"]token['\"]|token|sessionStorage\.getItem\s*\(\s*['\"]token['\"])\s*\)\s*\{(?:(?!\b(?:verify|decode|fetch|validate|jwt\.verify).*$)(?:.|\n))*?(?:<\s*button|navigate|router\.push|redirect|return\s+<)",
     "high",
     "Auth gate checks only token presence — token may be expired/forged",
     "Validate the token (decode + check expiry) on every protected route",
     "CWE-345", 0.7),

    ("ML-TEMPLATE-MULTI-INTERPOLATION",
     r"(?:innerHTML|dangerouslySetInnerHTML)\s*=\s*[^,;]*\$\{[^}]+\}[^,;]*\$\{[^}]+\}",
     "critical",
     "innerHTML with multiple ${} interpolations — XSS via concatenated user input",
     "Use DOMPurify.sanitize() or escape all interpolations",
     "CWE-79", 0.9),

    ("ML-SETINTERVAL-POLLING",
     r"useEffect\s*\(\s*\(\s*\)\s*=>\s*\{[^}]*setInterval\s*\([^)]*\)[^}]*\}\s*,\s*\[\s*\]\s*\)",
     "medium",
     "useEffect with setInterval and empty deps — polls forever, no cleanup",
     "Return a cleanup: () => clearInterval(id)",
     "CWE-404", 0.7),

    ("ML-QR-PARSER-NO-TRY",
     r"(?:new\s+QRCode|qrscanner|jsQR|qrcode)\s*\([^)]*\)(?:[^;]*;)?(?!(?:.|\n)*try)(?:.|\n){0,200}(?:\.split|JSON\.parse|parseInt|\.toString)",
     "medium",
     "QR code parsing without try/catch — malformed QR crashes the app",
     "Wrap parsing in try/catch and validate the result",
     "CWE-755", 0.65),

    ("ML-NO-CODE-SPLITTING",
     r"(?:import\s+\w+\s+from\s+['\"](?:\.\.?\/)(?:pages|views|components)\/[^'\"]+['\"]\s*;?\s*){5,}",
     "low",
     "Many top-level page imports — no React.lazy / code splitting",
     "Use React.lazy() + Suspense for route-level code splitting",
     "CWE-400", 0.4),

    ("ML-ROLES-NO-NULL-GUARD",
     r"(?:const|let|var)\s+\{\s*roles?\s*\}\s*=\s*use(?:Auth|User|Session)\s*\(\s*\)(?:[^;]*;)(?!(?:.|\n)*roles?\s*===\s*null|roles?\s*===\s*undefined|!roles|\?\?)(?:.|\n){0,100}roles?\.\w+",
     "medium",
     "roles from useAuth() dereferenced without null guard — crash on logged-out user",
     "Add: if (!roles) return <Login />",
     "CWE-476", 0.6),

    ("ML-DEFAULT-ALLOW-SWITCH",
     r"switch\s*\(\s*role\s*\)\s*\{[^}]*default\s*:\s*(?:return\s+true|allow|grantAccess|setAllowed\s*\(\s*true)",
     "high",
     "Role-based switch with permissive default — unknown roles get full access",
     "Use `default: return false` (deny by default)",
     "CWE-862", 0.8),

    ("ML-SHARED-REFRESH-PROMISE",
     r"(?:let|var|const)\s+\w*[Rr]efresh\w*\s*=\s*(?:null|undefined|Promise(?:\.resolve)?)(?:[^;]*;)(?:.|\n){0,300}refreshToken\w*\s*\(\s*\)\s*\{[^}]*\w*[Rr]efresh\w*\s*=\s*(?:fetch|axios|new\s+Promise)",
     "medium",
     "Shared refresh-promise module-level variable — race conditions across concurrent callers",
     "Use a per-request refresh lock or single-flight pattern",
     "CWE-362", 0.65),

    ("ML-CREATE-CREDENTIALS-NO-CHECK",
     r"navigator\.credentials\.create\s*\(\s*\{[^}]*\}\s*\)(?:[^;]*;?)(?!(?:.|\n)*(?:if\s*\(|\.catch|try\s*\{|throw\s+new\s+Error))(?:.|\n){0,100}(?:\.then|await)",
     "high",
     "navigator.credentials.create() result used without checking for null — user may cancel",
     "Check `if (!cred) return` before using the credential",
     "CWE-755", 0.6),
]


_COMPILED = [(rid, re.compile(rx, re.DOTALL | re.MULTILINE), sev, desc, fix, cwe, conf)
              for rid, rx, sev, desc, fix, cwe, conf in PATTERNS]


def scan_file_multiline(file_path: Path) -> List[MultilineFinding]:
    """Scan a single JS/TS file with all multi-line patterns."""
    if not file_path.exists():
        return []
    if file_path.suffix.lower() not in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
        return []
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []
    out: List[MultilineFinding] = []
    file_str = str(file_path)
    for rid, rx, sev, desc, fix, cwe, conf in _COMPILED:
        for m in rx.finditer(source):
            line = source[:m.start()].count("\n") + 1
            out.append(MultilineFinding(
                file=file_str, line=line, rule_id=rid,
                severity=sev, description=desc, fix=fix,
                cwe=cwe, confidence=conf))
    return out


def scan_repo_multiline(repo_root: Path) -> List[MultilineFinding]:
    """Walk a repo and run all multi-line patterns on every JS/TS file."""
    out: List[MultilineFinding] = []
    skip = {"node_modules", ".git", "dist", "build", ".next", "vendor"}
    for path in repo_root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
            continue
        if any(s in str(path) for s in skip):
            continue
        out.extend(scan_file_multiline(path))
    return out
