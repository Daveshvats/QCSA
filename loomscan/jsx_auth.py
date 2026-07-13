"""JSX-aware authorization extraction for React/Next.js codebases.

Understands:
  - HOC patterns:        withAuth(Component), requireAuth(Component)
  - Hook patterns:       const {user} = useAuth();  const {isAuthed} = useUser();
  - Component patterns:  <ProtectedRoute>, <AuthGuard>, <RequireRole role="admin">
  - Permission checks:   hasPermission('edit'), can('delete'), checkRole('admin')
  - Route guards:        next.js middleware, react-router <PrivateRoute>

Detects:
  - Pages without any auth wrapper (likely missing auth)
  - Inconsistent patterns (some pages use HOC, others use hook, others none)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

from .business_logic import AuthRule, AuthViolation


@dataclass
class JSXAuthRule(AuthRule):
    """A JSX-specific auth rule (extends AuthRule)."""
    component: str = ""           # component name being wrapped
    wrapper_kind: str = ""        # hoc | hook | component | route_guard | permission_check
    role: str = ""                # role/permission required, if any
    pattern_text: str = ""


# =============================================================================
# Pattern catalogs
# =============================================================================

# HOC patterns: `withAuth(MyComp)`, `export default requireAuth(Comp)`
_HOC_PATTERNS: List[tuple] = [
    (r"\bwith(?:Auth|Login|Role|Permission|Role)\w*\s*\(\s*(?P<comp>\w+)\s*\)", "hoc"),
    (r"\brequire(?:Auth|Login|Role|Permission)\s*\(\s*(?P<comp>\w+)\s*\)", "hoc"),
    (r"\b@(?:WithAuth|RequireAuth|LoginRequired)\b", "hoc"),
]

# Hook patterns: `const { user } = useAuth();`
_HOOK_PATTERNS: List[tuple] = [
    (r"(?:const|let|var)\s*\{[^}]*\}\s*=\s*useAuth\s*\(\s*\)", "hook"),
    (r"(?:const|let|var)\s*\{[^}]*\}\s*=\s*useUser\s*\(\s*\)", "hook"),
    (r"(?:const|let|var)\s*\{[^}]*\}\s*=\s*useSession\s*\(\s*\)", "hook"),
    (r"(?:const|let|var)\s+\w+\s*=\s*useIsAuthenticated\s*\(\s*\)", "hook"),
]

# Component patterns: <ProtectedRoute>, <AuthGuard role="admin">
_COMPONENT_PATTERNS: List[tuple] = [
    (r"<\s*(?P<comp>ProtectedRoute|AuthGuard|RequireAuth|RequireRole|RequirePermission|PrivateRoute|Gate|Can)(\s[^>]*)?>",
     "component"),
]

# Permission checks: `hasPermission('edit')`, `can('delete')`, `checkRole('admin')`
_PERMISSION_PATTERNS: List[tuple] = [
    (r"\bhasPermission\s*\(\s*['\"](?P<perm>[\w:]+)['\"]\s*\)", "permission_check"),
    (r"\bcan\s*\(\s*['\"](?P<perm>[\w:]+)['\"]\s*\)", "permission_check"),
    (r"\bcheckRole\s*\(\s*['\"](?P<role>\w+)['\"]\s*\)", "permission_check"),
    (r"\bhasRole\s*\(\s*['\"](?P<role>\w+)['\"]\s*\)", "permission_check"),
    (r"\bisAdmin\s*\(\s*\)", "permission_check"),
    (r"\bisAuthenticated\s*\(\s*\)", "permission_check"),
]

# Route guards: next.js middleware, react-router <PrivateRoute>
_ROUTE_GUARD_PATTERNS: List[tuple] = [
    (r"export\s+default\s+function\s+middleware\s*\(", "route_guard"),
    (r"export\s+function\s+middleware\s*\(", "route_guard"),
    (r"<\s*PrivateRoute\b", "route_guard"),
    (r"<\s*Route\s+[^>]*element\s*=\s*\{?\s*<\s*(?:RequireAuth|Protected)", "route_guard"),
    (r"getServerSideProps\s*[=(]", "route_guard"),  # next.js SSR auth
]


# =============================================================================
# JSX auth extractor
# =============================================================================

class JSXAuthExtractor:
    """Extract JSX/React auth rules from a single .jsx/.tsx file."""

    def extract_from_file(self, file_path: Path) -> List[JSXAuthRule]:
        if not file_path.exists() or file_path.suffix.lower() not in {".jsx", ".tsx", ".js", ".ts"}:
            return []
        try:
            source = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return []
        return self._extract_source(source, str(file_path))

    def _extract_source(self, source: str, file: str) -> List[JSXAuthRule]:
        out: List[JSXAuthRule] = []
        lines = source.splitlines()
        for i, line in enumerate(lines, 1):
            for pat, kind in _HOC_PATTERNS:
                for m in re.finditer(pat, line):
                    comp = m.groupdict().get("comp", "")
                    out.append(JSXAuthRule(
                        file=file, line=i, rule_type="hoc", pattern=pat,
                        roles=[], function=comp, component=comp,
                        wrapper_kind=kind, pattern_text=line.strip(),
                        description=f"HOC '{line.strip()}' wraps component '{comp}'"))
            for pat, kind in _HOOK_PATTERNS:
                if re.search(pat, line):
                    out.append(JSXAuthRule(
                        file=file, line=i, rule_type="hook", pattern=pat,
                        roles=["user"], wrapper_kind=kind,
                        pattern_text=line.strip(),
                        description=f"Auth hook: '{line.strip()}'"))
            for pat, kind in _COMPONENT_PATTERNS:
                for m in re.finditer(pat, line):
                    comp = m.groupdict().get("comp", "")
                    role = ""
                    role_m = re.search(r"role\s*=\s*['\"](\w+)['\"]", line)
                    if role_m:
                        role = role_m.group(1)
                    out.append(JSXAuthRule(
                        file=file, line=i, rule_type="component", pattern=pat,
                        roles=[role] if role else [], component=comp,
                        wrapper_kind=kind, role=role,
                        pattern_text=line.strip(),
                        description=f"Auth component <{comp}> wraps children" +
                                    (f" (role={role})" if role else "")))
            for pat, kind in _PERMISSION_PATTERNS:
                for m in re.finditer(pat, line):
                    role = m.groupdict().get("role") or m.groupdict().get("perm") or ""
                    out.append(JSXAuthRule(
                        file=file, line=i, rule_type="permission_check",
                        pattern=pat, roles=[role] if role else [],
                        wrapper_kind=kind, role=role,
                        pattern_text=line.strip(),
                        description=f"Permission check: '{line.strip()}'"))
            for pat, kind in _ROUTE_GUARD_PATTERNS:
                if re.search(pat, line):
                    out.append(JSXAuthRule(
                        file=file, line=i, rule_type="route_guard",
                        pattern=pat, roles=["user"], wrapper_kind=kind,
                        pattern_text=line.strip(),
                        description=f"Route guard: '{line.strip()}'"))
        return out


# =============================================================================
# Violation detector
# =============================================================================

# A "page" is any file in pages/, app/, src/pages/ — React/Next convention.
_PAGE_DIRS = {"pages", "app", "src/pages", "src/app"}


class JSXAuthViolationDetector:
    """Detect pages without auth wrappers and inconsistent auth patterns."""

    def __init__(self, rules: Optional[List[JSXAuthRule]] = None) -> None:
        self.rules: List[JSXAuthRule] = rules or []

    def analyze(self, repo_root: Path) -> List[AuthViolation]:
        out: List[AuthViolation] = []
        # Group rules by file
        by_file: Dict[str, List[JSXAuthRule]] = {}
        for r in self.rules:
            by_file.setdefault(r.file, []).append(r)

        # Find page files
        page_files: List[Path] = []
        for path in repo_root.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in {".jsx", ".tsx", ".js", ".ts"}:
                continue
            if any(s in str(path) for s in ("node_modules", ".next", "dist", "build")):
                continue
            if any(page_dir in path.parts for page_dir in _PAGE_DIRS):
                page_files.append(path)
        # Find missing auth on pages
        for p in page_files:
            file_rules = by_file.get(str(p), [])
            if not file_rules:
                out.append(AuthViolation(
                    file=str(p), line=0,
                    rule_id="JSX-PAGE-NO-AUTH",
                    severity="high",
                    description=f"Page '{p.name}' has no auth wrapper, hook, or route guard — likely missing auth",
                    fix="Wrap page in withAuth() or add useAuth() hook check",
                    cwe="CWE-862"))
        # Find inconsistent patterns
        wrapper_kinds: Dict[str, Set[str]] = {}
        for r in self.rules:
            wrapper_kinds.setdefault(r.rule_type, set()).add(r.file)
        if len(wrapper_kinds) > 2:
            out.append(AuthViolation(
                file="<repo>", line=0,
                rule_id="JSX-INCONSISTENT-AUTH-PATTERN",
                severity="low",
                description=f"Inconsistent auth patterns detected: {sorted(wrapper_kinds.keys())}",
                fix="Standardize on one auth pattern across the codebase",
                cwe="CWE-862"))
        return out


# =============================================================================
# Top-level
# =============================================================================

def extract_all_jsx_auth(repo_root: Path) -> List[JSXAuthRule]:
    """Walk a repo and extract all JSX auth rules."""
    out: List[JSXAuthRule] = []
    extractor = JSXAuthExtractor()
    skip = {"node_modules", ".next", ".git", "dist", "build"}
    for path in repo_root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in {".jsx", ".tsx", ".js", ".ts"}:
            continue
        if any(s in str(path) for s in skip):
            continue
        out.extend(extractor.extract_from_file(path))
    return out
