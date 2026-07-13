"""Multi-language business logic detector.

Uses the normalized AST layer to run all BL detection techniques on
any supported language (Python, JS/TS, Go, Java, C, C++).

This is the single entry point for all BL detection — it routes to
the appropriate detectors based on what's available and collects all
findings in a unified format.
"""
from __future__ import annotations

from pathlib import Path
from typing import List, Optional, Dict, Any, Set, Tuple
from dataclasses import dataclass

from .normalized_ast import (
    NormalizedNode, parse_file, get_language, is_supported, _HAS_TS,
    _TS_LANGUAGE_MODULES
)
from .models import Finding, Severity, BlastRadius, LayerID, Category


@dataclass
class BLFinding:
    """A business logic finding (language-agnostic)."""
    rule_id: str
    severity: str
    description: str
    file: str
    line: int
    function: str = ""
    language: str = ""
    cwe: str = ""
    fix: str = ""
    call_chain: List[str] = None
    invariant: str = ""
    counterexample: str = ""


# Sensitive actions that should require authorization
SENSITIVE_ACTIONS = {
    "delete", "remove", "destroy", "purge", "wipe",
    "transfer", "withdraw", "refund", "charge", "payment",
    "update_role", "grant", "revoke", "change_password", "reset_password",
    "export", "download_all", "bulk",
    # Go-specific
    "Delete", "Remove", "Destroy",
    # Java-specific
    "deleteAccount", "grantRole", "resetPassword",
}

# Auth-related decorator/annotation patterns (per language)
AUTH_DECORATOR_PATTERNS = {
    "python": {"login_required", "permission_required", "requires_auth",
               "requires_role", "admin_required"},
    "javascript": {"UseGuards", "AuthGuard", "CanActivate", "RoleGuard",
                   "UseInterceptors"},
    "typescript": {"UseGuards", "AuthGuard", "CanActivate", "RoleGuard"},
    "go": {"AuthMiddleware", "RequireAuth"},  # Go uses middleware, not decorators
    "java": {"PreAuthorize", "PostAuthorize", "Secured", "RolesAllowed",
             "DenyAll", "PermitAll"},
    "c": set(),  # C has no auth decorators
    "cpp": set(),
    "rust": {"guard", "from_fn"},  # Actix guards
}

# Auth-related function call patterns
AUTH_CALL_PATTERNS = {
    "check_auth", "require_auth", "check_permission", "check_role",
    "is_authenticated", "current_user", "login_required", "verify_token",
    "is_admin", "is_authorized", "has_permission", "is_superuser",
    "is_staff", "is_owner",
}

# External call patterns (for reentrancy detection)
EXTERNAL_CALL_PATTERNS = {
    "callback", "hook", "listener", "notify", "on_",
    "emit", "fire", "trigger", "send", "publish",
    "dispatch", "broadcast", "call", "invoke",
}


def detect_auth_violations(tree: NormalizedNode) -> List[BLFinding]:
    """Detect sensitive actions without auth checks.

    Works on any language via the normalized AST.
    """
    findings: List[BLFinding] = []
    lang = tree.language

    # Get auth decorators for this language
    auth_decorators = AUTH_DECORATOR_PATTERNS.get(lang, set())

    for func in tree.find_function_defs():
        # Check if function has auth decorators
        has_auth = False
        for dec in func.find_decorators():
            if dec.decorator_name in auth_decorators or \
               any(ad.lower() in dec.decorator_name.lower() for ad in auth_decorators):
                has_auth = True
                break

        # Check for auth-related calls in the function body
        if not has_auth:
            for call in func.find_calls():
                if any(pat in call.name.lower() for pat in AUTH_CALL_PATTERNS):
                    has_auth = True
                    break

        # Check for auth-related attribute access (is_authenticated, etc.)
        if not has_auth:
            for attr in func.find_all("attribute"):
                if any(pat in attr.attr.lower() for pat in AUTH_CALL_PATTERNS):
                    has_auth = True
                    break

        # Check for 'if not <auth>:' patterns (conservative)
        if not has_auth:
            for if_node in func.find_all("if"):
                if any(pat in if_node.condition.lower() for pat in AUTH_CALL_PATTERNS):
                    has_auth = True
                    break

        if has_auth:
            continue

        # Check for sensitive calls without auth
        for call in func.find_calls():
            if call.name in SENSITIVE_ACTIONS or \
               any(call.name.lower().startswith(sa) for sa in SENSITIVE_ACTIONS):
                # Determine the kind
                kind = "delete" if "delete" in call.name.lower() or "remove" in call.name.lower() else \
                       "payment" if any(p in call.name.lower() for p in ("refund", "charge", "payment", "withdraw")) else \
                       "privilege" if any(p in call.name.lower() for p in ("grant", "revoke", "role", "password")) else \
                       "data-export" if any(p in call.name.lower() for p in ("export", "download", "bulk")) else \
                       "sensitive"

                findings.append(BLFinding(
                    rule_id=f"BL.AUTH-NO-CHECK-{kind.upper()}",
                    severity="high",
                    description=f"Sensitive {kind} action '{call.name}()' in '{func.name}()' "
                                f"has no auth check",
                    file=tree.file,
                    line=call.line,
                    function=func.name,
                    language=lang,
                    cwe="CWE-862",
                    fix=f"Add auth check to {func.name}()",
                ))
                break  # one per function

    return findings


def detect_reentrancy(tree: NormalizedNode) -> List[BLFinding]:
    """Detect potential reentrancy: external call before state update.

    Works on any language via the normalized AST.
    """
    findings: List[BLFinding] = []

    for func in tree.find_function_defs():
        events: List[Tuple[str, str, int]] = []

        for node in func.walk():
            if node.kind == "call":
                if any(pat in node.name.lower() for pat in EXTERNAL_CALL_PATTERNS):
                    events.append(("external_call", node.name, node.line))
            elif node.kind == "assignment":
                if node.target:
                    # Check if this is a state modification (self.X, obj.attr, etc.)
                    target = node.target
                    # Also check the raw text for augmented assignments
                    if hasattr(node, 'text') and node.text and \
                       any(op in node.text for op in ('+=', '-=', '*=', '/=')):
                        events.append(("state_update", target, node.line))
                    elif target:
                        events.append(("state_update", target, node.line))

        events.sort(key=lambda x: x[2])

        for i, (etype, ename, eline) in enumerate(events):
            if etype == "external_call":
                for j in range(i + 1, len(events)):
                    if events[j][0] == "state_update":
                        findings.append(BLFinding(
                            rule_id="BL.REENTRANCY",
                            severity="high",
                            description=f"Potential reentrancy in {func.name}(): external call "
                                        f"'{ename}()' at line {eline} is followed by state update "
                                        f"'{events[j][1]}' at line {events[j][2]}",
                            file=tree.file,
                            line=eline,
                            function=func.name,
                            language=tree.language,
                            cwe="CWE-836",
                            call_chain=[func.name, ename],
                        ))
                        break

    return findings


def detect_toctou(tree: NormalizedNode) -> List[BLFinding]:
    """Detect Time-Of-Check-Time-Of-Use patterns.

    If a condition checks a variable, then a call uses that variable,
    the state could change between check and use.
    """
    findings: List[BLFinding] = []

    for func in tree.find_function_defs():
        for if_node in func.find_all("if"):
            # Extract variables from the condition
            checked_vars: Set[str] = set()
            for child in if_node.walk():
                if child.kind == "identifier":
                    checked_vars.add(child.name)

            # Find calls in the if body that use checked variables
            reported_calls: Set[str] = set()  # dedup
            for call in if_node.find_calls():
                if call.name in reported_calls:
                    continue
                for arg in call.args:
                    for var in checked_vars:
                        if var in arg:
                            findings.append(BLFinding(
                                rule_id="BL.TOCTOU",
                                severity="medium",
                                description=f"Potential TOCTOU in {func.name}(): condition checks "
                                            f"'{', '.join(checked_vars)}' then calls '{call.name}()' "
                                            f"with those variables",
                                file=tree.file,
                                line=call.line,
                                function=func.name,
                                language=tree.language,
                                cwe="CWE-367",
                                call_chain=[func.name, call.name],
                            ))
                            reported_calls.add(call.name)
                            break

    return findings


def detect_missing_auth_in_chain(tree: NormalizedNode) -> List[BLFinding]:
    """Detect call chains where a sensitive action is reachable without auth."""
    findings: List[BLFinding] = []

    # Build call graph from the normalized AST
    call_graph: Dict[str, List[Tuple[str, int]]] = {}
    func_has_auth: Dict[str, bool] = {}

    for func in tree.find_function_defs():
        has_auth = False
        auth_decorators = AUTH_DECORATOR_PATTERNS.get(tree.language, set())

        for dec in func.find_decorators():
            if dec.decorator_name in auth_decorators:
                has_auth = True
                break

        if not has_auth:
            for call in func.find_calls():
                if any(pat in call.name.lower() for pat in AUTH_CALL_PATTERNS):
                    has_auth = True
                    break

        func_has_auth[func.name] = has_auth

        for call in func.find_calls():
            if call.name:
                call_graph.setdefault(func.name, []).append((call.name, call.line))

    # Find chains: A → B → sensitive without auth
    for caller, callees in call_graph.items():
        if func_has_auth.get(caller, False):
            continue

        for callee, line in callees:
            if callee in SENSITIVE_ACTIONS:
                findings.append(BLFinding(
                    rule_id="BL.MISSING-AUTH-CHAIN",
                    severity="high",
                    description=f"{caller}() calls sensitive action '{callee}()' without auth",
                    file=tree.file,
                    line=line,
                    function=caller,
                    language=tree.language,
                    cwe="CWE-862",
                    call_chain=[caller, callee],
                ))

            # Check one more level
            for callee2, _ in call_graph.get(callee, []):
                if callee2 in SENSITIVE_ACTIONS and not func_has_auth.get(callee, False):
                    findings.append(BLFinding(
                        rule_id="BL.MISSING-AUTH-CHAIN",
                        severity="high",
                        description=f"{caller}() → {callee}() → {callee2}() — sensitive "
                                    f"action reachable without auth",
                        file=tree.file,
                        line=line,
                        function=caller,
                        language=tree.language,
                        cwe="CWE-862",
                        call_chain=[caller, callee, callee2],
                    ))

    return findings


def detect_typestate_violations(tree: NormalizedNode) -> List[BLFinding]:
    """Detect typestate violations (use-after-close, missing-open).

    Tracks method calls on objects and checks against common protocol patterns.

    v4.3 fix: Requires TYPE EVIDENCE before applying a protocol — either a
    strong variable-name convention (conn, session, file, db, etc.) or an
    assignment from a known constructor (connect(), open(), login(), etc.).
    This prevents false positives on common methods like cache.get(),
    dict.get(), apiClient.get(), etc.

    This mirrors the type-evidence gating fix already applied to Python's
    typestate.py (v2) and v4_restored.py (v4.3), ported here for consistency.
    Without this fix, this function and v4_restored.detect_typestate_multi
    would both fire on the same false positives — redundant AND wrong.
    """
    findings: List[BLFinding] = []

    # Protocol definitions (method name → required prior method)
    PROTOCOLS = {
        "close": {"terminal": True},
        "open": {"required_for": ("read", "write", "seek", "tell", "flush", "readline", "readlines")},
        "connect": {"required_for": ("execute", "commit", "rollback", "query", "fetchone", "fetchall")},
        "login": {"required_for": ("get", "post", "put", "patch", "request")},
        "begin": {"required_for": ("execute", "commit", "rollback")},
        "start": {"required_for": ("send", "recv", "stop")},
    }

    # Build reverse map: method → required_prior
    method_requires: Dict[str, str] = {}
    terminal_methods: Set[str] = set()
    for prior, config in PROTOCOLS.items():
        for method in config.get("required_for", ()):
            method_requires[method] = prior
        if config.get("terminal"):
            terminal_methods.add(prior)

    # Variable-name conventions that strongly suggest a protocol type.
    # Only variables matching these patterns get protocol analysis applied.
    VAR_NAME_CONVENTIONS = {
        "session", "auth", "token", "jwt",
        "conn", "connection", "db", "database", "cursor", "client",
        "file", "fp", "fhandle", "fh", "f", "stream", "reader", "writer",
        "txn", "transaction",
        "payment", "pay", "charge",
    }

    # Constructor patterns that establish a protocol type
    CONSTRUCTOR_PATTERNS = {
        "connect", "open", "login", "begin", "start", "session", "socket",
    }

    def _has_type_evidence(var_name: str, func_node: NormalizedNode) -> bool:
        """Check if a variable has type evidence justifying protocol analysis."""
        var_lower = var_name.lower()
        for conv in VAR_NAME_CONVENTIONS:
            if var_lower == conv or var_lower.startswith(conv + "_") or var_lower.endswith("_" + conv):
                return True
        for node in func_node.walk():
            if node.kind == "assignment" and node.target == var_name and node.text:
                for ctor in CONSTRUCTOR_PATTERNS:
                    if ctor + "(" in node.text or ctor + ".create(" in node.text:
                        return True
        return False

    for func in tree.find_function_defs():
        var_calls: Dict[str, List[Tuple[str, int]]] = {}

        for node in func.walk():
            # v4.4: Check both "attribute" (JS/Go) AND "call" with obj+attr (Java)
            if (node.kind == "attribute" or
                (node.kind == "call" and node.obj and node.attr)) and node.obj and node.attr:
                var_name = node.obj
                method = node.attr.lower()
                if method in method_requires or method in terminal_methods:
                    # v4.3: Only track calls on variables with TYPE EVIDENCE
                    if not _has_type_evidence(var_name, func):
                        continue
                    var_calls.setdefault(var_name, []).append((method, node.line))
                elif method in ("close", "open", "connect", "disconnect", "login",
                                "logout", "begin", "commit", "rollback", "start", "stop"):
                    if not _has_type_evidence(var_name, func):
                        continue
                    var_calls.setdefault(var_name, []).append((method, node.line))

        # Check for violations
        for var, calls in var_calls.items():
            history: List[Tuple[str, int]] = []
            for method, line in calls:
                # Check requires_prior — only for methods that have a required prior
                if method in method_requires:
                    required = method_requires[method]
                    if not any(m == required for m, _ in history):
                        findings.append(BLFinding(
                            rule_id="BL.TYPESTATE-REQUIRES-PRIOR",
                            severity="medium",
                            description=f"{var}.{method}() called without prior {required}() — "
                                        f"typestate violation",
                            file=tree.file,
                            line=line,
                            function=func.name,
                            language=tree.language,
                            cwe="CWE-664",
                        ))

                # Check terminal (use after close) — only for non-terminal methods
                # called after a terminal method
                if method not in terminal_methods and history:
                    for prev_method, prev_line in history:
                        if prev_method in terminal_methods:
                            findings.append(BLFinding(
                                rule_id="BL.TYPESTATE-USE-AFTER-CLOSE",
                                severity="high",
                                description=f"{var}.{method}() called after {prev_method}() at "
                                            f"line {prev_line} — use after terminal operation",
                                file=tree.file,
                                line=line,
                                function=func.name,
                                language=tree.language,
                                cwe="CWE-416",
                            ))
                            break

                history.append((method, line))

    return findings


def detect_all(file_path: Path) -> List[BLFinding]:
    """Run all multi-language BL detectors on a file.

    This is the main entry point — detects the language, parses the file,
    and runs all applicable detectors.
    """
    if not is_supported(file_path):
        return []

    tree = parse_file(file_path)
    if tree is None:
        return []

    findings: List[BLFinding] = []
    findings.extend(detect_auth_violations(tree))
    findings.extend(detect_reentrancy(tree))
    findings.extend(detect_toctou(tree))
    findings.extend(detect_missing_auth_in_chain(tree))
    findings.extend(detect_typestate_violations(tree))

    return findings


def detect_repo(repo_root: Path, max_files: int = 200) -> List[BLFinding]:
    """Run multi-language BL detection on an entire repo."""
    skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules",
                 ".loomscan-cache", "build", "dist", ".pytest_cache", "coverage",
                 "target", ".loomscan-reports", ".loomscan-fixes"}
    findings: List[BLFinding] = []
    count = 0

    for py_file in sorted(repo_root.rglob("*")):
        if not py_file.is_file():
            continue
        if any(part in skip_dirs for part in py_file.parts):
            continue
        if not is_supported(py_file):
            continue
        if count >= max_files:
            break
        count += 1

        file_findings = detect_all(py_file)
        findings.extend(file_findings)

    return findings


def get_supported_languages() -> List[str]:
    """Return the list of languages with BL detection support."""
    langs = ["python"]  # always supported via built-in ast
    for lang in ["javascript", "typescript", "go", "java", "c", "cpp", "rust"]:
        if lang in _TS_LANGUAGE_MODULES:
            langs.append(lang)
    return langs


def get_capabilities() -> Dict[str, Any]:
    """Return a summary of current BL detection capabilities."""
    supported = get_supported_languages()
    return {
        "supported_languages": supported,
        "tree_sitter_available": _HAS_TS,
        "tree_sitter_languages": list(_TS_LANGUAGE_MODULES.keys()),
        "detectors": [
            "auth_violations",
            "reentrancy",
            "toctou",
            "missing_auth_in_chain",
            "typestate_violations",
        ],
        "techniques_per_language": {
            lang: {
                "auth_violations": True,
                "reentrancy": True,
                "toctou": True,
                "missing_auth_in_chain": True,
                "typestate_violations": True,
            }
            for lang in supported
        },
    }
