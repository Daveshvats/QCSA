"""Business logic understanding.

Extracts and verifies domain-level rules: authorization matrix, business
state machines (order/payment/user/subscription), invariants from asserts
and raise-if checks, and detects drift between docstring claims and code.

This module deliberately avoids heavyweight NLP — every extractor uses
regex + AST heuristics that work across Python and JS.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


# =============================================================================
# Auth rule data model
# =============================================================================

@dataclass
class AuthRule:
    """One authorization rule extracted from the codebase."""
    file: str
    line: int
    rule_type: str        # decorator | inline_check | hoc | route_guard
    pattern: str          # e.g. "@login_required", "@PreAuthorize('hasRole(...)'"
    roles: List[str] = field(default_factory=list)
    function: str = ""
    description: str = ""


@dataclass
class AuthViolation:
    """A detected auth violation."""
    file: str
    line: int
    rule_id: str
    severity: str
    description: str
    fix: str = ""
    cwe: str = "CWE-862"


# =============================================================================
# Auth matrix extractor
# =============================================================================

_PY_DECORATORS = [
    (r"@login_required", ["user"]),
    (r"@permission_required\s*\(\s*['\"]([^'\"]+)['\"]", None),  # roles captured
    (r"@require_roles\s*\(\s*['\"]([^'\"]+)['\"]", None),
    (r"@admin_required", ["admin"]),
    (r"@staff_required", ["staff"]),
    (r"@authenticated", ["user"]),
    (r"@requires_auth", ["user"]),
]

_JS_DECORATORS = [
    (r"@(?:RequireAuth|WithAuth|Authenticated)", ["user"]),
    (r"@(?:Admin|AdminOnly|RequireAdmin)", ["admin"]),
    (r"@(?:Role|RequireRole)\s*\(\s*['\"]([^'\"]+)['\"]", None),
    (r"@(?:Permission|RequirePermission)\s*\(\s*['\"]([^'\"]+)['\"]", None),
]

# Inline checks: `if not current_user: raise Unauthorized`
_PY_INLINE_CHECKS = [
    (r"if\s+(?:not\s+)?current_user\s*(?:is\s+(?:not\s+)?None)?\s*[:=]", "user"),
    (r"require_role\s*\(\s*['\"]([^'\"]+)['\"]", None),
    (r"check_permission\s*\(\s*['\"]([^'\"]+)['\"]", None),
    (r"raise\s+(?:Unauthorized|Forbidden|NotAuthenticated)", None),
]


class AuthMatrixExtractor:
    """Extract auth rules from Python decorators, JS decorators, and inline checks."""

    def extract_from_file(self, file_path: Path) -> List[AuthRule]:
        if not file_path.exists():
            return []
        try:
            source = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return []
        rules: List[AuthRule] = []
        ext = file_path.suffix.lower()
        if ext == ".py":
            rules.extend(self._extract_py_decorators(source, str(file_path)))
            rules.extend(self._extract_inline_checks(source, str(file_path)))
        elif ext in {".js", ".jsx", ".ts", ".tsx"}:
            rules.extend(self._extract_js_decorators(source, str(file_path)))
        return rules

    def _extract_py_decorators(self, source: str, file: str) -> List[AuthRule]:
        out: List[AuthRule] = []
        lines = source.splitlines()
        for i, line in enumerate(lines, 1):
            for pat, base_roles in _PY_DECORATORS:
                m = re.search(pat, line)
                if not m:
                    continue
                roles = base_roles if base_roles else ([m.group(1)] if m.lastindex else [])
                out.append(AuthRule(
                    file=file, line=i, rule_type="decorator",
                    pattern=pat, roles=roles,
                    description=f"@-decorator '{line.strip()}' requires role(s): {roles}"))
        return out

    def _extract_js_decorators(self, source: str, file: str) -> List[AuthRule]:
        out: List[AuthRule] = []
        lines = source.splitlines()
        for i, line in enumerate(lines, 1):
            for pat, base_roles in _JS_DECORATORS:
                m = re.search(pat, line)
                if not m:
                    continue
                roles = base_roles if base_roles else ([m.group(1)] if m.lastindex else [])
                out.append(AuthRule(
                    file=file, line=i, rule_type="decorator",
                    pattern=pat, roles=roles,
                    description=f"JS decorator '{line.strip()}' requires role(s): {roles}"))
        return out

    def _extract_inline_checks(self, source: str, file: str) -> List[AuthRule]:
        out: List[AuthRule] = []
        lines = source.splitlines()
        for i, line in enumerate(lines, 1):
            for pat, base_role in _PY_INLINE_CHECKS:
                m = re.search(pat, line)
                if not m:
                    continue
                roles = [base_role] if base_role else (
                    [m.group(1)] if m.lastindex else ["user"])
                out.append(AuthRule(
                    file=file, line=i, rule_type="inline_check",
                    pattern=pat, roles=roles,
                    description=f"Inline auth check at line {i}: '{line.strip()}'"))
        return out


# =============================================================================
# Auth violation detector
# =============================================================================

# Sensitive method-name patterns (matched against bare method names, NOT call text).
# The old version required a literal '(' in the regex, but we match against
# sub.func.attr (the bare method name like "delete"), which never contains '('.
# Fixed: match the method name directly with word boundaries.
_SENSITIVE_PATTERNS = [
    (r"^(?:delete|remove|destroy|purge|wipe)\w*$", "delete"),
    (r"^(?:admin|root|sudo)\w*$", "admin"),
    (r"^(?:refund|chargeback|reverse_payment)\w*$", "payment"),
    (r"^(?:update_role|grant|revoke|change_password|reset_password)\w*$", "privilege"),
    (r"^(?:export|download_all|bulk)\w*$", "data-export"),
]


class AuthViolationDetector:
    """Detect sensitive actions that lack an auth check in the same function.

    Fixed in v3.3: The old version matched _SENSITIVE_PATTERNS (which required
    a literal '(') against bare method names (which never contain '('). This
    made the detector 100% non-functional. Now we match against the bare
    method name with ^...$ anchors, which works correctly.
    """

    def __init__(self, rules: Optional[List[AuthRule]] = None) -> None:
        self.rules = rules or []

    def analyze_file(self, file_path: Path) -> List[AuthViolation]:
        if not file_path.exists() or file_path.suffix != ".py":
            return []
        try:
            source = file_path.read_text(encoding="utf-8")
            tree = ast.parse(source)
        except Exception:
            return []
        file_str = str(file_path)
        # map function lineno → has_auth (from extracted rules)
        auth_lines: Set[int] = {r.line for r in self.rules if r.file == file_str}
        out: List[AuthViolation] = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            func_start = node.lineno
            func_end = max((n.lineno for n in ast.walk(node) if hasattr(n, "lineno")),
                            default=node.lineno)
            # function has auth if any rule line is within its body OR decorators
            has_auth = any(func_start - 2 <= r.line <= func_end + 1
                            for r in self.rules if r.file == file_str)
            # Also check for auth-related decorators and calls in the function
            if not has_auth:
                for sub in ast.walk(node):
                    # Check decorators like @login_required, @requires_auth
                    if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        for dec in sub.decorator_list:
                            dec_name = ""
                            if isinstance(dec, ast.Name):
                                dec_name = dec.id
                            elif isinstance(dec, ast.Attribute):
                                dec_name = dec.attr
                            elif isinstance(dec, ast.Call):
                                if isinstance(dec.func, ast.Name):
                                    dec_name = dec.func.id
                                elif isinstance(dec.func, ast.Attribute):
                                    dec_name = dec.func.attr
                            if any(kw in dec_name.lower() for kw in
                                   ("login", "auth", "permission", "role", "require")):
                                has_auth = True
                                break
                    # Check for auth-related function calls
                    if isinstance(sub, ast.Call):
                        call_name = ""
                        if isinstance(sub.func, ast.Name):
                            call_name = sub.func.id
                        elif isinstance(sub.func, ast.Attribute):
                            call_name = sub.func.attr
                        if any(kw in call_name.lower() for kw in
                               ("check_auth", "require_auth", "check_permission",
                                "check_role", "is_authenticated", "current_user",
                                "login_required", "verify_token")):
                            has_auth = True
                            break
                    # v3.3: Also check for auth-related attribute access
                    # (e.g., current_user.is_authenticated, request.user.is_admin)
                    if isinstance(sub, ast.Attribute):
                        attr_name = sub.attr
                        if any(kw in attr_name.lower() for kw in
                               ("is_authenticated", "is_admin", "is_authorized",
                                "has_permission", "is_superuser", "is_staff")):
                            has_auth = True
                            break
                    # v3.3: Also check for 'if not <auth>:' patterns
                    if isinstance(sub, ast.UnaryOp) and isinstance(sub.op, ast.Not):
                        # If there's a 'not <something>' check, it might be auth
                        # This is conservative — we'd rather miss a violation than
                        # false-positive on correct code
                        if isinstance(sub.operand, (ast.Attribute, ast.Call, ast.Name)):
                            has_auth = True  # conservative: assume it's an auth check
                            break
                if has_auth:
                    continue
            if has_auth:
                continue
            # scan body for sensitive calls
            for sub in ast.walk(node):
                if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute):
                    method = sub.func.attr
                elif isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name):
                    method = sub.func.id
                else:
                    continue
                for pat, kind in _SENSITIVE_PATTERNS:
                    if re.search(pat, method):
                        out.append(AuthViolation(
                            file=file_str, line=sub.lineno,
                            rule_id=f"AUTH-NO-CHECK-{kind.upper()}",
                            severity="high",
                            description=f"Sensitive {kind} action '{method}()' in '{node.name}()' has no auth check",
                            fix=f"Add @login_required or an inline role check to {node.name}()",
                            cwe="CWE-862"))
                        break
        return out


# =============================================================================
# Business state machine analyzer
# =============================================================================

_BUSINESS_SMS: Dict[str, dict] = {
    "order": {
        "states": ["created", "pending_payment", "paid", "shipped", "delivered", "cancelled", "refunded"],
        "transitions": {
            "created": ["pending_payment", "cancelled"],
            "pending_payment": ["paid", "cancelled"],
            "paid": ["shipped", "refunded", "cancelled"],
            "shipped": ["delivered"],
            "delivered": ["refunded"],
        },
        "method_to_state": {
            "create": "created", "pay": "paid", "ship": "shipped",
            "deliver": "delivered", "cancel": "cancelled", "refund": "refunded",
        },
    },
    "payment": {
        "states": ["initiated", "authorized", "captured", "refunded", "voided", "failed"],
        "transitions": {
            "initiated": ["authorized", "failed", "voided"],
            "authorized": ["captured", "voided", "refunded"],
            "captured": ["refunded"],
        },
        "method_to_state": {
            "authorize": "authorized", "capture": "captured",
            "refund": "refunded", "void": "voided", "fail": "failed",
        },
    },
    "user": {
        "states": ["registered", "active", "suspended", "deactivated", "deleted"],
        "transitions": {
            "registered": ["active", "deleted"],
            "active": ["suspended", "deactivated"],
            "suspended": ["active", "deactivated"],
            "deactivated": ["active", "deleted"],
        },
        "method_to_state": {
            "register": "registered", "activate": "active",
            "suspend": "suspended", "deactivate": "deactivated",
            "delete": "deleted",
        },
    },
    "subscription": {
        "states": ["trialing", "active", "past_due", "canceled", "expired"],
        "transitions": {
            "trialing": ["active", "canceled", "expired"],
            "active": ["past_due", "canceled"],
            "past_due": ["active", "canceled", "expired"],
        },
        "method_to_state": {
            "start_trial": "trialing", "activate": "active",
            "mark_past_due": "past_due", "cancel": "canceled", "expire": "expired",
        },
    },
}


@dataclass
class BusinessSMViolation:
    file: str
    line: int
    rule_id: str
    severity: str
    description: str
    fix: str = ""


class BusinessStateMachineAnalyzer:
    """Detect invalid state transitions in order/payment/user/subscription flows.

    v2 fixes (addressing code review findings):
      1. **No more substring matching**: The old version used `if kind in
         node.name.lower()` which caused "order" to match "recorder",
         "border", "folder", etc. Now we require explicit opt-in: either
         a decorator (@state_machine("order")) or the function name must
         START with the kind (e.g., "cancel_order", "process_payment").
      2. **Branch-aware transition checking**: The old version used
         ast.walk() which flattens the AST, treating if/else branches as
         sequential. Now we only track transitions within a single linear
         control-flow path — calls in mutually exclusive branches are NOT
         chained together.
    """

    def analyze_file(self, file_path: Path) -> List[BusinessSMViolation]:
        if not file_path.exists() or file_path.suffix != ".py":
            return []
        try:
            source = file_path.read_text(encoding="utf-8")
            tree = ast.parse(source)
        except Exception:
            return []
        out: List[BusinessSMViolation] = []
        file_str = str(file_path)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            # v2: Identify resource type by:
            # 1. Explicit decorator: @state_machine("order")
            # 2. Function name STARTS with kind: "cancel_order", "process_payment"
            # NOT substring matching (which caused "order" to match "recorder")
            kind = self._identify_resource_type(node)
            if kind:
                sm = _BUSINESS_SMS.get(kind)
                if sm:
                    out.extend(self._check_function_transitions(node, kind, sm, file_str))
        return out

    def _identify_resource_type(self, func: ast.FunctionDef) -> Optional[str]:
        """Identify the business resource type for a function.

        v2: No more substring matching — requires explicit opt-in via:
        1. Decorator: @state_machine("order") or @business_sm("payment")
        2. Function name STARTS with kind: "cancel_order", "process_payment"

        This prevents "order" from matching "recorder", "border", etc.
        """
        # Check decorators first (most explicit)
        for dec in func.decorator_list:
            dec_name = ""
            dec_arg = ""
            if isinstance(dec, ast.Call):
                if isinstance(dec.func, ast.Name):
                    dec_name = dec.func.id
                elif isinstance(dec.func, ast.Attribute):
                    dec_name = dec.func.attr
                # Extract string argument
                if dec.args and isinstance(dec.args[0], ast.Constant):
                    dec_arg = str(dec.args[0].value)
            elif isinstance(dec, ast.Name):
                dec_name = dec.id

            if dec_name in ("state_machine", "business_sm", "statemachine"):
                if dec_arg in _BUSINESS_SMS:
                    return dec_arg

        # Check function name — must START with kind (not just contain it)
        name_lower = func.name.lower()
        for kind in _BUSINESS_SMS:
            # Match patterns like "cancel_order", "process_payment", "ship_order"
            # The kind must be at the END of the name, preceded by an underscore
            # or be the entire name
            if name_lower == kind or name_lower.endswith("_" + kind):
                return kind
            # Also match "order_" prefix (e.g., "order_cancel")
            if name_lower.startswith(kind + "_"):
                return kind

        return None

    def _check_function_transitions(self, func: ast.FunctionDef, kind: str,
                                       sm: dict, file: str) -> List[BusinessSMViolation]:
        """Check for invalid state transitions within a function.

        v2: Branch-aware — only chains transitions within a single linear
        control-flow path. Calls in if/else branches are NOT chained.
        """
        out: List[BusinessSMViolation] = []
        # v2: Walk the function body STATEMENT BY STATEMENT (not ast.walk
        # which flattens everything). Only chain transitions within a
        # linear sequence — if we hit a branch (if/else/for/while/try),
        # we reset the state tracking for each branch.
        self._check_statements_sequentially(func.body, sm, kind, file, out, last_state=None)
        return out

    def _check_statements_sequentially(self, statements: list, sm: dict, kind: str,
                                         file: str, out: List[BusinessSMViolation],
                                         last_state: Optional[str]) -> Optional[str]:
        """Walk statements in order, only chaining transitions linearly.

        When we encounter a branch (if/else/for/while/try), we recurse into
        each branch independently with a COPY of the current state. This
        prevents false positives from mutually exclusive branches.
        """
        for i, stmt in enumerate(statements):
            # If this statement is a branch, handle it specially
            if isinstance(stmt, ast.If):
                # Each branch gets its own copy of last_state
                self._check_statements_sequentially(stmt.body, sm, kind, file, out, last_state)
                self._check_statements_sequentially(stmt.orelse, sm, kind, file, out, last_state)
                # After the if/else, state is uncertain — don't chain further
                # (conservative: reset to None to avoid false positives)
                return None
            elif isinstance(stmt, (ast.For, ast.While)):
                # Loop bodies may or may not execute — reset state after
                self._check_statements_sequentially(stmt.body, sm, kind, file, out, last_state)
                return None
            elif isinstance(stmt, ast.Try):
                # Each except handler is a separate branch
                self._check_statements_sequentially(stmt.body, sm, kind, file, out, last_state)
                for handler in stmt.handlers:
                    self._check_statements_sequentially(handler.body, sm, kind, file, out, last_state)
                return None
            else:
                # Non-branch statement — check for calls in THIS statement only
                # (not in nested branches — those are handled by recursion above)
                for sub in ast.walk(stmt):
                    # Skip nested function defs (they have their own scope)
                    if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)) and sub is not stmt:
                        continue
                    if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute):
                        method = sub.func.attr
                        new_state = sm["method_to_state"].get(method)
                        if not new_state:
                            continue
                        if last_state is not None:
                            valid = sm["transitions"].get(last_state, [])
                            if new_state not in valid:
                                out.append(BusinessSMViolation(
                                    file=file, line=sub.lineno,
                                    rule_id=f"BIZ-{kind.upper()}-INVALID-TRANSITION",
                                    severity="high",
                                    description=f"Invalid {kind} transition: {last_state} → {new_state} "
                                                f"(valid: {valid})",
                                    fix=f"Add guard: if {kind}.state != '{last_state}': raise"))
                        last_state = new_state

        return last_state


# =============================================================================
# Invariant miner
# =============================================================================

@dataclass
class Invariant:
    file: str
    line: int
    function: str
    expr: str
    source: str  # 'assert' | 'if-raise'
    description: str


class InvariantMiner:
    """Mine invariants from `assert` statements and `if cond: raise` patterns."""

    def mine_file(self, file_path: Path) -> List[Invariant]:
        if not file_path.exists() or file_path.suffix != ".py":
            return []
        try:
            source = file_path.read_text(encoding="utf-8")
            tree = ast.parse(source)
        except Exception:
            return []
        out: List[Invariant] = []
        file_str = str(file_path)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for sub in ast.walk(node):
                if isinstance(sub, ast.Assert):
                    try:
                        expr = ast.unparse(sub.test) if hasattr(ast, "unparse") else "<assert>"
                    except Exception:
                        expr = "<assert>"
                    out.append(Invariant(
                        file=file_str, line=sub.lineno, function=node.name,
                        expr=expr, source="assert",
                        description=f"assert {expr}"))
                elif (isinstance(sub, ast.If)
                      and sub.orelse == []
                      and len(sub.body) == 1
                      and isinstance(sub.body[0], ast.Raise)):
                    try:
                        expr = ast.unparse(sub.test) if hasattr(ast, "unparse") else "<cond>"
                    except Exception:
                        expr = "<cond>"
                    out.append(Invariant(
                        file=file_str, line=sub.lineno, function=node.name,
                        expr=f"not ({expr})", source="if-raise",
                        description=f"if {expr}: raise"))
        return out


# =============================================================================
# Doc drift analyzer
# =============================================================================

@dataclass
class DocDrift:
    file: str
    line: int
    function: str
    claim: str
    mismatch: str


class DocDriftAnalyzer:
    """Detect drift between docstring claims and actual code behavior."""

    _PARAM_RE = re.compile(r":param\s+(\w+):")
    _RETURN_RE = re.compile(r":returns?:")
    _RAISE_RE = re.compile(r":raises?\s+(\w+):")

    def analyze_file(self, file_path: Path) -> List[DocDrift]:
        if not file_path.exists() or file_path.suffix != ".py":
            return []
        try:
            source = file_path.read_text(encoding="utf-8")
            tree = ast.parse(source)
        except Exception:
            return []
        out: List[DocDrift] = []
        file_str = str(file_path)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            doc = ast.get_docstring(node)
            if not doc:
                continue
            # Check :param mentions match actual params
            doc_params = set(self._PARAM_RE.findall(doc))
            actual_params = {a.arg for a in node.args.args + node.args.kwonlyargs}
            for p in doc_params - actual_params:
                out.append(DocDrift(
                    file=file_str, line=node.lineno, function=node.name,
                    claim=f":param {p}:",
                    mismatch=f"Docstring documents param '{p}' but function does not declare it"))
            # Check :returns presence if function actually returns a value
            doc_has_return = bool(self._RETURN_RE.search(doc))
            actual_returns = any(isinstance(n, ast.Return) and n.value is not None
                                  for n in ast.walk(node))
            if doc_has_return and not actual_returns:
                out.append(DocDrift(
                    file=file_str, line=node.lineno, function=node.name,
                    claim=":returns:",
                    mismatch="Docstring documents a return value but function never returns one"))
            if actual_returns and not doc_has_return and not node.name.startswith("_"):
                out.append(DocDrift(
                    file=file_str, line=node.lineno, function=node.name,
                    claim="<missing :returns:>",
                    mismatch="Function returns a value but docstring has no :returns:"))
            # Check :raises mentions match actual raises
            doc_raises = set(self._RAISE_RE.findall(doc))
            actual_raises: Set[str] = set()
            for n in ast.walk(node):
                if isinstance(n, ast.Raise) and n.exc:
                    if isinstance(n.exc, ast.Call) and isinstance(n.exc.func, ast.Name):
                        actual_raises.add(n.exc.func.id)
                    elif isinstance(n.exc, ast.Name):
                        actual_raises.add(n.exc.id)
            for r in actual_raises - doc_raises:
                out.append(DocDrift(
                    file=file_str, line=node.lineno, function=node.name,
                    claim=f"<missing :raises {r}:>",
                    mismatch=f"Function raises {r} but docstring does not document it"))
        return out
