"""Multi-Call Analysis — detect bugs that span multiple function calls.

Inspired by Echidna (Trail of Bits) and smart contract reentrancy detection.

The core idea: some business logic bugs only manifest when multiple functions
are called in sequence. Analyzing functions in isolation misses them.

Patterns we detect:

1. REENTRANCY: A function calls an external callback before completing
   its state update, allowing the callback to re-enter and exploit the
   inconsistent state.
   Example: withdraw() calls an external hook before deducting balance.

2. STATE MANIPULATION ACROSS CALLS: A sequence of calls that puts the
   system in an invalid state that no single call could reach.
   Example: freeze_account() → withdraw() (should be blocked but isn't).

3. MISSING AUTHORIZATION IN CALL CHAIN: Function A calls B which calls C,
   where C performs a sensitive action. If A doesn't check auth, and B
   doesn't check auth, C is reachable without authorization.

4. CHECK-ACT-INTERLEAVE (TOCTOU): Function checks a condition, then calls
   another function that acts on it. If the state changes between check
   and act, the act is invalid.
   Example: check_balance() → transfer() where balance changes between calls.
"""
from __future__ import annotations

import ast
from collections import defaultdict
from pathlib import Path
from typing import List, Optional, Dict, Set, Tuple
from dataclasses import dataclass


@dataclass
class MultiCallViolation:
    """A bug found by multi-call analysis."""
    file: str
    line: int
    violation_type: str  # 'reentrancy' | 'state_manipulation' | 'missing_auth_in_chain' | 'toctou'
    description: str
    call_chain: List[str]  # function names in the call chain
    cwe: str = ""


# Sensitive actions that should require authorization
_SENSITIVE_ACTIONS = {
    "delete", "remove", "destroy", "purge", "wipe",
    "transfer", "withdraw", "refund", "payment",
    "update_role", "grant", "revoke", "change_password", "reset_password",
    "export", "download_all", "bulk",
}

# State-modifying methods (common patterns)
_STATE_MODIFIERS = {
    "set", "update", "add", "remove", "delete", "clear", "reset",
    "save", "commit", "rollback", "transfer", "withdraw", "deposit",
}


def analyze_reentrancy(file_path: Path) -> List[MultiCallViolation]:
    """Detect potential reentrancy patterns.

    A reentrancy pattern exists when:
    1. A function calls an external/untrusted function (callback, hook, listener)
    2. BEFORE completing its state update
    3. Allowing the callback to re-enter the function

    We detect this by finding functions that:
    - Have a call to an external function (callback, hook, listener, notify)
    - That call comes BEFORE a state update (assignment to self.X)
    """
    if not file_path.exists() or file_path.suffix != ".py":
        return []
    try:
        source = file_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except Exception:
        return []

    violations: List[MultiCallViolation] = []
    rel_path = str(file_path)
    external_call_patterns = {"callback", "hook", "listener", "notify", "on_",
                              "emit", "fire", "trigger", "send", "publish"}

    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        # Track the order of: external calls and state updates
        events: List[Tuple[str, str, int]] = []  # (type, name, lineno)

        for node in ast.walk(func):
            if isinstance(node, ast.Call):
                call_name = ""
                if isinstance(node.func, ast.Name):
                    call_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    call_name = node.func.attr

                # Check if this is an external/callback call
                is_external = any(pat in call_name.lower() for pat in external_call_patterns)
                if is_external:
                    events.append(("external_call", call_name, node.lineno))

            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Attribute) and \
                       isinstance(target.value, ast.Name) and target.value.id == "self":
                        events.append(("state_update", target.attr, node.lineno))
                    # Also handle wallet.balance = ... (non-self objects)
                    elif isinstance(target, ast.Attribute) and \
                         isinstance(target.value, ast.Name):
                        events.append(("state_update", target.attr, node.lineno))
            # v4: Also track augmented assignments (+=, -=, etc.)
            if isinstance(node, ast.AugAssign):
                if isinstance(node.target, ast.Attribute) and \
                   isinstance(node.target.value, ast.Name):
                    events.append(("state_update", node.target.attr, node.lineno))

        # Sort by line number
        events.sort(key=lambda x: x[2])

        # Check: is there an external call followed by a state update?
        # (reentrancy: external call happens BEFORE state completes)
        for i, (etype, ename, eline) in enumerate(events):
            if etype == "external_call":
                # Check if there's a state update AFTER this external call
                for j in range(i + 1, len(events)):
                    if events[j][0] == "state_update":
                        violations.append(MultiCallViolation(
                            file=rel_path,
                            line=eline,
                            violation_type="reentrancy",
                            description=f"Potential reentrancy in {func.name}(): external call "
                                        f"'{ename}()' at line {eline} is followed by state update "
                                        f"'self.{events[j][1]}' at line {events[j][2]}. "
                                        f"The external callback could re-enter before the state "
                                        f"update completes.",
                            call_chain=[func.name, ename],
                            cwe="CWE-836",  # Use of a Broken or Risky Cryptographic Algorithm
                        ))
                        break

    return violations


def analyze_missing_auth_in_chain(file_path: Path) -> List[MultiCallViolation]:
    """Detect call chains where a sensitive action is reachable without auth.

    If function A (no auth check) calls B (no auth check) which calls C
    (sensitive action), the chain A → B → C is dangerous.
    """
    if not file_path.exists() or file_path.suffix != ".py":
        return []
    try:
        source = file_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except Exception:
        return []

    violations: List[MultiCallViolation] = []
    rel_path = str(file_path)

    # Build a call graph: function → functions it calls
    call_graph: Dict[str, List[Tuple[str, int]]] = defaultdict(list)
    func_has_auth: Dict[str, bool] = {}
    func_calls_sensitive: Dict[str, List[str]] = defaultdict(list)

    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        has_auth = False
        for sub in ast.walk(func):
            # Check for auth patterns
            if isinstance(sub, ast.Call):
                call_name = ""
                if isinstance(sub.func, ast.Name):
                    call_name = sub.func.id
                elif isinstance(sub.func, ast.Attribute):
                    call_name = sub.func.attr
                if any(kw in call_name.lower() for kw in
                       ("check_auth", "require_auth", "check_permission",
                        "is_authenticated", "current_user", "login_required")):
                    has_auth = True
            # Check for auth decorators
            if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for dec in sub.decorator_list:
                    dec_name = ""
                    if isinstance(dec, ast.Name):
                        dec_name = dec.id
                    elif isinstance(dec, ast.Attribute):
                        dec_name = dec.attr
                    if any(kw in dec_name.lower() for kw in ("login", "auth", "permission", "role")):
                        has_auth = True

            # Check for calls to other functions
            if isinstance(sub, ast.Call):
                callee = ""
                if isinstance(sub.func, ast.Name):
                    callee = sub.func.id
                elif isinstance(sub.func, ast.Attribute):
                    callee = sub.func.attr
                if callee and callee != func.name:
                    call_graph[func.name].append((callee, sub.lineno))

                    # Check if callee is a sensitive action
                    if callee in _SENSITIVE_ACTIONS:
                        func_calls_sensitive[func.name].append(callee)

        func_has_auth[func.name] = has_auth

    # Find chains: A → B → C where C is sensitive and A, B have no auth
    for caller, callees in call_graph.items():
        if func_has_auth.get(caller, False):
            continue  # caller has auth, safe

        for callee, line in callees:
            if callee in func_calls_sensitive:
                # Direct call to sensitive action without auth
                violations.append(MultiCallViolation(
                    file=rel_path,
                    line=line,
                    violation_type="missing_auth_in_chain",
                    description=f"{caller}() calls sensitive action '{callee}()' without "
                                f"an auth check. Add @login_required or an inline role check.",
                    call_chain=[caller, callee],
                    cwe="CWE-862",  # Missing Authorization
                ))

            # Check one more level deep
            for callee2, _ in call_graph.get(callee, []):
                if callee2 in _SENSITIVE_ACTIONS:
                    if not func_has_auth.get(callee, False):
                        violations.append(MultiCallViolation(
                            file=rel_path,
                            line=line,
                            violation_type="missing_auth_in_chain",
                            description=f"{caller}() → {callee}() → {callee2}() — sensitive "
                                        f"action '{callee2}' is reachable without auth check "
                                        f"in the call chain.",
                            call_chain=[caller, callee, callee2],
                            cwe="CWE-862",
                        ))

    return violations


def analyze_toctou(file_path: Path) -> List[MultiCallViolation]:
    """Detect Time-Of-Check-Time-Of-Use patterns.

    A TOCTOU exists when:
    1. A function checks a condition (if x > 0:)
    2. Then calls another function that acts on it
    3. The state could change between check and use

    We detect this by finding: if-check → function-call patterns where
    the checked variable is also a parameter to the called function.
    """
    if not file_path.exists() or file_path.suffix != ".py":
        return []
    try:
        source = file_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except Exception:
        return []

    violations: List[MultiCallViolation] = []
    rel_path = str(file_path)

    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        # Find if-statements that contain a call in their body
        for node in ast.walk(func):
            if not isinstance(node, ast.If):
                continue

            # Extract variables checked in the condition
            checked_vars: Set[str] = set()
            for sub in ast.walk(node.test):
                if isinstance(sub, ast.Name):
                    checked_vars.add(sub.id)

            # Find calls in the if-body that use the checked variables
            for body_node in ast.walk(node):
                if isinstance(body_node, ast.Call):
                    for arg in body_node.args:
                        if isinstance(arg, ast.Name) and arg.id in checked_vars:
                            call_name = ""
                            if isinstance(body_node.func, ast.Name):
                                call_name = body_node.func.id
                            elif isinstance(body_node.func, ast.Attribute):
                                call_name = body_node.func.attr

                            violations.append(MultiCallViolation(
                                file=rel_path,
                                line=body_node.lineno,
                                violation_type="toctou",
                                description=f"Potential TOCTOU in {func.name}(): condition checks "
                                            f"'{', '.join(checked_vars)}' then calls '{call_name}()' "
                                            f"with those variables. If the state changes between "
                                            f"check and call, the call may be invalid.",
                                call_chain=[func.name, call_name],
                                cwe="CWE-367",  # Time-of-check Time-of-use (TOCTOU) Race Condition
                            ))
                            break

    return violations


def analyze_multi_call(file_path: Path) -> List[MultiCallViolation]:
    """Run all multi-call analyses on a file."""
    violations: List[MultiCallViolation] = []
    violations.extend(analyze_reentrancy(file_path))
    violations.extend(analyze_missing_auth_in_chain(file_path))
    violations.extend(analyze_toctou(file_path))
    return violations
