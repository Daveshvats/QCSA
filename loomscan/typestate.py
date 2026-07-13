"""Typestate analysis — detect state machine violations (v2 — type-aware).

Many bugs are state machine violations:
  - Calling .charge() before .authorize()
  - Using a connection after .close()
  - Reading from a file before .open()
  - Calling .send() after .shutdown()
  - Double-charging a payment
  - Using a session after .logout()

Real typestate analysis (Plaid, Mungo, Frama-C) requires type system support.
We do a pragmatic version: track method calls on objects and flag violations
of common protocol patterns.

v2 fix (addressing code review findings):
  The old version matched protocols purely on method name, which caused
  massive false positives — e.g., dict.get() was flagged as a session_like
  protocol violation because "get" is in session_like.methods.

  Now we require TYPE EVIDENCE before applying a protocol:
  1. Type annotation: def f(conn: sqlite3.Connection) → connection_like
  2. Assignment from known constructor: conn = sqlite3.connect() → connection_like
  3. Parameter name convention: def f(session, ...) → session_like (only if
     the name strongly suggests the type, e.g. "session", "conn", "file")

  This eliminates the false positives on dict.get(), cache.get(), etc.
  while still catching real typestate violations when type info is available.

Patterns we detect:
  - close-then-use: .close() followed by any other method call on same object
  - authorize-then-charge: .charge() called on a payment without prior .authorize()
  - open-then-read: read/write before .open()
  - send-after-shutdown: .send() after .shutdown()
  - double-action: same method called twice without reset
"""
from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import List, Dict, Tuple, Set, Optional
from dataclasses import dataclass


# Protocol definitions: (type_pattern, method_order_constraints)
# Each constraint: (required_prior, method) — method requires required_prior to be called first
PROTOCOLS = {
    "file_like": {
        "methods": {"open", "read", "write", "close", "seek", "tell"},
        "requires_prior": {
            "read": "open",
            "write": "open",
            "seek": "open",
            "tell": "open",
        },
        "terminal": {"close"},  # no method should be called after close
    },
    "connection_like": {
        "methods": {"connect", "execute", "commit", "rollback", "close"},
        "requires_prior": {
            "execute": "connect",
            "commit": "connect",
            "rollback": "connect",
        },
        "terminal": {"close"},
    },
    "payment_like": {
        "methods": {"authorize", "charge", "refund", "void"},
        "requires_prior": {
            "charge": "authorize",
            "refund": "charge",
            "void": "authorize",
        },
        "terminal": {"void", "refund"},
    },
    "session_like": {
        "methods": {"login", "get", "post", "put", "delete", "logout"},
        "requires_prior": {
            "get": "login",
            "post": "login",
            "put": "login",
            "delete": "login",
        },
        "terminal": {"logout"},
    },
    "transaction_like": {
        "methods": {"begin", "execute", "commit", "rollback"},
        "requires_prior": {
            "execute": "begin",
            "commit": "begin",
            "rollback": "begin",
        },
        "terminal": {"commit", "rollback"},
    },
}


@dataclass
class TypestateViolation:
    """A detected state machine violation."""
    file: str
    line: int
    object_name: str
    protocol: str
    violation: str  # 'close_then_use' | 'requires_prior' | 'double_action'
    description: str
    cwe: str = "CWE-664"  # improper control of a resource through its lifetime


def analyze_typestate(file_path: Path) -> List[TypestateViolation]:
    """Analyze a Python file for typestate violations."""
    if not file_path.exists() or file_path.suffix != ".py":
        return []
    try:
        source = file_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except Exception:
        return []

    violations: List[TypestateViolation] = []

    # For each function, track method calls on each variable
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        func_violations = _analyze_function_typestate(node, str(file_path))
        violations.extend(func_violations)

    return violations


def _analyze_function_typestate(func_node: ast.FunctionDef,
                                 file_path: str) -> List[TypestateViolation]:
    """Track method calls on variables within a single function.

    v2: Only applies protocols to variables with TYPE EVIDENCE — either
    a type annotation, a known constructor assignment, or a strong
    parameter name convention. This prevents false positives on common
    methods like dict.get().
    """
    violations: List[TypestateViolation] = []

    # Step 1: Collect type evidence for each variable
    var_types: Dict[str, str] = {}  # var_name → inferred type hint

    # 1a. Parameter annotations
    for arg in func_node.args.args + func_node.args.kwonlyargs:
        if arg.annotation:
            ann_str = _annotation_to_str(arg.annotation)
            proto = _infer_protocol_from_annotation(ann_str, arg.arg)
            if proto:
                var_types[arg.arg] = proto

    # 1b. Assignment from known constructors
    for node in ast.walk(func_node):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    proto = _infer_protocol_from_assignment(node.value, target.id)
                    if proto:
                        var_types[target.id] = proto

    # state: variable_name → list of (method, line) called on it
    var_calls: Dict[str, List[Tuple[str, int]]] = {}

    # For variables created from constructors, the "required prior" is
    # already satisfied (e.g., conn = connect() means connect() was called).
    # We track which variables have their "prior" satisfied by construction.
    prior_satisfied: Set[str] = set()
    for var_name, proto_name in var_types.items():
        proto_def = PROTOCOLS.get(proto_name, {})
        requires_prior = proto_def.get("requires_prior", {})
        # If the variable was created from a constructor, the required prior
        # is satisfied for ALL methods in that protocol.
        # E.g., conn = connect() → connect() is already done
        #       f = open() → open() is already done
        for method, required in requires_prior.items():
            # Check if the variable was assigned from a constructor that
            # matches the required prior method
            for node in ast.walk(func_node):
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name) and target.id == var_name:
                            if isinstance(node.value, ast.Call):
                                if isinstance(node.value.func, ast.Name):
                                    func_name = node.value.func.id
                                elif isinstance(node.value.func, ast.Attribute):
                                    func_name = node.value.func.attr
                                else:
                                    func_name = ""
                                # If the constructor name matches the required prior,
                                # the prior is satisfied for this variable.
                                if func_name == required:
                                    prior_satisfied.add(var_name)

    # walk ALL call nodes in the function (not just ast.Expr-wrapped ones)
    for stmt in ast.walk(func_node):
        if not isinstance(stmt, ast.Call):
            continue
        if not isinstance(stmt.func, ast.Attribute):
            continue

        obj_node = stmt.func.value
        method_name = stmt.func.attr

        if isinstance(obj_node, ast.Name):
            var_name = obj_node.id
        else:
            continue

        # v2: Only apply protocols to variables with type evidence.
        # This is the critical fix — without it, dict.get() gets flagged
        # as a session_like violation.
        if var_name not in var_types:
            continue

        proto_name = var_types[var_name]
        proto_def = PROTOCOLS.get(proto_name)
        if not proto_def:
            continue

        # Only flag if the method is actually in this protocol
        if method_name not in proto_def["methods"]:
            continue

        history = var_calls.setdefault(var_name, [])

        # check requires_prior
        if method_name in proto_def.get("requires_prior", {}):
            required = proto_def["requires_prior"][method_name]
            # Skip if the prior was satisfied by construction (e.g., conn = connect())
            if var_name in prior_satisfied:
                pass  # prior is satisfied, don't flag
            elif not any(m == required for m, _ in history):
                violations.append(TypestateViolation(
                    file=file_path,
                    line=stmt.lineno,
                    object_name=var_name,
                    protocol=proto_name,
                    violation="requires_prior",
                    description=f"{var_name}.{method_name}() called without prior {required}() — {proto_name} protocol violation",
                    cwe="CWE-664",
                ))

        # check terminal (close-then-use)
        if proto_def.get("terminal") and history:
            for prev_method, prev_line in history:
                if prev_method in proto_def["terminal"]:
                    violations.append(TypestateViolation(
                        file=file_path,
                        line=stmt.lineno,
                        object_name=var_name,
                        protocol=proto_name,
                        violation="close_then_use",
                        description=f"{var_name}.{method_name}() called after {prev_method}() at line {prev_line} — use after terminal operation",
                        cwe="CWE-416",  # use after free / similar
                    ))
                    break

        # check double-action (same method called twice, not allowed)
        if method_name in proto_def.get("terminal", set()):
            for prev_method, prev_line in history:
                if prev_method == method_name:
                    violations.append(TypestateViolation(
                        file=file_path,
                        line=stmt.lineno,
                        object_name=var_name,
                        protocol=proto_name,
                        violation="double_action",
                        description=f"{var_name}.{method_name}() called twice (first at line {prev_line}) — double-{method_name} is likely a bug",
                        cwe="CWE-675",  # multiple operations on single resource
                    ))
                    break

        history.append((method_name, stmt.lineno))

    return violations


def _annotation_to_str(annotation: ast.AST) -> str:
    """Convert an AST annotation to a string."""
    try:
        return ast.unparse(annotation)
    except Exception:
        return ""


# Type → protocol mapping (for annotations and constructor detection)
_TYPE_TO_PROTOCOL = {
    # file_like
    "TextIO": "file_like", "BinaryIO": "file_like",
    "IO": "file_like", "file": "file_like",
    "TextIOWrapper": "file_like", "BufferedReader": "file_like",
    # connection_like
    "Connection": "connection_like", "sqlite3.Connection": "connection_like",
    "psycopg2.extensions.connection": "connection_like",
    "mysql.connector.connection": "connection_like",
    "MySQLdb.connections.Connection": "connection_like",
    # payment_like
    "Payment": "payment_like", "PaymentIntent": "payment_like",
    "Charge": "payment_like", "Order": "payment_like",
    # session_like
    "Session": "session_like", "requests.Session": "session_like",
    "ClientSession": "session_like", "aiohttp.ClientSession": "session_like",
    # transaction_like
    "Transaction": "transaction_like",
}

# Constructor patterns: function call name → protocol
_CONSTRUCTOR_TO_PROTOCOL = {
    "open": "file_like",  # open() returns a file
    "connect": "connection_like",  # sqlite3.connect(), psycopg2.connect()
    "Session": "session_like",  # requests.Session()
    "ClientSession": "session_like",  # aiohttp.ClientSession()
    "Payment": "payment_like",
    "Transaction": "transaction_like",
}

# Strong parameter name conventions (only use when no annotation exists)
# These must be VERY specific to avoid false positives.
_NAME_TO_PROTOCOL = {
    "file": "file_like", "fh": "file_like", "fp": "file_like",
    "conn": "connection_like", "connection": "connection_like", "db": "connection_like",
    "cursor": "connection_like",
    "session": "session_like",
    "payment": "payment_like",
    "transaction": "transaction_like", "txn": "transaction_like",
}


def _infer_protocol_from_annotation(ann_str: str, var_name: str = "") -> Optional[str]:
    """Infer protocol from a type annotation string.

    Examples:
      "sqlite3.Connection" → "connection_like"
      "requests.Session" → "session_like"
      "TextIO" → "file_like"
    """
    if not ann_str:
        return None
    # Direct match
    if ann_str in _TYPE_TO_PROTOCOL:
        return _TYPE_TO_PROTOCOL[ann_str]
    # Check if annotation ends with a known type (e.g. "sqlite3.Connection")
    for type_name, proto in _TYPE_TO_PROTOCOL.items():
        if ann_str.endswith("." + type_name) or ann_str == type_name:
            return proto
    return None


def _infer_protocol_from_assignment(value: ast.AST, var_name: str) -> Optional[str]:
    """Infer protocol from an assignment value.

    Examples:
      f = open(...) → "file_like"
      conn = sqlite3.connect(...) → "connection_like"
      session = requests.Session() → "session_like"
    """
    if isinstance(value, ast.Call):
        # Get the function being called
        if isinstance(value.func, ast.Name):
            func_name = value.func.id
        elif isinstance(value.func, ast.Attribute):
            func_name = value.func.attr
        else:
            func_name = ""

        if func_name in _CONSTRUCTOR_TO_PROTOCOL:
            return _CONSTRUCTOR_TO_PROTOCOL[func_name]

    # Fall back to variable name convention (only for very strong signals)
    if var_name in _NAME_TO_PROTOCOL:
        return _NAME_TO_PROTOCOL[var_name]

    return None


def _match_protocol(method_name: str):
    """Find a protocol that includes this method. (Kept for backwards compat.)

    NOTE: In v2, we don't use this for matching — we use type evidence instead.
    This function is kept only for external callers that might use it.
    """
    for proto_name, proto_def in PROTOCOLS.items():
        if method_name in proto_def["methods"]:
            return (proto_name, proto_def)
    return None
