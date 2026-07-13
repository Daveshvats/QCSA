from __future__ import annotations

import ast
import re
import os
import json
import subprocess
import sys
import textwrap
import tempfile
import logging
from pathlib import Path
from typing import List, Optional, Dict, Any, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict

try:
    from .normalized_ast import parse_file, get_language, is_supported, NormalizedNode, _HAS_TS, _TS_LANGUAGE_MODULES
except ImportError:
    _HAS_TS = False
    _TS_LANGUAGE_MODULES = {}

_v4_logger = logging.getLogger("loomscan.v4_restored")
from .v4_types import UnifiedFinding

def detect_state_machine_multi(tree: NormalizedNode) -> List[UnifiedFinding]:
    """Detect invalid state transitions in any language via normalized AST.

    Uses the same state machines (order, payment) but works on NormalizedNode.

    v4.3 fix: Branch-aware state tracking. The previous version used
    func.walk() (a flat traversal) and threaded a single last_state across
    the entire function body. This caused false positives on if/else branches
    — e.g., `if (reason === "customer_request") { order.cancel() } else { order.ship() }`
    was flagged as "cancelled → shipped" even though the two calls are
    mutually exclusive.

    The fix: collect all state-transition calls with their line numbers and
    their containing branch context, then only flag transitions where two
    calls are in the SAME branch (sequential execution). Calls in different
    branches of the same if/else are not sequential and should not be
    flagged as transitions.

    This mirrors the branch-awareness fix already applied to Python's
    business_logic.py, ported to the multi-language NormalizedNode layer.
    """
    SMS = {
        "order": {"create": "created", "pay": "paid", "ship": "shipped", "deliver": "delivered", "cancel": "cancelled", "refund": "refunded",
                  "transitions": {"created": ["pending_payment", "cancelled"], "pending_payment": ["paid", "cancelled"], "paid": ["shipped", "refunded", "cancelled"], "shipped": ["delivered"], "delivered": ["refunded"]}},
        "payment": {"authorize": "authorized", "capture": "captured", "refund": "refunded", "void": "voided", "fail": "failed",
                    "transitions": {"initiated": ["authorized", "failed", "voided"], "authorized": ["captured", "voided", "refunded"], "captured": ["refunded"]}},
    }
    findings = []
    for func in tree.find_function_defs():
        name_lower = func.name.lower()
        for kind, sm in SMS.items():
            # v4.4: Support both snake_case AND camelCase naming conventions.
            # Previously only snake_case was matched (process_order, order_create),
            # which made the detector blind on Java/camelCase JS codebases.
            # Now also matches camelCase: processOrder, cancelOrder, etc.
            kind_lower = kind.lower()
            if (name_lower == kind_lower or
                name_lower.endswith("_" + kind_lower) or
                name_lower.startswith(kind_lower + "_") or
                # camelCase: processOrder → "process" + "order"
                name_lower.endswith(kind_lower) and len(name_lower) > len(kind_lower) or
                # processOrder → "process" + "order"
                kind_lower in name_lower and
                (name_lower.index(kind_lower) > 0 and
                 name_lower[name_lower.index(kind_lower) - 1].isalpha())):
                # v4.3: Collect (method, state, line, branch_path) tuples.
                # branch_path is the list of node kinds from func root to the call.
                # Two calls in different branches of the same if/else will have
                # different branch_paths (one goes through the if's first child,
                # the other through a sibling).
                state_method_map = {k: v for k, v in sm.items() if k != "transitions"}

                # Build parent map: node → parent node, so we can trace path
                parent_map: Dict[int, Optional[NormalizedNode]] = {id(func): None}
                for node in func.walk():
                    for child in node.children:
                        parent_map[id(child)] = node

                def _branch_path(target: NormalizedNode) -> List[int]:
                    """Return list of line numbers of if-statements on path from func to target."""
                    path = []
                    cur = parent_map.get(id(target))
                    while cur is not None and cur is not func:
                        if cur.kind == "if":
                            path.append(cur.line)
                        cur = parent_map.get(id(cur))
                    return path

                def _in_different_branch(call1: NormalizedNode, call2: NormalizedNode) -> bool:
                    """Check if two calls are in different branches of the same if/else.

                    Two calls are in different branches if they share a common
                    if-ancestor, but diverge at that if's children (one in the
                    if-body, one in the else-body).
                    """
                    # Get the path of if-ancestors for each call
                    path1 = _branch_path(call1)
                    path2 = _branch_path(call2)
                    # If they share a common if-ancestor line, they might be
                    # in different branches of that if
                    common = set(path1) & set(path2)
                    if not common:
                        return False
                    # For each common if-ancestor, check if the calls are in
                    # different immediate children of that if
                    for if_line in common:
                        # Find the if node
                        if_node = None
                        for n in func.walk():
                            if n.kind == "if" and n.line == if_line:
                                if_node = n
                                break
                        if not if_node:
                            continue
                        # Get the immediate children of the if node that
                        # contain each call
                        def _containing_child(ifn: NormalizedNode, target: NormalizedNode) -> Optional[NormalizedNode]:
                            """Find which immediate child of ifn contains target."""
                            for child in ifn.children:
                                for sub in child.walk():
                                    if sub is target:
                                        return child
                            return None
                        child1 = _containing_child(if_node, call1)
                        child2 = _containing_child(if_node, call2)
                        if child1 is not None and child2 is not None and child1 is not child2:
                            return True  # different branches of the same if
                    return False

                # Collect all state-transition calls with their node references
                calls = []
                for node in func.walk():
                    if node.kind == "call" and node.name:
                        method = node.name.lower()
                        state = state_method_map.get(method)
                        if state:
                            calls.append((method, state, node.line, node))

                # v4.3: Only flag transitions between calls that are in the
                # SAME branch (not in different if/else branches)
                last_state = None
                last_node = None
                for method, state, line, node in calls:
                    # If this call is in a different branch than the previous,
                    # reset last_state (the branches are mutually exclusive)
                    if last_node is not None and _in_different_branch(last_node, node):
                        last_state = None
                    if last_state:
                        valid = sm["transitions"].get(last_state, [])
                        if state not in valid:
                            findings.append(UnifiedFinding(
                                rule_id=f"SM.{kind.upper()}-INVALID-TRANSITION", severity="high",
                                description=f"Invalid {kind} transition: {last_state} → {state} (valid: {valid})",
                                file=tree.file, line=line, function=func.name, language=tree.language,
                                category="state_machine", cwe="CWE-754"))
                    last_state = state
                    last_node = node
                break
    return findings

def detect_typestate_multi(tree: NormalizedNode) -> List[UnifiedFinding]:
    """Detect typestate violations (use-after-close, missing-open) in any language.

    v4.3 fix: Requires TYPE EVIDENCE before applying a protocol — either a
    strong variable-name convention (conn, session, file, db, etc.) or an
    assignment from a known constructor (connect(), open(), login(), etc.).
    This prevents false positives on common methods like cache.get(),
    dict.get(), apiClient.get(), etc. that share method names with protocol
    methods but are not protocol objects.

    This mirrors the type-evidence gating fix already applied to Python's
    typestate.py (v2), ported to the multi-language NormalizedNode layer.
    """
    PROTOCOLS = {
        "close": {"terminal": True},
        "open": {"required_for": ("read", "write", "seek", "tell", "flush", "readline", "readlines")},
        "connect": {"required_for": ("execute", "commit", "rollback", "query", "fetchone", "fetchall")},
        "login": {"required_for": ("get", "post", "put", "patch", "request")},
        "begin": {"required_for": ("execute", "commit", "rollback")},
        "start": {"required_for": ("send", "recv", "stop")},
    }
    method_requires = {}
    terminal = set()
    for p, cfg in PROTOCOLS.items():
        for m in cfg.get("required_for", ()): method_requires[m] = p
        if cfg.get("terminal"): terminal.add(p)

    # Variable-name conventions that strongly suggest a protocol type.
    # Only variables matching these patterns get protocol analysis applied.
    # This is the key fix: without type evidence, we DON'T flag.
    VAR_NAME_CONVENTIONS = {
        # session_like: var names suggesting an auth/session object
        "session", "auth", "token", "jwt",
        # connection_like: var names suggesting a DB/network connection
        "conn", "connection", "db", "database", "cursor", "client",
        # file_like: var names suggesting a file handle
        "file", "fp", "fhandle", "fh", "stream", "reader", "writer",
        # transaction_like
        "txn", "transaction",
        # payment_like
        "payment", "pay", "charge",
    }

    # Constructor patterns that establish a protocol type.
    # If a variable is assigned from one of these, it gets protocol analysis.
    CONSTRUCTOR_PATTERNS = {
        "connect": "connect",
        "open": "open",
        "login": "login",
        "begin": "begin",
        "start": "start",
        "session": "login",  # session = create_session() → session_like
        "socket": "connect",  # socket() → connection_like
    }

    def _has_type_evidence(var_name: str, func_node: NormalizedNode) -> bool:
        """Check if a variable has type evidence justifying protocol analysis."""
        var_lower = var_name.lower()
        # 1. Strong name convention
        for conv in VAR_NAME_CONVENTIONS:
            if var_lower == conv or var_lower.startswith(conv + "_") or var_lower.endswith("_" + conv):
                return True
        # 2. Assignment from a known constructor
        for node in func_node.walk():
            if node.kind == "assignment" and node.target == var_name and node.text:
                for ctor, proto in CONSTRUCTOR_PATTERNS.items():
                    if ctor + "(" in node.text or ctor + ".create(" in node.text:
                        return True
        return False

    findings = []
    for func in tree.find_function_defs():
        var_calls: Dict[str, List[Tuple[str, int]]] = {}
        for node in func.walk():
            # v4.4: Check both "attribute" nodes (JS/Go) AND "call" nodes
            # that have obj+attr set (Java method_invocation). Previously
            # Java was completely blind to typestate because its method
            # calls come through as "call" nodes, not "attribute" nodes.
            if node.kind == "attribute" and node.obj and node.attr:
                method = node.attr.lower()
                if method in method_requires or method in terminal or method in ("close", "open", "connect", "login", "logout", "begin", "commit", "rollback", "start", "stop"):
                    if not _has_type_evidence(node.obj, func):
                        continue
                    var_calls.setdefault(node.obj, []).append((method, node.line))
            elif node.kind == "call" and node.obj and node.attr:
                # v4.4: Java method_invocation — obj and attr synthesized
                method = node.attr.lower()
                if method in method_requires or method in terminal or method in ("close", "open", "connect", "login", "logout", "begin", "commit", "rollback", "start", "stop"):
                    if not _has_type_evidence(node.obj, func):
                        continue
                    var_calls.setdefault(node.obj, []).append((method, node.line))
        for var, calls in var_calls.items():
            history = []
            for method, line in calls:
                if method in method_requires:
                    req = method_requires[method]
                    if not any(m == req for m, _ in history):
                        findings.append(UnifiedFinding(
                            rule_id="TS.REQUIRES-PRIOR", severity="medium",
                            description=f"{var}.{method}() called without prior {req}() — typestate violation",
                            file=tree.file, line=line, function=func.name, language=tree.language,
                            category="typestate", cwe="CWE-664"))
                if method not in terminal and history:
                    for pm, pl in history:
                        if pm in terminal:
                            findings.append(UnifiedFinding(
                                rule_id="TS.USE-AFTER-CLOSE", severity="high",
                                description=f"{var}.{method}() called after {pm}() at line {pl} — use after terminal operation",
                                file=tree.file, line=line, function=func.name, language=tree.language,
                                category="typestate", cwe="CWE-416"))
                            break
                history.append((method, line))
    return findings

def detect_spec_mining_multi(repo_root: Path, max_files=100) -> List[UnifiedFinding]:
    """Mine API call patterns from the codebase and flag deviations (all languages)."""
    from .spec_mining import mine_api_patterns, check_spec_violations
    patterns = mine_api_patterns(repo_root)
    violations = check_spec_violations(repo_root, patterns)
    return [UnifiedFinding(
        rule_id=f"SM.SPEC-VIOLATION", severity="medium",
        description=v.description, file=v.file, line=v.line,
        language="multi", category="spec_mining", cwe="CWE-754",
        evidence=v.expected_pattern) for v in violations]

def detect_metamorphic_multi(file_path: Path) -> List[UnifiedFinding]:
    """Generate language-appropriate metamorphic test and run if possible."""
    lang = get_language(file_path) if _HAS_TS else "python"
    if lang == "python":
        # Python already has full metamorphic support
        return []
    elif lang in ("javascript", "typescript"):
        test = generate_js_pbt_test(file_path)
        if test: return [UnifiedFinding(rule_id="META.JS-GENERATED", severity="info",
            description="JS PBT test generated (run with jest to execute)", file=str(file_path),
            line=0, language=lang, category="metamorphic")]
    elif lang == "go":
        test = generate_go_pbt_test(file_path)
        if test: return [UnifiedFinding(rule_id="META.GO-GENERATED", severity="info",
            description="Go PBT test generated (run with go test to execute)", file=str(file_path),
            line=0, language=lang, category="metamorphic")]
    elif lang == "java":
        test = generate_java_pbt_test(file_path)
        if test: return [UnifiedFinding(rule_id="META.JAVA-GENERATED", severity="info",
            description="Java PBT test generated (run with mvn test to execute)", file=str(file_path),
            line=0, language=lang, category="metamorphic")]
    elif lang == "rust":
        test = generate_rust_proptest(file_path)
        if test: return [UnifiedFinding(rule_id="META.RUST-GENERATED", severity="info",
            description="Rust proptest generated (run with cargo test to execute)", file=str(file_path),
            line=0, language=lang, category="metamorphic")]
    elif lang in ("c", "cpp"):
        harness = generate_cpp_fuzz_harness(file_path)
        if harness: return [UnifiedFinding(rule_id="META.C-FUZZ-GENERATED", severity="info",
            description="C/C++ fuzz harness generated (compile with clang++ -fsanitize=fuzzer)", file=str(file_path),
            line=0, language=lang, category="metamorphic")]
    return []


# =============================================================================
# MAIN ENTRY POINTS
# =============================================================================
