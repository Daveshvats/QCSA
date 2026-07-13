"""Resource lifecycle state machines.

Tracks resource-typed objects (files, connections, sessions, transactions,
cursors) through their lifecycle and detects:
  - use_after_close:   method call after .close()
  - missing_close:     resource allocated but never released
  - wrong_order:       method called out of declared lifecycle order

Lightweight regex + AST hybrid (works for Python; the patterns translate to
JS/Go with minor changes — see analyze_protocols).
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


# Per-resource lifecycle definitions:
#   states:        ordered states the resource goes through
#   open_methods:  methods that transition INTO the open state
#   close_methods: methods that transition to the terminal "closed" state
#   use_methods:   methods that are valid only in the open state
RESOURCE_LIFECYCLES: Dict[str, dict] = {
    "file": {
        "states": ["uninitialized", "open", "closed"],
        "open_methods": ["open", "Open", "openFile"],
        "close_methods": ["close", "Close", "closeFile", "dispose"],
        "use_methods": ["read", "readline", "readlines", "write", "writelines",
                        "seek", "tell", "flush", "readinto"],
    },
    "connection": {
        "states": ["disconnected", "connected", "closed"],
        "open_methods": ["connect", "Connect", "open"],
        "close_methods": ["close", "Close", "disconnect", "dispose"],
        "use_methods": ["execute", "executemany", "fetchone", "fetchall",
                        "commit", "rollback", "query", "send", "recv"],
    },
    "session": {
        "states": ["logged_out", "logged_in", "closed"],
        "open_methods": ["login", "signin", "begin", "start"],
        "close_methods": ["logout", "signout", "end", "close", "dispose"],
        "use_methods": ["get", "post", "put", "delete", "patch", "request",
                        "send", "recv"],
    },
    "transaction": {
        "states": ["none", "active", "committed", "rolled_back"],
        "open_methods": ["begin", "start", "Begin"],
        "close_methods": ["commit", "rollback", "abort", "end"],
        "use_methods": ["execute", "executemany", "query", "run"],
    },
    "cursor": {
        "states": ["closed", "open", "exhausted"],
        "open_methods": ["cursor", "open", "execute"],
        "close_methods": ["close", "Close", "dispose"],
        "use_methods": ["fetchone", "fetchall", "fetchmany", "next", "execute"],
    },
}


@dataclass
class StateMachineViolation:
    """A detected resource lifecycle violation."""
    file: str
    line: int
    object_name: str
    resource_type: str
    violation: str  # 'use_after_close' | 'missing_close' | 'wrong_order'
    description: str
    cwe: str = "CWE-664"


# =============================================================================
# State Machine Analyzer
# =============================================================================

class StateMachineAnalyzer:
    """Per-function resource lifecycle tracker for Python."""

    def __init__(self) -> None:
        self.violations: List[StateMachineViolation] = []

    def analyze_file(self, file_path: Path) -> List[StateMachineViolation]:
        if not file_path.exists() or file_path.suffix != ".py":
            return []
        try:
            source = file_path.read_text(encoding="utf-8")
            tree = ast.parse(source)
        except Exception:
            return []
        self.violations = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._analyze_function(node, str(file_path))
        return self.violations

    def _analyze_function(self, func: ast.FunctionDef, file: str) -> None:
        # var_name -> {"type": <kind>, "state": <state>, "line": <int>}
        tracked: Dict[str, dict] = {}

        for stmt in ast.walk(func):
            if not isinstance(stmt, ast.Call):
                continue
            if not isinstance(stmt.func, ast.Attribute):
                continue
            obj_node = stmt.func.value
            method = stmt.func.attr
            if not isinstance(obj_node, ast.Name):
                continue
            var = obj_node.id

            kind = self._infer_resource_type(var, method, tracked.get(var))
            if kind is None:
                continue
            state = tracked.setdefault(var, {"type": kind, "state": "uninitialized",
                                             "line": stmt.lineno})
            state["type"] = kind
            lifecycle = RESOURCE_LIFECYCLES[kind]
            self._check_transition(var, method, state, lifecycle, file, stmt.lineno)

    def _infer_resource_type(self, var_name: str, method: str,
                              current: Optional[dict]) -> Optional[str]:
        # 1) already tracked
        if current:
            return current["type"]
        # 2) match method against lifecycle definitions
        for kind, lc in RESOURCE_LIFECYCLES.items():
            if method in lc["open_methods"] or method in lc["close_methods"] or method in lc["use_methods"]:
                # try to confirm by variable name heuristic
                name_hints = {
                    "file": ["file", "fp", "fh", "f"],
                    "connection": ["conn", "connection", "db", "client", "session"],
                    "session": ["session", "sess", "client"],
                    "transaction": ["txn", "transaction", "tx"],
                    "cursor": ["cursor", "cur"],
                }
                v = var_name.lower()
                for hint in name_hints.get(kind, []):
                    if hint in v:
                        return kind
                # if exactly one lifecycle defines this method, use it
                owners = [k for k, lc in RESOURCE_LIFECYCLES.items()
                          if method in lc["open_methods"] or method in lc["close_methods"]]
                if len(owners) == 1:
                    return owners[0]
        return None

    def _check_transition(self, var: str, method: str, state: dict,
                          lc: dict, file: str, line: int) -> None:
        cur_state = state["state"]
        if method in lc["close_methods"]:
            if cur_state == "closed":
                self.violations.append(StateMachineViolation(
                    file=file, line=line, object_name=var,
                    resource_type=state["type"], violation="wrong_order",
                    description=f"{var}.{method}() called but resource is already closed"))
            state["state"] = "closed"
            state["line"] = line
            return
        if method in lc["open_methods"]:
            state["state"] = "open"
            state["line"] = line
            return
        if method in lc["use_methods"]:
            if cur_state == "closed":
                self.violations.append(StateMachineViolation(
                    file=file, line=line, object_name=var,
                    resource_type=state["type"], violation="use_after_close",
                    description=f"{var}.{method}() after .close() — use-after-close",
                    cwe="CWE-416"))
            elif cur_state == "uninitialized":
                self.violations.append(StateMachineViolation(
                    file=file, line=line, object_name=var,
                    resource_type=state["type"], violation="wrong_order",
                    description=f"{var}.{method}() before open — wrong order"))
            state["line"] = line

    # ----- missing_close: scan whole file for allocated-but-never-closed -----
    def find_missing_closes(self, file_path: Path) -> List[StateMachineViolation]:
        if not file_path.exists() or file_path.suffix != ".py":
            return []
        try:
            source = file_path.read_text(encoding="utf-8")
            tree = ast.parse(source)
        except Exception:
            return []
        findings: List[StateMachineViolation] = []
        # heuristic: look for `with ... as <var>:` and skip those (they close themselves)
        with_vars: Set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.With):
                for item in node.items:
                    if item.optional_vars and isinstance(item.optional_vars, ast.Name):
                        with_vars.add(item.optional_vars.id)
        # for each function, find open()-assigned vars and check for matching close()
        for func in ast.walk(tree):
            if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            opened: Dict[str, Tuple[int, str]] = {}
            closed: Set[str] = set()
            for stmt in ast.walk(func):
                if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
                    target = stmt.targets[0]
                    if isinstance(target, ast.Name):
                        call = stmt.value
                        if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute):
                            method = call.func.attr
                            for kind, lc in RESOURCE_LIFECYCLES.items():
                                if method in lc["open_methods"]:
                                    opened[target.id] = (stmt.lineno, kind)
                if isinstance(stmt, ast.Call) and isinstance(stmt.func, ast.Attribute):
                    if stmt.func.attr in sum(
                        (lc["close_methods"] for lc in RESOURCE_LIFECYCLES.values()), []
                    ) and isinstance(stmt.func.value, ast.Name):
                        closed.add(stmt.func.value.id)
            for var, (line, kind) in opened.items():
                if var in with_vars:
                    continue
                if var not in closed:
                    findings.append(StateMachineViolation(
                        file=str(file_path), line=line, object_name=var,
                        resource_type=kind, violation="missing_close",
                        description=f"{var} opened at line {line} but never closed in {func.name}() — "
                                    f"possible resource leak"))
        return findings


# =============================================================================
# Protocol analyzer — works on any text (JS/Go/Java/Python).
# =============================================================================

_PROTOCOL_TEXT_PATTERNS: Dict[str, List[Tuple[str, str]]] = {
    "python": [
        (r"(\w+)\.close\s*\(\s*\)", "close"),
        (r"(\w+)\.(?:execute|fetchone|fetchall|read|write|commit|rollback)\s*\(", "use"),
    ],
    "javascript": [
        (r"(\w+)\.close\s*\(\s*\)", "close"),
        (r"(\w+)\.(?:execute|query|fetch|send|recv|commit)\s*\(", "use"),
    ],
    "go": [
        (r"(\w+)\.Close\s*\(\s*\)", "close"),
        (r"(\w+)\.(?:Exec|Query|QueryRow|Send|Recv)\s*\(", "use"),
    ],
}


def analyze_protocols(file_path: Path, language: Optional[str] = None) -> List[StateMachineViolation]:
    """Lightweight regex-based protocol scan for any language.

    Detects use_after_close by scanning for `<var>.close()` followed later by
    `<var>.<use>()` on the same variable within the same function/block.
    """
    if not file_path.exists():
        return []
    lang = language or _guess_language(file_path)
    patterns = _PROTOCOL_TEXT_PATTERNS.get(lang)
    if not patterns:
        return []
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []
    findings: List[StateMachineViolation] = []
    lines = source.splitlines()
    # state: var -> (last_close_line, resource_kind_guess)
    closed_at: Dict[str, Tuple[int, str]] = {}
    for i, line in enumerate(lines, 1):
        for pat, kind in patterns:
            for m in re.finditer(pat, line):
                var = m.group(1)
                if kind == "close":
                    closed_at[var] = (i, "connection")
                else:
                    prev = closed_at.get(var)
                    if prev and prev[0] < i:
                        findings.append(StateMachineViolation(
                            file=str(file_path), line=i, object_name=var,
                            resource_type=prev[1], violation="use_after_close",
                            description=f"{var} used at line {i} after .close() at line {prev[0]}",
                            cwe="CWE-416"))
    return findings


def _guess_language(file_path: Path) -> str:
    ext = file_path.suffix.lower()
    if ext == ".py": return "python"
    if ext in {".js", ".jsx", ".ts", ".tsx"}: return "javascript"
    if ext == ".go": return "go"
    return "python"


def analyze_repo(repo_root: Path) -> List[StateMachineViolation]:
    """Scan all source files in a repo for state machine violations."""
    analyzer = StateMachineAnalyzer()
    findings: List[StateMachineViolation] = []
    exts = {".py", ".js", ".jsx", ".ts", ".tsx", ".go"}
    for path in repo_root.rglob("*"):
        if path.suffix.lower() not in exts:
            continue
        if any(p in str(path) for p in ("node_modules", ".git", "vendor", "__pycache__")):
            continue
        if path.suffix == ".py":
            findings.extend(analyzer.analyze_file(path))
            findings.extend(analyzer.find_missing_closes(path))
        else:
            findings.extend(analyze_protocols(path))
    return findings
