"""Async / concurrency analysis for Python (asyncio), JS (Promises), Go (channels).

Detects common concurrency bugs that AST + pattern scanning can surface:
  - Python asyncio TOCTOU:    await followed by use of a value that may change
  - asyncio.gather without try/except: one failing task kills all
  - asyncio.create_task without storing the reference (task may be GC'd)
  - JS Promise without .catch() / async fn without try/catch
  - JS Promise.all without per-promise error handling
  - Go: send on closed channel, goroutine leak (no exit condition), receive without sender
"""
from __future__ import annotations
from .text_utils import extract_block as _extract_block

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


@dataclass
class ConcurrencyIssue:
    """A detected concurrency issue."""
    file: str
    line: int
    rule_id: str
    severity: str
    description: str
    fix: str = ""
    cwe: str = ""
    language: str = ""
    confidence: float = 0.7


# =============================================================================
# Python asyncio analyzer
# =============================================================================

class PythonAsyncAnalyzer:
    """AST-based analyzer for Python asyncio concurrency bugs."""

    def analyze_file(self, file_path: Path) -> List[ConcurrencyIssue]:
        if not file_path.exists() or file_path.suffix != ".py":
            return []
        try:
            source = file_path.read_text(encoding="utf-8")
            tree = ast.parse(source)
        except Exception:
            return []
        findings: List[ConcurrencyIssue] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                findings.extend(self._analyze_function(node, str(file_path)))
        return findings

    def _analyze_function(self, func: ast.FunctionDef, file: str) -> List[ConcurrencyIssue]:
        out: List[ConcurrencyIssue] = []
        # asyncio.gather without try/except wrapping
        for node in ast.walk(func):
            if isinstance(node, ast.Await) and isinstance(node.value, ast.Call):
                call = node.value
                if isinstance(call.func, ast.Attribute) and call.func.attr == "gather":
                    # v4.7: Verify the receiver is actually asyncio (not a user-defined
                    # method that happens to be named gather). Claude found this
                    # false positive: collector.gather() flagged as asyncio.gather().
                    if self._is_asyncio_receiver(call.func):
                        if not self._has_try_except_around(func, node.lineno):
                            out.append(ConcurrencyIssue(
                                file=file, line=node.lineno,
                                rule_id="ASYNC-GATHER-NO-TRY",
                                severity="medium",
                                description="asyncio.gather() without try/except — one failing task cancels all others",
                                fix="Wrap in try/except or use asyncio.gather(*tasks, return_exceptions=True)",
                                cwe="CWE-755", language="python", confidence=0.7))
            # create_task without storing the reference
            if (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "create_task"):
                # v4.7: Same receiver check for create_task
                if self._is_asyncio_receiver(node.func):
                    if not self._is_assigned(node, func):
                        out.append(ConcurrencyIssue(
                            file=file, line=node.lineno,
                            rule_id="ASYNC-CREATE-TASK-NOT-STORED",
                            severity="medium",
                            description="asyncio.create_task() result not stored — task may be garbage-collected mid-execution",
                            fix="Store the task: `task = asyncio.create_task(...)` and await it",
                            cwe="CWE-404", language="python", confidence=0.6))
            # TOCTOU: await x; ...; if x is None  (x may have changed)
            if isinstance(node, ast.Await):
                out.extend(self._check_toctou(func, node, file))
        return out

    def _is_asyncio_receiver(self, attr_node: ast.Attribute) -> bool:
        """v4.7: Check if an attribute access's receiver is the asyncio module.

        Prevents false positives where a user-defined class has a method
        named 'gather' or 'create_task' that has nothing to do with asyncio.
        Only flags when the receiver is 'asyncio' or 'asyncio.' (i.e.,
        asyncio.gather() or asyncio.create_task()).
        """
        if not isinstance(attr_node.value, ast.Name):
            return False
        return attr_node.value.id == "asyncio"

    def _has_try_except_around(self, func: ast.FunctionDef, lineno: int) -> bool:
        for node in ast.walk(func):
            if isinstance(node, ast.Try):
                if node.lineno <= lineno <= max(
                    (n.lineno for n in ast.walk(node) if hasattr(n, "lineno")), default=node.lineno
                ):
                    return True
        return False

    def _is_assigned(self, call: ast.Call, func: ast.FunctionDef = None) -> bool:
        """v4.9: Check if a call's result is stored in a variable.

        v4.8 returned False unconditionally, causing ASYNC-CREATE-TASK-NOT-STORED
        to fire on every create_task call. v4.9 passes the function AST and
        checks whether the call is the RHS of an ast.Assign.
        """
        if func is None:
            return True  # can't check — conservatively assume assigned
        for node in ast.walk(func):
            if isinstance(node, ast.Assign):
                # Check if this assignment's value is the call we're checking
                if node.value is call:
                    return True
                # Also check by line number (the call and assign are on the same line)
                if hasattr(node.value, 'lineno') and node.value.lineno == call.lineno:
                    if isinstance(node.value, ast.Call):
                        return True
        return False

    def _check_toctou(self, func: ast.FunctionDef, await_node: ast.Await,
                       file: str) -> List[ConcurrencyIssue]:
        """v4.8: Basic TOCTOU detection — await followed by check-then-use.

        Pattern: `result = await fetch()` then `if result is None: ...`
        followed by use of result. This is actually SAFE (the check guards
        the use), so we should NOT flag it.

        The real TOCTOU pattern is: `await cache.get(key)` then later
        `if cache.has(key): return cache.get(key)` — the second get is
        a TOCTOU because the cache may have been invalidated between
        the check and the use. We check for this pattern.
        """
        issues: List[ConcurrencyIssue] = []
        # Get the awaited expression's source
        if not isinstance(await_node.value, ast.Call):
            return issues
        call = await_node.value
        if not isinstance(call.func, ast.Attribute):
            return issues

        # Look for a subsequent check-then-call on the same object
        # (e.g., if cache.has(key): ... cache.get(key))
        obj_name = ""
        if isinstance(call.func.value, ast.Name):
            obj_name = call.func.value.id
        if not obj_name:
            return issues

        # Walk the function for if-statements that check obj_name
        # followed by another call on obj_name
        for node in ast.walk(func):
            if isinstance(node, ast.If) and node.lineno > await_node.lineno:
                # Check if the if-condition references obj_name
                if_text = ""
                try:
                    import ast as _ast
                    if_text = _ast.unparse(node.test)
                except Exception:
                    pass
                if obj_name in if_text:
                    # v4.9: Only flag if the SAME method is called again (real TOCTOU).
                    # v4.8 flagged ANY method call on the same object, which
                    # produced false positives on safe patterns like
                    # `if cache.has(key): cache.delete(key)`.
                    for child in ast.walk(node):
                        if (isinstance(child, ast.Call)
                                and isinstance(child.func, ast.Attribute)
                                and isinstance(child.func.value, ast.Name)
                                and child.func.value.id == obj_name
                                and child.func.attr == call.func.attr  # v4.9: same method
                                and child.lineno > node.lineno):
                            issues.append(ConcurrencyIssue(
                                file=file, line=child.lineno,
                                rule_id="ASYNC-TOCTOU",
                                severity="medium",
                                description=f"Potential TOCTOU: {obj_name} checked after await but "
                                            f"may have changed before use at line {child.lineno}",
                                fix="Cache the result of the await and use the cached value",
                                cwe="CWE-367", language="python", confidence=0.5))
                            break
        return issues


# =============================================================================
# JS Promise analyzer
# =============================================================================

_JSPattern = tuple  # (rule_id, regex, severity, description, fix, cwe, confidence)

_JS_PATTERNS: List[_JSPattern] = [
    ("PROMISE-NO-CATCH", r"\bPromise\s*\([^)]*\)\s*(?:\.\s*then\s*\([^)]*\)\s*)?(?:;|\n)(?!\s*\.catch)",
     "medium", "Promise chain without .catch() — unhandled rejection",
     "Add .catch(err => console.error(err))", "CWE-755", 0.7),
    ("ASYNC-NO-TRY-CATCH", r"\basync\s+function\s+\w+\s*\([^)]*\)\s*\{(?![^}]*try)",
     "medium", "async function without try/catch — unhandled promise rejection",
     "Wrap body in try/catch", "CWE-755", 0.6),
    ("PROMISE-ALL-NO-INDIVIDUAL-CATCH", r"\bPromise\.all\s*\(",
     "low", "Promise.all without per-promise error handling — one reject fails all",
     "Add .catch to each promise or use Promise.allSettled", "CWE-755", 0.5),
    ("ASYNC-ARROW-NO-TRY", r"=>\s*\{(?![^}]*try)[^}]*await\s+",
     "low", "async arrow function with await but no try/catch",
     "Wrap await in try/catch", "CWE-755", 0.5),
]


class JSPromiseAnalyzer:
    """Regex-based analyzer for JS Promise / async concurrency issues."""

    def analyze_file(self, file_path: Path) -> List[ConcurrencyIssue]:
        if not file_path.exists() or file_path.suffix.lower() not in {".js", ".jsx", ".ts", ".tsx", ".mjs"}:
            return []
        try:
            source = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return []
        return self._scan_source(source, str(file_path))

    def _scan_source(self, source: str, file: str) -> List[ConcurrencyIssue]:
        out: List[ConcurrencyIssue] = []
        lines = source.splitlines()
        for i, line in enumerate(lines, 1):
            for rule_id, pat, sev, desc, fix, cwe, conf in _JS_PATTERNS:
                try:
                    if re.search(pat, line):
                        out.append(ConcurrencyIssue(
                            file=file, line=i, rule_id=rule_id, severity=sev,
                            description=desc, fix=fix, cwe=cwe,
                            language="javascript", confidence=conf))
                except re.error:
                    continue
        # multi-line: async fn body scan
        for m in re.finditer(r"async\s+function\s+\w+\s*\([^)]*\)\s*\{", source):
            body = _extract_block(source, m.end())
            if body and "await" in body and "try" not in body:
                line_num = source[:m.start()].count("\n") + 1
                out.append(ConcurrencyIssue(
                    file=file, line=line_num, rule_id="ASYNC-FN-AWAIT-NO-TRY",
                    severity="medium",
                    description="async function uses await but has no try/catch",
                    fix="Wrap await calls in try/catch", cwe="CWE-755",
                    language="javascript", confidence=0.65))
        return out




# =============================================================================
# Go channel analyzer
# =============================================================================

_GO_PATTERNS: List[_JSPattern] = [
    ("GO-SEND-ON-CLOSED", r"^\s*\w+\s*<-+\s*ch\b",
     "high", "Possible send on closed channel — panic",
     "Guard with select or check closed flag", "CWE-664", 0.6),
    ("GO-CHANNEL-NO-CLOSE", r"make\s*\(\s*chan\s+",
     "low", "Channel created without obvious close — possible leak",
     "Ensure close() is called by the sender", "CWE-404", 0.4),
    ("GO-GOROUTINE-NO-EXIT", r"go\s+func\s*\(\s*\)\s*\{",
     "medium", "Goroutine started without explicit exit condition — leak risk",
     "Use context cancellation or done channel", "CWE-404", 0.5),
]


class GoChannelAnalyzer:
    """Regex + simple AST-like analysis for Go channel issues."""

    def analyze_file(self, file_path: Path) -> List[ConcurrencyIssue]:
        if not file_path.exists() or file_path.suffix != ".go":
            return []
        try:
            source = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return []
        out: List[ConcurrencyIssue] = []
        lines = source.splitlines()
        # First pass: find channel close locations
        closed_channels = set()
        for i, line in enumerate(lines, 1):
            m = re.search(r"close\s*\(\s*(\w+)\s*\)", line)
            if m:
                closed_channels.add(m.group(1))
        # Second pass: find sends on possibly-closed channels
        for i, line in enumerate(lines, 1):
            # send: ch <- value
            m = re.search(r"\b(\w+)\s*<-+\s*[^=]", line)
            if m and m.group(1) in closed_channels:
                out.append(ConcurrencyIssue(
                    file=str(file_path), line=i, rule_id="GO-SEND-ON-CLOSED",
                    severity="high",
                    description=f"Possible send on closed channel '{m.group(1)}' — will panic",
                    fix="Track closed state and skip send, or use recover()",
                    cwe="CWE-664", language="go", confidence=0.55))
            # goroutine leak: `go func() { ... }()` without context.WithCancel
            if re.search(r"go\s+func\s*\(\s*\)\s*\{", line):
                body = _extract_block("\n".join(lines[i-1:]), line.index("func"))
                if body and "context" not in body and "<-" not in body and "select" not in body:
                    out.append(ConcurrencyIssue(
                        file=str(file_path), line=i, rule_id="GO-GOROUTINE-LEAK",
                        severity="medium",
                        description="Goroutine started without exit signal (no context, no done channel)",
                        fix="Pass a context.Context and exit on ctx.Done()",
                        cwe="CWE-404", language="go", confidence=0.5))
            # receive without sender: `<-ch` outside select without default
            m = re.search(r"^\s*<-\s*(\w+)", line)
            if m and "select" not in line and "default" not in line:
                out.append(ConcurrencyIssue(
                    file=str(file_path), line=i, rule_id="GO-RECV-WITHOUT-SENDER",
                    severity="low",
                    description=f"Receive on channel '{m.group(1)}' without sender check — may block forever",
                    fix="Use select with default or check len(ch) > 0",
                    cwe="CWE-664", language="go", confidence=0.4))
        return out


# =============================================================================
# Top-level entry point
# =============================================================================

def analyze_concurrency(file_path: Path) -> List[ConcurrencyIssue]:
    """Dispatch to the right analyzer based on file extension."""
    ext = file_path.suffix.lower()
    if ext == ".py":
        return PythonAsyncAnalyzer().analyze_file(file_path)
    if ext in {".js", ".jsx", ".ts", ".tsx", ".mjs"}:
        return JSPromiseAnalyzer().analyze_file(file_path)
    if ext == ".go":
        return GoChannelAnalyzer().analyze_file(file_path)
    return []


def analyze_repo_concurrency(repo_root: Path) -> List[ConcurrencyIssue]:
    """Walk a repo and run the appropriate analyzer on every source file."""
    out: List[ConcurrencyIssue] = []
    skip = {"node_modules", ".git", "vendor", "__pycache__", "dist", "build"}
    for path in repo_root.rglob("*"):
        if not path.is_file():
            continue
        if any(s in str(path) for s in skip):
            continue
        if path.suffix.lower() in {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".go"}:
            out.extend(analyze_concurrency(path))
    return out
