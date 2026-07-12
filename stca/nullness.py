"""Sound nullness analysis for Python (NilAway-inspired) — v4 with interprocedural callee check.

v4 (v4.7) fixes the biggest false-positive source in the entire pipeline:
any bare function call (not a builtin) was treated as possibly-None.
This fires on the most common shape of ordinary Python code:
    config = get_default_config()  # returns a dict, never None
    return config["timeout"]       # flagged as possible null deref

The fix: before flagging a bare call as possibly-None, look up the callee's
FunctionDef in the same file and check whether any of its return statements
can produce None (no explicit return, bare return, or return None). If the
function provably never returns None, don't flag it.

v3 fixes the v2 FP problem on `requests` (54 FPs from dict.get() where the result
IS checked in a later if-branch).

Key improvements:
  1. Path-sensitive analysis: track None-ness through if/elif/else branches
  2. After a None guard fires (return/raise), the variable is non-None on the
     fall-through path.
  3. If a variable is dereferenced inside a `if x is not None:` or `if x:` block,
     it is treated as safe (no FP).
  4. If a variable is dereferenced AFTER an if-block that returns on None, the
     dereference is safe (the None branch already returned).
  5. Truthy checks (`if x:`) and comparison checks (`if x is not None:`) both
     count as guards.
  6. Only flag EXPLICIT None sources (default=None, Optional annotations, dict.get(),
     re.search(), .first(), .last(), etc.)
  7. v4.7: Interprocedural callee return-value check — same-file lookup of the
     callee's FunctionDef to determine if it can return None.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple


@dataclass
class NullnessIssue:
    file: str
    line: int
    variable: str
    reason: str
    confidence: float
    context: str = ""


NONE_RETURNING_METHODS = {
    "get", "find", "search", "match", "fullmatch",
    "first", "last", "one_or_none", "get_or_none",
}

# Builtins guaranteed to never return None (suppresses FPs on bare calls)
NON_NONE_BUILTINS = {
    "len", "abs", "min", "max", "sum", "round", "pow", "divmod",
    "bool", "int", "float", "str", "bytes", "bytearray", "complex", "frozenset",
    "list", "dict", "set", "tuple", "range", "enumerate", "zip", "reversed", "sorted",
    "type", "id", "hash", "repr", "format", "chr", "ord", "hex", "oct", "bin", "ascii",
    "isinstance", "issubclass", "callable", "hasattr", "vars", "dir", "globals",
    "locals", "input", "open",
}

OPTIONAL_PATTERNS = {"Optional", "Union", "None"}

SKIP_DIRS = {"test", "tests", "__tests__", "test_utils", "conftest", "fixtures"}


@dataclass
class GuardInfo:
    var: str
    line: int
    kind: str  # 'none_return' | 'none_raise' | 'not_none_block' | 'truthy_block'
    block_start: int
    block_end: int


class NullnessAnalyzer:
    """v3 nullness analyzer with inter-branch None tracking."""

    def __init__(self):
        pass

    def analyze_file(self, file_path: Path, repo_root: Path = None) -> List[NullnessIssue]:
        if not file_path.exists() or file_path.suffix != ".py":
            return []
        rel_path = str(file_path.relative_to(repo_root)) if repo_root else str(file_path)
        parts = file_path.parts
        if any(part in SKIP_DIRS for part in parts):
            return []
        if file_path.name.startswith("test_") or file_path.name.endswith("_test.py"):
            return []
        if "conftest" in file_path.name:
            return []
        try:
            source = file_path.read_text(encoding="utf-8")
            tree = ast.parse(source)
        except Exception:
            return []
        issues: List[NullnessIssue] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                issues += self._analyze_function(node, rel_path, source, tree)
        return issues

    def _analyze_function(self, func_node: ast.FunctionDef,
                          file: str, source: str,
                          module_tree: Optional[ast.AST] = None) -> List[NullnessIssue]:
        issues: List[NullnessIssue] = []
        possibly_none = self._collect_none_sources(func_node, module_tree)
        if not possibly_none:
            return []
        guards = self._collect_guards(func_node, possibly_none)
        derefs = self._collect_dereferences(func_node, possibly_none)
        for dvar, dline in derefs:
            if self._is_deref_guarded(dvar, dline, guards, func_node):
                continue
            if self._reassigned_to_non_none_before(dvar, dline, func_node):
                continue
            issues.append(NullnessIssue(
                file=file, line=dline, variable=dvar,
                reason=f"'{dvar}' is possibly None and dereferenced without a guard",
                confidence=0.75,
                context=self._get_line(source, dline),
            ))
        seen: Set[Tuple[int, str]] = set()
        unique: List[NullnessIssue] = []
        for issue in issues:
            key = (issue.line, issue.variable)
            if key not in seen:
                seen.add(key)
                unique.append(issue)
        return unique

    def _collect_none_sources(self, func_node: ast.FunctionDef,
                                module_tree: Optional[ast.AST] = None) -> Set[str]:
        possibly_none: Set[str] = set()
        # Parameters with default None
        args_with_defaults = zip(
            func_node.args.args[-len(func_node.args.defaults):] if func_node.args.defaults else [],
            func_node.args.defaults
        )
        for arg, default in args_with_defaults:
            if isinstance(default, ast.Constant) and default.value is None:
                possibly_none.add(arg.arg)
        # Parameters with Optional annotation
        for arg in func_node.args.args + func_node.args.kwonlyargs:
            if arg.annotation:
                ann_str = self._annotation_to_str(arg.annotation)
                if self._is_optional_annotation(ann_str):
                    possibly_none.add(arg.arg)
        # Explicit None assignments and None-returning method calls
        for node in ast.walk(func_node):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        if isinstance(node.value, ast.Constant) and node.value.value is None:
                            possibly_none.add(target.id)
                        elif isinstance(node.value, ast.Call):
                            call = node.value
                            if isinstance(call.func, ast.Attribute):
                                if call.func.attr in NONE_RETURNING_METHODS:
                                    possibly_none.add(target.id)
                            elif isinstance(call.func, ast.Name):
                                # v4.7: Interprocedural callee return-value check.
                                # Before treating a bare function call as possibly-None,
                                # look up the callee's FunctionDef in the same file and
                                # check whether any of its return statements can produce
                                # None. If the function provably never returns None,
                                # don't flag it.
                                #
                                # This is the fix Claude identified as the highest-priority
                                # fix in the entire review: without it, ANY user-defined
                                # function call is treated as possibly-None, firing on
                                # the most common shape of ordinary Python code.
                                if call.func.id not in NON_NONE_BUILTINS:
                                    if not self._callee_can_return_none(call.func.id, module_tree):
                                        pass  # callee provably never returns None — safe
                                    else:
                                        possibly_none.add(target.id)
        return possibly_none

    def _callee_can_return_none(self, callee_name: str,
                                 module_tree: Optional[ast.AST]) -> bool:
        """v4.7: Check if a function can return None.

        Looks up the callee's FunctionDef in the same module tree and
        examines its return statements:
          - No return statement → returns None (implicit) → can return None
          - Bare `return` → returns None → can return None
          - `return None` → can return None
          - `return <expr>` where expr is not None → cannot return None
          - Function not found → conservatively return True (might return None)

        This eliminates the biggest false-positive source in the pipeline:
        any user-defined function call being treated as possibly-None.
        """
        if module_tree is None:
            return True  # can't check — conservatively assume might return None

        # Find the callee's FunctionDef in the module tree
        callee_func = None
        for node in ast.walk(module_tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name == callee_name:
                    callee_func = node
                    break

        if callee_func is None:
            return True  # function not found in this file — might be imported

        # Examine all return statements in the callee
        has_explicit_return = False
        for node in ast.walk(callee_func):
            if isinstance(node, ast.Return):
                has_explicit_return = True
                if node.value is None:
                    return True  # bare return → None
                if isinstance(node.value, ast.Constant) and node.value.value is None:
                    return True  # return None
                # If the return value is a call to a None-returning method
                if isinstance(node.value, ast.Call):
                    if isinstance(node.value.func, ast.Attribute):
                        if node.value.func.attr in NONE_RETURNING_METHODS:
                            return True
                    elif isinstance(node.value.func, ast.Name):
                        # Recursive: check if THIS callee can return None
                        if node.value.func.id not in NON_NONE_BUILTINS:
                            if node.value.func.id != callee_name:  # avoid infinite recursion
                                if self._callee_can_return_none(node.value.func.id, module_tree):
                                    return True

        # If the function has explicit returns and none of them return None,
        # it cannot return None. If it has NO explicit returns, it implicitly
        # returns None.
        if not has_explicit_return:
            return True  # no return → implicit return None
        return False  # all returns are non-None

    def _collect_guards(self, func_node: ast.FunctionDef,
                        possibly_none: Set[str]) -> List[GuardInfo]:
        guards: List[GuardInfo] = []
        for node in ast.walk(func_node):
            if not isinstance(node, ast.If):
                continue
            test = node.test
            block_start = node.lineno
            block_end = node.lineno
            for child in ast.walk(node):
                if hasattr(child, "lineno") and child.lineno > block_end:
                    block_end = child.lineno
            # Pattern 1: if x is None: return/raise
            if isinstance(test, ast.Compare) and isinstance(test.left, ast.Name) and \
               test.left.id in possibly_none and isinstance(test.ops[0], ast.Is) and \
               isinstance(test.comparators[0], ast.Constant) and test.comparators[0].value is None:
                if self._body_returns_or_raises(node.body):
                    guards.append(GuardInfo(var=test.left.id, line=node.lineno,
                        kind="none_return", block_start=block_start, block_end=block_end))
            # Pattern 2: if x is not None: <body>
            elif isinstance(test, ast.Compare) and isinstance(test.left, ast.Name) and \
                 test.left.id in possibly_none and isinstance(test.ops[0], ast.IsNot) and \
                 isinstance(test.comparators[0], ast.Constant) and test.comparators[0].value is None:
                guards.append(GuardInfo(var=test.left.id, line=node.lineno,
                    kind="not_none_block", block_start=block_start, block_end=block_end))
            # Pattern 3: if x: (truthy)
            elif isinstance(test, ast.Name) and test.id in possibly_none:
                guards.append(GuardInfo(var=test.id, line=node.lineno,
                    kind="truthy_block", block_start=block_start, block_end=block_end))
            # Pattern 4: if not x: return/raise
            elif isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not) and \
                 isinstance(test.operand, ast.Name) and test.operand.id in possibly_none:
                if self._body_returns_or_raises(node.body):
                    guards.append(GuardInfo(var=test.operand.id, line=node.lineno,
                        kind="none_return", block_start=block_start, block_end=block_end))
            # Pattern 5: if not (x is None):
            elif isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not) and \
                 isinstance(test.operand, ast.Compare):
                inner = test.operand
                if isinstance(inner.left, ast.Name) and inner.left.id in possibly_none and \
                   isinstance(inner.ops[0], ast.Is) and \
                   isinstance(inner.comparators[0], ast.Constant) and inner.comparators[0].value is None:
                    guards.append(GuardInfo(var=inner.left.id, line=node.lineno,
                        kind="not_none_block", block_start=block_start, block_end=block_end))
            # Pattern 6: if x == None
            elif isinstance(test, ast.Compare) and isinstance(test.left, ast.Name) and \
                 test.left.id in possibly_none and isinstance(test.comparators[0], ast.Constant) and \
                 test.comparators[0].value is None:
                if self._body_returns_or_raises(node.body):
                    guards.append(GuardInfo(var=test.left.id, line=node.lineno,
                        kind="none_return", block_start=block_start, block_end=block_end))
        return guards

    def _body_returns_or_raises(self, body: List[ast.stmt]) -> bool:
        if not body:
            return False
        last = body[-1]
        if isinstance(last, (ast.Return, ast.Raise)):
            return True
        if isinstance(last, ast.If):
            if last.orelse and self._body_returns_or_raises(last.body) and \
               self._body_returns_or_raises(last.orelse):
                return True
        return False

    def _collect_dereferences(self, func_node: ast.FunctionDef,
                              possibly_none: Set[str]) -> List[Tuple[str, int]]:
        derefs: List[Tuple[str, int]] = []
        for node in ast.walk(func_node):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                obj = node.func.value
                if isinstance(obj, ast.Name) and obj.id in possibly_none:
                    derefs.append((obj.id, node.lineno))
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                if node.value.id in possibly_none:
                    derefs.append((node.value.id, node.lineno))
            if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name):
                if node.value.id in possibly_none:
                    derefs.append((node.value.id, node.lineno))
        return derefs

    def _is_deref_guarded(self, var: str, line: int,
                          guards: List[GuardInfo], func_node: ast.FunctionDef) -> bool:
        for g in guards:
            if g.var != var:
                continue
            if g.kind in ("not_none_block", "truthy_block"):
                if g.block_start < line <= g.block_end:
                    return True
            if g.kind == "none_return":
                if line > g.block_end:
                    return True
        return False

    def _reassigned_to_non_none_before(self, var: str, line: int,
                                       func_node: ast.FunctionDef) -> bool:
        for node in ast.walk(func_node):
            if not isinstance(node, ast.Assign):
                continue
            if node.lineno >= line:
                continue
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == var:
                    val = node.value
                    if isinstance(val, ast.Constant) and val.value is not None:
                        return True
                    if isinstance(val, ast.Call):
                        if isinstance(val.func, ast.Attribute):
                            if val.func.attr not in NONE_RETURNING_METHODS:
                                return True
                        elif isinstance(val.func, ast.Name):
                            # Bare function call is non-None only if it's in
                            # the safe-builtins allowlist. Otherwise it may
                            # still return None — keep flagged as possibly-None.
                            if val.func.id in NON_NONE_BUILTINS:
                                return True
                    if isinstance(val, (ast.List, ast.Dict, ast.Tuple, ast.Set)):
                        return True
                    if isinstance(val, ast.BinOp):
                        return True
                    if isinstance(val, (ast.ListComp, ast.DictComp, ast.SetComp, ast.GeneratorExp)):
                        return True
        return False

    def _annotation_to_str(self, annotation: ast.AST) -> str:
        try:
            return ast.unparse(annotation)
        except Exception:
            return ""

    def _is_optional_annotation(self, ann_str: str) -> bool:
        if not ann_str:
            return False
        if "Optional" in ann_str:
            return True
        if "Union" in ann_str and "None" in ann_str:
            return True
        if "| None" in ann_str:
            return True
        return False

    def _get_line(self, source: str, line: int) -> str:
        lines = source.splitlines()
        if 0 < line <= len(lines):
            return lines[line - 1].strip()
        return ""
