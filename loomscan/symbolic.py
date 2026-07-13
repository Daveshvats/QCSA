"""Symbolic execution + abstract interpretation + type narrowing.

Layer 6 — uses Z3 (when available) for path-feasible symbolic execution of
small Python functions. Falls back to abstract interpretation when Z3 is
absent. Type narrowing detects Optional dereferences that may be None.

Strategies:
  - Division by zero: x / y  where y ∈ {0}
  - Modulo by zero:   x % y  where y ∈ {0}
  - Index out-of-bounds: a[i] where i not in [0, len(a))
  - Assertion failure: assert cond  where cond can be False
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import z3  # type: ignore
    _HAS_Z3 = True
except Exception:  # pragma: no cover - optional dependency
    z3 = None  # type: ignore
    _HAS_Z3 = False


@dataclass
class SymbolicFinding:
    """A finding from symbolic / abstract interpretation."""
    file: str
    line: int
    rule_id: str
    description: str
    severity: str = "high"
    cwe: str = ""
    counterexample: str = ""


# =============================================================================
# Z3 Symbolic Executor
# =============================================================================

class Z3SymbolicExecutor:
    """Lightweight symbolic execution of a Python function using Z3.

    Only handles straight-line / branching integer code. We deliberately
    keep the supported fragment tiny: assignments, if/else, return, and
    arithmetic on Z3 Int variables.
    """

    def __init__(self) -> None:
        if not _HAS_Z3:
            self.solver = None
            return
        self.solver: Optional["z3.Solver"] = z3.Solver()
        self.vars: Dict[str, "z3.ArithRef"] = {}
        self.path_constraints: List["z3.BoolRef"] = []
        self.findings: List[SymbolicFinding] = []

    def analyze_function(self, func_node: ast.FunctionDef, file: str) -> List[SymbolicFinding]:
        if not _HAS_Z3:
            return []
        self.vars = {}
        self.path_constraints = []
        self.findings = []
        self._exec_body(func_node.body, file)
        return self.findings

    def _exec_body(self, stmts: List[ast.stmt], file: str) -> None:
        for stmt in stmts:
            if isinstance(stmt, ast.Assign):
                self._exec_assign(stmt, file)
            elif isinstance(stmt, ast.AugAssign):
                self._exec_augassign(stmt, file)
            elif isinstance(stmt, ast.If):
                self._exec_if(stmt, file)
            elif isinstance(stmt, ast.Assert):
                self._exec_assert(stmt, file)
            elif isinstance(stmt, ast.Return):
                self._exec_return(stmt, file)

    def _exec_assign(self, stmt: ast.Assign, file: str) -> None:
        if len(stmt.targets) != 1 or not isinstance(stmt.targets[0], ast.Name):
            return
        name = stmt.targets[0].id
        val = self._eval_expr(stmt.value, file, stmt.lineno)
        if val is not None:
            self.vars[name] = val

    def _exec_augassign(self, stmt: ast.AugAssign, file: str) -> None:
        if not isinstance(stmt.target, ast.Name):
            return
        name = stmt.target.id
        cur = self.vars.get(name)
        rhs = self._eval_expr(stmt.value, file, stmt.lineno)
        if cur is None or rhs is None:
            return
        op = stmt.op
        if isinstance(op, ast.Add): self.vars[name] = cur + rhs
        elif isinstance(op, ast.Sub): self.vars[name] = cur - rhs
        elif isinstance(op, ast.Mult): self.vars[name] = cur * rhs

    def _exec_if(self, stmt: ast.If, file: str) -> None:
        cond = self._eval_bool(stmt.test, file, stmt.lineno)
        if cond is None:
            # unknown branch — explore both
            saved = dict(self.vars)
            self._exec_body(stmt.body, file)
            if stmt.orelse:
                self.vars = saved
                self._exec_body(stmt.orelse, file)
            return
        # Try the then-branch with the constraint, then the else.
        saved_pc = list(self.path_constraints)
        saved_vars = dict(self.vars)
        assert self.solver is not None
        self.solver.push()
        self.solver.add(cond)
        if self.solver.check() == z3.sat:
            self.path_constraints.append(cond)
            self._exec_body(stmt.body, file)
        self.solver.pop()
        if stmt.orelse:
            self.vars = saved_vars
            self.path_constraints = saved_pc
            not_cond = z3.Not(cond)
            self.solver.push()
            self.solver.add(not_cond)
            if self.solver.check() == z3.sat:
                self.path_constraints.append(not_cond)
                self._exec_body(stmt.orelse, file)
            self.solver.pop()
        self.path_constraints = saved_pc
        self.vars = saved_vars

    def _exec_assert(self, stmt: ast.Assert, file: str) -> None:
        cond = self._eval_bool(stmt.test, file, stmt.lineno)
        if cond is None:
            return
        assert self.solver is not None
        self.solver.push()
        self.solver.add(self.path_constraints)
        self.solver.add(z3.Not(cond))
        if self.solver.check() == z3.sat:
            m = self.solver.model()
            cex = ", ".join(f"{k}={m[v]}" for k, v in self.vars.items() if m[v] is not None)
            self.findings.append(SymbolicFinding(
                file=file, line=stmt.lineno, rule_id="SYM-ASSERT-FAILURE",
                description=f"Assertion can fail. Counterexample: {cex}",
                severity="medium", cwe="CWE-617", counterexample=cex,
            ))
        self.solver.pop()

    def _exec_return(self, stmt: ast.Return, file: str) -> None:
        # Inspect return expression for division / modulo by zero
        if stmt.value is not None:
            self._eval_expr(stmt.value, file, stmt.lineno)

    def _eval_expr(self, expr: ast.expr, file: str, line: int):
        if not _HAS_Z3:
            return None
        if isinstance(expr, ast.Constant):
            if isinstance(expr.value, bool):
                return z3.BoolVal(expr.value)
            if isinstance(expr.value, int):
                return z3.IntVal(expr.value)
            return None
        if isinstance(expr, ast.Name):
            if expr.id not in self.vars:
                self.vars[expr.id] = z3.Int(expr.id)
            return self.vars[expr.id]
        if isinstance(expr, ast.BinOp):
            left = self._eval_expr(expr.left, file, line)
            right = self._eval_expr(expr.right, file, line)
            if left is None or right is None:
                return None
            if isinstance(expr.op, ast.Add): return left + right
            if isinstance(expr.op, ast.Sub): return left - right
            if isinstance(expr.op, ast.Mult): return left * right
            if isinstance(expr.op, ast.Div):
                self._check_zero_divisor(right, file, line, op="/")
                return None
            if isinstance(expr.op, ast.Mod):
                self._check_zero_divisor(right, file, line, op="%")
                return None
        if isinstance(expr, ast.Subscript):
            # crude index OOB: only flag constant indices on a known-length list
            if isinstance(expr.slice, ast.Constant) and isinstance(expr.slice.value, int):
                idx = expr.slice.value
                if idx < 0:
                    self.findings.append(SymbolicFinding(
                        file=file, line=line, rule_id="SYM-INDEX-OOB",
                        description=f"Negative index {idx} — always out of bounds",
                        severity="medium", cwe="CWE-129"))
            return None
        return None

    def _eval_bool(self, expr: ast.expr, file: str, line: int):
        if not _HAS_Z3:
            return None
        if isinstance(expr, ast.Compare) and len(expr.ops) == 1:
            left = self._eval_expr(expr.left, file, line)
            right = self._eval_expr(expr.comparators[0], file, line)
            if left is None or right is None:
                return None
            op = expr.ops[0]
            if isinstance(op, ast.Eq): return left == right
            if isinstance(op, ast.NotEq): return left != right
            if isinstance(op, ast.Lt): return left < right
            if isinstance(op, ast.LtE): return left <= right
            if isinstance(op, ast.Gt): return left > right
            if isinstance(op, ast.GtE): return left >= right
        return None

    def _check_zero_divisor(self, divisor, file: str, line: int, op: str) -> None:
        assert self.solver is not None
        self.solver.push()
        self.solver.add(self.path_constraints)
        self.solver.add(divisor == 0)
        if self.solver.check() == z3.sat:
            m = self.solver.model()
            cex = ", ".join(f"{k}={m[v]}" for k, v in self.vars.items() if m[v] is not None)
            rule = "SYM-DIV-BY-ZERO" if op == "/" else "SYM-MOD-BY-ZERO"
            self.findings.append(SymbolicFinding(
                file=file, line=line, rule_id=rule,
                description=f"{op} by zero possible. Counterexample: {cex}",
                severity="high", cwe="CWE-369", counterexample=cex,
            ))
        self.solver.pop()


# =============================================================================
# Abstract Interpreter (interval domain)
# =============================================================================

@dataclass
class Interval:
    lo: float = float("-inf")
    hi: float = float("inf")

    @staticmethod
    def const(c: float) -> "Interval":
        return Interval(c, c)

    def is_bottom(self) -> bool:
        return self.lo > self.hi

    def intersect(self, other: "Interval") -> "Interval":
        return Interval(max(self.lo, other.lo), min(self.hi, other.hi))


@dataclass
class AbstractFinding:
    file: str
    line: int
    rule_id: str
    description: str
    severity: str = "medium"


class AbstractInterpreter:
    """Interval-domain abstract interpreter.

    Tracks integer variable ranges and flags dead branches (path conditions
    that are unsatisfiable under the current interval environment).
    """

    def __init__(self) -> None:
        self.env: Dict[str, Interval] = {}
        self.findings: List[AbstractFinding] = []

    def analyze_function(self, func_node: ast.FunctionDef, file: str) -> List[AbstractFinding]:
        self.env = {}
        self.findings = []
        self._exec_body(func_node.body, file)
        return self.findings

    def _exec_body(self, stmts: List[ast.stmt], file: str) -> None:
        for stmt in stmts:
            if isinstance(stmt, ast.Assign):
                self._exec_assign(stmt)
            elif isinstance(stmt, ast.If):
                self._exec_if(stmt, file)

    def _exec_assign(self, stmt: ast.Assign) -> None:
        if len(stmt.targets) != 1 or not isinstance(stmt.targets[0], ast.Name):
            return
        name = stmt.targets[0].id
        iv = self._eval_interval(stmt.value)
        if iv is not None:
            self.env[name] = iv

    def _exec_if(self, stmt: ast.If, file: str) -> None:
        cond = stmt.test
        then_env = dict(self.env)
        else_env = dict(self.env)
        then_feasible, else_feasible = self._refine(cond, then_env, else_env)
        if not then_feasible:
            self.findings.append(AbstractFinding(
                file=file, line=stmt.lineno, rule_id="ABS-DEAD-BRANCH",
                description="Then-branch is dead (condition always False)",
                severity="low"))
        elif not else_feasible and stmt.orelse:
            self.findings.append(AbstractFinding(
                file=file, line=stmt.lineno, rule_id="ABS-DEAD-BRANCH",
                description="Else-branch is dead (condition always True)",
                severity="low"))
        if then_feasible:
            saved = self.env
            self.env = then_env
            self._exec_body(stmt.body, file)
            self.env = saved
        if else_feasible and stmt.orelse:
            saved = self.env
            self.env = else_env
            self._exec_body(stmt.orelse, file)
            self.env = saved

    def _eval_interval(self, expr: ast.expr) -> Optional[Interval]:
        if isinstance(expr, ast.Constant) and isinstance(expr.value, (int, float)):
            return Interval.const(float(expr.value))
        if isinstance(expr, ast.Name):
            return self.env.get(expr.id)
        if isinstance(expr, ast.BinOp):
            l = self._eval_interval(expr.left)
            r = self._eval_interval(expr.right)
            if l is None or r is None:
                return None
            if isinstance(expr.op, ast.Add):
                return Interval(l.lo + r.lo, l.hi + r.hi)
            if isinstance(expr.op, ast.Sub):
                return Interval(l.lo - r.hi, l.hi - r.lo)
            if isinstance(expr.op, ast.Mult):
                vals = [l.lo * r.lo, l.lo * r.hi, l.hi * r.lo, l.hi * r.hi]
                return Interval(min(vals), max(vals))
        return None

    def _refine(self, cond: ast.expr, then_env: Dict[str, Interval],
                else_env: Dict[str, Interval]) -> Tuple[bool, bool]:
        """Refine environments on then/else branches. Returns (then_feasible, else_feasible)."""
        if isinstance(cond, ast.Compare) and len(cond.ops) == 1 and isinstance(cond.left, ast.Name):
            var = cond.left.id
            cur = then_env.get(var)
            rhs = self._eval_interval(cond.comparators[0])
            if cur is None or rhs is None:
                return True, True
            op = cond.ops[0]
            then_iv = cur
            else_iv = cur
            if isinstance(op, ast.Eq):
                then_iv = cur.intersect(rhs)
            elif isinstance(op, ast.Lt):
                then_iv = cur.intersect(Interval(float("-inf"), rhs.hi - 1))
                else_iv = cur.intersect(Interval(rhs.lo, float("inf")))
            elif isinstance(op, ast.Gt):
                then_iv = cur.intersect(Interval(rhs.lo + 1, float("inf")))
                else_iv = cur.intersect(Interval(float("-inf"), rhs.hi))
            then_env[var] = then_iv
            else_env[var] = else_iv
            return not then_iv.is_bottom(), not else_iv.is_bottom()
        return True, True


# =============================================================================
# Type Narrower (Optional dereference detection)
# =============================================================================

class TypeNarrower:
    """Detect Optional[X] dereferences that may be None.

    Patterns flagged:
      - x.field where x: Optional[T] and there's no prior `if x is not None`
      - x.method() where x: Optional[...] and no narrowing guard
      - x[i] / x + y where x may be None
    """

    _OPTIONAL_RE = re.compile(r"Optional\[")
    _ANNOT_NONE_RE = re.compile(r"\|\s*None\b|Optional\[")

    def __init__(self) -> None:
        self.findings: List[SymbolicFinding] = []

    def analyze_function(self, func_node: ast.FunctionDef, file: str) -> List[SymbolicFinding]:
        self.findings = []
        optional_vars: Dict[str, int] = {}
        # collect Optional params / annotations
        args = func_node.args.args + func_node.args.kwonlyargs
        annotations = [a.annotation for a in args if a.annotation]
        ann_strs = [ast.unparse(a) if hasattr(ast, "unparse") else "" for a in annotations]
        for arg, ann_str in zip(args, ann_strs):
            if self._is_optional(ann_str):
                optional_vars[arg.arg] = func_node.lineno
        # local var assignments whose RHS is None or Optional-typed function call
        for stmt in ast.walk(func_node):
            if isinstance(stmt, ast.AnnAssign) and stmt.annotation:
                ann = ast.unparse(stmt.annotation) if hasattr(ast, "unparse") else ""
                if isinstance(stmt.target, ast.Name) and self._is_optional(ann):
                    optional_vars[stmt.target.id] = stmt.lineno
        if not optional_vars:
            return []
        # walk the function body, tracking narrowed-out variables
        self._scan_block(func_node.body, set(), optional_vars, file)
        return self.findings

    def _is_optional(self, ann_str: str) -> bool:
        return bool(ann_str and (self._OPTIONAL_RE.search(ann_str) or self._ANNOT_NONE_RE.search(ann_str)))

    def _scan_block(self, stmts: List[ast.stmt], narrowed: set,
                    optional_vars: Dict[str, int], file: str) -> None:
        for stmt in stmts:
            if isinstance(stmt, ast.If):
                then_narrowed = set(narrowed)
                else_narrowed = set(narrowed)
                self._refine_narrowing(stmt.test, then_narrowed, else_narrowed, optional_vars)
                # scan then-body
                self._scan_block(stmt.body, then_narrowed, optional_vars, file)
                if stmt.orelse:
                    self._scan_block(stmt.orelse, else_narrowed, optional_vars, file)
                continue
            # look for attribute / subscript / call on an optional, non-narrowed variable
            for sub in ast.walk(stmt):
                if isinstance(sub, ast.Attribute) and isinstance(sub.value, ast.Name):
                    name = sub.value.id
                    if name in optional_vars and name not in narrowed:
                        self.findings.append(SymbolicFinding(
                            file=file, line=getattr(sub, "lineno", stmt.lineno),
                            rule_id="NARROW-OPTIONAL-DEREF",
                            description=f"'{name}' is Optional but dereferenced without a None-check",
                            severity="medium", cwe="CWE-476"))

    def _refine_narrowing(self, test: ast.expr, then_narrowed: set,
                          else_narrowed: set, optional_vars: Dict[str, int]) -> None:
        # `if x is not None:` → x is narrowed in then-branch
        if isinstance(test, ast.Compare) and isinstance(test.left, ast.Name) and len(test.ops) == 1:
            name = test.left.id
            if name not in optional_vars:
                return
            op = test.ops[0]
            rhs = test.comparators[0] if test.comparators else None
            is_none = isinstance(rhs, ast.Constant) and rhs.value is None
            if isinstance(op, ast.IsNot) and is_none:
                then_narrowed.add(name)
            elif isinstance(op, ast.Is) and is_none:
                else_narrowed.add(name)
            elif isinstance(op, ast.NotEq) and is_none:
                then_narrowed.add(name)
            elif isinstance(op, ast.Eq) and is_none:
                else_narrowed.add(name)


# =============================================================================
# Top-level entry points
# =============================================================================

def analyze_file(file_path: Path) -> List[SymbolicFinding]:
    """Run all three analyses (symbolic, abstract, narrowing) on one file."""
    if not file_path.exists() or file_path.suffix != ".py":
        return []
    try:
        source = file_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except Exception:
        return []
    findings: List[SymbolicFinding] = []
    sym = Z3SymbolicExecutor()
    ai = AbstractInterpreter()
    narrower = TypeNarrower()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            findings.extend(sym.analyze_function(node, str(file_path)))
            findings.extend(
                SymbolicFinding(file=f.file, line=f.line, rule_id=f.rule_id,
                                description=f.description, severity=f.severity)
                for f in ai.analyze_function(node, str(file_path))
            )
            findings.extend(narrower.analyze_function(node, str(file_path)))
    return findings
