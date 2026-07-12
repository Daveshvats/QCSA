"""Concrete Counterexample Generation — Z3 symbolic execution for BL bugs.

When we find a business logic bug (e.g., "invalid state transition"),
we should produce the SPECIFIC INPUT that triggers it. This makes
findings actionable — instead of "a bug exists," we report "this bug
is triggered when amount=-1 and user_type='guest'."

How it works:
  1. Parse the function's conditions into Z3 constraints
  2. Negate the "expected" invariant (e.g., negate "balance >= 0")
  3. Solve with Z3 — if satisfiable, the solution is the triggering input
  4. Report the concrete counterexample

Example:
  Function: def withdraw(amount): if amount > 0: balance -= amount
  Invariant: balance >= 0 (should always hold)
  Z3 query: exists amount, balance such that amount > 0 AND balance - amount < 0
  Solution: amount=100, balance=50 → balance becomes -50 (invariant violated)
  Report: "withdraw(100) when balance=50 causes balance to go negative"
"""
from __future__ import annotations
from .z3_utils import ast_to_z3 as _ast_to_z3

import ast
import textwrap
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple
from dataclasses import dataclass

try:
    from z3 import (
        Int, Real, String, Bool, BoolVal, Solver, sat, unsat, And, Or, Not,
        If, Implies, Function, IntSort, BoolSort
    )
    _HAS_Z3 = True
except ImportError:
    _HAS_Z3 = False


@dataclass
class Counterexample:
    """A concrete input that triggers a business logic bug."""
    function: str
    inputs: Dict[str, Any]  # variable_name -> triggering value
    description: str
    file: str
    line: int
    invariant: str  # the invariant that's violated


def generate_counterexample_for_invariant(
    func_source: str,
    invariant_expr: str,
    func_name: str = "",
    file: str = "",
    line: int = 0,
) -> Optional[Counterexample]:
    """Generate a concrete counterexample for an invariant violation.

    Given a function's source and an invariant that should hold, find
    the specific input that violates the invariant.

    Returns a Counterexample if one exists, None otherwise.
    """
    if not _HAS_Z3:
        return None

    try:
        tree = ast.parse(func_source)
    except SyntaxError:
        return None

    # Find the function
    func_node = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if func_name and node.name == func_name:
                func_node = node
                break
            elif not func_name:
                func_node = node
                break

    if not func_node:
        return None

    # Extract parameters
    params = [arg.arg for arg in func_node.args.args if arg.arg != "self"]

    # Create Z3 variables for each parameter
    z3_vars: Dict[str, Any] = {}
    for param in params:
        # Default to Int — most BL parameters are integers
        z3_vars[param] = Int(param)

    # Parse the function body to extract conditions
    # We look for: if-conditions, assignments, and the invariant
    solver = Solver()

    # Extract conditions from if-statements
    conditions: List[Any] = []
    for node in ast.walk(func_node):
        if isinstance(node, ast.If):
            # Try to convert the condition to Z3
            z3_cond = _ast_to_z3(node.test, z3_vars)
            if z3_cond is not None:
                conditions.append(z3_cond)

    # Extract assignments (simple ones: var = expr)
    for node in ast.walk(func_node):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in z3_vars:
                    z3_expr = _ast_to_z3(node.value, z3_vars)
                    if z3_expr is not None:
                        # Add: var == expr (simplified — doesn't handle sequencing)
                        solver.add(z3_vars[target.id] == z3_expr)

    # Add the conditions (must be true for the path to execute)
    for cond in conditions:
        solver.add(cond)

    # Negate the invariant — we want to find inputs that VIOLATE it
    # Normalize: strip "return " prefix, handle "True"/"False"
    inv_normalized = invariant_expr.strip()
    if inv_normalized.lower().startswith("return "):
        inv_normalized = inv_normalized[len("return "):].strip()
    if inv_normalized in ("True", "False"):
        z3_invariant = BoolVal(inv_normalized == "True")
    else:
        try:
            inv_ast = ast.parse(inv_normalized, mode="eval").body
            z3_invariant = _ast_to_z3(inv_ast, z3_vars)
        except SyntaxError:
            return None
    if z3_invariant is None:
        return None

    solver.add(Not(z3_invariant))

    # Solve
    if solver.check() == sat:
        model = solver.model()
        inputs: Dict[str, Any] = {}
        for param in params:
            if param in z3_vars:
                val = model.eval(z3_vars[param], model_completion=True)
                try:
                    inputs[param] = int(str(val))
                except (ValueError, TypeError):
                    inputs[param] = str(val)

        return Counterexample(
            function=func_node.name,
            inputs=inputs,
            description=f"Calling {func_node.name}({', '.join(f'{k}={v}' for k, v in inputs.items())}) "
                       f"violates the invariant '{invariant_expr}'",
            file=file,
            line=line,
            invariant=invariant_expr,
        )

    return None




def generate_counterexamples_for_file(file_path: Path) -> List[Counterexample]:
    """Generate counterexamples for all functions in a file.

    For each function, tries common invariants:
      - balance >= 0
      - amount > 0
      - return >= 0
      - len(param) > 0
    """
    if not _HAS_Z3:
        return []

    if not file_path.exists() or file_path.suffix != ".py":
        return []

    try:
        source = file_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except Exception:
        return []

    rel_path = str(file_path)
    counterexamples: List[Counterexample] = []

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        func_source = ast.unparse(node)
        params = [arg.arg for arg in node.args.args if arg.arg != "self"]

        # Try common invariants
        common_invariants = []

        # If there's a parameter named "amount" or similar, check > 0
        for param in params:
            if any(kw in param.lower() for kw in ("amount", "qty", "quantity", "count", "price")):
                common_invariants.append(f"{param} > 0")

        # If there's a "balance" or "total" in the function body, check >= 0
        for sub in ast.walk(node):
            if isinstance(sub, ast.Attribute) and isinstance(sub.value, ast.Name) and sub.value.id == "self":
                if any(kw in sub.attr.lower() for kw in ("balance", "total", "amount")):
                    common_invariants.append(f"self.{sub.attr} >= 0")

        # Try each invariant
        for inv in common_invariants:
            ce = generate_counterexample_for_invariant(
                func_source, inv, node.name, rel_path, node.lineno
            )
            if ce:
                counterexamples.append(ce)

    return counterexamples
