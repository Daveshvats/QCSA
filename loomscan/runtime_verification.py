"""Runtime Verification — Scribble-inspired @invariant decorator.

The core idea: some bugs only manifest at runtime with specific data.
Static analysis can't catch them. Runtime verification instruments code
to check invariants during actual execution.

How it works:
  1. User annotates functions/classes with @invariant(expr)
  2. LoomScan instruments the code (AST transformation) to check the invariant
     after each state-modifying operation
  3. During testing (or production), violations are logged
  4. Violations are reported as findings

Example:
  @invariant("balance >= 0")
  class Wallet:
      def deposit(self, amount):
          self.balance += amount
      def withdraw(self, amount):
          self.balance -= amount  # if amount > balance, invariant violated

  When withdraw() is called with amount > balance, the instrumented code
  checks "balance >= 0" after the withdrawal and raises if violated.

This catches bugs that static analysis cannot:
  - Data-dependent violations (balance goes negative only with specific inputs)
  - Multi-step state corruption
  - Concurrency-induced invariant breaks
"""
from __future__ import annotations

import ast
import textwrap
import inspect
from pathlib import Path
from typing import List, Optional, Dict, Any
from dataclasses import dataclass


@dataclass
class RuntimeViolation:
    """A runtime invariant violation found by instrumented testing."""
    file: str
    line: int
    invariant: str
    function: str
    description: str
    context: str  # variable values at time of violation


def find_invariant_annotations(file_path: Path) -> List[Dict[str, Any]]:
    """Find @invariant annotations in a file.

    Looks for:
      @invariant("balance >= 0")
      @invariant("len(self.items) > 0")
      @loomscan.invariant("self.state in ['active', 'pending']")

    Returns list of {class, function, invariant_expr, line}.
    """
    if not file_path.exists() or file_path.suffix != ".py":
        return []
    try:
        source = file_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except Exception:
        return []

    annotations: List[Dict[str, Any]] = []

    for node in ast.walk(tree):
        if not isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        for dec in node.decorator_list:
            dec_name = ""
            dec_arg = ""
            if isinstance(dec, ast.Call):
                if isinstance(dec.func, ast.Name):
                    dec_name = dec.func.id
                elif isinstance(dec.func, ast.Attribute):
                    dec_name = dec.func.attr
                if dec.args and isinstance(dec.args[0], ast.Constant):
                    dec_arg = str(dec.args[0].value)
            elif isinstance(dec, ast.Name):
                dec_name = dec.id

            if dec_name == "invariant" and dec_arg:
                annotations.append({
                    "target_type": "class" if isinstance(node, ast.ClassDef) else "function",
                    "target_name": node.name,
                    "invariant_expr": dec_arg,
                    "line": node.lineno,
                    "node": node,
                })

    return annotations


def instrument_code_with_invariants(file_path: Path) -> Optional[str]:
    """Transform a file's code to add runtime invariant checks.

    For each @invariant("expr") annotation on a class, inserts a check
    after every method that modifies state:
        def method(self, ...):
            <original body>
            assert eval("expr"), "Invariant violated: expr"

    Returns the instrumented source code, or None if no invariants found.
    """
    if not file_path.exists() or file_path.suffix != ".py":
        return None
    try:
        source = file_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except Exception:
        return None

    annotations = find_invariant_annotations(file_path)
    if not annotations:
        return None

    # Group invariants by target
    class_invariants: Dict[str, List[str]] = {}
    func_invariants: Dict[str, List[str]] = {}
    for ann in annotations:
        if ann["target_type"] == "class":
            class_invariants.setdefault(ann["target_name"], []).append(ann["invariant_expr"])
        else:
            func_invariants.setdefault(ann["target_name"], []).append(ann["invariant_expr"])

    # Transform: add invariant checks to methods
    class InvariantInstrumenter(ast.NodeTransformer):
        def visit_ClassDef(self, node):
            # First, visit children
            self.generic_visit(node)

            # If this class has invariants, add checks to each method
            if node.name in class_invariants:
                invs = class_invariants[node.name]
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        if item.name.startswith("_") and item.name != "__init__":
                            continue
                        # Add invariant checks at the end of the method body
                        for inv_expr in invs:
                            try:
                                check = ast.parse(f"assert {inv_expr}, 'Invariant violated: {inv_expr}'").body[0]
                                item.body.append(check)
                            except SyntaxError:
                                pass

            # If methods have their own invariants
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if item.name in func_invariants:
                        invs = func_invariants[item.name]
                        for inv_expr in invs:
                            try:
                                check = ast.parse(f"assert {inv_expr}, 'Invariant violated: {inv_expr}'").body[0]
                                item.body.append(check)
                            except SyntaxError:
                                pass

            return node

        def visit_FunctionDef(self, node):
            # Top-level functions (not in classes)
            self.generic_visit(node)
            if node.name in func_invariants:
                invs = func_invariants[node.name]
                for inv_expr in invs:
                    try:
                        check = ast.parse(f"assert {inv_expr}, 'Invariant violated: {inv_expr}'").body[0]
                        node.body.append(check)
                    except SyntaxError:
                        pass
            return node

    new_tree = InvariantInstrumenter().visit(tree)
    ast.fix_missing_locations(new_tree)

    try:
        return ast.unparse(new_tree)
    except Exception:
        return None


def provide_invariant_decorator() -> str:
    """Return the source code for the @invariant decorator.

    Users add this to their code or import it from loomscan.
    """
    return textwrap.dedent("""
# LoomScan Runtime Verification — @invariant decorator
# Usage:
#   from loomscan.runtime_verification import invariant
#
#   @invariant("self.balance >= 0")
#   class Wallet:
#       def __init__(self):
#           self.balance = 0
#       def withdraw(self, amount):
#           self.balance -= amount
#
# LoomScan will instrument this to check the invariant after each method call.

def invariant(expr):
    \"\"\"Decorator that marks a class/function for runtime invariant checking.

    LoomScan instruments the code to check this invariant after each
    state-modifying operation.
    \"\"\"
    def decorator(target):
        # Store the invariant expression on the target
        if not hasattr(target, '_loomscan_invariants'):
            target._loomscan_invariants = []
        target._loomscan_invariants.append(expr)
        return target
    return decorator
""").strip()
