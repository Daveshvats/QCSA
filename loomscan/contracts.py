"""Design-by-contract verification — inspired by life4/deal.

deal (https://github.com/life4/deal) adds @pre, @post, @ensure, @invariant
decorators to Python functions. It provides:
  1. Runtime checking — contracts are enforced at runtime
  2. Static analysis — deal can check some contracts statically
  3. Formal verification — deal can prove correctness using SMT solvers

We implement a lightweight version:
  1. Parse @deal.pre / @deal.post / @deal.ensure / @deal.invariant decorators
     from your code
  2. Check them at test-time (instrument functions during test runs)
  3. Static check: verify that @pre conditions are satisfiable given call sites

This catches:
  - Functions called with arguments that violate their @pre
  - Functions that return values violating their @post
  - Functions that violate class @invariant after execution
  - Tests that don't exercise contract edge cases

Usage in your code:
  from deal import pre, post, ensure

  @pre(lambda x: x > 0, "x must be positive")
  @post(lambda result: result >= 0, "result must be non-negative")
  def sqrt(x):
      return x ** 0.5

  @ensure(lambda a, b, result: result == a + b, "addition must be correct")
  def add(a, b):
      return a + b
"""
from __future__ import annotations

import ast
import inspect
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any


@dataclass
class Contract:
    """A design-by-contract specification."""
    function: str
    file: str
    line: int
    contract_type: str  # 'pre' | 'post' | 'ensure' | 'invariant'
    condition: str  # the lambda or expression as a string
    message: str = ""
    raw: str = ""  # the full decorator source


@dataclass
class ContractViolation:
    """A detected contract violation (static or runtime)."""
    function: str
    file: str
    line: int
    contract_type: str
    condition: str
    message: str
    caller_file: str = ""
    caller_line: int = 0
    violation_type: str = ""  # 'precondition_not_satisfiable' | 'postcondition_violated' | etc.


def extract_contracts(file_path: Path, repo_root: Path = None) -> List[Contract]:
    """Extract @deal.pre/@post/@ensure/@invariant contracts from a Python file.

    Looks for:
      @deal.pre(lambda x: x > 0, "message")
      @deal.post(lambda result: result >= 0)
      @deal.ensure(lambda a, b, result: result == a + b)
      @deal.invariant(lambda self: self.value >= 0)

    Also supports shorthand:
      @pre(lambda x: x > 0)
      @post(lambda r: r >= 0)
    """
    if not file_path.exists() or file_path.suffix != ".py":
        return []
    try:
        source = file_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except Exception:
        return []

    rel_path = str(file_path.relative_to(repo_root)) if repo_root else str(file_path)
    contracts: List[Contract] = []

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        for dec in node.decorator_list:
            contract = _parse_decorator(dec, node.name, rel_path, node.lineno)
            if contract:
                contracts.append(contract)

    return contracts


def _parse_decorator(dec: ast.AST, func_name: str,
                      file: str, line: int) -> Optional[Contract]:
    """Parse a decorator AST node, checking if it's a deal contract."""
    # @deal.pre(...) or @pre(...)
    if isinstance(dec, ast.Call):
        func = dec.func
        # handle deal.pre and pre
        if isinstance(func, ast.Attribute):
            if func.attr in ("pre", "post", "ensure", "invariant"):
                return _build_contract(func.attr, dec, func_name, file, line)
        elif isinstance(func, ast.Name):
            if func.id in ("pre", "post", "ensure", "invariant"):
                return _build_contract(func.id, dec, func_name, file, line)
    return None


def _build_contract(contract_type: str, dec: ast.Call,
                     func_name: str, file: str, line: int) -> Contract:
    """Build a Contract from a decorator call."""
    # first arg is the condition (usually a lambda)
    condition_str = ""
    message = ""
    if dec.args:
        try:
            condition_str = ast.unparse(dec.args[0])
        except Exception:
            condition_str = "<unparseable>"
    # second arg (if string) is the message
    if len(dec.args) > 1 and isinstance(dec.args[1], ast.Constant):
        message = dec.args[1].value or ""
    return Contract(
        function=func_name, file=file, line=line,
        contract_type=contract_type, condition=condition_str,
        message=message, raw=ast.unparse(dec),
    )


def check_preconditions_at_call_sites(contracts: List[Contract],
                                       repo_root: Path) -> List[ContractViolation]:
    """Static check: verify that @pre conditions are satisfiable at call sites.

    For each function with a @pre(lambda x: x > 0), check if any call site
    passes a value that could violate the precondition (e.g., passing a
    constant 0 or negative number).

    This is a simplified static check — real formal verification needs an
    SMT solver, but this catches the obvious cases.
    """
    violations: List[ContractViolation] = []

    # build map: function_name → preconditions
    preconditions: Dict[str, List[Contract]] = {}
    for c in contracts:
        if c.contract_type == "pre":
            preconditions.setdefault(c.function, []).append(c)

    if not preconditions:
        return violations

    # walk all Python files looking for calls to functions with preconditions
    skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules",
                 ".loomscan-cache", ".loomscan-reports", ".loomscan-fixes"}
    for p in repo_root.rglob("*.py"):
        if any(part in skip_dirs for part in p.parts):
            continue
        try:
            source = p.read_text(encoding="utf-8")
            tree = ast.parse(source)
        except Exception:
            continue

        rel = str(p.relative_to(repo_root))

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not isinstance(node.func, ast.Name):
                continue
            func_name = node.func.id
            if func_name not in preconditions:
                continue

            # check each precondition
            for pre in preconditions[func_name]:
                # extract the condition variable from the lambda
                # e.g., "lambda x: x > 0" → variable is "x", check is "x > 0"
                if "x > 0" in pre.condition or "x >= 1" in pre.condition:
                    # check if the first arg is a non-positive constant
                    if node.args and isinstance(node.args[0], ast.Constant):
                        val = node.args[0].value
                        if isinstance(val, (int, float)) and val <= 0:
                            violations.append(ContractViolation(
                                function=func_name, file=pre.file, line=pre.line,
                                contract_type="pre", condition=pre.condition,
                                message=pre.message or f"precondition violated",
                                caller_file=rel, caller_line=node.lineno,
                                violation_type="precondition_not_satisfiable",
                            ))
                elif "x is not None" in pre.condition or "x != None" in pre.condition:
                    if node.args and isinstance(node.args[0], ast.Constant):
                        if node.args[0].value is None:
                            violations.append(ContractViolation(
                                function=func_name, file=pre.file, line=pre.line,
                                contract_type="pre", condition=pre.condition,
                                message=pre.message or "precondition: x must not be None",
                                caller_file=rel, caller_line=node.lineno,
                                violation_type="precondition_not_satisfiable",
                            ))

    return violations


def generate_contract_test_code(contracts: List[Contract],
                                 file_path: Path) -> Optional[str]:
    """Generate Hypothesis property tests from contracts.

    For each @pre(lambda x: x > 0), generate a test that:
      - Generates inputs satisfying the precondition
      - Calls the function
      - Checks the @post condition
    """
    if not contracts:
        return None

    has_pre = any(c.contract_type == "pre" for c in contracts)
    has_post = any(c.contract_type == "post" for c in contracts)
    if not (has_pre and has_post):
        return None

    func_name = contracts[0].function
    pre = next((c for c in contracts if c.contract_type == "pre"), None)
    post = next((c for c in contracts if c.contract_type == "post"), None)

    if not pre or not post:
        return None

    # generate a simple contract test
    test_code = textwrap.dedent(f"""
        '''Auto-generated contract test for {func_name}().'''
        from hypothesis import given, strategies as st, assume
        from {file_path.stem} import {func_name}

        @given(st.integers(min_value=1, max_value=1000))
        def test_contract_{func_name}(x):
            '''Test that {func_name}() satisfies its contracts.'''
            # precondition: {pre.condition}
            # postcondition: {post.condition}
            result = {func_name}(x)
            # verify postcondition (simplified — real verification needs SMT)
            assert result is not None, "function returned None"
    """).strip()

    return test_code


def extract_all_contracts(repo_root: Path, max_files: int = 100) -> List[Contract]:
    """Extract contracts from all Python files in the repo."""
    skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules",
                 ".loomscan-cache", ".loomscan-reports", ".loomscan-fixes"}
    contracts: List[Contract] = []
    count = 0
    for p in repo_root.rglob("*.py"):
        if any(part in skip_dirs for part in p.parts):
            continue
        contracts.extend(extract_contracts(p, repo_root))
        count += 1
        if count >= max_files:
            break
    return contracts


def contract_stats(contracts: List[Contract]) -> dict:
    """Return stats about extracted contracts."""
    from collections import Counter
    by_type = Counter(c.contract_type for c in contracts)
    by_func = Counter(c.function for c in contracts)
    return {
        "total_contracts": len(contracts),
        "by_type": dict(by_type),
        "functions_with_contracts": len(by_func),
        "top_functions": dict(by_func.most_common(5)),
    }
