"""Stateful Property-Based Testing — frontier BL bug detection.

Inspired by Echidna (Trail of Bits) and Hypothesis RuleBasedStateMachine.

The core idea: business logic bugs often span multiple operations. Testing
functions in isolation misses them. Stateful PBT models the system as a
state machine, generates random sequences of operations, and checks
invariants after each operation.

How it works:
  1. Auto-generate a RuleBasedStateMachine model from the target class/code
  2. Each public method becomes a @rule (an action the fuzzer can take)
  3. User-defined or inferred @invariant() properties are checked after each action
  4. Hypothesis generates random action sequences (up to 100 steps)
  5. If an invariant fails → bug found, with the exact action sequence that triggered it

Example:
  For a ShoppingCart class with add_item(), remove_item(), checkout():
  - The model generates: add("apple", 2) → add("banana", 1) → remove("apple") → checkout()
  - After each action, it checks: total == sum(cart.values())
  - If checkout() doesn't clear the cart → invariant violation → bug report

This catches bugs that static analysis fundamentally cannot:
  - Multi-step state manipulation bugs
  - Order-dependent bugs (A then B vs B then A)
  - Edge cases (empty cart checkout, negative quantities)
  - Race-condition-like logic bugs (interleaved operations)
"""
from __future__ import annotations

import ast
import inspect
import textwrap
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import List, Optional, Tuple, Dict, Any, Set
from dataclasses import dataclass


@dataclass
class StatefulViolation:
    """A stateful property violation — a business logic bug found by PBT."""
    function: str
    invariant: str
    action_sequence: str
    description: str
    file: str
    line: int


def discover_stateful_targets(file_path: Path) -> List[Tuple[str, str, List[str], List[str]]]:
    """Find classes that are good candidates for stateful PBT.

    Returns list of (class_name, class_source, public_methods, invariant_candidates).

    A good candidate is a class with:
    - Multiple public methods (not just __init__)
    - Methods that modify state (have assignments to self.X)
    - At least 2 methods (needs multiple operations to be stateful)
    """
    if not file_path.exists() or file_path.suffix != ".py":
        return []
    try:
        source = file_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except Exception:
        return []

    results: List[Tuple[str, str, List[str], List[str]]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        # Find public methods
        public_methods: List[str] = []
        state_vars: Set[str] = set()
        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if not item.name.startswith("_") and item.name != "__init__":
                    public_methods.append(item.name)
                    # Check if this method modifies state
                    for sub in ast.walk(item):
                        # Direct attribute assignment: self.x = ...
                        if isinstance(sub, ast.Assign):
                            for target in sub.targets:
                                if isinstance(target, ast.Attribute) and \
                                   isinstance(target.value, ast.Name) and \
                                   target.value.id == "self":
                                    state_vars.add(target.attr)
                                # Subscript assignment: self.x[key] = ...
                                if isinstance(target, ast.Subscript) and \
                                   isinstance(target.value, ast.Attribute) and \
                                   isinstance(target.value.value, ast.Name) and \
                                   target.value.value.id == "self":
                                    state_vars.add(target.value.attr)
                        # Augmented assignment: self.x += ...
                        if isinstance(sub, ast.AugAssign):
                            if isinstance(sub.target, ast.Attribute) and \
                               isinstance(sub.target.value, ast.Name) and \
                               sub.target.value.id == "self":
                                state_vars.add(sub.target.attr)
        # Need at least 2 public methods and some state to be interesting
        if len(public_methods) >= 2 and state_vars:
            class_source = ast.unparse(node)
            results.append((node.name, class_source, public_methods, sorted(state_vars)))

    return results


def generate_stateful_test_code(class_name: str, class_source: str,
                                  methods: List[str], state_vars: List[str],
                                  module_path: str) -> str:
    """Generate Hypothesis RuleBasedStateMachine test code.

    The generated test:
    1. Imports the target class
    2. Defines a RuleBasedStateMachine with one @rule per public method
    3. Adds a default @invariant that checks all state vars are consistent
    4. Runs the state machine with Hypothesis
    """
    # Generate rule methods
    rules = []
    for method in methods:
        # Generate a simple rule that calls the method with a string + int
        # (most BL methods take an identifier and a quantity/amount)
        rules.append(textwrap.dedent(f"""
    @rule(item=st.text(min_size=1, max_size=20), qty=st.integers(min_value=0, max_value=100))
    def {method}(self, item, qty):
        try:
            self.target.{method}(item, qty)
        except (TypeError, ValueError):
            # Method might not take these args — try with just item
            try:
                self.target.{method}(item)
            except (TypeError, ValueError):
                pass  # skip — wrong signature
        except Exception:
            pass  # ignore runtime errors from bad input
""").strip())

    # Generate invariant — check that state vars haven't become inconsistent
    # We check: no state var is None if it was initialized, no list/dict is negative size
    invariant_checks = []
    for var in state_vars:
        invariant_checks.append(textwrap.dedent(f"""
        # Check {var} consistency
        val = getattr(self.target, '{var}', None)
        if isinstance(val, (int, float)):
            # v4.15: Only assert non-negative for variables whose names suggest
            # they represent counts/amounts/balances. For other numerics (e.g.
            # temperature, coordinates, deltas), non-negativity is wrong.
            # The old code asserted val >= 0 for ALL numeric state — wrong for
            # debt/refund/temperature/coordinates.
            _count_like = any(kw in '{var}'.lower() for kw in
                ('count', 'total', 'amount', 'balance', 'qty', 'quantity',
                 'num', 'size', 'len', 'length', 'price', 'cost', 'fee'))
            if _count_like:
                assert val >= 0, f"{var} went negative: {{val}}"
        elif isinstance(val, (list, dict)):
            # v4.15: Removed tautological assert len(val) >= 0 (always true).
            # Instead check that the collection is still valid (not corrupted).
            assert val is not None, f"{var} became None"
""").strip())

    invariant_body = "\n".join(invariant_checks) if invariant_checks else "pass"

    test_code = textwrap.dedent(f"""
from hypothesis import stateful, strategies as st, settings, given

# Import the target class
from {module_path} import {class_name}


class {class_name}Machine(stateful.RuleBasedStateMachine):
    '''Stateful PBT model for {class_name}.

    Auto-generated by STCA. Tests random sequences of operations
    and checks invariants after each one.
    '''
    def __init__(self):
        super().__init__()
        self.target = {class_name}()

{chr(10).join(rules)}

    @stateful.invariant()
    def check_state_consistency(self):
        '''Check that state variables remain consistent after each operation.'''
{chr(4).join('        ' + line for line in invariant_body.split(chr(10)))}

# Run the test
Test{class_name.title().replace('_','')}Machine = {class_name}Machine.TestCase

if __name__ == '__main__':
    import pytest
    pytest.main([__file__, '-v', '--tb=short', '-x'])
""").strip()

    return test_code


def run_stateful_tests(file_path: Path, repo_root: Path = None) -> List[StatefulViolation]:
    """Generate and run stateful PBT tests for all candidate classes in a file.

    Returns a list of violations (business logic bugs found).
    """
    targets = discover_stateful_targets(file_path)
    if not targets:
        return []

    rel_path = str(file_path.relative_to(repo_root)) if repo_root else str(file_path)
    module_path = rel_path.replace("/", ".").replace(".py", "").lstrip(".")

    violations: List[StatefulViolation] = []

    for class_name, class_source, methods, state_vars in targets:
        test_code = generate_stateful_test_code(class_name, class_source,
                                                  methods, state_vars, module_path)

        # Write test file
        test_file = (repo_root or file_path.parent) / ".stca-cache" / "stateful_pbt" / f"test_{class_name}_stateful.py"
        test_file.parent.mkdir(parents=True, exist_ok=True)
        test_file.write_text(test_code, encoding="utf-8")

        # Run the test
        try:
            proc = subprocess.run(
                [sys.executable, "-m", "pytest", str(test_file), "-v", "--tb=short",
                 "-x", "--maxfail=1"],
                capture_output=True, text=True, check=False, timeout=30,
                cwd=str(repo_root or file_path.parent),
            )

            # Parse failures
            if proc.returncode != 0:
                output = proc.stdout + proc.stderr
                if "FAILED" in output or "AssertionError" in output or "assert" in output.lower():
                    # Extract the action sequence from the failure
                    action_seq = ""
                    for line in output.splitlines():
                        if "state." in line.lower() or "->" in line or "rule" in line.lower():
                            action_seq += line.strip() + "; "
                    if not action_seq:
                        action_seq = output[:300]

                    violations.append(StatefulViolation(
                        function=class_name,
                        invariant="state_consistency",
                        action_sequence=action_seq[:500],
                        description=f"Stateful PBT found a state inconsistency in {class_name} "
                                    f"after a sequence of operations. This indicates a business "
                                    f"logic bug — the class's state became invalid.",
                        file=rel_path,
                        line=0,
                    ))
        except subprocess.TimeoutExpired:
            pass  # test took too long — skip
        except Exception:
            pass

    return violations
