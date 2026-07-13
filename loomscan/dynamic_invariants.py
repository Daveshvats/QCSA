"""Dynamic Invariant Inference — Daikon-inspired runtime invariant discovery.

The core idea: static analysis can only find bugs that match known patterns.
Dynamic inference observes the program's ACTUAL behavior at runtime and
infers invariants that hold in practice. Any code that would violate these
inferred invariants is suspicious.

How it works:
  1. Instrument target functions to record variable values at entry/exit
  2. Run the user's test suite (or generate inputs via property-based testing)
  3. At every program point, test invariant templates:
     - x == c (constant)
     - x > 0, x >= 0 (range)
     - len(x) > 0 (non-empty)
     - a == f(b) (relationship: a == b, a == b + 1, a > b, etc.)
  4. Keep only invariants that hold in 100% of observations
  5. Flag functions where the code would violate its own inferred invariants

Example:
  If withdraw(amount) is always called with amount > 0 in tests, we infer
  "amount > 0" as an invariant. If someone later calls withdraw(-100), that's
  a likely bug (depositing instead of withdrawing).

This catches bugs that static analysis fundamentally cannot:
  - Implicit invariants (not stated in asserts)
  - Domain-specific constraints (amount > 0, balance >= 0)
  - Relationship invariants (return_value == input * 2)
"""
from __future__ import annotations

import ast
import textwrap
import subprocess
import sys
import json
import os
import tempfile  # v4.14 BUG #11 FIX: was missing, caused NameError on first call
from pathlib import Path
from typing import List, Optional, Tuple, Dict, Any, Set
from dataclasses import dataclass, field
from collections import defaultdict


@dataclass
class InferredInvariant:
    """An invariant inferred from runtime observations."""
    function: str
    variable: str  # variable name or "return"
    invariant_type: str  # 'constant', 'positive', 'non_empty', 'relationship', 'range'
    expression: str  # human-readable: "amount > 0", "return == input * 2"
    confidence: float  # fraction of observations where it held
    file: str
    line: int


@dataclass
class InvariantViolation:
    """A function that would violate its own inferred invariants."""
    function: str
    invariant: str
    description: str
    file: str
    line: int


# Invariant templates we check
def _check_constant(values: list) -> Optional[str]:
    """Check if all values are the same constant."""
    if not values:
        return None
    try:
        first = values[0]
        if all(v == first for v in values):
            return f"== {first!r}"
    except Exception:
        pass
    return None


def _check_positive(values: list) -> Optional[str]:
    """Check if all values are positive / non-negative."""
    if not values:
        return None
    try:
        nums = [v for v in values if isinstance(v, (int, float)) and not isinstance(v, bool)]
        if not nums:
            return None
        if all(v > 0 for v in nums):
            return "> 0"
        if all(v >= 0 for v in nums):
            return ">= 0"
    except Exception:
        pass
    return None


def _check_non_empty(values: list) -> Optional[str]:
    """Check if all collection values are non-empty."""
    if not values:
        return None
    try:
        cols = [v for v in values if hasattr(v, "__len__") and not isinstance(v, (int, float, bool, str))]
        if cols and all(len(v) > 0 for v in cols):
            return "len > 0"
        strs = [v for v in values if isinstance(v, str)]
        if strs and all(len(v) > 0 for v in strs):
            return "non-empty string"
    except Exception:
        pass
    return None


def _check_range(values: list) -> Optional[str]:
    """Check if values fall within a range."""
    if not values:
        return None
    try:
        nums = [v for v in values if isinstance(v, (int, float)) and not isinstance(v, bool)]
        if len(nums) < 3:
            return None
        lo, hi = min(nums), max(nums)
        # If the range is tight, report it
        if hi - lo < 1000:
            return f"in [{lo}, {hi}]"
    except Exception:
        pass
    return None


def _check_relationship(var_name: str, var_values: list,
                         other_vars: Dict[str, list]) -> Optional[str]:
    """Check if this variable has a relationship with another variable."""
    if not var_values or len(var_values) < 3:
        return None
    try:
        nums1 = [(i, v) for i, v in enumerate(var_values) if isinstance(v, (int, float)) and not isinstance(v, bool)]
        if len(nums1) < 3:
            return None
        for other_name, other_values in other_vars.items():
            if other_name == var_name:
                continue
            nums2 = [(i, v) for i, v in enumerate(other_values) if isinstance(v, (int, float)) and not isinstance(v, bool)]
            if len(nums2) < 3:
                continue
            # Find common indices
            common = [(i, v1, v2) for i, v1 in nums1 for i2, v2 in nums2 if i == i2]
            if len(common) < 3:
                continue
            vals1 = [v1 for _, v1, _ in common]
            vals2 = [v2 for _, _, v2 in common]
            # Check: var == other
            if all(v1 == v2 for v1, v2 in zip(vals1, vals2)):
                return f"== {other_name}"
            # Check: var == other + c
            diffs = [v1 - v2 for v1, v2 in zip(vals1, vals2)]
            if len(set(diffs)) == 1:
                c = diffs[0]
                if c == 0:
                    return f"== {other_name}"
                return f"== {other_name} + {c}" if c > 0 else f"== {other_name} - {-c}"
            # Check: var > other
            if all(v1 > v2 for v1, v2 in zip(vals1, vals2)):
                return f"> {other_name}"
            # Check: var < other
            if all(v1 < v2 for v1, v2 in zip(vals1, vals2)):
                return f"< {other_name}"
    except Exception:
        pass
    return None


def infer_invariants_from_observations(observations: List[Dict[str, Any]],
                                         function_name: str,
                                         file: str = "",
                                         line: int = 0) -> List[InferredInvariant]:
    """Infer invariants from a list of runtime observations.

    Each observation is a dict of variable_name -> value, recorded at a
    single function entry or exit.
    """
    if len(observations) < 2:
        return []  # need at least 2 observations to infer anything

    # Collect all variable names
    all_vars: Set[str] = set()
    for obs in observations:
        all_vars.update(obs.keys())

    # Collect values per variable
    var_values: Dict[str, list] = defaultdict(list)
    for obs in observations:
        for var in all_vars:
            if var in obs:
                var_values[var].append(obs[var])

    invariants: List[InferredInvariant] = []

    for var, values in var_values.items():
        if len(values) < 2:
            continue

        # Check each invariant template
        for inv_type, checker in [
            ("constant", _check_constant),
            ("positive", _check_positive),
            ("non_empty", _check_non_empty),
            ("range", _check_range),
        ]:
            result = checker(values)
            if result:
                invariants.append(InferredInvariant(
                    function=function_name,
                    variable=var,
                    invariant_type=inv_type,
                    expression=f"{var} {result}",
                    confidence=1.0,  # held in 100% of observations
                    file=file,
                    line=line,
                ))
                break  # only keep one invariant per variable per type

        # Check relationships (only for numeric vars)
        rel = _check_relationship(var, values, var_values)
        if rel:
            invariants.append(InferredInvariant(
                function=function_name,
                variable=var,
                invariant_type="relationship",
                expression=f"{var} {rel}",
                confidence=1.0,
                file=file,
                line=line,
            ))

    return invariants


def generate_instrumented_test(file_path: Path, repo_root: Path = None) -> Tuple[Optional[Path], List[str]]:
    """Generate an instrumented test that records variable values.

    Returns (test_file_path, list_of_function_names_to_test).
    """
    if not file_path.exists() or file_path.suffix != ".py":
        return None, []

    try:
        source = file_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except Exception:
        return None, []

    rel_path = str(file_path.relative_to(repo_root)) if repo_root else str(file_path)
    module_path = rel_path.replace("/", ".").replace(".py", "").lstrip(".")

    # Find functions to instrument
    functions_to_test: List[str] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if not node.name.startswith("_") and len(node.args.args) >= 1:
                functions_to_test.append(node.name)

    if not functions_to_test:
        return None, []

    # Generate instrumented test
    test_code_parts = [f"""
import json
import sys
import os
sys.path.insert(0, {str(repo_root or file_path.parent)!r})
from {module_path} import *

OBSERVATIONS_FILE = os.environ.get('STCA_OBSERVATIONS_FILE', '/tmp/loomscan_observations.json')
observations = []

def record(func_name, **kwargs):
    obs = {{"__function__": func_name}}
    obs.update(kwargs)
    observations.append(obs)

def flush():
    with open(OBSERVATIONS_FILE, 'a') as f:
        for obs in observations:
            f.write(json.dumps(obs, default=str) + '\\n')
    observations.clear()
"""]

    for func_name in functions_to_test:
        test_code_parts.append(textwrap.dedent(f"""
def test_record_{func_name}():
    import inspect
    try:
        sig = inspect.signature({func_name})
        params = list(sig.parameters.keys())
        # Generate a few test inputs
        test_inputs = [
            {{p: 1 for p in params}},
            {{p: 10 for p in params}},
            {{p: 100 for p in params}},
        ]
        for inputs in test_inputs:
            try:
                entry_obs = {{"__function__": "{func_name}", "__point__": "entry"}}
                entry_obs.update(inputs)
                observations.append(entry_obs)
                result = {func_name}(**inputs)
                exit_obs = {{"__function__": "{func_name}", "__point__": "exit", "return": result}}
                observations.append(exit_obs)
            except Exception as e:
                pass
        flush()
    except Exception:
        pass
""").strip())

    test_code = "\n\n".join(test_code_parts)

    test_file = (repo_root or file_path.parent) / ".loomscan-cache" / "dynamic_invariants" / f"test_{file_path.stem}_dyninv.py"
    test_file.parent.mkdir(parents=True, exist_ok=True)
    test_file.write_text(test_code, encoding="utf-8")

    return test_file, functions_to_test


def run_dynamic_invariant_inference(file_path: Path,
                                      repo_root: Path = None) -> Tuple[List[InferredInvariant], List[InvariantViolation]]:
    """Run dynamic invariant inference on a file.

    Returns (inferred_invariants, violations).
    """
    test_file, func_names = generate_instrumented_test(file_path, repo_root)
    if not test_file or not func_names:
        return [], []

    rel_path = str(file_path.relative_to(repo_root)) if repo_root else str(file_path)

    # Set up observations file
    obs_file = tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False)
    obs_file.close()
    obs_path = obs_file.name

    env = os.environ.copy()
    env["STCA_OBSERVATIONS_FILE"] = obs_path
    if repo_root:
        env["PYTHONPATH"] = str(repo_root) + os.pathsep + env.get("PYTHONPATH", "")

    # Run the instrumented test
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", str(test_file), "-v", "--tb=short", "-x"],
            capture_output=True, text=True, check=False, timeout=30,
            cwd=str(repo_root or file_path.parent),
            env=env,
        )
    except Exception:
        try:
            os.unlink(obs_path)
        except Exception:
            pass
        return [], []

    # Read observations
    observations_by_func: Dict[str, List[Dict]] = defaultdict(list)
    try:
        with open(obs_path) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        obs = json.loads(line)
                        func = obs.pop("__function__", None)
                        if func:
                            observations_by_func[func].append(obs)
                    except json.JSONDecodeError:
                        pass
    except Exception:
        pass

    try:
        os.unlink(obs_path)
    except Exception:
        pass

    # Infer invariants per function
    all_invariants: List[InferredInvariant] = []
    violations: List[InvariantViolation] = []

    for func_name, observations in observations_by_func.items():
        if len(observations) < 2:
            continue

        # Find the function's line number
        func_line = 0
        try:
            source = file_path.read_text(encoding="utf-8")
            tree = ast.parse(source)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == func_name:
                    func_line = node.lineno
                    break
        except Exception:
            pass

        invariants = infer_invariants_from_observations(
            observations, func_name, rel_path, func_line
        )
        all_invariants.extend(invariants)

        # Check if the function's code would violate its own invariants
        # (e.g., inferred "amount > 0" but function doesn't check it)
        for inv in invariants:
            if inv.invariant_type == "positive" and inv.variable != "return":
                # Check if the function has a guard for this variable
                try:
                    source = file_path.read_text(encoding="utf-8")
                    tree = ast.parse(source)
                    for node in ast.walk(tree):
                        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == func_name:
                            # Look for assertions or checks on this variable
                            has_guard = False
                            for sub in ast.walk(node):
                                if isinstance(sub, ast.Compare):
                                    for comp in sub.comparators:
                                        if isinstance(comp, ast.Name) and comp.id == inv.variable:
                                            has_guard = True
                                if isinstance(sub, ast.Assert):
                                    has_guard = True
                            if not has_guard:
                                violations.append(InvariantViolation(
                                    function=func_name,
                                    invariant=inv.expression,
                                    description=f"{func_name}() is always called with {inv.expression} "
                                                f"(inferred from runtime), but has no guard to enforce it. "
                                                f"A caller could violate this invariant.",
                                    file=rel_path,
                                    line=func_line,
                                ))
                            break
                    break
                except Exception:
                    pass

    return all_invariants, violations
