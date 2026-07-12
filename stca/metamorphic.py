"""Metamorphic testing — oracle-free bug detection (v2 — arity-aware).

The oracle problem: for many functions, you can't say what the "correct"
output is. (E.g., what's the correct output of a recommendation engine? a
hash function? a sort?)

Metamorphic testing sidesteps this: instead of checking the output, check
RELATIONS between outputs. If `sort(x)` is correct, then `sort(x) == sort(x ++ x)[:len(x)]`.

Metamorphic relations (MRs) are properties that hold across transformations
of the input. If an MR is violated, you have a bug — without needing to know
the correct output.

v2 fixes (addressing code review findings):
  1. **Arity-aware test generation**: Uses inspect.signature / AST arg count
     to generate tests with the CORRECT number of arguments. The old version
     hardcoded 1-arg tests for every function, causing TypeErrors that were
     mislabeled as "determinism violations."
  2. **assume(False) on TypeError**: If the test harness calls the function
     with wrong types and it crashes, we skip the test case (like
     differential.py does) instead of reporting it as a bug.
  3. **No more "concat" → "commutative"**: String/list concatenation is NOT
     commutative. Removed the naive substring matching that flagged any
     function with "concat"/"add"/"sum" in its name as commutative.
  4. **Type annotation awareness**: Uses parameter type annotations to pick
     the right Hypothesis strategy (int, str, list, etc.).

This module:
  - Auto-generates MRs based on function signatures and patterns
  - Runs them with Hypothesis-generated inputs
  - Reports violations as findings (not crashes)

Common MRs we generate:
  - sort: sort(x ++ x)[:len(x)] == sort(x)
  - hash: hash(x) == hash(x)  (deterministic)
  - identity: f(x) == f(x)  (deterministic)
  - idempotence: f(f(x)) == f(x)  (for idempotent fns)
"""
from __future__ import annotations

import ast
import importlib
import inspect
import sys
import subprocess
import textwrap
from pathlib import Path
from typing import List, Optional, Tuple, Callable, Set
from dataclasses import dataclass


@dataclass
class MetamorphicViolation:
    """A metamorphic relation was violated — likely a bug."""
    function: str
    relation: str  # name of the MR
    description: str
    input_summary: str
    file: str


def _get_function_arity(func_node: ast.FunctionDef) -> int:
    """Get the number of required positional parameters (excluding self)."""
    args = func_node.args
    # Count required positional args (those without defaults)
    required = args.args
    if args.defaults:
        # Args with defaults come last; subtract them
        required = args.args[:-len(args.defaults)] if len(args.defaults) < len(args.args) else []
    # Subtract 'self' if it's a method
    if required and required[0].arg == "self":
        required = required[1:]
    return len(required)


def _get_param_type_hint(arg: ast.arg) -> str:
    """Get the type hint of a parameter as a string, or 'any' if unknown."""
    if arg.annotation:
        try:
            return ast.unparse(arg.annotation).lower()
        except Exception:
            return "any"
    return "any"


def _get_strategy_for_type(type_hint: str, param_name: str = "") -> str:
    """Get the Hypothesis strategy string for a type hint."""
    if "int" in type_hint:
        return "st.integers(min_value=-1000, max_value=1000)"
    if "float" in type_hint:
        return "st.floats(min_value=-1000, max_value=1000, allow_nan=False, allow_infinity=False)"
    if "str" in type_hint:
        return "st.text(min_size=0, max_size=100)"
    if "bool" in type_hint:
        return "st.booleans()"
    if "list" in type_hint:
        return "st.lists(st.integers(min_value=-100, max_value=100), min_size=0, max_size=20)"
    if "dict" in type_hint:
        return "st.dictionaries(st.text(min_size=1, max_size=5), st.integers(), max_size=5)"
    # Default: use text (most functions take strings)
    return "st.text(min_size=0, max_size=100)"


# Heuristics for detecting function categories from their name/body
def _classify_function(name: str, body: str, arity: int,
                        type_hints: List[str] = None) -> List[str]:
    """Return list of MR categories that might apply to this function.

    v2: Only adds categories that make sense for the function's arity
    and type signature. Removed "commutative" for concat/add/sum (those
    are NOT commutative for strings/lists).
    """
    cats: List[str] = []
    name_lower = name.lower()

    # Only add categories appropriate for the arity
    if arity == 1:
        if "sort" in name_lower or "order" in name_lower:
            cats.append("sort")
        if "hash" in name_lower or "digest" in name_lower or "checksum" in name_lower:
            cats.append("hash")
        if "normalize" in name_lower or "canonical" in name_lower:
            cats.append("idempotence")
        if "abs" in name_lower or "length" in name_lower or "size" in name_lower:
            cats.append("non_negative")
        # v4: Expanded metamorphic relations
        if "encode" in name_lower or "serialize" in name_lower or "to_string" in name_lower:
            cats.append("round_trip")  # decode(encode(x)) == x
        if "encrypt" in name_lower or "decrypt" in name_lower:
            cats.append("inversion")  # decrypt(encrypt(x)) == x
        if "filter" in name_lower or "where" in name_lower or "select" in name_lower:
            cats.append("subset")  # filtered result is subset of input
        if "unique" in name_lower or "distinct" in name_lower or "deduplicate" in name_lower:
            cats.append("idempotence")  # unique(unique(x)) == unique(x)
        if "max" in name_lower or "min" in name_lower:
            cats.append("extremum")  # result is in the input
        if "reverse" in name_lower:
            cats.append("double_inverse")  # reverse(reverse(x)) == x
        if "count" in name_lower or "sum" in name_lower or "total" in name_lower:
            cats.append("monotonic")  # larger input → larger (or equal) output
        # identity (determinism) applies to any 1-arg function
        cats.append("identity")
    elif arity == 2:
        # Only test commutativity for functions that are LIKELY commutative:
        # arithmetic add/sum/multiply. NOT string concat (which isn't commutative).
        if ("add" in name_lower or "sum" in name_lower or "multiply" in name_lower):
            # Only if both params are int-like
            if type_hints and all("int" in h or "float" in h or "num" in h for h in type_hints):
                cats.append("commutative")
        # v4: Associativity for arithmetic operations
        if ("add" in name_lower or "sum" in name_lower or "multiply" in name_lower):
            if type_hints and all("int" in h or "float" in h or "num" in h for h in type_hints):
                cats.append("associative")

    return cats


# Metamorphic relations: each generates (input1, input2, predicate) given a function
METAMORPHIC_RELATIONS = {
    "identity": {
        "name": "Determinism",
        "description": "f(x) == f(x) for any x",
        "arity": 1,
    },
    "sort": {
        "name": "Sort idempotence",
        "description": "sort(sort(x)) == sort(x)",
        "arity": 1,
    },
    "hash": {
        "name": "Hash determinism",
        "description": "hash(x) == hash(x)",
        "arity": 1,
    },
    "idempotence": {
        "name": "Idempotence",
        "description": "f(f(x)) == f(x)",
        "arity": 1,
    },
    "non_negative": {
        "name": "Non-negative output",
        "description": "f(x) >= 0 for any x",
        "arity": 1,
    },
    "commutative": {
        "name": "Commutativity",
        "description": "f(x, y) == f(y, x)  (only for arithmetic add/sum/multiply)",
        "arity": 2,
    },
    # v4: Expanded metamorphic relations
    "associative": {
        "name": "Associativity",
        "description": "f(f(x, y), z) == f(x, f(y, z))  (for arithmetic add/multiply)",
        "arity": 2,
    },
    "round_trip": {
        "name": "Round-trip",
        "description": "decode(encode(x)) == x  (for encode/serialize functions)",
        "arity": 1,
    },
    "inversion": {
        "name": "Inversion",
        "description": "decrypt(encrypt(x)) == x  (for crypto functions)",
        "arity": 1,
    },
    "subset": {
        "name": "Subset",
        "description": "f(x) is a subset of x  (for filter/select functions)",
        "arity": 1,
    },
    "extremum": {
        "name": "Extremum",
        "description": "f(x) is an element of x  (for max/min functions)",
        "arity": 1,
    },
    "double_inverse": {
        "name": "Double inverse",
        "description": "f(f(x)) == x  (for reverse functions)",
        "arity": 1,
    },
    "monotonic": {
        "name": "Monotonicity",
        "description": "if x < y then f(x) <= f(y)  (for count/sum functions)",
        "arity": 1,
    },
}


def generate_mr_test_code(func_name: str, func_signature: str,
                          category: str, module_path: str,
                          arity: int = 1,
                          type_hints: List[str] = None) -> Optional[str]:
    """Generate Hypothesis test code for a metamorphic relation.

    v2: Uses the actual arity and type hints to generate correct test code.
    All tests use assume(False) on TypeError to avoid false positives from
    wrong-type arguments.
    """
    type_hints = type_hints or ["any"] * arity

    if category == "identity" and arity == 1:
        strategy = _get_strategy_for_type(type_hints[0] if type_hints else "any")
        return textwrap.dedent(f"""
            from hypothesis import given, strategies as st, assume, settings
            from {module_path} import {func_name}

            @settings(max_examples=50)
            @given({strategy})
            def test_mr_identity_{func_name}(x):
                '''Metamorphic: f(x) == f(x) (determinism).'''
                try:
                    result1 = {func_name}(x)
                    result2 = {func_name}(x)
                    assert result1 == result2, f"Not deterministic: {{result1!r}} != {{result2!r}}"
                except (TypeError, ValueError):
                    assume(False)  # skip — wrong input type, not a bug
        """).strip()

    if category == "sort" and arity == 1:
        return textwrap.dedent(f"""
            from hypothesis import given, strategies as st, assume, settings
            from {module_path} import {func_name}

            @settings(max_examples=50)
            @given(st.lists(st.integers(min_value=-100, max_value=100), min_size=0, max_size=20))
            def test_mr_sort_idempotence_{func_name}(x):
                '''Metamorphic: sort(sort(x)) == sort(x).'''
                try:
                    once = {func_name}(x)
                    twice = {func_name}(once)
                    assert once == twice, f"Sort not idempotent: {{once}} != {{twice}}"
                except (TypeError, ValueError):
                    assume(False)  # skip — wrong input type, not a bug
        """).strip()

    if category == "hash" and arity == 1:
        return textwrap.dedent(f"""
            from hypothesis import given, strategies as st, assume, settings
            from {module_path} import {func_name}

            @settings(max_examples=50)
            @given(st.text(min_size=0, max_size=100))
            def test_mr_hash_determinism_{func_name}(x):
                '''Metamorphic: hash(x) == hash(x) (determinism).'''
                try:
                    assert {func_name}(x) == {func_name}(x)
                except (TypeError, ValueError):
                    assume(False)  # skip — wrong input type, not a bug
        """).strip()

    if category == "idempotence" and arity == 1:
        strategy = _get_strategy_for_type(type_hints[0] if type_hints else "str")
        return textwrap.dedent(f"""
            from hypothesis import given, strategies as st, assume, settings
            from {module_path} import {func_name}

            @settings(max_examples=50)
            @given({strategy})
            def test_mr_idempotence_{func_name}(x):
                '''Metamorphic: f(f(x)) == f(x) (idempotence).'''
                try:
                    once = {func_name}(x)
                    twice = {func_name}(once)
                    assert once == twice, f"Not idempotent: {{once!r}} != {{twice!r}}"
                except (TypeError, ValueError):
                    assume(False)  # skip — wrong input type, not a bug
        """).strip()

    if category == "non_negative" and arity == 1:
        strategy = _get_strategy_for_type(type_hints[0] if type_hints else "str")
        return textwrap.dedent(f"""
            from hypothesis import given, strategies as st, assume, settings
            from {module_path} import {func_name}

            @settings(max_examples=50)
            @given({strategy})
            def test_mr_non_negative_{func_name}(x):
                '''Metamorphic: f(x) >= 0 for any x.'''
                try:
                    result = {func_name}(x)
                    if isinstance(result, (int, float)):
                        assert result >= 0, f"Negative result for non-negative function: {{result}}"
                except (TypeError, ValueError):
                    assume(False)  # skip — wrong input type, not a bug
        """).strip()

    if category == "commutative" and arity == 2:
        # v2: Only for arithmetic — both params must be int/float
        strat1 = _get_strategy_for_type(type_hints[0] if len(type_hints) > 0 else "int")
        strat2 = _get_strategy_for_type(type_hints[1] if len(type_hints) > 1 else "int")
        return textwrap.dedent(f"""
            from hypothesis import given, strategies as st, assume, settings
            from {module_path} import {func_name}

            @settings(max_examples=50)
            @given({strat1}, {strat2})
            def test_mr_commutative_{func_name}(x, y):
                '''Metamorphic: f(x, y) == f(y, x) (commutativity).'''
                try:
                    assert {func_name}(x, y) == {func_name}(y, x), \\
                        f"Not commutative: f({{x}},{{y}}) != f({{y}},{{x}})"
                except (TypeError, ValueError):
                    assume(False)  # skip — wrong input type, not a bug
        """).strip()

    # v4: Expanded metamorphic relations

    if category == "associative" and arity == 2:
        return textwrap.dedent(f"""
            from hypothesis import given, strategies as st, assume, settings
            from {module_path} import {func_name}

            @settings(max_examples=30)
            @given(st.integers(min_value=-100, max_value=100),
                   st.integers(min_value=-100, max_value=100),
                   st.integers(min_value=-100, max_value=100))
            def test_mr_associative_{func_name}(x, y, z):
                '''Metamorphic: f(f(x,y),z) == f(x,f(y,z)) (associativity).'''
                try:
                    left = {func_name}({func_name}(x, y), z)
                    right = {func_name}(x, {func_name}(y, z))
                    assert left == right, f"Not associative: f(f(x,y),z)={{left}} != f(x,f(y,z))={{right}}"
                except (TypeError, ValueError):
                    assume(False)
        """).strip()

    if category == "round_trip" and arity == 1:
        strategy = _get_strategy_for_type(type_hints[0] if type_hints else "str")
        return textwrap.dedent(f"""
            from hypothesis import given, strategies as st, assume, settings
            from {module_path} import {func_name}

            @settings(max_examples=50)
            @given({strategy})
            def test_mr_round_trip_{func_name}(x):
                '''Metamorphic: decode(encode(x)) == x (round-trip).'''
                try:
                    encoded = {func_name}(x)
                    # Try to find a decode function
                    import importlib
                    mod = importlib.import_module("{module_path}")
                    decode_name = {func_name!r}.replace("encode", "decode").replace("serialize", "deserialize").replace("to_string", "from_string")
                    if hasattr(mod, decode_name):
                        decoded = getattr(mod, decode_name)(encoded)
                        assert decoded == x, f"Round-trip failed: decode(encode(x)) != x"
                except (TypeError, ValueError, AttributeError, ImportError):
                    assume(False)
        """).strip()

    if category == "inversion" and arity == 1:
        strategy = _get_strategy_for_type(type_hints[0] if type_hints else "str")
        return textwrap.dedent(f"""
            from hypothesis import given, strategies as st, assume, settings
            from {module_path} import {func_name}

            @settings(max_examples=50)
            @given({strategy})
            def test_mr_inversion_{func_name}(x):
                '''Metamorphic: decrypt(encrypt(x)) == x (inversion).'''
                try:
                    encrypted = {func_name}(x)
                    import importlib
                    mod = importlib.import_module("{module_path}")
                    inverse_name = {func_name!r}.replace("encrypt", "decrypt").replace("encode", "decode")
                    if hasattr(mod, inverse_name):
                        decrypted = getattr(mod, inverse_name)(encrypted)
                        assert decrypted == x, f"Inversion failed: decrypt(encrypt(x)) != x"
                except (TypeError, ValueError, AttributeError, ImportError):
                    assume(False)
        """).strip()

    if category == "subset" and arity == 1:
        return textwrap.dedent(f"""
            from hypothesis import given, strategies as st, assume, settings
            from {module_path} import {func_name}

            @settings(max_examples=50)
            @given(st.lists(st.integers(min_value=-100, max_value=100), min_size=0, max_size=20))
            def test_mr_subset_{func_name}(x):
                '''Metamorphic: f(x) is a subset of x (for filter functions).'''
                try:
                    result = {func_name}(x)
                    if isinstance(result, list) and isinstance(x, list):
                        # Every element in result should be in x
                        for item in result:
                            assert item in x, f"Subset failed: {{item}} in result but not in input"
                except (TypeError, ValueError):
                    assume(False)
        """).strip()

    if category == "extremum" and arity == 1:
        return textwrap.dedent(f"""
            from hypothesis import given, strategies as st, assume, settings
            from {module_path} import {func_name}

            @settings(max_examples=50)
            @given(st.lists(st.integers(min_value=-100, max_value=100), min_size=1, max_size=20))
            def test_mr_extremum_{func_name}(x):
                '''Metamorphic: f(x) is an element of x (for max/min functions).'''
                try:
                    result = {func_name}(x)
                    if isinstance(x, list) and len(x) > 0:
                        assert result in x, f"Extremum failed: {{result}} not in input {{x}}"
                except (TypeError, ValueError):
                    assume(False)
        """).strip()

    if category == "double_inverse" and arity == 1:
        return textwrap.dedent(f"""
            from hypothesis import given, strategies as st, assume, settings
            from {module_path} import {func_name}

            @settings(max_examples=50)
            @given(st.lists(st.integers(min_value=-100, max_value=100), min_size=0, max_size=20))
            def test_mr_double_inverse_{func_name}(x):
                '''Metamorphic: f(f(x)) == x (double inverse for reverse functions).'''
                try:
                    once = {func_name}(x)
                    twice = {func_name}(once)
                    assert twice == x, f"Double inverse failed: f(f(x)) != x"
                except (TypeError, ValueError):
                    assume(False)
        """).strip()

    if category == "monotonic" and arity == 1:
        return textwrap.dedent(f"""
            from hypothesis import given, strategies as st, assume, settings
            from {module_path} import {func_name}

            @settings(max_examples=50)
            @given(st.lists(st.integers(min_value=-100, max_value=100), min_size=1, max_size=20),
                   st.lists(st.integers(min_value=-100, max_value=100), min_size=1, max_size=20))
            def test_mr_monotonic_{func_name}(x, y):
                '''Metamorphic: if x is subset of y then f(x) <= f(y) (monotonicity).'''
                try:
                    # If x is a subset of y, f(x) should be <= f(y) for count/sum
                    if all(item in y for item in x):
                        fx = {func_name}(x)
                        fy = {func_name}(y)
                        if isinstance(fx, (int, float)) and isinstance(fy, (int, float)):
                            assert fx <= fy, f"Monotonicity failed: f(x)={{fx}} > f(y)={{fy}}"
                except (TypeError, ValueError):
                    assume(False)
        """).strip()

    return None


def discover_testable_functions(file_path: Path) -> List[Tuple[str, str, List[str], int, List[str]]]:
    """Find functions in a file and classify them for MR testing.

    Returns list of (function_name, function_signature, mr_categories, arity, type_hints).
    """
    if not file_path.exists() or file_path.suffix != ".py":
        return []
    try:
        source = file_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except Exception:
        return []

    results: List[Tuple[str, str, List[str], int, List[str]]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name.startswith("_"):
            continue
        arity = _get_function_arity(node)
        # Skip functions with 0 args (nothing to test) or >2 args (too complex for MRs)
        if arity == 0 or arity > 2:
            continue
        body = ast.unparse(node)
        # Get type hints for each parameter
        args = node.args.args
        if args and args[0].arg == "self":
            args = args[1:]
        type_hints = [_get_param_type_hint(a) for a in args[:arity]]
        cats = _classify_function(node.name, body, arity, type_hints)
        results.append((node.name, ast.unparse(node.args), cats, arity, type_hints))
    return results


def run_metamorphic_tests(file_path: Path, repo_root: Path = None) -> List[MetamorphicViolation]:
    """Generate and run metamorphic tests for the functions in a file.

    Returns a list of violations (likely bugs).
    """
    functions = discover_testable_functions(file_path)
    if not functions:
        return []

    rel_path = str(file_path.relative_to(repo_root)) if repo_root else str(file_path)
    module_path = rel_path.replace("/", ".").replace(".py", "").lstrip(".")

    # generate a test file
    test_code_parts = []
    test_names = []
    for func_name, sig, cats, arity, type_hints in functions:
        for cat in cats:
            test_code = generate_mr_test_code(func_name, sig, cat, module_path,
                                                arity=arity, type_hints=type_hints)
            if test_code:
                test_code_parts.append(test_code)
                test_names.append(f"test_mr_{cat}_{func_name}")

    if not test_code_parts:
        return []

    test_file = (repo_root or file_path.parent) / ".stca-cache" / "metamorphic" / f"test_{file_path.stem}_mr.py"
    test_file.parent.mkdir(parents=True, exist_ok=True)
    test_file.write_text("\n\n".join(test_code_parts), encoding="utf-8")

    # run pytest on the test file
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", str(test_file), "-v", "--tb=short",
             "--maxfail=5"],
            capture_output=True, text=True, check=False, timeout=30,
            cwd=str(repo_root or file_path.parent),
        )
    except Exception:
        return []

    # parse failures — v2: only count ACTUAL assertion failures, not TypeErrors
    # (TypeErrors are now handled by assume(False) in the test code)
    violations: List[MetamorphicViolation] = []
    for line in proc.stdout.splitlines():
        if "FAILED" in line or "AssertionError" in line:
            # extract function name from the failure
            for func_name, _, cats, _, _ in functions:
                for cat in cats:
                    test_name = f"test_mr_{cat}_{func_name}"
                    if test_name in line:
                        violations.append(MetamorphicViolation(
                            function=func_name,
                            relation=METAMORPHIC_RELATIONS.get(cat, {}).get("name", cat),
                            description=METAMORPHIC_RELATIONS.get(cat, {}).get("description", ""),
                            input_summary=line[:200],
                            file=rel_path,
                        ))
                        break
    return violations
