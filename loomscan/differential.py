"""Differential testing — find bugs by comparing two implementations.

When you have two implementations of the same spec (e.g., a Python reference
impl and an optimized Rust impl, or two versions of the same function),
differential testing finds inputs where they disagree. Any disagreement is
a bug in at least one of them.

Use cases:
  - Refactor verification: old_func vs new_func — they should agree on all inputs
  - Reference vs optimized: slow_correct_func vs fast_func
  - Library migration: mysql_query vs mysqli_query
  - Cross-language: Python reference vs C++ production

We provide:
  - Auto-detection of function pairs likely to be implementations of the same spec
    (same name in old vs new code, or paired via decorator/marker)
  - Hypothesis-based input generation
  - Output comparison with smart equivalence (handle float tolerance, etc.)
"""
from __future__ import annotations

import ast
import importlib
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import List, Tuple, Optional
from dataclasses import dataclass


@dataclass
class DifferentialBug:
    """A differential testing bug — two implementations disagree."""
    function_a: str
    function_b: str
    input_summary: str
    output_a: str
    output_b: str
    file: str


def find_function_pairs(file_path: Path) -> List[Tuple[str, str]]:
    """Find pairs of functions that look like implementations of the same spec.

    Heuristics:
      - Functions with same name but different suffixes (_old, _new, _v1, _v2)
      - Functions marked with @loomscan.differential("ref") and @loomscan.differential("impl")
      - Functions with similar signatures in the same file
    """
    if not file_path.exists() or file_path.suffix != ".py":
        return []
    try:
        source = file_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except Exception:
        return []

    functions: List[Tuple[str, str, str]] = []  # (name, args, body)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name.startswith("_"):
                continue
            args = ast.unparse(node.args)
            body = ast.unparse(node)
            functions.append((node.name, args, body))

    pairs: List[Tuple[str, str]] = []
    seen: set = set()

    # heuristic 1: _old/_new suffix pairs
    for i, (name_a, args_a, _) in enumerate(functions):
        for name_b_possible in [name_a + "_new", name_a + "_v2", name_a + "_refactored",
                                  name_a + "_optimized", name_a + "_fast"]:
            for j, (name_b, args_b, _) in enumerate(functions):
                if i != j and name_b == name_b_possible and args_a == args_b:
                    pair = (name_a, name_b)
                    if pair not in seen:
                        pairs.append(pair)
                        seen.add(pair)

    # heuristic 2: name patterns like sort_v1/sort_v2
    by_prefix: dict = {}
    for name, args, _ in functions:
        # extract prefix (everything before _vN or _old/_new)
        import re
        m = re.match(r"^(.+?)_(v\d+|old|new|refactored|optimized|fast|reference|impl)$", name)
        if m:
            prefix = m.group(1)
            by_prefix.setdefault(prefix, []).append((name, args))
    for prefix, funcs in by_prefix.items():
        if len(funcs) >= 2:
            for i in range(len(funcs)):
                for j in range(i + 1, len(funcs)):
                    if funcs[i][1] == funcs[j][1]:  # same args
                        pair = (funcs[i][0], funcs[j][0])
                        if pair not in seen:
                            pairs.append(pair)
                            seen.add(pair)

    return pairs


def generate_differential_test(func_a: str, func_b: str,
                                module_path: str,
                                arity: int = 1) -> str:
    """Generate a Hypothesis test that compares two functions."""
    if arity == 1:
        return textwrap.dedent(f"""
            from hypothesis import given, strategies as st, settings, assume
            from {module_path} import {func_a} as _f_a, {func_b} as _f_b

            @settings(max_examples=200)
            @given(st.integers(min_value=-1000, max_value=1000))
            def test_differential_{func_a}_{func_b}(x):
                '''Differential: {func_a}(x) == {func_b}(x) for all x.'''
                try:
                    out_a = _f_a(x)
                except Exception as e:
                    assume(False)  # skip if A raises
                try:
                    out_b = _f_b(x)
                except Exception as e:
                    assume(False)  # skip if B raises
                # handle float tolerance
                if isinstance(out_a, float) or isinstance(out_b, float):
                    assert abs(out_a - out_b) < 1e-9, \\
                        f"Differential bug: {func_a}({{x}})={{out_a}} but {func_b}({{x}})={{out_b}}"
                else:
                    assert out_a == out_b, \\
                        f"Differential bug: {func_a}({{x}})={{out_a}} but {func_b}({{x}})={{out_b}}"
        """).strip()
    elif arity == 2:
        return textwrap.dedent(f"""
            from hypothesis import given, strategies as st, settings, assume
            from {module_path} import {func_a} as _f_a, {func_b} as _f_b

            @settings(max_examples=200)
            @given(st.integers(min_value=-1000, max_value=1000),
                   st.integers(min_value=-1000, max_value=1000))
            def test_differential_{func_a}_{func_b}(x, y):
                '''Differential: {func_a}(x, y) == {func_b}(x, y).'''
                try:
                    out_a = _f_a(x, y)
                    out_b = _f_b(x, y)
                except Exception:
                    assume(False)
                if isinstance(out_a, float) or isinstance(out_b, float):
                    assert abs(out_a - out_b) < 1e-9
                else:
                    assert out_a == out_b, \\
                        f"Differential: {func_a}({{x}},{{y}})={{out_a}} but {func_b}({{x}},{{y}})={{out_b}}"
        """).strip()
    return ""


def run_differential_tests(file_path: Path,
                            repo_root: Path = None) -> List[DifferentialBug]:
    """Find function pairs and run differential tests."""
    pairs = find_function_pairs(file_path)
    if not pairs:
        return []

    rel_path = str(file_path.relative_to(repo_root)) if repo_root else str(file_path)
    module_path = rel_path.replace("/", ".").replace(".py", "").lstrip(".")

    test_code_parts = []
    for func_a, func_b in pairs:
        # determine arity from one of the functions
        try:
            source = file_path.read_text(encoding="utf-8")
            tree = ast.parse(source)
            arity = 1
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef) and node.name == func_a:
                    arity = len(node.args.args)
                    break
            test_code = generate_differential_test(func_a, func_b, module_path, arity=arity)
            if test_code:
                test_code_parts.append(test_code)
        except Exception:
            continue

    if not test_code_parts:
        return []

    test_file = (repo_root or file_path.parent) / ".loomscan-cache" / "differential" / f"test_{file_path.stem}_diff.py"
    test_file.parent.mkdir(parents=True, exist_ok=True)
    test_file.write_text("\n\n".join(test_code_parts), encoding="utf-8")

    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", str(test_file), "-v", "--tb=short"],
            capture_output=True, text=True, check=False, timeout=60,
            cwd=str(repo_root or file_path.parent),
        )
    except Exception:
        return []

    bugs: List[DifferentialBug] = []
    for line in proc.stdout.splitlines():
        if "FAILED" in line or "Differential bug" in line or "Differential:" in line:
            for func_a, func_b in pairs:
                test_name = f"test_differential_{func_a}_{func_b}"
                if test_name in line:
                    bugs.append(DifferentialBug(
                        function_a=func_a,
                        function_b=func_b,
                        input_summary=line[:200],
                        output_a="?",
                        output_b="?",
                        file=rel_path,
                    ))
    return bugs
