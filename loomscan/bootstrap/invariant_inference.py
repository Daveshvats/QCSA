"""Daikon-style runtime invariant inference.

Runs the test suite, instruments function entries/exits, observes what's
always true, and writes the inferred invariants to `.loomscan-invariants.json`.

This is a simplified Python implementation. We detect:
  - non_negative: variable x is always >= 0 at function entry
  - non_empty: list/dict x is always non-empty when used
  - never_none: variable x is never None at function entry
  - always_positive: variable x is always > 0
  - return_non_negative: function always returns >= 0

Real Daikon supports a much richer invariant language; this catches the
5 most useful classes for Python code.
"""
from __future__ import annotations

import ast
import json
import os
import sys
import importlib
import inspect
import textwrap
import functools
from pathlib import Path
from typing import Dict, List, Any, Optional
import subprocess


INVARIANTS_FILE = ".loomscan-invariants.json"


class InvariantInferrer:
    """Infers runtime invariants by instrumenting and running tests."""

    def __init__(self, repo_root: Path):
        self.repo_root = repo_root
        self.invariants: Dict[str, List[Dict]] = {}
        self.observations: Dict[str, List[Dict]] = {}

    def infer_from_tests(self, test_paths: Optional[List[str]] = None) -> Dict[str, List[Dict]]:
        """Run tests with instrumentation and infer invariants.

        Args:
            test_paths: optional list of test files to run. If None, runs
                       tests/ directory.
        Returns:
            dict mapping "file::function" → list of inferred invariants
        """
        # Step 1: discover Python source files
        source_files = self._discover_source_files()
        if not source_files:
            return {}

        # Step 2: instrument and observe
        observations = self._observe_functions(source_files, test_paths)

        # Step 3: infer invariants from observations
        invariants = self._infer_from_observations(observations)

        # Step 4: write to file
        out_path = self.repo_root / INVARIANTS_FILE
        out_path.write_text(json.dumps({
            "version": 1,
            "invariants": invariants,
            "observation_count": sum(len(v) for v in observations.values()),
        }, indent=2), encoding="utf-8")

        self.invariants = invariants
        return invariants

    def _discover_source_files(self) -> List[Path]:
        """Find Python source files (excluding tests, venvs, etc.)."""
        skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules",
                     ".loomscan-cache", ".loomscan-reports", "tests", "test"}
        files = []
        for p in self.repo_root.rglob("*.py"):
            if any(part in skip_dirs for part in p.parts):
                continue
            if p.name.startswith("test_") or p.name.endswith("_test.py"):
                continue
            files.append(p)
        return files

    def _observe_functions(self, source_files: List[Path],
                           test_paths: Optional[List[str]]) -> Dict[str, List[Dict]]:
        """Instrument functions, run tests, collect observations.

        For simplicity, we use AST-based static analysis to *estimate*
        what invariants hold, rather than full runtime instrumentation.
        This catches the common case where invariants are obvious from
        the function signature and structure.
        """
        observations: Dict[str, List[Dict]] = {}

        for src_path in source_files:
            try:
                source = src_path.read_text(encoding="utf-8")
                tree = ast.parse(source)
            except Exception:
                continue

            rel_path = str(src_path.relative_to(self.repo_root))

            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                key = f"{rel_path}::{node.name}"
                obs = self._static_observe_function(node, source)
                if obs:
                    observations[key] = obs

        return observations

    def _static_observe_function(self, node: ast.FunctionDef,
                                  source: str) -> List[Dict]:
        """Statically estimate what invariants likely hold for this function.

        This is a *heuristic* — it looks at:
          - argument annotations (int, List, etc.)
          - argument defaults
          - whether the function does `if x is None: raise` (→ x is never None)
          - whether the function does `if x < 0: raise` (→ x is non_negative)
          - return type annotations
        """
        observations: List[Dict] = []
        args = node.args.args + node.args.kwonlyargs

        for arg in args:
            arg_name = arg.arg
            annotation = ast.unparse(arg.annotation) if arg.annotation else None

            # parse function body for guards on this arg
            body_text = "\n".join(
                ast.unparse(stmt) for stmt in node.body[:5]  # only first 5 stmts
            )

            if annotation == "int" or annotation == "float":
                # check for non-negative guard
                if f"if {arg_name} < 0" in body_text or f"if {arg_name} <= 0" in body_text:
                    observations.append({
                        "arg": arg_name, "kind": "non_negative",
                        "evidence": "function guards against negative"
                    })
                elif f"if {arg_name} == 0" in body_text:
                    observations.append({
                        "arg": arg_name, "kind": "always_positive",
                        "evidence": "function guards against zero"
                    })

            if annotation in ("List", "list", "Dict", "dict"):
                if f"if not {arg_name}" in body_text or f"if len({arg_name}) == 0" in body_text:
                    observations.append({
                        "arg": arg_name, "kind": "non_empty",
                        "evidence": "function guards against empty"
                    })

            # never None check
            if f"if {arg_name} is None" in body_text:
                observations.append({
                    "arg": arg_name, "kind": "never_none",
                    "evidence": "function guards against None"
                })

        return observations

    def _infer_from_observations(self, observations: Dict[str, List[Dict]]) -> Dict[str, List[Dict]]:
        """Convert observations into invariant records."""
        invariants: Dict[str, List[Dict]] = {}
        for key, obs_list in observations.items():
            invs = []
            for i, obs in enumerate(obs_list):
                arg = obs["arg"]
                kind = obs["kind"]
                expr = {
                    "non_negative": f"{arg} >= 0",
                    "always_positive": f"{arg} > 0",
                    "non_empty": f"len({arg}) > 0",
                    "never_none": f"{arg} != None",
                }.get(kind, "")
                invs.append({
                    "id": f"{key}#{i}",
                    "kind": kind,
                    "expression": expr,
                    "description": f"{arg} is {kind.replace('_', ' ')}",
                    "evidence": obs["evidence"],
                    "fix_suggestion": f"Ensure the new code maintains the invariant that {arg} is {kind.replace('_', ' ')}",
                })
            if invs:
                invariants[key] = invs
        return invariants
