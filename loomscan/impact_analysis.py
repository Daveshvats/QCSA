"""Impact analysis — inspired by gossiphs (gossip graphs).

gossiphs analyzes commit history and variable declaration/reference
relationships to build a code relationship graph. When you change a function,
it tells you what else might be affected.

We implement a simplified version:
  1. Build a call graph (who calls whom) from AST
  2. For changed functions in the diff, compute the blast radius:
     - Direct callers (functions that call the changed function)
     - Transitive callers (callers of callers, up to N hops)
     - Test files that test the changed function
  3. Flag findings in the blast radius as higher risk

This helps answer: "If I change this function, what tests should I run?
What other modules might break?"
"""
from __future__ import annotations

import ast
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Set, Tuple


@dataclass
class ImpactNode:
    """A node in the impact graph."""
    function: str
    file: str
    line: int
    is_changed: bool = False  # is this in the diff?


@dataclass
class ImpactResult:
    """Result of impact analysis for a changed function."""
    changed_function: str
    changed_file: str
    changed_line: int
    direct_callers: List[ImpactNode] = field(default_factory=list)
    transitive_callers: List[ImpactNode] = field(default_factory=list)
    test_files: List[str] = field(default_factory=list)
    blast_radius: int = 0  # total affected functions
    risk_level: str = "low"  # low, medium, high


class ImpactAnalyzer:
    """Analyzes the impact of code changes."""

    def __init__(self, repo_root: Path):
        self.repo_root = repo_root
        self.call_graph: Dict[str, Set[str]] = defaultdict(set)  # caller → callees
        self.reverse_call_graph: Dict[str, Set[str]] = defaultdict(set)  # callee → callers
        self.function_locations: Dict[str, ImpactNode] = {}  # func_id → node

    def build_call_graph(self, max_files: int = 100) -> int:
        """Build the call graph from AST analysis."""
        skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules",
                     ".loomscan-cache", ".loomscan-reports", ".loomscan-fixes", "build", "dist"}
        count = 0

        for p in self.repo_root.rglob("*.py"):
            if any(part in skip_dirs for part in p.parts):
                continue
            try:
                source = p.read_text(encoding="utf-8")
                tree = ast.parse(source)
            except Exception:
                continue

            rel = str(p.relative_to(self.repo_root))
            module = rel.replace("/", ".").replace(".py", "").lstrip(".")

            # find all function definitions and their calls
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    func_name = node.name
                    func_id = f"{rel}:{node.lineno}:{func_name}"
                    self.function_locations[func_id] = ImpactNode(
                        function=func_name, file=rel, line=node.lineno,
                    )
                    # find calls within this function
                    for child in ast.walk(node):
                        if isinstance(child, ast.Call):
                            callee = self._get_call_name(child.func)
                            if callee:
                                callee_id = self._resolve_callee(callee, rel)
                                if callee_id:
                                    self.call_graph[func_id].add(callee_id)
                                    self.reverse_call_graph[callee_id].add(func_id)

            count += 1
            if count >= max_files:
                break

        return len(self.function_locations)

    def _get_call_name(self, func: ast.AST) -> str:
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            return func.attr
        return ""

    def _resolve_callee(self, callee_name: str, current_file: str) -> str:
        """Resolve a callee name to a function ID."""
        # find functions with this name
        candidates = [
            fid for fid, node in self.function_locations.items()
            if node.function == callee_name
        ]
        if not candidates:
            return ""
        # prefer same file
        same_file = [c for c in candidates if c.startswith(current_file)]
        if same_file:
            return same_file[0]
        return candidates[0]  # first match

    def analyze_impact(self, changed_functions: List[Tuple[str, int, int]],
                       max_depth: int = 3) -> List[ImpactResult]:
        """Analyze the impact of changed functions.

        Args:
            changed_functions: list of (function_name, line, file) tuples
            max_depth: how many hops to trace transitive callers

        Returns:
            List of ImpactResult, one per changed function.
        """
        results: List[ImpactResult] = []

        for func_name, func_line, func_file in changed_functions:
            # find the function ID
            func_id = self._find_function_id(func_name, func_line, func_file)
            if not func_id:
                continue

            # mark as changed
            if func_id in self.function_locations:
                self.function_locations[func_id].is_changed = True

            # find direct callers
            direct_callers = self.reverse_call_graph.get(func_id, set())
            direct_nodes = [
                self.function_locations.get(caller)
                for caller in direct_callers
                if caller in self.function_locations
            ]
            direct_nodes = [n for n in direct_nodes if n]

            # BFS for transitive callers
            visited: Set[str] = {func_id}
            transitive: List[ImpactNode] = []
            queue = deque([(func_id, 0)])
            while queue:
                current_id, depth = queue.popleft()
                if depth >= max_depth:
                    continue
                callers = self.reverse_call_graph.get(current_id, set())
                for caller_id in callers:
                    if caller_id not in visited:
                        visited.add(caller_id)
                        node = self.function_locations.get(caller_id)
                        if node and node not in direct_nodes:
                            transitive.append(node)
                        queue.append((caller_id, depth + 1))

            # find test files that might test this function
            test_files = self._find_test_files(func_name, func_file)

            blast_radius = len(direct_nodes) + len(transitive) + len(test_files)
            risk = "high" if blast_radius > 10 else "medium" if blast_radius > 3 else "low"

            results.append(ImpactResult(
                changed_function=func_name,
                changed_file=func_file,
                changed_line=func_line,
                direct_callers=direct_nodes,
                transitive_callers=transitive,
                test_files=test_files,
                blast_radius=blast_radius,
                risk_level=risk,
            ))

        return results

    def _find_function_id(self, func_name: str, line: int, file: str) -> str:
        """Find a function ID by name, file, and approximate line."""
        for fid, node in self.function_locations.items():
            if node.function == func_name and node.file == file:
                if abs(node.line - line) < 20:  # within 20 lines
                    return fid
        # fallback: just match by name + file
        for fid, node in self.function_locations.items():
            if node.function == func_name and node.file == file:
                return fid
        return ""

    def _find_test_files(self, func_name: str, func_file: str) -> List[str]:
        """Find test files that might test this function."""
        skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules"}
        test_files: List[str] = []
        for p in self.repo_root.rglob("test_*.py"):
            if any(part in skip_dirs for part in p.parts):
                continue
            try:
                content = p.read_text(encoding="utf-8")
            except Exception:
                continue
            if func_name in content:
                test_files.append(str(p.relative_to(self.repo_root)))
        for p in self.repo_root.rglob("*_test.py"):
            if any(part in skip_dirs for part in p.parts):
                continue
            try:
                content = p.read_text(encoding="utf-8")
            except Exception:
                continue
            if func_name in content:
                test_files.append(str(p.relative_to(self.repo_root)))
        return list(set(test_files))  # dedupe

    def stats(self) -> dict:
        return {
            "total_functions": len(self.function_locations),
            "total_edges": sum(len(v) for v in self.call_graph.values()),
            "avg_callers_per_function": (
                sum(len(v) for v in self.reverse_call_graph.values()) /
                max(len(self.function_locations), 1)
            ),
        }
