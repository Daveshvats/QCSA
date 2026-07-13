"""Runtime dead code analysis — inspired by naver/scavenger.

scavenger instruments Java code at runtime to find methods that are NEVER
called during execution. This is more accurate than static dead code
detection because it accounts for:
  - Reflection (static analysis can't see reflective calls)
  - Dynamic dispatch
  - Runtime configuration

We implement a Python version:
  1. Instrument every function with a decorator that records execution
  2. Run the test suite (or any entry point)
  3. Report functions that were never called = dead code

This catches:
  - Functions that exist but no test or code path reaches them
  - Legacy code that's still imported but never called
  - Abstraction layers where half the methods are unused

Usage:
  loomscan deadcode instrument   # add instrumentation to all functions
  loomscan deadcode run pytest   # run tests with instrumentation
  loomscan deadcode report       # show functions that were never called
  loomscan deadcode cleanup      # remove instrumentation
"""
from __future__ import annotations

import ast
import json
import os
import textwrap
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set, Optional


DEADCODE_TRACE_FILE = ".loomscan-deadcode-trace.json"
DEADCODE_REPORT_FILE = ".loomscan-deadcode-report.json"


@dataclass
class FunctionInfo:
    """Info about a function for dead code tracking."""
    name: str
    file: str
    line: int
    module: str
    is_method: bool = False
    class_name: str = ""
    called: bool = False
    call_count: int = 0


class DeadCodeAnalyzer:
    """Runtime dead code analyzer."""

    def __init__(self, repo_root: Path):
        self.repo_root = repo_root
        self.functions: Dict[str, FunctionInfo] = {}
        self.trace_file = repo_root / DEADCODE_TRACE_FILE

    def discover_functions(self, max_files: int = 200) -> int:
        """Discover all functions in the repo by walking ASTs."""
        skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules",
                     ".loomscan-cache", ".loomscan-reports", ".loomscan-fixes", "tests", "test"}
        count = 0

        for p in self.repo_root.rglob("*.py"):
            if any(part in skip_dirs for part in p.parts):
                continue
            if p.name.startswith("test_") or p.name.endswith("_test.py"):
                continue
            try:
                source = p.read_text(encoding="utf-8")
                tree = ast.parse(source)
            except Exception:
                continue

            rel = str(p.relative_to(self.repo_root))
            module = rel.replace("/", ".").replace(".py", "").lstrip(".")

            current_class = ""
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    current_class = node.name
                elif isinstance(node, ast.ClassDef):
                    current_class = ""
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if node.name.startswith("_") and node.name != "__init__":
                        continue  # skip private
                    func_id = f"{rel}:{node.lineno}:{node.name}"
                    self.functions[func_id] = FunctionInfo(
                        name=node.name,
                        file=rel,
                        line=node.lineno,
                        module=module,
                        is_method=bool(current_class),
                        class_name=current_class,
                    )

            count += 1
            if count >= max_files:
                break

        return len(self.functions)

    def load_trace(self) -> None:
        """Load the execution trace from the trace file."""
        if not self.trace_file.exists():
            return
        try:
            data = json.loads(self.trace_file.read_text(encoding="utf-8"))
            called_funcs = set(data.get("called", []))
            for func_id in self.functions:
                if func_id in called_funcs:
                    self.functions[func_id].called = True
                    self.functions[func_id].call_count = data.get("counts", {}).get(func_id, 1)
        except Exception:
            pass

    def get_dead_code(self) -> List[FunctionInfo]:
        """Return functions that were never called."""
        return [f for f in self.functions.values() if not f.called]

    def get_live_code(self) -> List[FunctionInfo]:
        """Return functions that were called at least once."""
        return [f for f in self.functions.values() if f.called]

    def generate_report(self) -> dict:
        """Generate a dead code report."""
        dead = self.get_dead_code()
        live = self.get_live_code()
        return {
            "total_functions": len(self.functions),
            "live_functions": len(live),
            "dead_functions": len(dead),
            "dead_percentage": len(dead) / len(self.functions) * 100 if self.functions else 0,
            "dead_by_file": self._group_by_file(dead),
            "dead_by_module": self._group_by_module(dead),
            "generated_at": datetime.now().isoformat(),
        }

    def _group_by_file(self, funcs: List[FunctionInfo]) -> Dict[str, int]:
        from collections import Counter
        return dict(Counter(f.file for f in funcs))

    def _group_by_module(self, funcs: List[FunctionInfo]) -> Dict[str, int]:
        from collections import Counter
        return dict(Counter(f.module for f in funcs))

    def save_report(self) -> Path:
        """Save the report to a file."""
        report_path = self.repo_root / DEADCODE_REPORT_FILE
        report = self.generate_report()
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        return report_path

    def generate_instrumentation_snippet(self, func_id: str) -> str:
        """Generate instrumentation code for a function.

        This is the code that gets inserted to record execution.
        """
        func = self.functions.get(func_id)
        if not func:
            return ""
        return textwrap.dedent(f"""
            # LoomScan dead-code instrumentation for {func.name}
            import json as _loomscan_json
            import os as _loomscan_os
            _STCA_TRACE = _loomscan_os.path.join(_loomscan_os.path.dirname(__file__), "..", "{DEADCODE_TRACE_FILE}")
            try:
                _loomscan_data = _loomscan_json.loads(open(_STCA_TRACE).read()) if _loomscan_os.path.exists(_STCA_TRACE) else {{"called": [], "counts": {{}}}}
            except Exception:
                _loomscan_data = {{"called": [], "counts": {{}}}}
            _loomscan_fid = "{func_id}"
            if _loomscan_fid not in _loomscan_data["called"]:
                _loomscan_data["called"].append(_loomscan_fid)
            _loomscan_data["counts"][_loomscan_fid] = _loomscan_data["counts"].get(_loomscan_fid, 0) + 1
            try:
                with open(_STCA_TRACE, "w") as _loomscan_f:
                    _loomscan_json.dump(_loomscan_data, _loomscan_f)
            except Exception:
                pass
        """).strip()

    def stats(self) -> dict:
        """Return quick stats."""
        return {
            "total_discovered": len(self.functions),
            "dead": len(self.get_dead_code()),
            "live": len(self.get_live_code()),
            "trace_file": str(self.trace_file),
            "trace_exists": self.trace_file.exists(),
        }
