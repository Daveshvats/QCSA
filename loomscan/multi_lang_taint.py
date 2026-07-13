from __future__ import annotations

import ast
import re
import os
import json
import subprocess
import sys
import textwrap
import tempfile
import logging
from pathlib import Path
from typing import List, Optional, Dict, Any, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict

try:
    from .normalized_ast import parse_file, get_language, is_supported, NormalizedNode, _HAS_TS, _TS_LANGUAGE_MODULES
except ImportError:
    _HAS_TS = False
    _TS_LANGUAGE_MODULES = {}

_v4_logger = logging.getLogger("loomscan.v4_restored")
from .v4_types import UnifiedFinding

def detect_cpg_taint_multi(file_path: Path) -> List[UnifiedFinding]:
    """CPG-style taint tracking for any language using normalized AST.

    Builds a simplified per-function dataflow graph:
    1. Find sources (req.params, request.getParameter, etc.)
    2. Track variable assignments (propagation)
    3. Find sinks (eval, executeQuery, innerHTML, exec, etc.)
    4. BFS from sources to sinks
    """
    if not _HAS_TS:
        return _cpg_taint_py_fallback(file_path)

    tree = parse_file(file_path)
    if tree is None:
        return []

    lang = tree.language
    findings: List[UnifiedFinding] = []

    source_patterns = {
        "python": ("req", "request", "input", "args", "form", "cookies", "session"),
        "javascript": ("req.params", "req.query", "req.body", "req.headers", "location.hash", "location.search", "document.URL", "event.data"),
        "typescript": ("req.params", "req.query", "req.body", "req.headers", "location.hash", "location.search"),
        "go": ("r.URL.Query", "r.FormValue", "r.Header.Get", "r.Form", "os.Args"),
        "java": ("request.getParameter", "request.getHeader", "request.getParameterValues", "@RequestParam", "@RequestBody", "@PathVariable"),
        "c": ("argv", "getenv", "fgets", "scanf", "gets"),
        "cpp": ("argv", "getenv", "cin", "getline", "scanf"),
        "rust": ("env::args", "io::stdin", "read_line"),
    }

    sink_patterns = {
        "python": {"eval": ("CWE-95", "critical"), "exec": ("CWE-95", "critical"), "execute": ("CWE-89", "critical"), "system": ("CWE-78", "critical"), "popen": ("CWE-78", "high")},
        "javascript": {"eval": ("CWE-95", "critical"), "Function": ("CWE-95", "critical"), "query": ("CWE-89", "critical"), "exec": ("CWE-78", "critical"), "innerHTML": ("CWE-79", "high"), "write": ("CWE-79", "high")},
        "typescript": {"eval": ("CWE-95", "critical"), "Function": ("CWE-95", "critical"), "query": ("CWE-89", "critical"), "exec": ("CWE-78", "critical")},
        "go": {"Exec": ("CWE-78", "critical"), "Query": ("CWE-89", "critical"), "QueryRow": ("CWE-89", "critical"), "Open": ("CWE-22", "high"), "ReadFile": ("CWE-22", "high")},
        "java": {"executeQuery": ("CWE-89", "critical"), "executeUpdate": ("CWE-89", "critical"), "exec": ("CWE-78", "critical"), "sendRedirect": ("CWE-601", "high"), "readObject": ("CWE-502", "critical")},
        "c": {"system": ("CWE-78", "critical"), "popen": ("CWE-78", "critical"), "sprintf": ("CWE-120", "high"), "strcpy": ("CWE-120", "high"), "strcat": ("CWE-120", "high"), "gets": ("CWE-242", "critical")},
        "cpp": {"system": ("CWE-78", "critical"), "exec": ("CWE-78", "critical"), "sprintf": ("CWE-120", "high")},
        "rust": {"exec": ("CWE-78", "critical"), "Command::new": ("CWE-78", "high")},
    }

    sources = source_patterns.get(lang, ())
    sinks = sink_patterns.get(lang, {})

    if not sources or not sinks:
        return []

    for func in tree.find_function_defs():
        tainted: Set[str] = set()
        tainted_sources: Dict[str, str] = {}

        for node in func.walk():
            if node.kind == "assignment" and node.target:
                for src in sources:
                    if src in (node.text or ""):
                        tainted.add(node.target)
                        tainted_sources[node.target] = src
                        break

            if node.kind == "assignment" and node.target:
                for tvar in list(tainted):
                    if tvar in (node.text or "") and node.target != tvar:
                        tainted.add(node.target)
                        tainted_sources[node.target] = tainted_sources.get(tvar, tvar)
                        break

            if node.kind == "call" and node.name in sinks:
                cwe, severity = sinks[node.name]
                for arg in node.args:
                    if arg in tainted:
                        findings.append(UnifiedFinding(
                            rule_id=f"CPG.TAINT-FLOW-{node.name.upper()}",
                            severity=severity,
                            description=f"Taint flow: {tainted_sources.get(arg, arg)} -> {node.name}() "
                                        f"(variable '{arg}') - unsanitized user input reaches dangerous sink",
                            file=tree.file, line=node.line, function=func.name,
                            language=lang, category="taint_flow", cwe=cwe,
                            suggestion=f"Sanitize '{arg}' before passing to {node.name}()"))
                        break

            if node.kind == "attribute" and node.attr in sinks:
                cwe, severity = sinks[node.attr]
                if node.obj in tainted:
                    findings.append(UnifiedFinding(
                        rule_id=f"CPG.TAINT-FLOW-{node.attr.upper()}",
                        severity=severity,
                        description=f"Taint flow: {tainted_sources.get(node.obj, node.obj)} -> .{node.attr} "
                                    f"(variable '{node.obj}') - unsanitized input reaches sink",
                        file=tree.file, line=node.line, function=func.name,
                        language=lang, category="taint_flow", cwe=cwe,
                        suggestion=f"Sanitize '{node.obj}' before assigning to .{node.attr}"))

    return findings


def _cpg_taint_py_fallback(file_path: Path) -> List[UnifiedFinding]:
    """Python fallback for CPG taint (uses ast module)."""
    if file_path.suffix != ".py":
        return []
    try:
        source = file_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except Exception:
        return []

    findings: List[UnifiedFinding] = []
    py_sources = ("req", "request", "input", "args", "form", "cookies", "session", "user_id", "userid", "query", "body", "params")
    py_sinks = {"eval": ("CWE-95", "critical"), "exec": ("CWE-95", "critical"), "execute": ("CWE-89", "critical"),
                "system": ("CWE-78", "critical"), "popen": ("CWE-78", "high"), "innerHTML": ("CWE-79", "high")}

    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        tainted: Set[str] = set()
        tainted_sources: Dict[str, str] = {}

        for node in ast.walk(func):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        val_str = ""
                        try:
                            val_str = ast.unparse(node.value)
                        except Exception:
                            pass
                        for src in py_sources:
                            if src in val_str.lower():
                                tainted.add(target.id)
                                tainted_sources[target.id] = src
                                break
                        for tvar in list(tainted):
                            if tvar in val_str and target.id != tvar:
                                tainted.add(target.id)
                                tainted_sources[target.id] = tainted_sources.get(tvar, tvar)
                                break
            if isinstance(node, ast.Call):
                call_name = ""
                if isinstance(node.func, ast.Name):
                    call_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    call_name = node.func.attr
                if call_name in py_sinks:
                    cwe, sev = py_sinks[call_name]
                    for arg in node.args:
                        if isinstance(arg, ast.Name) and arg.id in tainted:
                            findings.append(UnifiedFinding(
                                rule_id=f"CPG.TAINT-FLOW-{call_name.upper()}",
                                severity=sev,
                                description=f"Taint flow: {tainted_sources.get(arg.id, arg.id)} -> {call_name}() (variable '{arg.id}')",
                                file=str(file_path), line=node.lineno, function=func.name,
                                language="python", category="taint_flow", cwe=cwe))
                            break

    return findings


