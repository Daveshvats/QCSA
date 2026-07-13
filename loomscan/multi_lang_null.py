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
from .semantic_bl import NULL_VALUES

def detect_null_dereference_multi(file_path: Path) -> List[UnifiedFinding]:
    if not _HAS_TS:
        # Fallback: use Python ast for .py files
        if file_path.suffix != ".py": return []
        return _detect_null_py(file_path)
    tree = parse_file(file_path)
    if tree is None: return []
    return _detect_null_normalized(tree)

def _detect_null_normalized(tree: NormalizedNode) -> List[UnifiedFinding]:
    findings = []
    lang = tree.language
    null_vals = NULL_VALUES.get(lang, ("null",))
    for func in tree.find_function_defs():
        possibly_null: Set[str] = set()
        for node in func.walk():
            if node.kind == "assignment" and node.target and hasattr(node, "text") and node.text:
                text = node.text.lower()
                for p in null_vals:
                    if p.lower() in text: possibly_null.add(node.target)
                for p in ("= get(", "= find(", "= search(", "= match(", "= first(", "= last("):
                    if p in text: possibly_null.add(node.target)
            if node.kind == "attribute" and node.obj:
                if node.obj in possibly_null:
                    findings.append(UnifiedFinding(
                        rule_id="NULL.DEREF", severity="high",
                        description=f"'{node.obj}' may be null and is dereferenced via '.{node.attr}'",
                        file=tree.file, line=node.line, function=func.name, language=lang,
                        category="nullness", cwe="CWE-476", evidence=node.obj))
    return findings

def _detect_null_py(file_path: Path) -> List[UnifiedFinding]:
    try:
        source = file_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except Exception:
        return []
    findings = []
    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)): continue
        possibly_null = set()
        for node in ast.walk(func):
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        if isinstance(node.value, ast.Constant) and node.value.value is None:
                            possibly_null.add(t.id)
                        elif isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name):
                            if node.value.func.id not in ("len", "abs", "min", "max", "sum", "round", "int", "float", "str", "bool", "list", "dict", "set", "tuple", "range", "enumerate", "sorted", "reversed", "type", "id", "hash", "isinstance", "open"):
                                possibly_null.add(t.id)
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                if node.value.id in possibly_null:
                    findings.append(UnifiedFinding(
                        rule_id="NULL.DEREF", severity="high",
                        description=f"'{node.value.id}' may be None and dereferenced via '.{node.attr}'",
                        file=str(file_path), line=node.lineno, function=func.name, language="python",
                        category="nullness", cwe="CWE-476"))
            if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name):
                if node.value.id in possibly_null:
                    findings.append(UnifiedFinding(
                        rule_id="NULL.SUBSCRIPT", severity="high",
                        description=f"'{node.value.id}' may be None and subscripted",
                        file=str(file_path), line=node.lineno, function=func.name, language="python",
                        category="nullness", cwe="CWE-476"))
    return findings

def detect_null_repo(repo_root: Path, max_files=200) -> List[UnifiedFinding]:
    skip = {".git", "__pycache__", ".venv", "venv", "node_modules", ".loomscan-cache", "build", "dist", "target"}
    findings = []
    count = 0
    for f in sorted(repo_root.rglob("*")):
        if not f.is_file() or any(p in skip for p in f.parts) or count >= max_files: continue
        lang = get_language(f) if _HAS_TS else "python"
        if lang == "unknown" and f.suffix != ".py": continue
        count += 1
        findings.extend(detect_null_dereference_multi(f))
    return findings


# =============================================================================
# 5. MULTI-LANGUAGE DYNAMIC TESTING (PBT/fuzzing generators for all langs)
# =============================================================================
