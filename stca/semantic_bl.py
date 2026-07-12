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

_v4_logger = logging.getLogger("stca.v4_restored")
from .v4_types import UnifiedFinding
from .codebase_understanding import SAFE_CONSTANTS
from .codebase_understanding import ENDPOINT_KEYWORDS

def _extract_endpoint(url):
    ep = url
    if "://" in ep: ep = "/" + ep.split("/", 3)[3] if ep.count("/") >= 3 else "/"
    if not ep.startswith("/"): ep = "/" + ep
    ep = ep.split("?")[0]
    ep = re.sub(r'\{[^}]+\}', '', ep)
    return ep

def _check_endpoint_mismatch(func_name, endpoint):
    ep_parts = endpoint.lower().strip("/").split("/")
    ep_action = None
    for part in ep_parts:
        for kw in ENDPOINT_KEYWORDS:
            if kw in part: ep_action = kw; break
        if ep_action: break
    if not ep_action: return None
    func_action = None
    for kw, syns in ENDPOINT_KEYWORDS.items():
        for s in syns:
            if s in func_name.lower(): func_action = kw; break
        if func_action: break
    if not func_action: return None
    if func_action != ep_action:
        if ep_action not in ENDPOINT_KEYWORDS.get(func_action, []) and func_action not in ENDPOINT_KEYWORDS.get(ep_action, []):
            return f"Function '{func_name}' suggests '{func_action}' but endpoint is '{ep_action}' — may not support needed fields"
    return None

def detect_semantic_bl(file_path: Path) -> List[UnifiedFinding]:
    try:
        source = file_path.read_text(encoding="utf-8")
    except Exception:
        return []
    lang = get_language(file_path) if _HAS_TS else "python"
    if lang == "unknown": return []
    findings = []
    lines = source.splitlines()
    cur_func = ""
    func_pats = {"python": re.compile(r'def\s+(\w+)\s*\('), "javascript": re.compile(r'function\s+(\w+)\s*\('), "typescript": re.compile(r'function\s+(\w+)\s*\('), "go": re.compile(r'func\s+(?:\([^)]*\)\s+)?(\w+)\s*\('), "java": re.compile(r'(?:public|private|protected|static)\s+\w+\s+(\w+)\s*\('), "c": re.compile(r'\w+\s+(\w+)\s*\([^)]*\)\s*\{'), "cpp": re.compile(r'\w+\s+(\w+)\s*\([^)]*\)\s*\{'), "rust": re.compile(r'fn\s+(\w+)\s*\(')}
    pat = func_pats.get(lang, func_pats["python"])
    for i, line in enumerate(lines, 1):
        m = pat.search(line)
        if m: cur_func = m.group(1)
        s = line.strip()
        if not s or s.startswith(("#", "//", "/*", "*", "--")): continue
        # Hardcoded thresholds
        for mm in re.finditer(r'\bif\s*\(?[\w\.\[\]]+\s*[<>=!]+\s*(\d+(?:\.\d+)?)', s, re.IGNORECASE):
            v = float(mm.group(1)) if "." in mm.group(1) else int(mm.group(1))
            if v not in SAFE_CONSTANTS and isinstance(v, int) and not (-4 <= v <= 4):
                findings.append(UnifiedFinding(rule_id="SEM.HARDCODED-THRESHOLD", severity="medium",
                    description=f"Hardcoded threshold {v} in condition — consider config/env",
                    file=str(file_path), line=i, function=cur_func, language=lang,
                    category="hardcoded_value", suggestion=f"Move {v} to config"))
        # Hardcoded URLs
        for mm in re.finditer(r'["\'](https?://[^\s"\']+)["\']', s):
            url = mm.group(1)
            if not any(x in url.lower() for x in ("example.com", "schema.org", "w3.org", "localhost")):
                findings.append(UnifiedFinding(rule_id="SEM.HARDCODED-URL", severity="medium",
                    description=f"Hardcoded URL '{url}'", file=str(file_path), line=i,
                    function=cur_func, language=lang, category="hardcoded_value", suggestion="Use config"))
        # Hardcoded API paths
        for mm in re.finditer(r'["\'](/(?:api|v\d+)/[^\s"\']+)["\']', s, re.IGNORECASE):
            path = mm.group(1)
            findings.append(UnifiedFinding(rule_id="SEM.HARDCODED-API-PATH", severity="low",
                description=f"Hardcoded API path '{path}'", file=str(file_path), line=i,
                function=cur_func, language=lang, category="hardcoded_value", suggestion="Centralize API paths"))
            # Check endpoint mismatch
            if cur_func:
                mismatch = _check_endpoint_mismatch(cur_func, path)
                if mismatch:
                    findings.append(UnifiedFinding(rule_id="SEM.API-MISMATCH", severity="high",
                        description=mismatch, file=str(file_path), line=i, function=cur_func,
                        language=lang, category="api_mismatch", suggestion="Check if endpoint supports needed fields"))
    return findings

def detect_semantic_repo(repo_root: Path, max_files=200) -> List[UnifiedFinding]:
    skip = {".git", "__pycache__", ".venv", "venv", "node_modules", ".stca-cache", "build", "dist", "target"}
    findings = []
    count = 0
    for f in sorted(repo_root.rglob("*")):
        if not f.is_file() or any(p in skip for p in f.parts) or count >= max_files: continue
        lang = get_language(f) if _HAS_TS else "python"
        if lang == "unknown" and f.suffix != ".py": continue
        count += 1
        findings.extend(detect_semantic_bl(f))
    return findings


# =============================================================================
# 4. MULTI-LANGUAGE NULLNESS (all languages via normalized AST)
# =============================================================================

NULL_VALUES = {
    "python": ("None", "Optional", "dict.get", "re.search", "re.match"),
    "javascript": ("null", "undefined", "Optional"),
    "typescript": ("null", "undefined", "Optional"),
    "go": ("nil",),
    "java": ("null", "Optional"),
    "c": ("NULL", "nullptr"),
    "cpp": ("nullptr", "NULL"),
    "rust": ("None", "Option"),
}
