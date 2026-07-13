"""Source discovery — Kunlun-M-inspired user input entry point detection."""
from __future__ import annotations
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from .multi_lang import get_language, ALL_SOURCE_EXTS

import logging
_logger = logging.getLogger(__name__.replace('loomscan.', ''))

@dataclass
class SourceInfo:
    file: str; line: int; param_name: str; source_type: str; framework: str; method_name: str = ""

SPRING_SOURCE_PATTERNS = [
    ("RequestParam", r'@RequestParam\s*(?:\([^)]*\))?\s+(?:\w+\s+)?(\w+)', "request_param", "spring"),
    ("PathVariable", r'@PathVariable\s*(?:\([^)]*\))?\s+(?:\w+\s+)?(\w+)', "path_variable", "spring"),
    ("RequestBody", r'@RequestBody\s+(?:\w+\s+)?(\w+)', "request_body", "spring"),
    ("RequestHeader", r'@RequestHeader\s*(?:\([^)]*\))?\s+(?:\w+\s+)?(\w+)', "header", "spring"),
]
JAXRS_SOURCE_PATTERNS = [
    ("QueryParam", r'@QueryParam\s*\(\s*["\']([^"\']+)["\']\s*\)\s+(?:\w+\s+)?(\w+)', "query", "jaxrs"),
    ("PathParam", r'@PathParam\s*\(\s*["\']([^"\']+)["\']\s*\)\s+(?:\w+\s+)?(\w+)', "path_variable", "jaxrs"),
]
PYTHON_SOURCE_PATTERNS = [
    ("FlaskArgsGet", r'request\.args\.get\s*\(\s*["\']([^"\']+)["\']', "query", "flask"),
    ("FlaskFormGet", r'request\.form\.get\s*\(\s*["\']([^"\']+)["\']', "form", "flask"),
    ("DjangoGET", r'request\.GET\.get\s*\(\s*["\']([^"\']+)["\']', "query", "django"),
    ("DjangoPOST", r'request\.POST\.get\s*\(\s*["\']([^"\']+)["\']', "form", "django"),
    ("Input", r'\binput\s*\(', "stdin", "python"),
    ("OsGetenv", r'\bos\.getenv\s*\(', "environment", "python"),
]
JS_SOURCE_PATTERNS = [
    ("ExpressParams", r'req\.params\.(\w+)', "path_variable", "express"),
    ("ExpressQuery", r'req\.query\.(\w+)', "query", "express"),
    ("ExpressBody", r'req\.body\.(\w+)', "request_body", "express"),
    ("LocalStorage", r'localStorage\.getItem\s*\(\s*["\']([^"\']+)["\']', "client_storage", "browser"),
]
GO_SOURCE_PATTERNS = [
    ("GoQueryGet", r'r\.URL\.Query\(\)\.Get\s*\(\s*["\']([^"\']+)["\']', "query", "go_http"),
    ("GoFormValue", r'r\.FormValue\s*\(\s*["\']([^"\']+)["\']', "form", "go_http"),
    ("GoGetenv", r'os\.Getenv\s*\(', "environment", "go"),
]

def get_patterns_for_language(lang):
    if lang == "java": return SPRING_SOURCE_PATTERNS + JAXRS_SOURCE_PATTERNS
    if lang == "python": return PYTHON_SOURCE_PATTERNS
    if lang == "javascript": return JS_SOURCE_PATTERNS
    if lang == "go": return GO_SOURCE_PATTERNS
    return []

def discover_sources_in_file(file_path, repo_root=None):
    lang = get_language(file_path)
    if lang == "unknown": return []
    patterns = get_patterns_for_language(lang)
    if not patterns: return []
    rel = str(file_path.relative_to(repo_root)) if repo_root else str(file_path)
    try: source = file_path.read_text(encoding="utf-8", errors="replace")
    except: return []
    sources = []
    lines = source.splitlines()
    current_method = ""
    for i, line in enumerate(lines, 1):
        if lang == "java":
            m = re.match(r'\s*(?:public|private|protected)\s+\w+\s+(\w+)\s*\(', line)
            if m: current_method = m.group(1)
        for _, regex, source_type, framework in patterns:
            m = re.search(regex, line)
            if m:
                sources.append(SourceInfo(file=rel, line=i, param_name=m.group(1) if m.lastindex else "",
                    source_type=source_type, framework=framework, method_name=current_method))
    return sources

def discover_sources_in_repo(repo_root, max_files=600):
    all_sources = []
    skip_dirs = {".git","__pycache__",".venv","venv","node_modules",".loomscan-cache","build","dist","target","test","tests"}
    count = 0
    for p in repo_root.rglob("*"):
        if not p.is_file() or any(part in skip_dirs for part in p.parts): continue
        if p.suffix.lower() in ALL_SOURCE_EXTS:
            try: all_sources += discover_sources_in_file(p, repo_root)
            except Exception: pass  # v4.5: suppressed — add logging
            count += 1
            if count >= max_files: break
    return all_sources

def source_summary(sources):
    from collections import Counter
    return {"total_sources":len(sources),"by_framework":dict(Counter(s.framework for s in sources)),
            "by_type":dict(Counter(s.source_type for s in sources)),
            "by_file":dict(Counter(s.file for s in sources).most_common(10)),
            "unique_param_names":len({s.param_name for s in sources if s.param_name})}
