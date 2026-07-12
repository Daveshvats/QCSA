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
from .v4_types import _detect_lang_by_ext

def detect_contracts_multi(file_path: Path) -> List[UnifiedFinding]:
    """Design-by-contract verification for any language."""
    try:
        source = file_path.read_text(encoding="utf-8")
    except Exception:
        return []

    lang = get_language(file_path) if _HAS_TS else _detect_lang_by_ext(file_path)
    if lang == "unknown":
        return []

    findings: List[UnifiedFinding] = []
    lines = source.splitlines()
    rel = str(file_path)

    func_patterns = {
        "python": re.compile(r'def\s+(\w+)\s*\(([^)]*)\)'),
        "javascript": re.compile(r'function\s+(\w+)\s*\(([^)]*)\)'),
        "go": re.compile(r'func\s+(?:\([^)]*\)\s+)?(\w+)\s*\(([^)]*)\)'),
        "java": re.compile(r'(?:public|private|protected|static)\s+\w+\s+(\w+)\s*\(([^)]*)\)'),
        "c": re.compile(r'\w+\s+(\w+)\s*\([^)]*\)\s*\{'),
        "cpp": re.compile(r'\w+\s+(\w+)\s*\([^)]*\)\s*\{'),
        "rust": re.compile(r'fn\s+(\w+)\s*\(([^)]*)\)'),
    }
    pat = func_patterns.get(lang)
    if not pat:
        return findings

    cur_func = ""
    cur_params: List[str] = []
    func_body_start = 0

    for i, line in enumerate(lines, 1):
        m = pat.search(line)
        if m:
            if cur_func and cur_params:
                _check_preconditions(cur_func, cur_params, lines[func_body_start:min(func_body_start + 20, i)], rel, func_body_start, lang, findings)

            cur_func = m.group(1)
            params_str = m.group(2) if m.lastindex >= 2 else ""
            # v4.7: Extract param name correctly for type-hinted params.
            # "data: str" → "data" (not "str"), "amount: int" → "amount" (not "int")
            cur_params = []
            for p in params_str.split(","):
                p = p.strip()
                if not p or "self" in p or "this" in p:
                    continue
                # Handle type annotations: "data: str" → "data"
                if ":" in p:
                    p = p.split(":")[0].strip()
                # Handle default values: "data: str = 'x'" → "data"
                if "=" in p:
                    p = p.split("=")[0].strip()
                # Handle pointer/ref: "*data" → "data", "&data" → "data"
                p = p.replace("*", "").replace("&", "").strip()
                # Handle "Type name" (Go/Java): "int amount" → "amount"
                if " " in p:
                    p = p.split()[-1]
                if p:
                    cur_params.append(p)
            func_body_start = i + 1

    if cur_func and cur_params:
        _check_preconditions(cur_func, cur_params, lines[func_body_start:func_body_start + 20], rel, func_body_start, lang, findings)

    return findings


def _check_preconditions(func_name: str, params: List[str], body_lines: List[str],
                           file: str, start_line: int, lang: str,
                           findings: List[UnifiedFinding]) -> None:
    """Check if a function validates its parameters.

    v4.7 fix: Validation patterns must reference at least one of the function's
    own parameter names. Previously, any occurrence of 'check', 'guard',
    'validate', etc. — even in unrelated calls like `FeatureFlags.check(...)`
    — would suppress the finding. Now we require the validation keyword to
    appear on the same line as a parameter name, or in an if/assert/raise
    statement that references a parameter.
    """
    if not params:
        return

    body_text = "\n".join(body_lines).lower()
    params_lower = [p.lower() for p in params]

    # v4.7: Check if validation patterns reference the function's own parameters.
    # Split into lines and check each line for both a validation keyword AND
    # a parameter name on the same line.
    validation_keywords = [
        'assert', 'raise', 'throw', 'require', 'validate',
        'if', 'guard', 'check',
    ]
    annotation_patterns = [
        r'@\w+(?:valid|notnull|notblank|notempty|size|min|max|pattern)',
    ]

    has_validation = False
    for line in body_lines:
        line_lower = line.lower()
        # Check if this line contains a validation keyword
        has_keyword = any(kw in line_lower for kw in validation_keywords)
        # Check if this line also references a parameter
        has_param = any(p in line_lower for p in params_lower)
        # Check for annotation-based validation (always counts)
        has_annotation = any(re.search(pat, line_lower) for pat in annotation_patterns)

        if has_annotation:
            has_validation = True
            break
        # v4.7: Only count keyword validation if it references a parameter
        if has_keyword and has_param:
            has_validation = True
            break

    if not has_validation and len(params) >= 2:
        findings.append(UnifiedFinding(
            rule_id="CONTRACT.MISSING-PRECONDITION", severity="low",
            description=f"Function '{func_name}()' takes {len(params)} parameters but has no input validation "
                        f"in its first 20 lines - consider adding precondition checks",
            file=file, line=start_line, function=func_name,
            language=lang, category="contract", cwe="CWE-20",
            suggestion="Add null/empty checks at function entry"))


def auto_fix_multi(file_path: Path) -> List[UnifiedFinding]:
    """Auto-fix suggestions for any language (doesn't modify files, just reports)."""
    try:
        source = file_path.read_text(encoding="utf-8")
    except Exception:
        return []

    lang = get_language(file_path) if _HAS_TS else _detect_lang_by_ext(file_path)
    if lang == "unknown":
        return []

    findings: List[UnifiedFinding] = []
    lines = source.splitlines()
    rel = str(file_path)

    for i, line in enumerate(lines, 1):
        stripped = line.strip()

        if lang == "python" and re.search(r'==\s*None\b', stripped):
            findings.append(UnifiedFinding(
                rule_id="FIX.PY-EQ-NONE", severity="low",
                description="Use 'is None' instead of '== None' (PEP 8)",
                file=rel, line=i, language=lang, category="style",
                suggestion="Replace == None with is None"))

        if re.search(r'catch\s*\([^)]*\)\s*\{\s*\}', stripped):
            findings.append(UnifiedFinding(
                rule_id="FIX.EMPTY-CATCH", severity="high",
                description="Empty catch block - add error logging",
                file=rel, line=i, language=lang, category="correctness",
                suggestion="Add: console.error(e) / logger.error(e) / log.error(e)"))

        if lang == "go" and re.search(r'\.Open\s*\(', stripped) and "defer" not in stripped:
            if not any("defer" in lines[j] for j in range(i, min(i + 5, len(lines)))):
                findings.append(UnifiedFinding(
                    rule_id="FIX.GO-MISSING-DEFER", severity="medium",
                    description="Resource opened without defer Close - potential leak",
                    file=rel, line=i, language=lang, category="correctness",
                    suggestion="Add 'defer f.Close()' immediately after opening"))

        if lang == "java" and re.search(r'new\s+Random\s*\(\s*\)', stripped):
            findings.append(UnifiedFinding(
                rule_id="FIX.JAVA-INSECURE-RANDOM", severity="high",
                description="Replace java.util.Random with SecureRandom for security",
                file=rel, line=i, language=lang, category="security",
                suggestion="Use: new SecureRandom()", cwe="CWE-330"))

        if lang in ("javascript", "typescript") and re.search(r'\bvar\s+\w+', stripped):
            findings.append(UnifiedFinding(
                rule_id="FIX.JS-VAR-TO-LET", severity="low",
                description="Use 'let' or 'const' instead of 'var' (ES6+)",
                file=rel, line=i, language=lang, category="style",
                suggestion="Replace 'var' with 'const' (or 'let' if reassigned)"))

    return findings


