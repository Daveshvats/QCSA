"""v4_restored.py — thin aggregator for v4 modules.

v4.27: Split from 1,581 lines into 8 real implementation modules.
This file now contains only:
  - Shared types (UnifiedFinding)
  - Shared utilities (_log_v4_error, _detect_lang_by_ext)
  - Complexity/quality checks (detect_complexity_multi, detect_code_quality_multi)
  - The analyze_all() aggregator that calls the extracted modules
  - _run_v41_features() backward-compat wrapper

All implementation code has been moved to:
  - loomscan/expanded_rules.py — scan_expanded_js/java/repo, JS_EXPANDED_RULES, JAVA_EXPANDED_RULES
  - loomscan/codebase_understanding.py — index_codebase, analyze_codebase, CodebaseModel
  - loomscan/semantic_bl.py — detect_semantic_bl, detect_semantic_repo
  - loomscan/multi_lang_null.py — detect_null_dereference_multi, detect_null_repo
  - loomscan/multi_lang_testing.py — generate_js/go/java/rust/cpp tests
  - loomscan/multi_lang_typestate.py — detect_state_machine_multi, detect_typestate_multi, detect_spec_mining, detect_metamorphic
  - loomscan/multi_lang_taint.py — detect_cpg_taint_multi, _cpg_taint_py_fallback
  - loomscan/multi_lang_contracts.py — detect_contracts_multi, auto_fix_multi
"""
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


def _log_v4_error(scanner_name: str, exc: BaseException) -> None:
    """Log a v4 scanner error without crashing."""
    _v4_logger.warning("v4 scanner %s failed: %s", scanner_name, exc)


def _detect_lang_by_ext(file_path: Path) -> str:
    """Detect language by file extension (fallback when tree-sitter unavailable)."""
    ext = file_path.suffix.lower()
    if ext == ".py": return "python"
    if ext in (".js", ".jsx", ".mjs", ".cjs"): return "javascript"
    if ext in (".ts", ".tsx"): return "typescript"
    if ext == ".go": return "go"
    if ext == ".java": return "java"
    if ext in (".c", ".h"): return "c"
    if ext in (".cpp", ".cc", ".cxx", ".hpp", ".hxx"): return "cpp"
    if ext == ".rs": return "rust"
    if ext in (".php", ".phtml"): return "php"
    if ext in (".rb", ".rake"): return "ruby"
    if ext == ".cs": return "csharp"
    if ext in (".kt", ".kts"): return "kotlin"
    if ext == ".swift": return "swift"
    if ext in (".scala", ".sc"): return "scala"
    return "unknown"


# ============================================================================
# Shared types — moved to v4_types.py to break circular imports
# ============================================================================

from .v4_types import UnifiedFinding, _detect_lang_by_ext


# ============================================================================
# v4.27: Import implementation from extracted modules
# ============================================================================

# Re-export everything from the extracted modules for backward compatibility.
# All existing `from .v4_restored import X` calls continue to work.
from .expanded_rules import (
    JS_EXPANDED_RULES, JAVA_EXPANDED_RULES,
    scan_expanded_js, scan_expanded_java, scan_expanded_repo,
)
from .codebase_understanding import (
    FunctionBehavior, ConfigEntry, CodebaseModel,
    index_codebase, _index_py_file, _index_multi_file, _index_config,
    analyze_codebase, _extract_endpoint, _check_endpoint_mismatch,
)
from .semantic_bl import detect_semantic_bl, detect_semantic_repo
from .multi_lang_null import (
    detect_null_dereference_multi, _detect_null_normalized,
    _detect_null_py, detect_null_repo,
)
from .multi_lang_testing import (
    generate_js_pbt_test, generate_go_pbt_test, generate_java_pbt_test,
    generate_rust_proptest, generate_cpp_fuzz_harness,
    get_dynamic_capabilities,
)
from .multi_lang_typestate import (
    detect_state_machine_multi, detect_typestate_multi,
    detect_spec_mining_multi, detect_metamorphic_multi,
)
from .multi_lang_taint import detect_cpg_taint_multi, _cpg_taint_py_fallback
from .multi_lang_contracts import (
    detect_contracts_multi, _check_preconditions, auto_fix_multi,
)
# NULL_VALUES was in the semantic_bl section of the original file
from .semantic_bl import NULL_VALUES


# ============================================================================
# Complexity and code quality (kept here — they're small and self-contained)
# ============================================================================

def detect_complexity_multi(file_path: Path) -> List[UnifiedFinding]:
    """Cyclomatic complexity for any language via line-based heuristic."""
    try:
        source = file_path.read_text(encoding="utf-8")
    except Exception:
        return []

    lang = get_language(file_path) if _HAS_TS else _detect_lang_by_ext(file_path)
    if lang == "unknown":
        return []

    findings: List[UnifiedFinding] = []
    lines = source.splitlines()

    decision_patterns = [
        r'\bif\s+[\(]', r'\bif\s+\w', r'\belif\s+\w', r'\belse\s+if\s+[\(w]',
        r'\bfor\s+[\(w]', r'\bwhile\s+[\(w]', r'\bcase\s+', r'\bcatch\s*\(',
        r'\bexcept\s+\w', r'\b&&\b', r'\b\|\|\b', r'\?\s*[^:]+:',
    ]

    func_patterns = {
        "python": re.compile(r'def\s+(\w+)\s*\('),
        "javascript": re.compile(r'function\s+(\w+)\s*\('),
        "typescript": re.compile(r'function\s+(\w+)\s*\('),
        "go": re.compile(r'func\s+(?:\([^)]*\)\s+)?(\w+)\s*\('),
        "java": re.compile(r'(?:public|private|protected|static)\s+\w+\s+(\w+)\s*\('),
        "c": re.compile(r'\w+\s+(\w+)\s*\([^)]*\)\s*\{'),
        "cpp": re.compile(r'\w+\s+(\w+)\s*\([^)]*\)\s*\{'),
        "rust": re.compile(r'fn\s+(\w+)\s*\('),
    }

    pat = func_patterns.get(lang)
    if not pat:
        return []

    cur_func = ""
    cur_func_line = 0
    complexity = 1

    for i, line in enumerate(lines, 1):
        m = pat.search(line)
        if m:
            if cur_func and complexity > 10:
                findings.append(UnifiedFinding(
                    rule_id=f"COMPLEXITY-HIGH", severity="medium",
                    description=f"High cyclomatic complexity ({complexity}) in {cur_func}()",
                    file=str(file_path), line=cur_func_line, function=cur_func,
                    language=lang, category="complexity",
                    suggestion="Refactor to reduce branching"))
            cur_func = m.group(1)
            cur_func_line = i
            complexity = 1
        else:
            for dp in decision_patterns:
                if re.search(dp, line):
                    complexity += 1

    if cur_func and complexity > 10:
        findings.append(UnifiedFinding(
            rule_id=f"COMPLEXITY-HIGH", severity="medium",
            description=f"High cyclomatic complexity ({complexity}) in {cur_func}()",
            file=str(file_path), line=cur_func_line, function=cur_func,
            language=lang, category="complexity",
            suggestion="Refactor to reduce branching"))

    return findings


def detect_code_quality_multi(file_path: Path) -> List[UnifiedFinding]:
    """Multi-language code quality checks via regex patterns."""
    try:
        source = file_path.read_text(encoding="utf-8")
    except Exception:
        return []

    lang = get_language(file_path) if _HAS_TS else _detect_lang_by_ext(file_path)
    if lang == "unknown":
        return []

    findings: List[UnifiedFinding] = []
    lines = source.splitlines()

    # Language-specific quality rules
    rules = {
        "python": [
            ("TODO-COMMENT", r'#\s*TODO', "low", "TODO comment", "Track in issue tracker"),
            ("FIXME-COMMENT", r'#\s*FIXME', "medium", "FIXME comment", "Fix this issue"),
            ("EMPTY-EXCEPT", r'except\s*:', "high", "Bare except", "Catch specific exceptions"),
        ],
        "javascript": [
            ("JS-CONSOLE-LOG", r'\bconsole\.log\s*\(', "low", "console.log in production", "Use logger"),
            ("JS-DEBUGGER", r'\bdebugger\b', "high", "debugger statement", "Remove debugger"),
        ],
        "go": [
            ("GO-FMT-ERROR", r'^\s*(if|for|func)\S', "low", "Missing space after keyword", "Run gofmt"),
        ],
        "java": [
            ("JAVA-SYSOUT", r'System\.out\.print', "low", "System.out in production", "Use SLF4J"),
        ],
    }

    lang_rules = rules.get(lang, [])
    for i, line in enumerate(lines, 1):
        for rule_id, pattern, severity, desc, fix in lang_rules:
            if re.search(pattern, line):
                findings.append(UnifiedFinding(
                    rule_id=rule_id, severity=severity, description=desc,
                    file=str(file_path), line=i, language=lang,
                    category="quality", suggestion=fix))

    return findings


# ============================================================================
# Analyze all — the aggregator that calls all extracted modules
# ============================================================================

def analyze_all(repo_root: Path) -> List[UnifiedFinding]:
    """Run all v4 analyzers on a repo. Aggregator for extracted modules."""
    findings: List[UnifiedFinding] = []

    skip = {".git", "__pycache__", ".venv", "venv", "node_modules", ".loomscan-cache",
            "build", "dist", "target", ".pytest_cache", ".loomscan-reports", ".loomscan-fixes"}
    count = 0
    for f in sorted(Path(repo_root).rglob("*")):
        if not f.is_file() or any(p in skip for p in f.parts) or count >= 300:
            continue
        lang = get_language(f) if _HAS_TS else _detect_lang_by_ext(f)
        if lang == "unknown" and f.suffix != ".py":
            continue
        count += 1
        try:
            findings.extend(scan_expanded_js(f) if f.suffix in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs") else [])
            findings.extend(scan_expanded_java(f) if f.suffix == ".java" else [])
            findings.extend(detect_semantic_bl(f) if lang != "unknown" else [])
            findings.extend(detect_null_dereference_multi(f) if lang != "unknown" else [])
            findings.extend(detect_complexity_multi(f))
            findings.extend(detect_code_quality_multi(f))
            findings.extend(detect_contracts_multi(f) if lang != "unknown" else [])
            findings.extend(detect_cpg_taint_multi(f) if lang != "unknown" else [])
            if lang != "unknown" and _HAS_TS:
                tree = parse_file(f)
                if tree:
                    findings.extend(detect_state_machine_multi(tree))
                    findings.extend(detect_typestate_multi(tree))
        except Exception as e:
            _log_v4_error(f"analyze_all:{f.name}", e)

    # Repo-level scans
    try:
        findings.extend(scan_expanded_repo(repo_root))
        # v4.29 FIX: Restore analyze_codebase() call (was dropped in v4.27 split)
        _, cu_findings = analyze_codebase(repo_root)
        findings.extend(cu_findings)
        findings.extend(detect_semantic_repo(repo_root))
        findings.extend(detect_null_repo(repo_root))
        findings.extend(detect_spec_mining_multi(repo_root))
        # v4.29 FIX: Restore auto_fix_multi() call (was dropped in v4.27 split)
        for f in sorted(Path(repo_root).rglob("*")):
            if not f.is_file() or any(p in skip for p in f.parts):
                continue
            try:
                findings.extend(auto_fix_multi(f))
            except Exception:
                pass
    except Exception as e:
        _log_v4_error("analyze_all:repo", e)

    return findings


def _run_v41_features(repo_root: Path) -> List[UnifiedFinding]:
    """Run v4.1 features (backward compat wrapper)."""
    return analyze_all(repo_root)
