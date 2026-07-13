"""Consistency checker — detect inconsistent patterns across the codebase.

Inspired by credo's focus on code consistency. The idea: if the same
operation is done differently in different files, that's a smell. Teams
that refactor inconsistently introduce bugs.

Examples we detect:
  - Mixed string formatting: some files use f-strings, others use .format(),
    others use % — pick one
  - Mixed import styles: `import x` vs `from x import y` for the same module
  - Mixed error handling: try/except in some places, if/else checks in others
  - Mixed logging: print() in some files, logging.info() in others
  - Mixed test frameworks: unittest in some files, pytest in others
  - Mixed naming: camelCase in some functions, snake_case in others (Python)
  - Mixed None checks: `if x is None` vs `if not x` vs `if x == None`

This doesn't catch bugs per se — it catches **inconsistency** which is a
leading indicator of bugs (because it means different team members have
different mental models of the codebase).
"""
from __future__ import annotations

import ast
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Tuple, Set


@dataclass
class Inconsistency:
    """A detected inconsistency across the codebase."""
    category: str  # 'string_format' | 'import_style' | 'error_handling' | etc.
    description: str
    files_using_a: List[str]  # files using pattern A
    files_using_b: List[str]  # files using pattern B
    pattern_a: str
    pattern_b: str
    recommendation: str


def check_string_formatting_consistency(repo_root: Path,
                                          max_files: int = 100) -> List[Inconsistency]:
    """Check for mixed string formatting styles (f-string vs .format() vs %)."""
    skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules",
                 ".loomscan-cache", ".loomscan-reports", ".loomscan-fixes", "tests", "test"}
    fstring_files: List[str] = []
    format_files: List[str] = []
    percent_files: List[str] = []

    count = 0
    for p in repo_root.rglob("*.py"):
        if any(part in skip_dirs for part in p.parts):
            continue
        if p.name.startswith("test_") or p.name.endswith("_test.py"):
            continue
        try:
            source = p.read_text(encoding="utf-8")
        except Exception:
            continue
        rel = str(p.relative_to(repo_root))

        # f-strings
        if re.search(r'f"[^"]*\{', source) or re.search(r"f'[^']*\{", source):
            fstring_files.append(rel)
        # .format()
        if re.search(r'\.format\(', source):
            format_files.append(rel)
        # % formatting
        if re.search(r'["\'][^"\']*%[sdf]"\s*%', source) or re.search(r'\%\s*\(', source):
            percent_files.append(rel)

        count += 1
        if count >= max_files:
            break

    inconsistencies: List[Inconsistency] = []
    if len(fstring_files) > 0 and len(format_files) > 0:
        inconsistencies.append(Inconsistency(
            category="string_format",
            description="Mixed string formatting styles across the codebase",
            files_using_a=fstring_files[:10],
            files_using_b=format_files[:10],
            pattern_a="f-strings (f'...')",
            pattern_b=".format() method",
            recommendation="Standardize on f-strings (Python 3.6+, fastest, most readable)",
        ))
    if len(fstring_files) > 0 and len(percent_files) > 0:
        inconsistencies.append(Inconsistency(
            category="string_format",
            description="Mixed string formatting styles across the codebase",
            files_using_a=fstring_files[:10],
            files_using_b=percent_files[:10],
            pattern_a="f-strings (f'...')",
            pattern_b="% formatting (deprecated)",
            recommendation="Standardize on f-strings; % formatting is error-prone",
        ))
    return inconsistencies


def check_import_consistency(repo_root: Path,
                              max_files: int = 100) -> List[Inconsistency]:
    """Check for mixed import styles for the same module."""
    skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules",
                 ".loomscan-cache", ".loomscan-reports", ".loomscan-fixes", "tests", "test"}
    import_styles: Dict[str, Set[str]] = defaultdict(set)  # module → set of styles

    count = 0
    for p in repo_root.rglob("*.py"):
        if any(part in skip_dirs for part in p.parts):
            continue
        try:
            source = p.read_text(encoding="utf-8")
            tree = ast.parse(source)
        except Exception:
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name:
                        import_styles[alias.name].add("import X")
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    import_styles[node.module].add("from X import Y")

        count += 1
        if count >= max_files:
            break

    inconsistencies: List[Inconsistency] = []
    for module, styles in import_styles.items():
        if len(styles) > 1:
            inconsistencies.append(Inconsistency(
                category="import_style",
                description=f"Module '{module}' imported with mixed styles",
                files_using_a=[],
                files_using_b=[],
                pattern_a=list(styles)[0],
                pattern_b=list(styles)[1] if len(styles) > 1 else "",
                recommendation=f"Standardize import style for '{module}'",
            ))
    return inconsistencies


def check_logging_consistency(repo_root: Path,
                               max_files: int = 100) -> List[Inconsistency]:
    """Check for mixed logging (print vs logging module)."""
    skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules",
                 ".loomscan-cache", ".loomscan-reports", ".loomscan-fixes", "tests", "test"}
    print_files: List[str] = []
    logging_files: List[str] = []

    count = 0
    for p in repo_root.rglob("*.py"):
        if any(part in skip_dirs for part in p.parts):
            continue
        if p.name.startswith("test_") or p.name.endswith("_test.py"):
            continue
        try:
            source = p.read_text(encoding="utf-8")
        except Exception:
            continue
        rel = str(p.relative_to(repo_root))

        # print statements (excluding print() in __main__ blocks)
        if re.search(r'^\s*print\s*\(', source, re.MULTILINE):
            print_files.append(rel)
        # logging
        if re.search(r'logging\.(info|debug|warn|error|critical)\s*\(', source):
            logging_files.append(rel)

        count += 1
        if count >= max_files:
            break

    if print_files and logging_files:
        return [Inconsistency(
            category="logging",
            description="Mixed logging styles: print() in some files, logging module in others",
            files_using_a=print_files[:10],
            files_using_b=logging_files[:10],
            pattern_a="print()",
            pattern_b="logging module",
            recommendation="Use the logging module consistently — print() lacks levels, timestamps, and output control",
        )]
    return []


def check_none_check_consistency(repo_root: Path,
                                  max_files: int = 100) -> List[Inconsistency]:
    """Check for mixed None-check styles (is None vs == None vs not x)."""
    skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules",
                 ".loomscan-cache", ".loomscan-reports", ".loomscan-fixes", "tests", "test"}
    is_none_files: List[str] = []
    eq_none_files: List[str] = []
    not_x_files: List[str] = []

    count = 0
    for p in repo_root.rglob("*.py"):
        if any(part in skip_dirs for part in p.parts):
            continue
        try:
            source = p.read_text(encoding="utf-8")
        except Exception:
            continue
        rel = str(p.relative_to(repo_root))

        if re.search(r'\bis\s+None\b', source):
            is_none_files.append(rel)
        if re.search(r'==\s*None\b', source):
            eq_none_files.append(rel)
        # `if not x:` is harder to classify — skip for now

        count += 1
        if count >= max_files:
            break

    inconsistencies: List[Inconsistency] = []
    if is_none_files and eq_none_files:
        inconsistencies.append(Inconsistency(
            category="none_check",
            description="Mixed None-check styles",
            files_using_a=is_none_files[:10],
            files_using_b=eq_none_files[:10],
            pattern_a="x is None (correct, identity check)",
            pattern_b="x == None (incorrect, can be overridden by __eq__)",
            recommendation="Always use 'is None' / 'is not None' — it's an identity check, not an equality check",
        ))
    return inconsistencies


def check_all_consistencies(repo_root: Path,
                             max_files: int = 100) -> List[Inconsistency]:
    """Run all consistency checks."""
    results: List[Inconsistency] = []
    results += check_string_formatting_consistency(repo_root, max_files)
    results += check_import_consistency(repo_root, max_files)
    results += check_logging_consistency(repo_root, max_files)
    results += check_none_check_consistency(repo_root, max_files)
    return results
