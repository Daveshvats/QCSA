"""Documentation audit — inspired by Valknut.

Valknut includes documentation audits: checking if functions have docstrings,
if docs are stale (don't match the code), if public APIs are documented.

We implement:
  1. Missing docstrings on public functions/classes
  2. Stale docstrings (function signature changed but docstring didn't)
  3. Missing module docstrings
  4. Missing __init__.py docstrings
  5. TODO/FIXME/HACK count (code smell indicator)
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List


@dataclass
class DocAuditIssue:
    """A documentation audit issue."""
    issue_type: str  # 'missing_docstring' | 'stale_docstring' | 'missing_module_doc' | 'todo' | 'fixme' | 'hack'
    file: str
    line: int
    name: str  # function/class/module name
    description: str
    severity: str  # 'info' | 'low' | 'medium'


def audit_file(file_path: Path, repo_root: Path = None) -> List[DocAuditIssue]:
    """Audit a Python file for documentation issues."""
    if not file_path.exists() or file_path.suffix != ".py":
        return []
    try:
        source = file_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except Exception:
        return []

    rel = str(file_path.relative_to(repo_root)) if repo_root else str(file_path)
    issues: List[DocAuditIssue] = []

    # Check module docstring
    if not ast.get_docstring(tree):
        issues.append(DocAuditIssue(
            issue_type="missing_module_doc", file=rel, line=1,
            name="<module>",
            description="Module has no docstring — add a brief description at the top",
            severity="info",
        ))

    # Check functions and classes
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name.startswith("_"):
                continue  # skip private

            docstring = ast.get_docstring(node)
            if not docstring:
                issues.append(DocAuditIssue(
                    issue_type="missing_docstring", file=rel, line=node.lineno,
                    name=node.name,
                    description=f"Public function '{node.name}()' has no docstring",
                    severity="low",
                ))
            else:
                # check for stale docstring — does it mention parameters that don't exist?
                args = [a.arg for a in node.args.args if a.arg != "self"]
                for arg in args:
                    if arg not in docstring and f":param {arg}" not in docstring:
                        # parameter not mentioned in docstring
                        pass  # too noisy — skip for now

                # check if docstring mentions parameters that NO LONGER exist
                param_mentions = re.findall(r':param\s+(\w+)', docstring)
                for mentioned in param_mentions:
                    if mentioned not in args and mentioned != "self":
                        issues.append(DocAuditIssue(
                            issue_type="stale_docstring", file=rel, line=node.lineno,
                            name=node.name,
                            description=f"Docstring mentions :param {mentioned} but function has no such parameter — docstring is stale",
                            severity="medium",
                        ))

        elif isinstance(node, ast.ClassDef):
            if node.name.startswith("_"):
                continue
            docstring = ast.get_docstring(node)
            if not docstring:
                issues.append(DocAuditIssue(
                    issue_type="missing_docstring", file=rel, line=node.lineno,
                    name=node.name,
                    description=f"Public class '{node.name}' has no docstring",
                    severity="low",
                ))

    # Check for TODO/FIXME/HACK comments
    for i, line in enumerate(source.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            lower = stripped.lower()
            if "todo" in lower:
                issues.append(DocAuditIssue(
                    issue_type="todo", file=rel, line=i,
                    name="<comment>",
                    description=f"TODO comment: {stripped[:100]}",
                    severity="info",
                ))
            elif "fixme" in lower:
                issues.append(DocAuditIssue(
                    issue_type="fixme", file=rel, line=i,
                    name="<comment>",
                    description=f"FIXME comment: {stripped[:100]}",
                    severity="low",
                ))
            elif "hack" in lower:
                issues.append(DocAuditIssue(
                    issue_type="hack", file=rel, line=i,
                    name="<comment>",
                    description=f"HACK comment: {stripped[:100]}",
                    severity="medium",
                ))

    return issues


def audit_repo(repo_root: Path, max_files: int = 100) -> List[DocAuditIssue]:
    """Audit all Python files for documentation issues."""
    skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules",
                 ".loomscan-cache", ".loomscan-reports", ".loomscan-fixes", "build", "dist"}
    issues: List[DocAuditIssue] = []
    count = 0
    for p in repo_root.rglob("*.py"):
        if any(part in skip_dirs for part in p.parts):
            continue
        if p.name.startswith("test_") or p.name.endswith("_test.py"):
            continue  # skip test files for doc audit
        issues.extend(audit_file(p, repo_root))
        count += 1
        if count >= max_files:
            break
    return issues


def doc_stats(issues: List[DocAuditIssue]) -> dict:
    """Return documentation audit statistics."""
    from collections import Counter
    by_type = Counter(i.issue_type for i in issues)
    by_severity = Counter(i.severity for i in issues)
    return {
        "total_issues": len(issues),
        "by_type": dict(by_type),
        "by_severity": dict(by_severity),
    }
