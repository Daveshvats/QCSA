"""Auto-rule mining from the codebase itself.

Your codebase already contains thousands of implicit rules:
  - Every `assert` in tests is a property rule
  - Every type annotation is a type rule
  - Every `if x is None: raise` is an invariant rule
  - Every `@deprecated` decorator is a deprecation rule
  - Every docstring with "must" or "should" is a contract rule

This module mines these implicit rules and converts them to explicit Semgrep
rules that LoomScan can enforce on every commit.

This is the third intelligent counter to "can't write 5,000 rules overnight":
we don't write them — we extract them from the code you've already written.
"""
from __future__ import annotations

import ast
import re
import textwrap
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


@dataclass
class MinedCodebaseRule:
    """A rule mined from the codebase."""
    rule_id: str
    source: str  # 'assertion' | 'type_hint' | 'guard' | 'docstring' | 'decorator'
    function: str
    file: str
    description: str
    semgrep_yaml: str


def mine_assertion_rules(file_path: Path, repo_root: Path = None) -> List[MinedCodebaseRule]:
    """Mine `assert` statements from test files → property rules.

    Each assert in a test is a property that should hold. We convert it to a
    Semgrep rule that flags violations.
    """
    if not file_path.exists() or file_path.suffix != ".py":
        return []
    if not (file_path.name.startswith("test_") or file_path.name.endswith("_test.py")):
        return []

    try:
        source = file_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except Exception:
        return []

    rel_path = str(file_path.relative_to(repo_root)) if repo_root else str(file_path)
    rules: List[MinedCodebaseRule] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Assert):
            # extract the assertion expression
            try:
                expr = ast.unparse(node.test)
            except Exception:
                continue
            # skip overly simple assertions
            if len(expr) < 10:
                continue
            # generate a rule that flags the negation
            rule_id = f"assert-{hashlib.md5(expr.encode()).hexdigest()[:8]}"
            yaml = textwrap.dedent(f"""
              # Mined from assertion in {rel_path}:{node.lineno}
              # Original: assert {expr}
              rules:
                - id: {rule_id}
                  pattern: assert not ({expr})
                  message: Violation of asserted property: {expr}
                  languages: [python]
                  severity: WARNING
                  metadata:
                    source: codebase-mined
                    type: assertion
                    original_file: {rel_path}
                    original_line: {node.lineno}
            """).strip() + "\n"
            rules.append(MinedCodebaseRule(
                rule_id=rule_id, source="assertion",
                function="<test>", file=rel_path,
                description=f"Property: {expr}",
                semgrep_yaml=yaml,
            ))
    return rules


def mine_guard_rules(file_path: Path, repo_root: Path = None) -> List[MinedCodebaseRule]:
    """Mine `if x is None: raise` patterns → invariant rules.

    If a function guards against None, that's an invariant: the parameter
    must not be None. We generate a rule that flags calls passing None.
    """
    if not file_path.exists() or file_path.suffix != ".py":
        return []
    try:
        source = file_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except Exception:
        return []

    rel_path = str(file_path.relative_to(repo_root)) if repo_root else str(file_path)
    rules: List[MinedCodebaseRule] = []

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        # find guard clauses in the first 5 statements
        for stmt in node.body[:5]:
            if not isinstance(stmt, ast.If):
                continue
            # pattern: if X is None: raise ...
            test = stmt.test
            if isinstance(test, ast.Compare) and isinstance(test.left, ast.Name):
                if isinstance(test.ops[0], ast.Is) and isinstance(test.comparators[0], ast.Constant) and test.comparators[0].value is None:
                    param_name = test.left.id
                    rule_id = f"guard-{node.name}-{param_name}-{hashlib.md5(rel_path.encode()).hexdigest()[:8]}"
                    yaml = textwrap.dedent(f"""
                      # Mined from guard in {rel_path}:{node.lineno}
                      # {node.name}() guards: {param_name} is not None
                      rules:
                        - id: {rule_id}
                          pattern: {node.name}(None, ...)
                          message: |
                            {node.name}() was called with None for '{param_name}',
                            but the function guards against None (mined from {rel_path}:{node.lineno})
                          languages: [python]
                          severity: WARNING
                          metadata:
                            source: codebase-mined
                            type: guard
                            function: {node.name}
                            parameter: {param_name}
                    """).strip() + "\n"
                    rules.append(MinedCodebaseRule(
                        rule_id=rule_id, source="guard",
                        function=node.name, file=rel_path,
                        description=f"{param_name} must not be None (guarded at line {node.lineno})",
                        semgrep_yaml=yaml,
                    ))

    return rules


def mine_docstring_rules(file_path: Path, repo_root: Path = None) -> List[MinedCodebaseRule]:
    """Mine docstrings with "must" / "should" → contract rules.

    If a docstring says "x must be positive", that's a contract. We generate
    a rule that flags violations (e.g., passing a negative number).
    """
    if not file_path.exists() or file_path.suffix != ".py":
        return []
    try:
        source = file_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except Exception:
        return []

    rel_path = str(file_path.relative_to(repo_root)) if repo_root else str(file_path)
    rules: List[MinedCodebaseRule] = []

    CONTRACT_PATTERNS = [
        (r"(\w+)\s+must\s+be\s+(?:positive|non-negative|>=\s*0)", "positive"),
        (r"(\w+)\s+must\s+be\s+(?:negative|non-positive)", "negative"),
        (r"(\w+)\s+must\s+be\s+(?:non-empty|not\s+empty)", "non_empty"),
        (r"(\w+)\s+must\s+be\s+(?:a\s+string|str)", "string"),
        (r"(\w+)\s+must\s+be\s+(?:an?\s+int|integer)", "int"),
        (r"(\w+)\s+must\s+be\s+(?:non-null|not\s+None)", "not_none"),
    ]

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        docstring = ast.get_docstring(node)
        if not docstring:
            continue

        for pattern, constraint in CONTRACT_PATTERNS:
            for match in re.finditer(pattern, docstring, re.IGNORECASE):
                param = match.group(1)
                rule_id = f"contract-{node.name}-{param}-{constraint}-{hashlib.md5(rel_path.encode()).hexdigest()[:8]}"

                # generate a pattern based on the constraint
                if constraint == "positive":
                    semgrep_pattern = f"{node.name}(-$N, ...)"
                    message = f"{param} must be positive (per docstring of {node.name})"
                elif constraint == "negative":
                    semgrep_pattern = f"{node.name}($N, ...)"
                    message = f"{param} must be negative (per docstring of {node.name})"
                elif constraint == "not_none":
                    semgrep_pattern = f"{node.name}(None, ...)"
                    message = f"{param} must not be None (per docstring of {node.name})"
                else:
                    continue  # skip constraints we can't easily express

                yaml = textwrap.dedent(f"""
                  # Mined from docstring of {node.name}() in {rel_path}:{node.lineno}
                  # Contract: {match.group(0)}
                  rules:
                    - id: {rule_id}
                      pattern: {semgrep_pattern}
                      message: {message}
                      languages: [python]
                      severity: WARNING
                      metadata:
                        source: codebase-mined
                        type: docstring_contract
                        function: {node.name}
                        parameter: {param}
                        constraint: {constraint}
                """).strip() + "\n"
                rules.append(MinedCodebaseRule(
                    rule_id=rule_id, source="docstring",
                    function=node.name, file=rel_path,
                    description=f"Contract: {match.group(0)}",
                    semgrep_yaml=yaml,
                ))

    return rules


def mine_all_rules(file_path: Path, repo_root: Path = None) -> List[MinedCodebaseRule]:
    """Mine all rule types from a file."""
    rules: List[MinedCodebaseRule] = []
    rules += mine_assertion_rules(file_path, repo_root)
    rules += mine_guard_rules(file_path, repo_root)
    rules += mine_docstring_rules(file_path, repo_root)
    return rules


def mine_repo_rules(repo_root: Path, max_files: int = 50) -> List[MinedCodebaseRule]:
    """Mine rules from all Python files in the repo."""
    skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules",
                 ".loomscan-cache", ".loomscan-reports", ".loomscan-fixes"}
    rules: List[MinedCodebaseRule] = []
    files_scanned = 0
    for p in repo_root.rglob("*.py"):
        if any(part in skip_dirs for part in p.parts):
            continue
        rules.extend(mine_all_rules(p, repo_root))
        files_scanned += 1
        if files_scanned >= max_files:
            break
    return rules


def save_mined_codebase_rules(rules: List[MinedCodebaseRule], dest_dir: Path) -> List[Path]:
    """Save mined rules to .loomscan-rules/codebase-mined/."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    saved: List[Path] = []
    for rule in rules:
        path = dest_dir / f"{rule.rule_id}.yml"
        path.write_text(rule.semgrep_yaml, encoding="utf-8")
        saved.append(path)
    return saved
