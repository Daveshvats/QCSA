"""Statistical Specification Mining — learn API usage patterns from code.

Inspired by Ammons et al. (ICSE 2002) and Whaley et al. (ICSE 2002).

The core idea: instead of hardcoding business state machines (order, payment,
user, subscription), MINE them from the codebase. If 95% of code calls
open() then close(), the 5% that doesn't is suspicious.

How it works:
  1. Scan all Python files for method call sequences on objects
  2. Build a probabilistic automaton: "open() is followed by close() 95% of the time"
  3. Learn state machines using frequency-based pattern mining
  4. Flag call sequences that deviate from the learned patterns
  5. Report as "unusual API usage pattern" findings

Example:
  If the codebase has 50 places that call cursor.execute(), and 48 of them
  are preceded by cursor.connect(), the 2 that aren't get flagged.

This makes the analyzer ADAPTIVE — it learns domain-specific patterns
from the actual codebase rather than relying on hardcoded rules.
"""
from __future__ import annotations

import ast
import re
from collections import defaultdict, Counter
from pathlib import Path
from typing import List, Optional, Dict, Set, Tuple
from dataclasses import dataclass


@dataclass
class MinedPattern:
    """A mined API usage pattern."""
    object_type: str  # e.g., "cursor", "file", "connection"
    sequence: Tuple[str, ...]  # e.g., ("connect", "execute", "close")
    frequency: int  # how many times this sequence appeared
    confidence: float  # frequency / total_sequences_for_this_object


@dataclass
class SpecViolation:
    """A call sequence that deviates from mined patterns."""
    file: str
    line: int
    object_type: str
    actual_sequence: Tuple[str, ...]
    expected_pattern: str
    description: str


def mine_api_patterns(repo_root: Path, max_files: int = 100) -> Dict[str, List[MinedPattern]]:
    """Mine API call patterns from the codebase.

    Returns a dict: object_variable_name -> list of MinedPatterns.

    For each variable (like "cursor", "file", "conn"), we track the
    sequence of methods called on it within each function, then find
    the most common sequences.
    """
    skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules",
                 ".loomscan-cache", "build", "dist", ".pytest_cache"}
    sequences: Dict[str, List[Tuple[str, ...]]] = defaultdict(list)

    count = 0
    for py_file in sorted(repo_root.rglob("*.py")):
        if any(part in skip_dirs for part in py_file.parts):
            continue
        if count >= max_files:
            break
        count += 1

        try:
            source = py_file.read_text(encoding="utf-8")
            tree = ast.parse(source)
        except Exception:
            continue

        # For each function, track method calls per variable
        for func in ast.walk(tree):
            if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            var_calls: Dict[str, List[Tuple[str, int]]] = defaultdict(list)

            for node in ast.walk(func):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    obj = node.func.value
                    method = node.func.attr
                    if isinstance(obj, ast.Name):
                        var_calls[obj.id].append((method, node.lineno))

            # Convert to sequences (ordered by line number)
            for var, calls in var_calls.items():
                calls.sort(key=lambda x: x[1])
                sequence = tuple(m for m, _ in calls)
                if len(sequence) >= 2:
                    sequences[var].append(sequence)

    # Mine patterns: find the most common sequences per variable
    patterns: Dict[str, List[MinedPattern]] = {}
    for var, seqs in sequences.items():
        if len(seqs) < 2:
            continue

        # Count sequence frequencies
        seq_counts = Counter(seqs)
        total = len(seqs)

        # Keep sequences that appear at least twice
        mined = []
        for seq, freq in seq_counts.most_common(10):
            if freq >= 2:
                mined.append(MinedPattern(
                    object_type=var,
                    sequence=seq,
                    frequency=freq,
                    confidence=freq / total,
                ))

        if mined:
            patterns[var] = mined

    return patterns


def check_spec_violations(repo_root: Path,
                           patterns: Dict[str, List[MinedPattern]],
                           max_files: int = 100,
                           min_confidence: float = 0.3) -> List[SpecViolation]:
    """Check the codebase for violations of mined patterns.

    A violation is a call sequence that deviates significantly from
    the mined patterns (e.g., missing a required close() after open()).

    v4.41: Added min_confidence parameter (default 0.3, was hardcoded 0.5).
    Lower values catch more violations but may produce false positives.
    Also added prefix-violation detection: if a sequence is a prefix of a
    strong pattern but the full pattern is significantly longer, flag it
    as a potential resource leak (e.g., open+read without close).
    """
    skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules",
                 ".loomscan-cache", "build", "dist", ".pytest_cache"}
    violations: List[SpecViolation] = []

    count = 0
    for py_file in sorted(repo_root.rglob("*.py")):
        if any(part in skip_dirs for part in py_file.parts):
            continue
        if count >= max_files:
            break
        count += 1

        try:
            source = py_file.read_text(encoding="utf-8")
            tree = ast.parse(source)
        except Exception:
            continue

        rel_path = str(py_file.relative_to(repo_root))

        for func in ast.walk(tree):
            if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            var_calls: Dict[str, List[Tuple[str, int]]] = defaultdict(list)
            for node in ast.walk(func):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    obj = node.func.value
                    method = node.func.attr
                    if isinstance(obj, ast.Name):
                        var_calls[obj.id].append((method, node.lineno))

            for var, calls in var_calls.items():
                calls.sort(key=lambda x: x[1])
                sequence = tuple(m for m, _ in calls)
                if len(sequence) < 2:
                    continue

                # Check against mined patterns for this variable name
                if var not in patterns:
                    continue

                mined_for_var = patterns[var]
                if not mined_for_var:
                    continue

                # v4.41: Use min_confidence instead of hardcoded 0.5
                strong_patterns = [p for p in mined_for_var if p.confidence >= min_confidence]
                if not strong_patterns:
                    continue

                # Check if this sequence matches any mined pattern
                # (as a subsequence or exact match)
                matches = False
                for pattern in mined_for_var:
                    if sequence == pattern.sequence:
                        matches = True
                        break
                    # Check if sequence is a subsequence of the pattern
                    if len(sequence) <= len(pattern.sequence):
                        if all(sequence[i] == pattern.sequence[i] for i in range(len(sequence))):
                            matches = True
                            break

                if not matches:
                    # This sequence doesn't match any common pattern
                    expected = strong_patterns[0].sequence
                    violations.append(SpecViolation(
                        file=rel_path,
                        line=calls[0][1],
                        object_type=var,
                        actual_sequence=sequence,
                        expected_pattern=f"{' → '.join(expected)}",
                        description=f"Unusual method sequence on '{var}': "
                                    f"{' → '.join(sequence)} (expected: {' → '.join(expected)})",
                    ))
                else:
                    # v4.41: Prefix-violation detection
                    # If the sequence is a prefix of a strong pattern but
                    # the strong pattern is significantly longer (>= 3 more
                    # methods), flag it as a potential resource leak.
                    for pattern in strong_patterns:
                        if len(sequence) < len(pattern.sequence) and len(sequence) >= 2:
                            # Check if sequence is a prefix of the pattern
                            is_prefix = all(sequence[i] == pattern.sequence[i]
                                          for i in range(len(sequence)))
                            if is_prefix and len(pattern.sequence) - len(sequence) >= 1:
                                # The sequence is a prefix — missing methods
                                missing = pattern.sequence[len(sequence):]
                                violations.append(SpecViolation(
                                    file=rel_path,
                                    line=calls[-1][1],
                                    object_type=var,
                                    actual_sequence=sequence,
                                    expected_pattern=f"{' → '.join(pattern.sequence)}",
                                    description=f"Incomplete method sequence on '{var}': "
                                                f"missing {' → '.join(missing)} after "
                                                f"{' → '.join(sequence)}",
                                ))
                                break  # only flag once per sequence

    return violations


def mine_and_check(repo_root: Path,
                   min_confidence: float = 0.3) -> Tuple[Dict[str, List[MinedPattern]], List[SpecViolation]]:
    """Mine patterns and check for violations in one call.

    v4.41: Added min_confidence parameter (default 0.3, was hardcoded 0.5).
    """
    patterns = mine_api_patterns(repo_root)
    violations = check_spec_violations(repo_root, patterns, min_confidence=min_confidence)
    return patterns, violations
