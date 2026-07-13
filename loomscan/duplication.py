"""Code duplication detection (CPD-style token-based).

Finds duplicated code blocks >= N tokens across the codebase. Useful for
identifying refactoring opportunities and detecting copy-paste bugs.

Algorithm: tokenize each file, hash sliding windows of N tokens, find
collisions. O(n) time, ~constant memory.
"""
from __future__ import annotations

import re
import hashlib
from pathlib import Path
from typing import List, Dict, Tuple, Set
from dataclasses import dataclass


@dataclass
class Duplication:
    file_a: str
    start_a: int
    file_b: str
    start_b: int
    length: int
    snippet: str


MIN_TOKENS = 40  # ~5-8 lines of code


def tokenize_python(source: str) -> List[Tuple[str, int]]:
    """Tokenize Python source. Returns list of (token, line_number)."""
    import ast
    tokens: List[Tuple[str, int]] = []
    try:
        tree = ast.parse(source)
        # walk and collect normalized tokens
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                tokens.append(("NAME", node.lineno))
            elif isinstance(node, ast.Constant):
                tokens.append(("CONST", node.lineno))
            elif isinstance(node, ast.arg):
                tokens.append(("ARG", node.lineno))
    except SyntaxError:
        # fall back to regex tokenization
        for i, line in enumerate(source.splitlines(), 1):
            for tok in re.findall(r"\w+|[^\s\w]", line):
                tokens.append((tok, i))
    return tokens


def tokenize_text(source: str) -> List[Tuple[str, int]]:
    """Generic tokenization for any language (regex-based)."""
    tokens: List[Tuple[str, int]] = []
    KEYWORDS = {"if", "else", "elif", "for", "while", "def", "class",
                "return", "import", "from", "try", "except", "finally",
                "with", "as", "in", "not", "and", "or", "is", "None",
                "True", "False", "lambda", "yield", "raise", "pass",
                "break", "continue", "global", "nonlocal", "del"}
    for i, line in enumerate(source.splitlines(), 1):
        for tok in re.findall(r"\w+|[^\s\w]", line):
            # normalize identifiers (replace with placeholder)
            if re.match(r"^[a-zA-Z_]\w*$", tok) and tok not in KEYWORDS:
                tokens.append(("ID", i))
            else:
                tokens.append((tok, i))
    return tokens


def find_duplicates(repo_root: Path, min_tokens: int = MIN_TOKENS) -> List[Duplication]:
    """Find duplicated code blocks across all source files in the repo."""
    skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules",
                 ".loomscan-cache", ".loomscan-reports", ".loomscan-fixes", "dist", "build"}
    files: List[Path] = []
    for p in repo_root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in skip_dirs for part in p.parts):
            continue
        if p.suffix in (".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".java", ".c", ".cpp", ".h"):
            files.append(p)

    # tokenize each file
    file_tokens: Dict[str, List[Tuple[str, int]]] = {}
    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
            if f.suffix == ".py":
                tokens = tokenize_python(text)
            else:
                tokens = tokenize_text(text)
            file_tokens[str(f.relative_to(repo_root))] = tokens
        except Exception:
            continue

    # sliding window hash
    windows: Dict[str, List[Tuple[str, int, int]]] = {}  # hash → [(file, start_line, length)]
    for file, tokens in file_tokens.items():
        for i in range(len(tokens) - min_tokens):
            window = tuple(t[0] for t in tokens[i:i + min_tokens])
            h = hashlib.sha256("|".join(window).encode()).hexdigest()[:16]
            start_line = tokens[i][1]
            windows.setdefault(h, []).append((file, start_line, min_tokens))

    # find collisions across files
    duplicates: List[Duplication] = []
    seen_pairs: Set[Tuple] = set()
    for h, locations in windows.items():
        if len(locations) < 2:
            continue
        # group by file to find cross-file duplicates
        for i, (file_a, line_a, _) in enumerate(locations):
            for file_b, line_b, _ in locations[i+1:]:
                if file_a == file_b and abs(line_a - line_b) < min_tokens:
                    continue  # same file, adjacent — not a duplicate
                pair_key = tuple(sorted([(file_a, line_a), (file_b, line_b)]))
                if pair_key in seen_pairs:
                    continue
                seen_pairs.add(pair_key)
                # extract snippet
                try:
                    snippet_lines = file_tokens[file_a][i:i+min_tokens]
                    snippet = " ".join(t[0] for t in snippet_lines)[:120]
                except Exception:
                    snippet = ""
                duplicates.append(Duplication(
                    file_a=file_a, start_a=line_a,
                    file_b=file_b, start_b=line_b,
                    length=min_tokens,
                    snippet=snippet,
                ))

    # cap to top 20 to avoid noise
    return sorted(duplicates, key=lambda d: (d.file_a, d.start_a))[:20]
