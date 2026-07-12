"""Shared text utilities — consolidated from concurrency.py + js_quality.py + learning.py."""
from __future__ import annotations


def extract_block(source: str, start: int) -> str:
    """Extract a balanced brace-delimited block starting at position `start`."""
    if start >= len(source) or source[start] != '{':
        return ""
    depth = 0
    end = start
    in_string = False
    string_char = None
    i = start
    while i < len(source):
        ch = source[i]
        if in_string:
            if ch == '\\':
                i += 2
                continue
            if ch == string_char:
                in_string = False
                string_char = None
        else:
            if ch in ('"', "'", '`'):
                in_string = True
                string_char = ch
            elif ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        i += 1
    return source[start:end]


def parse_python_file(file_path):
    """Shared Python file parser."""
    import ast
    if not file_path.exists() or file_path.suffix != ".py":
        return None, None
    try:
        source = file_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except Exception:
        return None, None
    return source, tree


def read_source(file_path):
    """Shared file reader."""
    try:
        return file_path.read_text(encoding="utf-8")
    except Exception:
        return None
