"""Tree-sitter based diff slicing.

Given a git diff, extract the changed *functions* (not just lines) and their
1-hop callees. This is the single biggest efficiency win for the pipeline —
layers review 20 lines instead of 800.
"""
from __future__ import annotations

import subprocess
import re
from pathlib import Path
from typing import List, Optional, Set, Tuple

from .models import DiffHunk

# tree-sitter is optional at runtime — degrade gracefully if not installed.
try:
    import tree_sitter_python as tspython
    import tree_sitter_javascript as tsjs
    from tree_sitter import Language, Parser, Node
    _HAS_TS = True
except ImportError:
    _HAS_TS = False

# Optional language packs — degrade gracefully if missing
try:
    import tree_sitter_go as tsgo
    _HAS_GO = True
except ImportError:
    _HAS_GO = False

try:
    import tree_sitter_java as tsjava
    _HAS_JAVA = True
except ImportError:
    _HAS_JAVA = False

try:
    import tree_sitter_c as tsc
    _HAS_C = True
except ImportError:
    _HAS_C = False

try:
    import tree_sitter_cpp as tscpp
    _HAS_CPP = True
except ImportError:
    _HAS_CPP = False


LANG_BY_EXT = {
    ".py":   ("python", "tspython"),
    ".js":   ("javascript", "tsjs"),
    ".ts":   ("javascript", "tsjs"),
    ".jsx":  ("javascript", "tsjs"),
    ".tsx":  ("javascript", "tsjs"),
    ".go":   ("go", "tsgo"),
    ".java": ("java", "tsjava"),
    ".c":    ("c", "tsc"),
    ".h":    ("c", "tsc"),
    ".cpp":  ("cpp", "tscpp"),
    ".cc":   ("cpp", "tscpp"),
    ".cxx":  ("cpp", "tscpp"),
    ".hpp":  ("cpp", "tscpp"),
    ".hxx":  ("cpp", "tscpp"),
    ".rs":   ("rust", "tsrust"),  # v4.15: Add Rust support (was missing since v4.7)
}


# --- git diff parsing --------------------------------------------------------

_DIFF_FILE_HEADER = re.compile(r"^diff --git a/(.+?) b/(.+?)$")
_DIFF_HUNK_HEADER = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def run_git(repo_root: Path, *args: str) -> str:
    try:
        out = subprocess.run(
            ["git", "-C", str(repo_root), *args],
            capture_output=True, text=True, check=False, timeout=30,
        )
        return out.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""


def get_diff(repo_root: Path, base: str = "HEAD", staged: bool = False) -> str:
    """Return the unified diff. If `staged`, diff against the index."""
    if staged:
        return run_git(repo_root, "diff", "--cached")
    return run_git(repo_root, "diff", base)


def parse_diff(diff_text: str) -> List[DiffHunk]:
    """Parse unified diff into DiffHunk objects.

    Each hunk captures the file, line range, and added/removed lines.
    Function-name resolution happens in a second pass via tree-sitter.
    """
    hunks: List[DiffHunk] = []
    current_file: Optional[str] = None

    for line in diff_text.splitlines():
        m_file = _DIFF_FILE_HEADER.match(line)
        if m_file:
            current_file = m_file.group(2)
            continue

        m_hunk = _DIFF_HUNK_HEADER.match(line)
        if m_hunk and current_file:
            new_start = int(m_hunk.group(3))
            new_count = int(m_hunk.group(4) or "1")
            hunks.append(DiffHunk(
                file=current_file,
                start_line=new_start,
                end_line=new_start + max(new_count - 1, 0),
            ))
            continue

        if hunks and line.startswith("+") and not line.startswith("+++"):
            hunks[-1].added_lines.append(line[1:])
        elif hunks and line.startswith("-") and not line.startswith("---"):
            hunks[-1].removed_lines.append(line[1:])

    return hunks


# --- tree-sitter function resolution ----------------------------------------

def _build_parsers() -> dict:
    if not _HAS_TS:
        return {}
    parsers = {}
    try:
        parsers["python"] = Parser(Language(tspython.language()))
    except Exception:
        pass
    try:
        parsers["javascript"] = Parser(Language(tsjs.language()))
    except Exception:
        pass
    if _HAS_GO:
        try:
            parsers["go"] = Parser(Language(tsgo.language()))
        except Exception:
            pass
    if _HAS_JAVA:
        try:
            parsers["java"] = Parser(Language(tsjava.language()))
        except Exception:
            pass
    if _HAS_C:
        try:
            parsers["c"] = Parser(Language(tsc.language()))
        except Exception:
            pass
    if _HAS_CPP:
        try:
            parsers["cpp"] = Parser(Language(tscpp.language()))
        except Exception:
            pass
    return parsers


_PARSERS = _build_parsers()


# function-definition node types per language
_FUNC_NODE_TYPES = {
    "python": {"function_definition"},
    "javascript": {"function_declaration", "method_definition", "arrow_function"},
    "go": {"function_declaration", "method_declaration"},
    "java": {"method_declaration", "constructor_declaration"},
    "c": {"function_definition"},
    "cpp": {"function_definition", "function_declaration"},
}


def find_function_for_line(file_path: Path, target_line: int, lang: str) -> Tuple[Optional[str], Optional[str]]:
    """Return (function_name, function_body) for the function containing target_line.

    Uses tree-sitter. Returns (None, None) if not available or not found.
    """
    if not _HAS_TS or lang not in _PARSERS or not file_path.exists():
        return None, None

    try:
        source = file_path.read_bytes()
        tree = _PARSERS[lang].parse(source)
        root = tree.root_node

        # find smallest function-def node containing the target line
        best: Optional[Node] = None
        def walk(node: Node):
            nonlocal best
            if node.type in _FUNC_NODE_TYPES.get(lang, set()):
                if node.start_byte < len(source) and node.start_point[0] + 1 <= target_line <= node.end_point[0] + 1:
                    # prefer the most specific (deepest) match
                    if best is None or (node.end_point[0] - node.start_point[0]) < (best.end_point[0] - best.start_point[0]):
                        best = node
            for child in node.children:
                walk(child)
        walk(root)

        if best is None:
            return None, None

        # extract function name
        name_node = best.child_by_field_name("name")
        name = source[name_node.start_byte:name_node.end_byte].decode("utf-8", errors="replace") if name_node else "<anonymous>"
        body = source[best.start_byte:best.end_byte].decode("utf-8", errors="replace")
        return name, body
    except Exception:
        return None, None


def resolve_functions(repo_root: Path, hunks: List[DiffHunk]) -> List[DiffHunk]:
    """Enrich each hunk with its enclosing function name and body."""
    for hunk in hunks:
        file_path = repo_root / hunk.file
        ext = file_path.suffix.lower()
        if ext in LANG_BY_EXT:
            lang = LANG_BY_EXT[ext][0]
            name, body = find_function_for_line(file_path, hunk.start_line, lang)
            hunk.function_name = name
            hunk.function_body = body
    return hunks


def extract_callees(function_body: str, lang: str) -> Set[str]:
    """Cheap regex-based callee extraction. Good enough for 1-hop reachability.

    For real cross-file resolution we'd use tree-sitter stack-graphs, but that's
    a heavy dependency. This catches the common case (direct calls in the function body).
    """
    if not function_body:
        return set()
    if lang == "python":
        # match `name(...)` — simple but effective
        return set(re.findall(r"\b([a-z_][a-z0-9_]*)\s*\(", function_body, re.IGNORECASE))
    if lang == "javascript":
        return set(re.findall(r"\b([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(", function_body))
    return set()


def slice_diff(repo_root: Path, base: str = "HEAD", staged: bool = False) -> List[DiffHunk]:
    """End-to-end: git diff → parse → resolve functions → return hunks."""
    diff_text = get_diff(repo_root, base=base, staged=staged)
    if not diff_text:
        return []
    hunks = parse_diff(diff_text)
    hunks = resolve_functions(repo_root, hunks)
    return hunks
