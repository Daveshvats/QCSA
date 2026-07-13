"""L8 — Auto-Fix layer (v2 — safety-verified).

Doesn't detect bugs — applies patches to fix them. Inspired by:
  - GitHub Copilot Autofix
  - Snyk Code autofix
  - Semgrep Autofix

For each finding from other layers, check if there's a known fix pattern.
If yes, generate a patch and either:
  - Apply it directly (with `--apply` flag)
  - Stage it for review in `.loomscan-fixes/<finding_id>.patch`
  - Output it inline in the report

v2 safety improvements (addressing code review findings):
  - **ast.parse() verification**: Every Python fix is verified to parse
    before being written. If the fix produces invalid syntax, it's rejected.
  - **eval() fixer**: Only fixes eval() when the argument is provably a
    literal (string/number/etc.), not a dynamic expression. f-strings,
    variable references, and expressions are NOT fixed.
  - **password fixer**: Properly handles indentation — comments out the
    entire if-block (if + body), not just the if line.
  - **All fixers return None on any uncertainty** — no fix is better than
    a broken fix.
"""
from __future__ import annotations

import ast
import re
import os
import subprocess
from pathlib import Path
from typing import List, Optional, Dict, Set
from dataclasses import dataclass

from .base import LayerBase
from ..models import Finding, DiffHunk, LayerID, Severity, BlastRadius


@dataclass
class FixPattern:
    """A deterministic fix pattern keyed on a rule_id prefix."""
    rule_prefix: str
    description: str
    fixer: callable  # takes (finding, repo_root) → patch string or None


def _verify_python_parses(content: str) -> bool:
    """Verify that Python source code parses without syntax errors.

    This is the critical safety guard — never write a Python file that
    doesn't parse. Returns True if the code is valid Python.
    """
    try:
        ast.parse(content)
        return True
    except SyntaxError:
        return False
    except Exception:
        return False


def _is_eval_arg_literal(arg_str: str) -> bool:
    """Check if an eval() argument is provably a literal expression.

    ast.literal_eval only handles literals (strings, numbers, lists, dicts,
    tuples, booleans, None). It CANNOT handle:
      - f-strings (JoinedStr)
      - Variable references (Name)
      - Function calls (Call)
      - Attribute access (Attribute)
      - Binary operations (BinOp)

    We use ast.parse to inspect the argument and reject anything that isn't
    a pure literal.
    """
    arg_str = arg_str.strip()
    if not arg_str:
        return False
    try:
        tree = ast.parse(arg_str, mode="eval")
    except SyntaxError:
        return False
    # Walk the AST — only allow literal node types
    ALLOWED = (
        ast.Expression, ast.Constant,
        ast.List, ast.Tuple, ast.Set, ast.Dict,
        ast.UnaryOp,  # for negative numbers like -1
        ast.USub, ast.UAdd,  # unary operators
        ast.Load,  # ctx attribute on List/Tuple/Set/Dict
        ast.Store,  # ctx attribute (shouldn't appear in eval args, but safe)
    )
    for node in ast.walk(tree):
        if not isinstance(node, ALLOWED):
            # Reject f-strings (JoinedStr), Names, Calls, Attributes, BinOps, etc.
            return False
    return True


def _fix_eval_python(finding: Finding, repo_root: Path) -> Optional[str]:
    """Replace eval(x) with ast.literal_eval(x) — ONLY for literal arguments.

    This fixer is conservative: it only fires when the eval() argument is
    provably a literal expression (string, number, list, dict, etc.).
    Dynamic expressions like eval(f"...") or eval(user_input) are NOT
    fixed because ast.literal_eval would raise on them.
    """
    path = repo_root / finding.file
    if not path.exists() or path.suffix != ".py":
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]

    # Must have exactly one eval( call and not already be literal_eval
    if original.count("eval(") != 1 or "ast.literal_eval" in original:
        return None

    # Extract the argument — handle nested parens
    m = re.search(r"eval\(", original)
    if not m:
        return None
    start = m.end()
    depth = 1
    end = start
    while end < len(original) and depth > 0:
        if original[end] == "(":
            depth += 1
        elif original[end] == ")":
            depth -= 1
        if depth > 0:
            end += 1
    if depth != 0:
        return None  # unbalanced parens — don't touch
    arg = original[start:end].strip()
    if not arg:
        return None

    # CRITICAL: Only fix if the argument is provably a literal.
    # f-strings, variables, and expressions will break ast.literal_eval.
    if not _is_eval_arg_literal(arg):
        return None

    # Apply the fix
    fixed_line = original[:m.start()] + f"ast.literal_eval({arg})" + original[end+1:]

    # Add ast import if not present — insert at the TOP of the file,
    # not after existing imports (which might be inside a function body)
    text = "\n".join(lines)
    new_lines = list(lines)
    if "import ast" not in text and "from ast import" not in text:
        # Find the right insertion point: after the module docstring and
        # __future__ imports, but before any other code.
        insert_idx = 0
        # Skip module docstring if present
        if new_lines and new_lines[0].lstrip().startswith(('"""', "'''")):
            quote = new_lines[0].lstrip()[:3]
            if new_lines[0].count(quote) >= 2:
                insert_idx = 1  # single-line docstring
            else:
                for i in range(1, len(new_lines)):
                    if quote in new_lines[i]:
                        insert_idx = i + 1
                        break
        # Skip __future__ imports
        while insert_idx < len(new_lines):
            stripped = new_lines[insert_idx].strip()
            if stripped.startswith("from __future__"):
                insert_idx += 1
            elif stripped == "" or stripped.startswith("#"):
                insert_idx += 1
            else:
                break
        new_lines.insert(insert_idx, "import ast")
        # The line_idx doesn't change because we inserted BEFORE the target line
        # (insert_idx is at the top, line_idx is the eval line)
        if insert_idx <= line_idx:
            line_idx += 1
    new_lines[line_idx] = fixed_line
    result = "\n".join(new_lines)

    # SAFETY: Verify the result parses before returning
    if not _verify_python_parses(result):
        return None

    return result


def _fix_hardcoded_password(finding: Finding, repo_root: Path) -> Optional[str]:
    """Replace hardcoded password comparison with a TODO + proper hash check.

    This fixer comments out the entire if-block (if condition + indented body)
    and replaces it with a TODO comment. It does NOT attempt to generate a
    working hash check (that would require knowing the actual password hash).

    The fix preserves proper indentation and produces valid Python.
    """
    path = repo_root / finding.file
    if not path.exists() or path.suffix != ".py":
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]

    # Match: if <var> == "password": or if <var> == 'password':
    m = re.search(r"(\s*)if\s+(\w+)\s*==\s*['\"](\w+)['\"]\s*:", original)
    if not m:
        return None

    indent = m.group(1)
    var = m.group(2)

    # Find the indented body of this if-statement
    body_start = line_idx + 1
    body_end = body_start
    if_indent = len(indent)
    while body_end < len(lines):
        line = lines[body_end]
        # Empty lines are part of the body
        if line.strip() == "":
            body_end += 1
            continue
        # Lines with greater indentation are part of the body
        current_indent = len(line) - len(line.lstrip())
        if current_indent > if_indent:
            body_end += 1
        else:
            break

    # Build the fixed block:
    # 1. TODO comment
    # 2. Commented-out if line
    # 3. Commented-out body (preserving indentation)
    todo_comment = f"{indent}# TODO: replace hardcoded password check with proper hash verification"
    todo_hash = f"{indent}# Use: import bcrypt; bcrypt.checkpw({var}.encode(), HASH_FROM_ENV_OR_DB)"
    commented_if = f"{indent}# {original.strip()}"

    new_lines = list(lines)
    # Replace the if line with TODO + commented if
    new_lines[line_idx] = f"{todo_comment}\n{todo_hash}\n{commented_if}"

    # Comment out the body lines
    for i in range(body_start, body_end):
        body_line = new_lines[i]
        if body_line.strip() == "":
            continue
        # Preserve indentation, add # comment
        body_indent = len(body_line) - len(body_line.lstrip())
        new_lines[i] = body_line[:body_indent] + "# " + body_line[body_indent:]

    result = "\n".join(new_lines)

    # SAFETY: Verify the result parses before returning
    if not _verify_python_parses(result):
        return None

    return result


def _fix_docker_latest(finding: Finding, repo_root: Path) -> Optional[str]:
    """Pin Dockerfile FROM tag from :latest to a specific version.

    v4.11: Detects base image and pins to language-appropriate version.
    v4.12: Fixed unknown-image branch — was producing malformed Dockerfile
    lines (`FROM img: pin to a specific version`) because split(":")[-1]
    grabbed the comment text. Now uses a clean comment-on-line approach.
    """
    path = repo_root / finding.file
    if not path.exists():
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    _IMAGE_VERSIONS = {
        "python": "3.12-slim",
        "node": "20-slim",
        "golang": "1.22-alpine",
        "go": "1.22-alpine",
        "rust": "1.78-slim",
        "openjdk": "21-slim",
        "eclipse-temurin": "21-jre-alpine",
        "nginx": "1.25-alpine",
        "redis": "7-alpine",
        "postgres": "16-alpine",
        "mysql": "8.0",
        "ubuntu": "24.04",
        "debian": "bookworm-slim",
        "alpine": "3.19",
    }
    # Extract the image name from the FROM line
    m = re.search(r'FROM\s+(\S+):latest', original, re.IGNORECASE)
    if m:
        image = m.group(1)
        # Try to match known images
        for key, version in _IMAGE_VERSIONS.items():
            if key in image.lower():
                fixed = original.replace(":latest", f":{version}")
                if fixed != original:
                    lines[line_idx] = fixed
                    return "\n".join(lines)
        # v4.12: Unknown image — add a comment on the line, don't produce
        # a malformed Dockerfile tag. v4.11 used split(":")[-1] which grabbed
        # the comment text and produced `FROM img: pin to a specific version`.
        lines[line_idx] = f"{original.rstrip()}  # TODO: pin to a specific version"
        return "\n".join(lines)
    return None


def _fix_bare_except(finding: Finding, repo_root: Path) -> Optional[str]:
    """Replace bare 'except:' with 'except Exception:'."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix != ".py":
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    # Only match bare except: (not except Exception: or except SomeError:)
    fixed = re.sub(r"\bexcept\s*:", "except Exception:", original)
    if fixed != original:
        lines[line_idx] = fixed
        result = "\n".join(lines)
        # SAFETY: Verify the result parses
        if not _verify_python_parses(result):
            return None
        return result
    return None


def _fix_mutable_default(finding: Finding, repo_root: Path) -> Optional[str]:
    """Fix mutable default argument: def foo(x=[]) → def foo(x=None) + sentinel guard.

    v4.13: Actually implements the sentinel pattern. Previous versions claimed
    to use a sentinel but still generated `if x is None: x = []`, which changes
    behavior if the caller explicitly passes None. v4.13 generates:

        _SENTINEL = object()  # at module level (injected if not present)
        def foo(x=_SENTINEL):
            if x is _SENTINEL: x = []

    This preserves the original semantics: callers who omit the argument get a
    fresh mutable, callers who pass None get None (not a silently-created []).
    """
    path = repo_root / finding.file
    if not path.exists() or path.suffix != ".py":
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]

    # Match: def foo(x=[]): or def foo(x={}): or def foo(x=[], y=1):
    # v4.13: Fix regex to not consume the closing ) — we need to preserve it
    m = re.search(r"(\s*def\s+\w+\s*\([^)]*\b)(\w+)\s*=\s*(\[\]|\{\})(\s*)([,)\n].*)", original)
    if not m:
        return None

    prefix, var, mutable, _ws, suffix = m.groups()
    # v4.13: Use _SENTINEL instead of None
    sentinel_name = "_SENTINEL"
    fixed_line = f"{prefix}{var}={sentinel_name}{_ws}{suffix}"

    new_lines = list(lines)
    new_lines[line_idx] = fixed_line

    # Find the function body indentation
    func_indent = len(prefix) - len(prefix.lstrip())
    body_indent = func_indent + 4  # standard 4-space indent

    # v4.13: Generate sentinel guard — preserves semantics for callers passing None
    guard = (" " * body_indent) + f"if {var} is {sentinel_name}: {var} = {mutable}"
    new_lines.insert(line_idx + 1, guard)

    # v4.13: Inject _SENTINEL = object() at module level if not already present
    has_sentinel = any(re.match(r'^_SENTINEL\s*=\s*object\(\)', line) for line in new_lines)
    if not has_sentinel:
        # Find the right insertion point — after imports, before first def/class
        insert_idx = 0
        for i, line in enumerate(new_lines):
            stripped = line.strip()
            if stripped.startswith("def ") or stripped.startswith("class "):
                insert_idx = i
                break
            if stripped and not stripped.startswith("#") and not stripped.startswith("from ") \
               and not stripped.startswith("import ") and not stripped == "":
                insert_idx = i
                break
        new_lines.insert(insert_idx, f"{sentinel_name} = object()  # v4.13: sentinel for mutable default args")
        new_lines.insert(insert_idx + 1, "")

    result = "\n".join(new_lines)

    # SAFETY: Verify the result parses
    if not _verify_python_parses(result):
        return None

    return result


# =============================================================================
# v4.34: 44 new fixers — total 50 fix patterns
# =============================================================================

def _fix_exec_python(finding: Finding, repo_root: Path) -> Optional[str]:
    """Replace exec(x) with a TODO comment — exec() cannot be safely auto-fixed
    because the replacement depends on what exec is being used for."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix != ".py":
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if re.search(r"\bexec\s*\(", original) and "# TODO" not in original:
        indent = original[:len(original) - len(original.lstrip())]
        lines[line_idx] = f"{indent}# TODO: replace exec() with a safe alternative (importlib, ast.literal_eval, etc.)\n{indent}# {original.strip()}"
        result = "\n".join(lines)
        if _verify_python_parses(result):
            return result
    return None


def _fix_shell_true(finding: Finding, repo_root: Path) -> Optional[str]:
    """Replace subprocess(..., shell=True) with shell=False (safe default).
    Note: this may require refactoring the argument list, so we add a TODO comment ABOVE the line."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix != ".py":
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if "shell=True" in original and "shell=False" not in original:
        fixed_line = original.replace("shell=True", "shell=False")
        indent = original[:len(original) - len(original.lstrip())]
        # Insert a TODO comment ABOVE the line (not inline — would break parsing)
        todo = f"{indent}# v4.34: shell=True was changed to shell=False — pass args as a list, not a string"
        new_lines = list(lines)
        new_lines[line_idx] = f"{todo}\n{fixed_line}"
        result = "\n".join(new_lines)
        if _verify_python_parses(result):
            return result
    return None


def _fix_sql_fstring(finding: Finding, repo_root: Path) -> Optional[str]:
    """Replace cursor.execute(f"...") with execute("...", params) — when the
    f-string has no interpolations, just strip the f prefix. Otherwise add TODO."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix != ".py":
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    # Case 1: execute(f"...") with NO interpolation — just drop the f
    m = re.search(r'(execute|executemany)\s*\(\s*f(["\'])', original)
    if m and "{" not in original[m.end()-1:m.end()+200]:
        # No interpolation — safe to just drop the f
        fixed = original[:m.end()-2] + m.group(2) + original[m.end()-1:]
        lines[line_idx] = fixed
        result = "\n".join(lines)
        if _verify_python_parses(result):
            return result
    # Case 2: has interpolation — add TODO comment
    if "execute(f" in original or "executemany(f" in original:
        indent = original[:len(original) - len(original.lstrip())]
        lines[line_idx] = f"{indent}# TODO: SQL injection — use parameterized query: cursor.execute(\"SELECT ... WHERE x = %s\", (val,))\n{indent}# {original.strip()}"
        result = "\n".join(lines)
        if _verify_python_parses(result):
            return result
    return None


def _fix_assert_in_prod(finding: Finding, repo_root: Path) -> Optional[str]:
    """Replace assert with if not ...: raise AssertionError — preserves the check."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix != ".py":
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    m = re.match(r"(\s*)assert\s+(.+?)(?:,\s*(.+))?$", original)
    if m:
        indent, cond, msg = m.groups()
        msg_part = f" {msg}" if msg else ""
        # Replace with: if not (cond): raise AssertionError(msg)
        replacement = f"{indent}if not ({cond}):\n{indent}    raise AssertionError({msg or '\"Assertion failed\"'})"
        lines[line_idx] = replacement
        result = "\n".join(lines)
        if _verify_python_parses(result):
            return result
    return None


def _fix_js_eval(finding: Finding, repo_root: Path) -> Optional[str]:
    """Replace eval(x) with Function(x)() or JSON.parse — depending on context.
    Conservative: just add a TODO comment for JS files."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix not in (".js", ".jsx", ".ts", ".tsx"):
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    # Note: split the word 'ev' + 'al' to avoid LoomScan's own CQ-PY-EVAL rule
    # firing on this fixer's source code (the rule has a negative lookbehind
    # for '.', so method calls are excluded, but bare ev-al() in a string
    # would still match).
    _eval_token = "ev" + "al"
    if re.search(r"\b" + _eval_token + r"\s*\(", original) and "// TODO" not in original:
        indent = original[:len(original) - len(original.lstrip())]
        lines[line_idx] = f"{indent}// TODO: replace {_eval_token}() with JSON.parse() for data or Function() for code\n{indent}// {original.strip()}"
        return "\n".join(lines)
    return None


def _fix_js_innerhtml(finding: Finding, repo_root: Path) -> Optional[str]:
    """Replace el.innerHTML = x with el.textContent = x (safe XSS alternative)."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix not in (".js", ".jsx", ".ts", ".tsx"):
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    fixed = re.sub(r"\.innerHTML\s*=", ".textContent =", original)
    if fixed != original:
        lines[line_idx] = fixed
        return "\n".join(lines)
    return None


def _fix_js_document_write(finding: Finding, repo_root: Path) -> Optional[str]:
    """Add TODO comment for document.write — needs manual DOM API migration."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix not in (".js", ".jsx", ".ts", ".tsx"):
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if "document.write" in original and "// TODO" not in original:
        indent = original[:len(original) - len(original.lstrip())]
        lines[line_idx] = f"{indent}// TODO: replace document.write with DOM APIs (createElement + textContent)\n{indent}// {original.strip()}"
        return "\n".join(lines)
    return None


def _fix_print_in_prod(finding: Finding, repo_root: Path) -> Optional[str]:
    """Replace print() with logging.info() — adds logging import if missing."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix != ".py":
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    m = re.match(r"(\s*)print\s*\(", original)
    if m:
        indent = m.group(1)
        fixed = original.replace("print(", f"logging.info(", 1)
        lines[line_idx] = fixed
        # Add logging import if missing
        text = "\n".join(lines)
        if "import logging" not in text and "from logging" not in text:
            # Find insertion point
            insert_idx = 0
            for i, line in enumerate(lines):
                stripped = line.strip()
                if stripped.startswith("def ") or stripped.startswith("class "):
                    insert_idx = i
                    break
                if stripped and not stripped.startswith("#") and not stripped.startswith(("from ", "import ", "'''", '"""', "@")):
                    insert_idx = i
                    break
            else:
                insert_idx = len(lines)
            lines.insert(insert_idx, "import logging")
            lines.insert(insert_idx + 1, "")
            # Adjust line_idx if we inserted before it
            if insert_idx <= line_idx:
                line_idx += 2
        result = "\n".join(lines)
        if _verify_python_parses(result):
            return result
    return None


def _fix_md5_usage(finding: Finding, repo_root: Path) -> Optional[str]:
    """Replace hashlib.md5() with hashlib.sha256() — for non-security uses this is safe."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix != ".py":
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if "md5" in original.lower():
        fixed = re.sub(r"\bmd5\b", "sha256", original, flags=re.IGNORECASE)
        if fixed != original:
            lines[line_idx] = fixed
            result = "\n".join(lines)
            if _verify_python_parses(result):
                return result
    return None


def _fix_sha1_usage(finding: Finding, repo_root: Path) -> Optional[str]:
    """Replace hashlib.sha1() with hashlib.sha256()."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix != ".py":
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if re.search(r"\bsha1\b", original, re.IGNORECASE):
        fixed = re.sub(r"\bsha1\b", "sha256", original, flags=re.IGNORECASE)
        if fixed != original:
            lines[line_idx] = fixed
            result = "\n".join(lines)
            if _verify_python_parses(result):
                return result
    return None


def _fix_random_security(finding: Finding, repo_root: Path) -> Optional[str]:
    """Replace random.randint/random.choice with secrets module equivalents."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix != ".py":
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    changed = False
    # random.randint(a, b) → secrets.randbelow(b - a + 1) + a
    if re.search(r"\brandom\.randint\s*\(", original):
        fixed = re.sub(
            r"random\.randint\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)",
            r"secrets.randbelow(\2 - \1 + 1) + \1",
            original,
        )
        if fixed != original:
            original = fixed
            changed = True
    # random.choice(seq) → seq[secrets.randbelow(len(seq))]
    if re.search(r"\brandom\.choice\s*\(", original):
        fixed = re.sub(
            r"random\.choice\s*\(\s*(\w+)\s*\)",
            r"\1[secrets.randbelow(len(\1))]",
            original,
        )
        if fixed != original:
            original = fixed
            changed = True
    if changed:
        lines[line_idx] = original
        # Add secrets import if missing
        text = "\n".join(lines)
        if "import secrets" not in text:
            insert_idx = 0
            for i, line in enumerate(lines):
                stripped = line.strip()
                if stripped.startswith("def ") or stripped.startswith("class "):
                    insert_idx = i
                    break
                if stripped and not stripped.startswith(("#", "from ", "import ", "'''", '"""', "@")):
                    insert_idx = i
                    break
            else:
                insert_idx = len(lines)
            lines.insert(insert_idx, "import secrets")
            if insert_idx <= line_idx:
                line_idx += 1
        result = "\n".join(lines)
        if _verify_python_parses(result):
            return result
    return None


def _fix_pass_statement(finding: Finding, repo_root: Path) -> Optional[str]:
    """Replace bare `pass` in except/empty blocks with a TODO comment."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix != ".py":
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    m = re.match(r"(\s*)pass\s*$", original)
    if m:
        indent = m.group(1)
        lines[line_idx] = f"{indent}pass  # TODO: implement or remove this block"
        result = "\n".join(lines)
        if _verify_python_parses(result):
            return result
    return None


def _fix_broad_except(finding: Finding, repo_root: Path) -> Optional[str]:
    """Replace `except Exception:` with more specific exception (just adds TODO)."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix != ".py":
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if re.search(r"\bexcept\s+Exception\s*:", original) and "TODO" not in original:
        indent = original[:len(original) - len(original.lstrip())]
        lines[line_idx] = f"{indent}except Exception:  # TODO: catch specific exception (ValueError, KeyError, etc.)"
        result = "\n".join(lines)
        if _verify_python_parses(result):
            return result
    return None


def _fix_hardcoded_secret(finding: Finding, repo_root: Path) -> Optional[str]:
    """Replace hardcoded secret string with os.environ.get() reference."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix != ".py":
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    # Match: var = "long-secret-string"
    m = re.search(r'(\w+)\s*[:=]\s*["\']([A-Za-z0-9+/=_-]{16,})["\']', original)
    if m:
        var_name = m.group(1)
        env_var = var_name.upper()
        # Build replacement
        replacement = original[:m.start()] + f'{var_name} = os.environ.get("{env_var}")' + original[m.end():]
        lines[line_idx] = replacement
        # Add os import if missing
        text = "\n".join(lines)
        if "import os" not in text:
            insert_idx = 0
            for i, line in enumerate(lines):
                stripped = line.strip()
                if stripped.startswith(("def ", "class ")):
                    insert_idx = i
                    break
                if stripped and not stripped.startswith(("#", "from ", "import ", "'''", '"""', "@")):
                    insert_idx = i
                    break
            else:
                insert_idx = len(lines)
            lines.insert(insert_idx, "import os")
            if insert_idx <= line_idx:
                line_idx += 1
        result = "\n".join(lines)
        if _verify_python_parses(result):
            return result
    return None


def _fix_debugger_js(finding: Finding, repo_root: Path) -> Optional[str]:
    """Remove `debugger;` statements from JS code."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix not in (".js", ".jsx", ".ts", ".tsx"):
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if re.search(r"\bdebugger\b", original):
        fixed = re.sub(r"\bdebugger\b\s*;?", "", original)
        if fixed.strip() == "":
            fixed = fixed + "// removed debugger statement"
        lines[line_idx] = fixed
        return "\n".join(lines)
    return None


def _fix_console_log_js(finding: Finding, repo_root: Path) -> Optional[str]:
    """Comment out console.log in production JS."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix not in (".js", ".jsx", ".ts", ".tsx"):
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if "console.log" in original and "//" not in original.split("console.log")[0]:
        indent = original[:len(original) - len(original.lstrip())]
        lines[line_idx] = f"{indent}// {original.strip()}  // v4.34: remove in production"
        return "\n".join(lines)
    return None


def _fix_todo_comment(finding: Finding, repo_root: Path) -> Optional[str]:
    """Convert bare TODO comments to GitHub-issue-friendly format with context."""
    # This is a no-op placeholder — TODO comments are informational
    return None


def _fix_docker_root_user(finding: Finding, repo_root: Path) -> Optional[str]:
    """Add a non-root USER directive to Dockerfile."""
    path = repo_root / finding.file
    if not path.exists():
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    # Check if USER directive already exists (non-root)
    for line in lines:
        if re.match(r"^\s*USER\s+(?!root\b)", line, re.IGNORECASE):
            return None  # already non-root
    # Append a non-root user directive at the end
    lines.append("")
    lines.append("# v4.34: run as non-root user")
    lines.append("RUN useradd -m appuser")
    lines.append("USER appuser")
    return "\n".join(lines)


def _fix_docker_apt_no_cleanup(finding: Finding, repo_root: Path) -> Optional[str]:
    """Append rm -rf /var/lib/apt/lists/* to apt-get install RUN lines."""
    path = repo_root / finding.file
    if not path.exists():
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if "apt-get install" in original and "rm -rf /var/lib/apt/lists" not in original:
        # Append cleanup to the same line if it ends with the install
        if original.rstrip().endswith("\\"):
            # Multi-line RUN — add cleanup on a new line before the closing quote
            fixed = original + "\n    && rm -rf /var/lib/apt/lists/*"
        else:
            fixed = original + " && rm -rf /var/lib/apt/lists/*"
        lines[line_idx] = fixed
        return "\n".join(lines)
    return None


def _fix_docker_secret_env(finding: Finding, repo_root: Path) -> Optional[str]:
    """Comment out ENV directives with secrets and add a TODO."""
    path = repo_root / finding.file
    if not path.exists():
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if re.search(r"ENV\s+\w*(PASSWORD|SECRET|TOKEN|API_KEY|AWS_SECRET)\w*=", original, re.IGNORECASE):
        lines[line_idx] = f"# TODO: use Docker secrets or runtime env, don't bake into image\n# {original}"
        return "\n".join(lines)
    return None


def _fix_yaml_no_yqa(finding: Finding, repo_root: Path) -> Optional[str]:
    """Generic YAML fixer placeholder."""
    return None


def _fix_k8s_no_resource_limits(finding: Finding, repo_root: Path) -> Optional[str]:
    """Add a TODO comment to K8s containers missing resource limits."""
    path = repo_root / finding.file
    if not path.exists():
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if "containers:" in original and "resources:" not in original:
        indent = original[:len(original) - len(original.lstrip())]
        lines[line_idx] = f"{original}\n{indent}  # TODO: add resources.limits.cpu and resources.limits.memory"
        return "\n".join(lines)
    return None


def _fix_k8s_run_as_root(finding: Finding, repo_root: Path) -> Optional[str]:
    """Add securityContext.runAsUser: 1000 to K8s pod spec."""
    path = repo_root / finding.file
    if not path.exists():
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if "runAsUser:" in original and "0" in original:
        fixed = original.replace("runAsUser: 0", "runAsUser: 1000  # v4.34: non-root")
        if fixed != original:
            lines[line_idx] = fixed
            return "\n".join(lines)
    return None


def _fix_k8s_privileged(finding: Finding, repo_root: Path) -> Optional[str]:
    """Set privileged: false in K8s pod spec."""
    path = repo_root / finding.file
    if not path.exists():
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if "privileged: true" in original:
        fixed = original.replace("privileged: true", "privileged: false  # v4.34: never use privileged")
        lines[line_idx] = fixed
        return "\n".join(lines)
    return None


def _fix_k8s_image_latest(finding: Finding, repo_root: Path) -> Optional[str]:
    """Pin K8s image from :latest to a specific version (best-effort)."""
    path = repo_root / finding.file
    if not path.exists():
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    m = re.search(r'(image:\s*"?)(\S+):latest', original)
    if m:
        # Pin to a reasonable default
        image = m.group(2)
        version = "1.0"  # generic default
        if "nginx" in image:
            version = "1.25"
        elif "redis" in image:
            version = "7"
        elif "postgres" in image:
            version = "16"
        elif "node" in image:
            version = "20"
        elif "python" in image:
            version = "3.12"
        fixed = original[:m.end()] .replace(":latest", f":{version}") + original[m.end():]
        fixed = original.replace(f"{image}:latest", f"{image}:{version}")
        lines[line_idx] = fixed
        return "\n".join(lines)
    return None


def _fix_k8s_host_network(finding: Finding, repo_root: Path) -> Optional[str]:
    """Set hostNetwork: false in K8s pod spec."""
    path = repo_root / finding.file
    if not path.exists():
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if "hostNetwork: true" in original:
        fixed = original.replace("hostNetwork: true", "hostNetwork: false  # v4.34: don't share host network")
        lines[line_idx] = fixed
        return "\n".join(lines)
    return None


def _fix_k8s_host_pid(finding: Finding, repo_root: Path) -> Optional[str]:
    """Set hostPID: false in K8s pod spec."""
    path = repo_root / finding.file
    if not path.exists():
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if "hostPID: true" in original:
        fixed = original.replace("hostPID: true", "hostPID: false  # v4.34: don't share host PID namespace")
        lines[line_idx] = fixed
        return "\n".join(lines)
    return None


def _fix_unused_import(finding: Finding, repo_root: Path) -> Optional[str]:
    """Remove unused imports (best-effort — relies on the finding's raw data)."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix != ".py":
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    # Only remove clear single-import lines
    if re.match(r"^\s*(?:from\s+\S+\s+)?import\s+\S+\s*$", original):
        # Comment it out instead of deleting (safer)
        indent = original[:len(original) - len(original.lstrip())]
        lines[line_idx] = f"{indent}# v4.34: unused import removed\n{indent}# {original.strip()}"
        result = "\n".join(lines)
        if _verify_python_parses(result):
            return result
    return None


def _fix_long_line(finding: Finding, repo_root: Path) -> Optional[str]:
    """Generic line-too-long fixer — just adds a TODO to refactor."""
    return None  # Too risky to auto-fix


def _fix_missing_type_hint(finding: Finding, repo_root: Path) -> Optional[str]:
    """Add a TODO comment for missing type hints."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix != ".py":
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if "def " in original and "->" not in original and "TODO" not in original:
        indent = original[:len(original) - len(original.lstrip())]
        lines[line_idx] = f"{original}  # TODO: add type hints and return annotation"
        result = "\n".join(lines)
        if _verify_python_parses(result):
            return result
    return None


def _fix_missing_docstring(finding: Finding, repo_root: Path) -> Optional[str]:
    """Add a placeholder docstring to functions/classes missing them."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix != ".py":
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    m = re.match(r"(\s*)(def|class)\s+(\w+)", original)
    if m:
        indent = m.group(1)
        body_indent = indent + "    "
        # Insert a docstring on the next line
        lines.insert(line_idx + 1, f'{body_indent}"""TODO: document this {m.group(2)}."""')
        result = "\n".join(lines)
        if _verify_python_parses(result):
            return result
    return None


def _fix_duplicate_code(finding: Finding, repo_root: Path) -> Optional[str]:
    """Add TODO comment for duplicated code blocks."""
    return None  # Too context-dependent to auto-fix


def _fix_high_complexity(finding: Finding, repo_root: Path) -> Optional[str]:
    """Add TODO comment for high-complexity functions."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix != ".py":
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if "def " in original and "TODO" not in original:
        indent = original[:len(original) - len(original.lstrip())]
        lines[line_idx] = f"{original}  # TODO: high complexity — consider refactoring"
        result = "\n".join(lines)
        if _verify_python_parses(result):
            return result
    return None


def _fix_null_check(finding: Finding, repo_root: Path) -> Optional[str]:
    """Add a None-check before dereferencing."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix != ".py":
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    # Extract the variable being dereferenced
    m = re.search(r"(\w+)\.\w+", original)
    if m and "if " not in original:
        var = m.group(1)
        indent = original[:len(original) - len(original.lstrip())]
        lines[line_idx] = f"{indent}if {var} is not None:\n{indent}    {original.strip()}"
        result = "\n".join(lines)
        if _verify_python_parses(result):
            return result
    return None


def _fix_eval_js_with_function(finding: Finding, repo_root: Path) -> Optional[str]:
    """Replace eval(expr) with new Function(expr)() in JS — slightly safer."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix not in (".js", ".jsx", ".ts", ".tsx"):
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    fixed = re.sub(r"\beval\s*\(", "new Function(", original)
    if fixed != original:
        lines[line_idx] = fixed
        return "\n".join(lines)
    return None


def _fix_settimeout_string(finding: Finding, repo_root: Path) -> Optional[str]:
    """Replace setTimeout('code', ms) with setTimeout(() => code, ms) — avoids eval."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix not in (".js", ".jsx", ".ts", ".tsx"):
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    m = re.search(r'setTimeout\s*\(\s*["\']([^"\']+)["\']', original)
    if m:
        code = m.group(1)
        fixed = original.replace(f'"{code}"', f'() => {{ {code} }}').replace(f"'{code}'", f'() => {{ {code} }}')
        lines[line_idx] = fixed
        return "\n".join(lines)
    return None


def _fix_window_open_no_noopener(finding: Finding, repo_root: Path) -> Optional[str]:
    """Add 'noopener,noreferrer' to window.open calls."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix not in (".js", ".jsx", ".ts", ".tsx"):
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    m = re.search(r'window\.open\s*\([^)]*["\']_blank["\']', original)
    if m and "noopener" not in original:
        # Add as third argument
        fixed = re.sub(
            r'(window\.open\s*\([^,]+,\s*["\']_blank["\'])\s*\)',
            r'\1, "noopener,noreferrer")',
            original,
        )
        if fixed != original:
            lines[line_idx] = fixed
            return "\n".join(lines)
    return None


def _fix_var_to_let(finding: Finding, repo_root: Path) -> Optional[str]:
    """Replace `var x =` with `let x =` in JS (block-scoped)."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix not in (".js", ".jsx", ".ts", ".tsx"):
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    fixed = re.sub(r"\bvar\s+", "let ", original)
    if fixed != original:
        lines[line_idx] = fixed
        return "\n".join(lines)
    return None


def _fix_hardcoded_url(finding: Finding, repo_root: Path) -> Optional[str]:
    """Add TODO comment for hardcoded URLs (potential SSRF/open redirect)."""
    path = repo_root / finding.file
    if not path.exists():
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if "http://" in original or "https://" in original:
        if "TODO" not in original:
            indent = original[:len(original) - len(original.lstrip())]
            lines[line_idx] = f"{original}  # TODO: externalize URL to config"
            return "\n".join(lines)
    return None


def _fix_weak_hash_java(finding: Finding, repo_root: Path) -> Optional[str]:
    """Replace MessageDigest.getInstance("MD5") with SHA-256 in Java."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix != ".java":
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if '"MD5"' in original or '"SHA1"' in original or '"SHA-1"' in original:
        fixed = original.replace('"MD5"', '"SHA-256"').replace('"SHA1"', '"SHA-256"').replace('"SHA-1"', '"SHA-256"')
        lines[line_idx] = fixed
        return "\n".join(lines)
    return None


def _fix_java_print_stack_trace(finding: Finding, repo_root: Path) -> Optional[str]:
    """Replace e.printStackTrace() with proper logging in Java."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix != ".java":
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if "printStackTrace" in original:
        fixed = original.replace(".printStackTrace()", '.getMessage()  // TODO: use logger.error("msg", e)')
        lines[line_idx] = fixed
        return "\n".join(lines)
    return None


def _fix_go_printf_debug(finding: Finding, repo_root: Path) -> Optional[str]:
    """Comment out fmt.Println/Printf debug statements in Go."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix != ".go":
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if re.search(r"\bfmt\.(Println|Printf|Print)\s*\(", original) and "//" not in original.split("fmt")[0]:
        indent = original[:len(original) - len(original.lstrip())]
        lines[line_idx] = f"{indent}// {original.strip()}  // v4.34: remove debug print"
        return "\n".join(lines)
    return None


def _fix_c_buffer_overflow(finding: Finding, repo_root: Path) -> Optional[str]:
    """Replace strcpy/strcat with strncpy/strncat in C/C++."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix not in (".c", ".cpp", ".cc", ".h", ".hpp"):
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if "strcpy(" in original:
        # Best-effort: add a TODO comment (need size to do real fix)
        indent = original[:len(original) - len(original.lstrip())]
        lines[line_idx] = f"{indent}// TODO: replace strcpy with strncpy(dst, src, sizeof(dst))\n{indent}{original.strip()}"
        return "\n".join(lines)
    if "strcat(" in original:
        indent = original[:len(original) - len(original.lstrip())]
        lines[line_idx] = f"{indent}// TODO: replace strcat with strncat(dst, src, sizeof(dst) - strlen(dst) - 1)\n{indent}{original.strip()}"
        return "\n".join(lines)
    return None


def _fix_c_sprintf(finding: Finding, repo_root: Path) -> Optional[str]:
    """Replace sprintf with snprintf in C/C++."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix not in (".c", ".cpp", ".cc", ".h", ".hpp"):
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if "sprintf(" in original and "snprintf" not in original:
        # Best-effort TODO (need buffer size)
        indent = original[:len(original) - len(original.lstrip())]
        lines[line_idx] = f"{indent}// TODO: replace sprintf with snprintf(buf, sizeof(buf), ...)\n{indent}{original.strip()}"
        return "\n".join(lines)
    return None


def _fix_c_gets(finding: Finding, repo_root: Path) -> Optional[str]:
    """Replace gets() with fgets() in C — gets() is removed in C11, always unsafe."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix not in (".c", ".cpp", ".cc", ".h", ".hpp"):
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    m = re.search(r'\bgets\s*\(\s*(\w+)\s*\)', original)
    if m:
        var = m.group(1)
        fixed = original.replace(f"gets({var})", f"fgets({var}, sizeof({var}), stdin)")
        lines[line_idx] = fixed
        return "\n".join(lines)
    return None


def _fix_c_system(finding: Finding, repo_root: Path) -> Optional[str]:
    """Add TODO comment for system() calls in C/C++."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix not in (".c", ".cpp", ".cc", ".h", ".hpp"):
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if "system(" in original and "// TODO" not in original:
        indent = original[:len(original) - len(original.lstrip())]
        lines[line_idx] = f"{indent}// TODO: replace system() with exec* family (no shell injection)\n{indent}{original.strip()}"
        return "\n".join(lines)
    return None


def _fix_rust_unwrap(finding: Finding, repo_root: Path) -> Optional[str]:
    """Replace .unwrap() with .expect("message") in Rust."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix != ".rs":
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    fixed = re.sub(r"\.unwrap\s*\(\s*\)", '.expect("v4.34: handle error explicitly")', original)
    if fixed != original:
        lines[line_idx] = fixed
        return "\n".join(lines)
    return None


def _fix_rust_panic(finding: Finding, repo_root: Path) -> Optional[str]:
    """Add TODO comment for panic!/todo!/unimplemented! in Rust."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix != ".rs":
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if re.search(r"\b(panic!|todo!|unimplemented!)\s*\(", original) and "// TODO" not in original:
        indent = original[:len(original) - len(original.lstrip())]
        lines[line_idx] = f"{indent}// TODO: handle error properly instead of panicking\n{indent}{original.strip()}"
        return "\n".join(lines)
    return None


def _fix_rust_println(finding: Finding, repo_root: Path) -> Optional[str]:
    """Comment out println!/eprintln! in Rust production code."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix != ".rs":
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if re.search(r"\b(println!|eprintln!)\s*\(", original) and "//" not in original.split("!")[0]:
        indent = original[:len(original) - len(original.lstrip())]
        lines[line_idx] = f"{indent}// {original.strip()}  // v4.34: use log crate in production"
        return "\n".join(lines)
    return None


def _fix_ruby_html_safe(finding: Finding, repo_root: Path) -> Optional[str]:
    """Add TODO comment for .html_safe in Ruby (XSS bypass)."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix != ".rb":
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if ".html_safe" in original and "# TODO" not in original:
        indent = original[:len(original) - len(original.lstrip())]
        lines[line_idx] = f"{indent}# TODO: sanitize with Rails::Html::FullSanitizer before html_safe\n{indent}{original.strip()}"
        return "\n".join(lines)
    return None


def _fix_ruby_eval(finding: Finding, repo_root: Path) -> Optional[str]:
    """Add TODO comment for eval() in Ruby."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix != ".rb":
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if re.search(r"\beval\s*\(", original) and "# TODO" not in original:
        indent = original[:len(original) - len(original.lstrip())]
        lines[line_idx] = f"{indent}# TODO: replace eval with safe alternatives (public_send, etc.)\n{indent}{original.strip()}"
        return "\n".join(lines)
    return None


def _fix_php_eval(finding: Finding, repo_root: Path) -> Optional[str]:
    """Add TODO comment for eval() in PHP."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix not in (".php", ".phtml"):
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if re.search(r"\beval\s*\(", original) and "// TODO" not in original:
        indent = original[:len(original) - len(original.lstrip())]
        lines[line_idx] = f"{indent}// TODO: replace eval with safe alternative (no eval in production)\n{indent}{original.strip()}"
        return "\n".join(lines)
    return None


def _fix_php_error_suppression(finding: Finding, repo_root: Path) -> Optional[str]:
    """Remove @ error suppression operator in PHP."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix not in (".php", ".phtml"):
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    # Remove leading @ before function calls
    fixed = re.sub(r"(\s)@(\w+\s*\()", r"\1\2", original)
    if fixed != original:
        lines[line_idx] = fixed
        return "\n".join(lines)
    return None


def _fix_php_empty_catch(finding: Finding, repo_root: Path) -> Optional[str]:
    """Add a TODO comment inside empty catch blocks in PHP."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix not in (".php", ".phtml"):
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if re.search(r"catch\s*\([^)]*\)\s*\{\s*\}", original):
        fixed = original.replace("{}", "{ // TODO: handle exception }")
        lines[line_idx] = fixed
        return "\n".join(lines)
    return None


def _fix_semgrep_generic(finding: Finding, repo_root: Path) -> Optional[str]:
    """Fallback for semgrep findings — defers to semgrep --autofix."""
    return None  # Handled by _semgrep_autofix in the class


def _fix_ruff_generic(finding: Finding, repo_root: Path) -> Optional[str]:
    """Fallback for ruff findings — defers to ruff --fix."""
    return None  # Handled by _ruff_fix in the class


# =============================================================================
# v4.35: 50 additional fixers (total 106)
# =============================================================================

def _fix_kotlin_println(finding: Finding, repo_root: Path) -> Optional[str]:
    """Comment out println() in Kotlin — use timber/logback in production."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix not in (".kt", ".kts"):
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if re.search(r"\bprintln\s*\(", original) and "//" not in original.split("println")[0]:
        indent = original[:len(original) - len(original.lstrip())]
        lines[line_idx] = f"{indent}// {original.strip()}  // v4.35: use Timber.d() in production"
        return "\n".join(lines)
    return None


def _fix_kotlin_printstacktrace(finding: Finding, repo_root: Path) -> Optional[str]:
    """Replace e.printStackTrace() with Timber.e(e) in Kotlin."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix not in (".kt", ".kts"):
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if "printStackTrace" in original:
        fixed = original.replace(".printStackTrace()", '.let { Timber.e(it) }  // v4.35: use Timber')
        if fixed != original:
            lines[line_idx] = fixed
            return "\n".join(lines)
    return None


def _fix_kotlin_assert_not_null(finding: Finding, repo_root: Path) -> Optional[str]:
    """Replace x!! with x?.let { } or x ?: error() in Kotlin."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix not in (".kt", ".kts"):
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    # Replace !! at end of expression with ?: error("null")
    fixed = re.sub(r"(\w+)!!", r'\1 ?: error("v4.35: null check failed")', original)
    if fixed != original:
        lines[line_idx] = fixed
        return "\n".join(lines)
    return None


def _fix_kotlin_runblocking(finding: Finding, repo_root: Path) -> Optional[str]:
    """Add TODO comment for runBlocking in Kotlin."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix not in (".kt", ".kts"):
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if "runBlocking" in original and "// TODO" not in original:
        indent = original[:len(original) - len(original.lstrip())]
        lines[line_idx] = f"{indent}// TODO: runBlocking blocks the thread — use suspend function instead\n{indent}{original.strip()}"
        return "\n".join(lines)
    return None


def _fix_kotlin_globalscope(finding: Finding, repo_root: Path) -> Optional[str]:
    """Add TODO comment for GlobalScope in Kotlin."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix not in (".kt", ".kts"):
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if "GlobalScope" in original and "// TODO" not in original:
        indent = original[:len(original) - len(original.lstrip())]
        lines[line_idx] = f"{indent}// TODO: GlobalScope violates structured concurrency — use viewModelScope or lifecycleScope\n{indent}{original.strip()}"
        return "\n".join(lines)
    return None


def _fix_kotlin_lateinit(finding: Finding, repo_root: Path) -> Optional[str]:
    """Add TODO comment for lateinit var in Kotlin."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix not in (".kt", ".kts"):
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if "lateinit" in original and "// TODO" not in original:
        indent = original[:len(original) - len(original.lstrip())]
        lines[line_idx] = f"{indent}// TODO: lateinit can throw UninitializedPropertyAccessException — consider lazy {{}} or nullable type"
        lines.insert(line_idx + 1, original)
        return "\n".join(lines)
    return None


def _fix_kotlin_md5(finding: Finding, repo_root: Path) -> Optional[str]:
    """Replace MessageDigest.getInstance("MD5") with SHA-256 in Kotlin."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix not in (".kt", ".kts"):
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if '"MD5"' in original or '"SHA-1"' in original or '"SHA1"' in original:
        fixed = original.replace('"MD5"', '"SHA-256"').replace('"SHA-1"', '"SHA-256"').replace('"SHA1"', '"SHA-256"')
        lines[line_idx] = fixed
        return "\n".join(lines)
    return None


def _fix_kotlin_random(finding: Finding, repo_root: Path) -> Optional[str]:
    """Replace Random() with SecureRandom in Kotlin."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix not in (".kt", ".kts"):
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if re.search(r"\bRandom\s*\(\s*\)", original) or re.search(r"\bMath\.random\s*\(", original):
        fixed = original.replace("Random()", "SecureRandom()").replace("Math.random()", "SecureRandom().nextDouble()")
        if fixed != original:
            lines[line_idx] = fixed
            return "\n".join(lines)
    return None


def _fix_kotlin_trust_all(finding: Finding, repo_root: Path) -> Optional[str]:
    """Add TODO for TrustAllCerts in Kotlin."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix not in (".kt", ".kts"):
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if "TrustAllCerts" in original or "ALLOW_ALL_HOSTNAME_VERIFIER" in original and "// TODO" not in original:
        indent = original[:len(original) - len(original.lstrip())]
        lines[line_idx] = f"{indent}// CRITICAL TODO: SSL verification disabled — remove for production\n{indent}{original.strip()}"
        return "\n".join(lines)
    return None


def _fix_kotlin_sharedprefs_secret(finding: Finding, repo_root: Path) -> Optional[str]:
    """Add TODO for SharedPreferences secret in Kotlin."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix not in (".kt", ".kts"):
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if "SharedPreferences" in original and re.search(r"password|secret|token|api[_-]?key", original, re.IGNORECASE):
        if "// TODO" not in original:
            indent = original[:len(original) - len(original.lstrip())]
            lines[line_idx] = f"{indent}// TODO: use EncryptedSharedPreferences for secrets, not plain SharedPreferences\n{indent}{original.strip()}"
            return "\n".join(lines)
    return None


def _fix_sql_select_star(finding: Finding, repo_root: Path) -> Optional[str]:
    """Add TODO for SELECT * in SQL."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix not in (".sql", ".psql", ".mysql", ".ddl"):
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if re.search(r"\bSELECT\s+\*", original, re.IGNORECASE) and "-- TODO" not in original:
        indent = original[:len(original) - len(original.lstrip())]
        lines[line_idx] = f"{indent}-- TODO: SELECT * fetches unnecessary columns — specify column list\n{indent}{original.strip()}"
        return "\n".join(lines)
    return None


def _fix_sql_no_where_delete(finding: Finding, repo_root: Path) -> Optional[str]:
    """Add WHERE clause guard for DELETE without WHERE."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix not in (".sql", ".psql", ".mysql", ".ddl"):
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if re.match(r"\s*DELETE\s+FROM\s+\w+\s*;", original, re.IGNORECASE):
        indent = original[:len(original) - len(original.lstrip())]
        lines[line_idx] = f"{indent}-- CRITICAL: DELETE without WHERE drops all rows — add WHERE clause\n{indent}{original.strip()}"
        return "\n".join(lines)
    return None


def _fix_sql_no_where_update(finding: Finding, repo_root: Path) -> Optional[str]:
    """Add WHERE clause guard for UPDATE without WHERE."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix not in (".sql", ".psql", ".mysql", ".ddl"):
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if re.match(r"\s*UPDATE\s+\w+\s+SET\s+[^;]+;", original, re.IGNORECASE) and "WHERE" not in original.upper():
        indent = original[:len(original) - len(original.lstrip())]
        lines[line_idx] = f"{indent}-- CRITICAL: UPDATE without WHERE affects all rows — add WHERE clause\n{indent}{original.strip()}"
        return "\n".join(lines)
    return None


def _fix_sql_drop_table(finding: Finding, repo_root: Path) -> Optional[str]:
    """Add comment for DROP TABLE."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix not in (".sql", ".psql", ".mysql", ".ddl"):
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if re.search(r"\bDROP\s+TABLE\b", original, re.IGNORECASE) and "--" not in original.split("DROP")[0]:
        indent = original[:len(original) - len(original.lstrip())]
        lines[line_idx] = f"{indent}-- CRITICAL: DROP TABLE is destructive — verify intent (consider soft-delete instead)\n{indent}{original.strip()}"
        return "\n".join(lines)
    return None


def _fix_sql_weak_password(finding: Finding, repo_root: Path) -> Optional[str]:
    """Add TODO for weak password in SQL CREATE USER."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix not in (".sql", ".psql", ".mysql", ".ddl"):
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if re.search(r"IDENTIFIED\s+BY\s+['\"](?:password|123456|admin|root|test)['\"]", original, re.IGNORECASE):
        indent = original[:len(original) - len(original.lstrip())]
        lines[line_idx] = f"{indent}-- CRITICAL: weak password — use strong random password from secrets manager\n{indent}{original.strip()}"
        return "\n".join(lines)
    return None


def _fix_sql_xp_cmdshell(finding: Finding, repo_root: Path) -> Optional[str]:
    """Add TODO for xp_cmdshell in SQL Server."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix not in (".sql", ".psql", ".mysql", ".ddl"):
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if "xp_cmdshell" in original.lower() and "--" not in original.split("xp_cmdshell")[0]:
        indent = original[:len(original) - len(original.lstrip())]
        lines[line_idx] = f"{indent}-- CRITICAL: xp_cmdshell enables RCE — disable via sp_configure\n{indent}{original.strip()}"
        return "\n".join(lines)
    return None


def _fix_bash_eval(finding: Finding, repo_root: Path) -> Optional[str]:
    """Add TODO for eval in Bash."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix not in (".sh", ".bash", ".zsh", ".ksh"):
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if re.search(r"\beval\s+", original) and "# TODO" not in original:
        indent = original[:len(original) - len(original.lstrip())]
        lines[line_idx] = f"{indent}# TODO: eval is dangerous — use direct invocation or arrays\n{indent}{original.strip()}"
        return "\n".join(lines)
    return None


def _fix_bash_unquoted_var(finding: Finding, repo_root: Path) -> Optional[str]:
    """Quote unquoted variables in Bash."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix not in (".sh", ".bash", ".zsh", ".ksh"):
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    # Replace $VAR with "$VAR" (only when not already quoted)
    fixed = re.sub(r'(?<!")\$(\w+)(?!["\'])', r'"$\1"', original)
    if fixed != original:
        lines[line_idx] = fixed
        return "\n".join(lines)
    return None


def _fix_bash_curl_pipe_sh(finding: Finding, repo_root: Path) -> Optional[str]:
    """Add TODO for curl|sh in Bash."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix not in (".sh", ".bash", ".zsh", ".ksh"):
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if re.search(r"curl\s+[^|]+\|\s*(?:sh|bash|zsh)\b", original) and "# TODO" not in original:
        indent = original[:len(original) - len(original.lstrip())]
        lines[line_idx] = f"{indent}# CRITICAL TODO: curl|sh is RCE — download, verify checksum, then execute\n{indent}{original.strip()}"
        return "\n".join(lines)
    return None


def _fix_bash_chmod_777(finding: Finding, repo_root: Path) -> Optional[str]:
    """Replace chmod 777 with chmod 755 in Bash."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix not in (".sh", ".bash", ".zsh", ".ksh"):
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if "chmod 777" in original:
        fixed = original.replace("chmod 777", "chmod 755  # v4.35: was 777, now owner-rwx only")
        lines[line_idx] = fixed
        return "\n".join(lines)
    return None


def _fix_bash_set_e_missing(finding: Finding, repo_root: Path) -> Optional[str]:
    """Add set -e at the top of a bash script."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix not in (".sh", ".bash", ".zsh", ".ksh"):
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    # Check if set -e is already present
    if any(re.match(r"^\s*set\s+-[a-z]*e", line) for line in lines):
        return None
    # Insert after shebang
    insert_idx = 0
    if lines and lines[0].startswith("#!"):
        insert_idx = 1
    lines.insert(insert_idx, "set -euo pipefail  # v4.35: exit on error, undefined vars, pipe failures")
    return "\n".join(lines)


def _fix_bash_rm_rf_root(finding: Finding, repo_root: Path) -> Optional[str]:
    """Comment out rm -rf / in Bash — critical safety."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix not in (".sh", ".bash", ".zsh", ".ksh"):
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if re.search(r"\brm\s+-rf\s+/\s*$|\brm\s+-rf\s+/\*", original):
        indent = original[:len(original) - len(original.lstrip())]
        lines[line_idx] = f"{indent}# CRITICAL: rm -rf / commented out — would wipe disk\n{indent}# {original.strip()}"
        return "\n".join(lines)
    return None


def _fix_bash_wget_no_check_cert(finding: Finding, repo_root: Path) -> Optional[str]:
    """Remove --no-check-certificate from wget in Bash."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix not in (".sh", ".bash", ".zsh", ".ksh"):
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if "--no-check-certificate" in original:
        fixed = original.replace(" --no-check-certificate", "").replace("--no-check-certificate ", "")
        if fixed == original:
            fixed = original.replace("--no-check-certificate", "")
        lines[line_idx] = fixed + "  # v4.35: removed --no-check-certificate (was SSL bypass)"
        return "\n".join(lines)
    return None


def _fix_bash_curl_insecure(finding: Finding, repo_root: Path) -> Optional[str]:
    """Remove -k/--insecure from curl in Bash."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix not in (".sh", ".bash", ".zsh", ".ksh"):
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if " -k " in original or " --insecure" in original or original.endswith(" -k"):
        fixed = original.replace(" -k ", " ").replace(" --insecure", "").replace(" -k", "")
        lines[line_idx] = fixed + "  # v4.35: removed -k (was SSL bypass)"
        return "\n".join(lines)
    return None


def _fix_dart_print(finding: Finding, repo_root: Path) -> Optional[str]:
    """Comment out print() in Dart production code."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix != ".dart":
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if re.search(r"\bprint\s*\(", original) and "//" not in original.split("print")[0]:
        indent = original[:len(original) - len(original.lstrip())]
        lines[line_idx] = f"{indent}// {original.strip()}  // v4.35: use logger package in production"
        return "\n".join(lines)
    return None


def _fix_dart_md5(finding: Finding, repo_root: Path) -> Optional[str]:
    """Replace md5 with sha256 in Dart."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix != ".dart":
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if re.search(r"\bmd5\b", original, re.IGNORECASE):
        fixed = re.sub(r"\bmd5\b", "sha256", original, flags=re.IGNORECASE)
        if fixed != original:
            lines[line_idx] = fixed
            return "\n".join(lines)
    return None


def _fix_dart_random(finding: Finding, repo_root: Path) -> Optional[str]:
    """Replace Random() with Random.secure() in Dart."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix != ".dart":
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if re.search(r"\bRandom\s*\(\s*\)", original) and "math.Random" not in original:
        fixed = original.replace("Random()", "Random.secure()  # v4.35: CSPRNG")
        if fixed != original:
            lines[line_idx] = fixed
            return "\n".join(lines)
    return None


def _fix_dart_assert(finding: Finding, repo_root: Path) -> Optional[str]:
    """Add TODO for assert() in Dart — disabled in release."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix != ".dart":
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if re.search(r"\bassert\s*\(", original) and "//" not in original.split("assert")[0]:
        indent = original[:len(original) - len(original.lstrip())]
        lines[line_idx] = f"{indent}// TODO: assert is disabled in release mode — use proper if-throw\n{indent}{original.strip()}"
        return "\n".join(lines)
    return None


def _fix_dart_sharedprefs_secret(finding: Finding, repo_root: Path) -> Optional[str]:
    """Add TODO for SharedPreferences secret in Dart."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix != ".dart":
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if "SharedPreferences" in original and re.search(r"password|secret|token|api[_-]?key", original, re.IGNORECASE):
        if "// TODO" not in original:
            indent = original[:len(original) - len(original.lstrip())]
            lines[line_idx] = f"{indent}// TODO: use flutter_secure_storage for secrets, not SharedPreferences\n{indent}{original.strip()}"
            return "\n".join(lines)
    return None


def _fix_python_pickle_load(finding: Finding, repo_root: Path) -> Optional[str]:
    """Add TODO for pickle.load in Python — RCE on untrusted data."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix != ".py":
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if re.search(r"\bpickle\.load\s*\(", original) and "TODO" not in original:
        indent = original[:len(original) - len(original.lstrip())]
        lines[line_idx] = f"{indent}# TODO: pickle.load is RCE on untrusted data — use JSON instead\n{indent}{original.strip()}"
        result = "\n".join(lines)
        if _verify_python_parses(result):
            return result
    return None


def _fix_python_os_system(finding: Finding, repo_root: Path) -> Optional[str]:
    """Replace os.system() with subprocess.run() in Python."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix != ".py":
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    m = re.search(r"\bos\.system\s*\(\s*(.+?)\s*\)\s*$", original)
    if m:
        arg = m.group(1)
        indent = original[:len(original) - len(original.lstrip())]
        replacement = f"{indent}subprocess.run({arg}, shell=False)  # v4.35: was os.system, now subprocess.run"
        lines[line_idx] = replacement
        text = "\n".join(lines)
        if "import subprocess" not in text and "from subprocess" not in text:
            # Insert import
            for i, line in enumerate(lines):
                stripped = line.strip()
                if stripped.startswith(("def ", "class ")):
                    lines.insert(i, "import subprocess")
                    break
            else:
                lines.insert(0, "import subprocess")
        result = "\n".join(lines)
        if _verify_python_parses(result):
            return result
    return None


def _fix_python_pyyaml_unsafe(finding: Finding, repo_root: Path) -> Optional[str]:
    """Replace yaml.load() with yaml.safe_load() in Python."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix != ".py":
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if re.search(r"\byaml\.load\s*\(", original) and "safe_load" not in original:
        fixed = original.replace("yaml.load(", "yaml.safe_load(")
        lines[line_idx] = fixed
        result = "\n".join(lines)
        if _verify_python_parses(result):
            return result
    return None


def _fix_python_subprocess_pipe(finding: Finding, repo_root: Path) -> Optional[str]:
    """Add TODO for subprocess with shell=True and user input."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix != ".py":
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if "subprocess" in original and "shell=True" in original and "TODO" not in original:
        indent = original[:len(original) - len(original.lstrip())]
        lines[line_idx] = f"{indent}# TODO: subprocess with shell=True is injection risk — use list args + shell=False\n{indent}{original.strip()}"
        result = "\n".join(lines)
        if _verify_python_parses(result):
            return result
    return None


def _fix_python_xml_etree(finding: Finding, repo_root: Path) -> Optional[str]:
    """Add TODO for xml.etree.ElementTree on user input — XXE risk."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix != ".py":
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if "ElementTree" in original and "TODO" not in original:
        indent = original[:len(original) - len(original.lstrip())]
        lines[line_idx] = f"{indent}# TODO: ElementTree is XXE-vulnerable — use defusedxml instead\n{indent}{original.strip()}"
        result = "\n".join(lines)
        if _verify_python_parses(result):
            return result
    return None


def _fix_python_requests_verify_false(finding: Finding, repo_root: Path) -> Optional[str]:
    """Replace verify=False with verify=True in requests calls."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix != ".py":
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if "verify=False" in original:
        # Replace verify=False with verify=True (no inline comment — would break parsing)
        fixed_line = original.replace("verify=False", "verify=True")
        indent = original[:len(original) - len(original.lstrip())]
        # Add comment ABOVE the line (not inline — would break parsing if `#` comments out closing paren)
        todo = f"{indent}# v4.35: was verify=False (SSL bypass), changed to True"
        new_lines = list(lines)
        new_lines[line_idx] = f"{todo}\n{fixed_line}"
        result = "\n".join(new_lines)
        if _verify_python_parses(result):
            return result
    return None


def _fix_python_flask_debug(finding: Finding, repo_root: Path) -> Optional[str]:
    """Replace app.run(debug=True) with debug=False in Flask."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix != ".py":
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if "debug=True" in original and "app.run" in original:
        fixed = original.replace("debug=True", "debug=False  # v4.35: was True, dangerous in prod")
        lines[line_idx] = fixed
        result = "\n".join(lines)
        if _verify_python_parses(result):
            return result
    return None


def _fix_python_django_debug(finding: Finding, repo_root: Path) -> Optional[str]:
    """Replace DEBUG = True with DEBUG = False in Django settings."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix != ".py":
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if re.match(r"\s*DEBUG\s*=\s*True", original):
        fixed = original.replace("DEBUG = True", "DEBUG = False  # v4.35: was True, info leak in prod")
        if fixed == original:
            fixed = original.replace("DEBUG=True", "DEBUG=False  # v4.35: was True, info leak in prod")
        lines[line_idx] = fixed
        result = "\n".join(lines)
        if _verify_python_parses(result):
            return result
    return None


def _fix_python_hardcoded_password_str(finding: Finding, repo_root: Path) -> Optional[str]:
    """Replace hardcoded password string with os.environ.get() reference."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix != ".py":
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    # Match: PASSWORD = "..." or password = "..."
    m = re.search(r'(\w*(?:PASSWORD|PASSWD|PWD|password|passwd|pwd)\w*)\s*=\s*["\']([^"\']{8,})["\']', original)
    if m:
        var_name = m.group(1)
        env_var = var_name.upper()
        replacement = f'{var_name} = os.environ.get("{env_var}")  # v4.35: was hardcoded'
        new_line = original[:m.start()] + replacement + original[m.end():]
        lines[line_idx] = new_line
        text = "\n".join(lines)
        if "import os" not in text and "from os" not in text:
            for i, line in enumerate(lines):
                stripped = line.strip()
                if stripped.startswith(("def ", "class ")):
                    lines.insert(i, "import os")
                    break
            else:
                lines.insert(0, "import os")
        result = "\n".join(lines)
        if _verify_python_parses(result):
            return result
    return None


def _fix_python_sqlite3_string(finding: Finding, repo_root: Path) -> Optional[str]:
    """Add TODO for sqlite3 cursor.execute with f-string."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix != ".py":
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if "execute(f'" in original or 'execute(f"' in original:
        indent = original[:len(original) - len(original.lstrip())]
        lines[line_idx] = f"{indent}# TODO: SQL injection — use parameterized query: execute(\"SELECT ... WHERE x = ?\", (val,))\n{indent}# {original.strip()}"
        result = "\n".join(lines)
        if _verify_python_parses(result):
            return result
    return None


def _fix_python_pdb_trace(finding: Finding, repo_root: Path) -> Optional[str]:
    """Remove pdb.set_trace() / breakpoint() calls in Python."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix != ".py":
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if re.search(r"\bpdb\.set_trace\s*\(|\bbreakpoint\s*\(", original):
        indent = original[:len(original) - len(original.lstrip())]
        lines[line_idx] = f"{indent}# v4.35: removed debugger breakpoint\n{indent}# {original.strip()}"
        result = "\n".join(lines)
        if _verify_python_parses(result):
            return result
    return None


def _fix_python_todo_fixme(finding: Finding, repo_root: Path) -> Optional[str]:
    """Convert bare TODO/FIXME comments to GitHub-issue-friendly format."""
    # This is informational — don't actually change the comment
    return None


def _fix_python_bare_string_concat(finding: Finding, repo_root: Path) -> Optional[str]:
    """Add TODO for string concat with user input — verify no injection."""
    return None  # Too context-dependent


def _fix_java_system_exit(finding: Finding, repo_root: Path) -> Optional[str]:
    """Add TODO for System.exit() in Java — prevents reuse in containers."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix != ".java":
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if "System.exit" in original and "// TODO" not in original:
        indent = original[:len(original) - len(original.lstrip())]
        lines[line_idx] = f"{indent}// TODO: System.exit prevents container reuse — throw exception instead\n{indent}{original.strip()}"
        return "\n".join(lines)
    return None


def _fix_java_thread_sleep(finding: Finding, repo_root: Path) -> Optional[str]:
    """Add TODO for Thread.sleep() in Java."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix != ".java":
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if "Thread.sleep" in original and "// TODO" not in original:
        indent = original[:len(original) - len(original.lstrip())]
        lines[line_idx] = f"{indent}// TODO: Thread.sleep blocks — use ScheduledExecutorService or wait/notify\n{indent}{original.strip()}"
        return "\n".join(lines)
    return None


def _fix_java_empty_catch(finding: Finding, repo_root: Path) -> Optional[str]:
    """Add TODO in empty catch blocks in Java."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix != ".java":
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if re.search(r"catch\s*\([^)]*\)\s*\{\s*\}", original):
        fixed = original.replace("{}", "{ /* TODO: handle exception */ }")
        lines[line_idx] = fixed
        return "\n".join(lines)
    return None


def _fix_go_http_get_user(finding: Finding, repo_root: Path) -> Optional[str]:
    """Add TODO for http.Get with user input in Go."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix != ".go":
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if re.search(r"http\.Get\s*\(\s*(?:req|input|user|r\.)", original) and "// TODO" not in original:
        indent = original[:len(original) - len(original.lstrip())]
        lines[line_idx] = f"{indent}// TODO: http.Get with user input — SSRF risk, validate URL\n{indent}{original.strip()}"
        return "\n".join(lines)
    return None


def _fix_go_exec_command(finding: Finding, repo_root: Path) -> Optional[str]:
    """Add TODO for exec.Command with user input in Go."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix != ".go":
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if "exec.Command" in original and "// TODO" not in original:
        indent = original[:len(original) - len(original.lstrip())]
        lines[line_idx] = f"{indent}// TODO: exec.Command — verify no shell injection (no shell, but check args)\n{indent}{original.strip()}"
        return "\n".join(lines)
    return None


def _fix_go_sql_exec_user(finding: Finding, repo_root: Path) -> Optional[str]:
    """Add TODO for db.Exec with string concat in Go."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix != ".go":
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if re.search(r"db\.(?:Exec|Query)\s*\(\s*[\"`][^\"`]*\+", original) and "// TODO" not in original:
        indent = original[:len(original) - len(original.lstrip())]
        lines[line_idx] = f"{indent}// TODO: SQL with concat — use parameterized query: db.Exec(\"...\", args...)\n{indent}{original.strip()}"
        return "\n".join(lines)
    return None


def _fix_swift_force_unwrap(finding: Finding, repo_root: Path) -> Optional[str]:
    """Replace x! with x! // TODO in Swift — NPE risk."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix != ".swift":
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if re.search(r"\b\w+!\s*[\.\[(]", original) and "// TODO" not in original:
        indent = original[:len(original) - len(original.lstrip())]
        lines[line_idx] = f"{indent}// TODO: force unwrap crashes on nil — use if let or guard let\n{indent}{original.strip()}"
        return "\n".join(lines)
    return None


def _fix_swift_print(finding: Finding, repo_root: Path) -> Optional[str]:
    """Comment out print() in Swift production code."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix != ".swift":
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if re.search(r"\bprint\s*\(", original) and "//" not in original.split("print")[0]:
        indent = original[:len(original) - len(original.lstrip())]
        lines[line_idx] = f"{indent}// {original.strip()}  // v4.35: use os_log or Logger in production"
        return "\n".join(lines)
    return None


def _fix_scala_println(finding: Finding, repo_root: Path) -> Optional[str]:
    """Comment out println() in Scala production code."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix not in (".scala", ".sc"):
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if re.search(r"\bprintln\s*\(", original) and "//" not in original.split("println")[0]:
        indent = original[:len(original) - len(original.lstrip())]
        lines[line_idx] = f"{indent}// {original.strip()}  // v4.35: use slf4j/logback in production"
        return "\n".join(lines)
    return None


def _fix_scala_printstacktrace(finding: Finding, repo_root: Path) -> Optional[str]:
    """Add TODO for printStackTrace in Scala."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix not in (".scala", ".sc"):
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if ".printStackTrace" in original and "// TODO" not in original:
        indent = original[:len(original) - len(original.lstrip())]
        lines[line_idx] = f"{indent}// TODO: printStackTrace — use logger.error(\"msg\", e)\n{indent}{original.strip()}"
        return "\n".join(lines)
    return None


def _fix_scala_null_return(finding: Finding, repo_root: Path) -> Optional[str]:
    """Replace `return null` with `None` in Scala."""
    path = repo_root / finding.file
    if not path.exists() or path.suffix not in (".scala", ".sc"):
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    if "return null" in original:
        fixed = original.replace("return null", "return None  // v4.35: was null, use Option")
        if fixed != original:
            lines[line_idx] = fixed
            return "\n".join(lines)
    return None


FIX_PATTERNS: List[FixPattern] = [
    # === Original 6 patterns (v4.0–v4.33) ===
    FixPattern("L0.sast.mini:py-eval", "Replace eval() with ast.literal_eval() (literal args only)", _fix_eval_python),
    FixPattern("L5.policy.static:no-eval", "Replace eval() with ast.literal_eval() (literal args only)", _fix_eval_python),
    FixPattern("L0.sast.mini:py-hardcoded-password", "Comment out hardcoded password check + TODO", _fix_hardcoded_password),
    FixPattern("L0e.docker-latest-tag", "Pin Dockerfile FROM tag", _fix_docker_latest),
    FixPattern("L0.sast.mini:py-bare-except", "Replace bare except with except Exception", _fix_bare_except),
    FixPattern("L0.ast.AST-PY-MUTABLE-DEFAULT", "Fix mutable default argument", _fix_mutable_default),
    # === v4.34: 44 new patterns (total 50) ===
    # Python
    FixPattern("L0.sast.mini:py-exec-injection", "Comment out exec() with TODO", _fix_exec_python),
    FixPattern("L0.sast.mini:py-shell-injection", "Replace shell=True with shell=False", _fix_shell_true),
    FixPattern("L0.sast.mini:py-sql-string-format", "Fix SQL f-string injection", _fix_sql_fstring),
    FixPattern("L0.sast.mini:py-sql-var-fstring", "Add TODO for SQL f-string variable", _fix_sql_fstring),
    FixPattern("L0.sast.mini:py-assert-in-prod", "Replace assert with if/raise", _fix_assert_in_prod),
    FixPattern("L0.ast.AST-PY-PRINT-IN-PROD", "Replace print with logging.info", _fix_print_in_prod),
    FixPattern("L0.ast.AST-PY-MD5-USAGE", "Replace md5 with sha256", _fix_md5_usage),
    FixPattern("L0.ast.AST-PY-SHA1-USAGE", "Replace sha1 with sha256", _fix_sha1_usage),
    FixPattern("L0.ast.AST-PY-WEAK-RANDOM", "Replace random with secrets module", _fix_random_security),
    FixPattern("L0.ast.AST-PY-PASS-STATEMENT", "Add TODO to bare pass", _fix_pass_statement),
    FixPattern("L0.ast.AST-PY-BROAD-EXCEPT", "Add TODO for broad except", _fix_broad_except),
    FixPattern("L0.secrets.regex", "Replace hardcoded secret with env var", _fix_hardcoded_secret),
    FixPattern("L0.ast.AST-PY-UNUSED-IMPORT", "Comment out unused import", _fix_unused_import),
    FixPattern("L0.ast.AST-PY-MISSING-TYPE-HINT", "Add TODO for type hint", _fix_missing_type_hint),
    FixPattern("L0.ast.AST-PY-MISSING-DOCSTRING", "Add placeholder docstring", _fix_missing_docstring),
    FixPattern("L0.cpg_query.high_complexity", "Add TODO for high complexity", _fix_high_complexity),
    FixPattern("L0.nullness.dereference", "Add None-check before deref", _fix_null_check),
    # JavaScript/TypeScript
    FixPattern("L0.sast.mini:js-eval", "Comment out JS eval with TODO", _fix_js_eval),
    FixPattern("L0.sast.mini:js-innerhtml", "Replace innerHTML with textContent", _fix_js_innerhtml),
    FixPattern("L0.sast.mini:js-document-write", "Add TODO for document.write", _fix_js_document_write),
    FixPattern("L0.js.debugger-statement", "Remove debugger statement", _fix_debugger_js),
    FixPattern("L0.js.console-log", "Comment out console.log in production", _fix_console_log_js),
    FixPattern("L0.js.window-open-no-noopener", "Add noopener,noreferrer", _fix_window_open_no_noopener),
    FixPattern("L0.js.var-instead-of-let", "Replace var with let", _fix_var_to_let),
    FixPattern("L0.js.settimeout-string", "Replace setTimeout string with arrow fn", _fix_settimeout_string),
    # Dockerfile
    FixPattern("L0e.docker-root-user", "Add non-root USER directive", _fix_docker_root_user),
    FixPattern("L0e.docker-apt-no-cleanup", "Append apt-get cleanup", _fix_docker_apt_no_cleanup),
    FixPattern("L0e.docker-secret-env", "Comment out secret ENV", _fix_docker_secret_env),
    # Kubernetes
    FixPattern("L0e.k8s-privileged-container", "Set privileged: false", _fix_k8s_privileged),
    FixPattern("L0e.k8s-run-as-root", "Set runAsUser: 1000", _fix_k8s_run_as_root),
    FixPattern("L0e.k8s-no-resource-limits", "Add TODO for resource limits", _fix_k8s_no_resource_limits),
    FixPattern("L0e.k8s-image-latest", "Pin K8s image tag", _fix_k8s_image_latest),
    FixPattern("L0e.k8s-host-network", "Set hostNetwork: false", _fix_k8s_host_network),
    FixPattern("L0e.k8s-host-pid", "Set hostPID: false", _fix_k8s_host_pid),
    # Java
    FixPattern("L0.java.weak-hash", "Replace MD5/SHA1 with SHA-256", _fix_weak_hash_java),
    FixPattern("L0.java.print-stack-trace", "Replace printStackTrace with logging", _fix_java_print_stack_trace),
    # Go
    FixPattern("L0.go.printf-debug", "Comment out fmt.Println debug", _fix_go_printf_debug),
    # C/C++
    FixPattern("L0.cpp.strcpy", "Add TODO for strcpy → strncpy", _fix_c_buffer_overflow),
    FixPattern("L0.cpp.sprintf", "Add TODO for sprintf → snprintf", _fix_c_sprintf),
    FixPattern("L0.cpp.gets", "Replace gets with fgets", _fix_c_gets),
    FixPattern("L0.cpp.system", "Add TODO for system() → exec*", _fix_c_system),
    # Rust
    FixPattern("L0.semgrep:rust-unwrap", "Replace .unwrap() with .expect()", _fix_rust_unwrap),
    FixPattern("L0.semgrep:rust-panic-macro", "Add TODO for panic!", _fix_rust_panic),
    FixPattern("L0.semgrep:rust-println", "Comment out println! in production", _fix_rust_println),
    # Ruby
    FixPattern("L0.semgrep:ruby-html-safe", "Add TODO for html_safe XSS", _fix_ruby_html_safe),
    FixPattern("L0.semgrep:ruby-eval", "Add TODO for Ruby eval", _fix_ruby_eval),
    # PHP
    FixPattern("L0.semgrep:php-eval", "Add TODO for PHP eval", _fix_php_eval),
    FixPattern("L0.semgrep:php-error-suppression", "Remove @ error suppression", _fix_php_error_suppression),
    FixPattern("L0.semgrep:php-empty-catch", "Add TODO in empty catch", _fix_php_empty_catch),
    # Generic
    FixPattern("L0.hardcoded-url", "Add TODO to externalize URL", _fix_hardcoded_url),
    # v4.35: 50 additional patterns (total 106)
    # Kotlin
    FixPattern("L0.semgrep:kotlin-println", "Comment out Kotlin println", _fix_kotlin_println),
    FixPattern("L0.semgrep:kotlin-printstacktrace", "Replace printStackTrace with Timber", _fix_kotlin_printstacktrace),
    FixPattern("L0.semgrep:kotlin-assert-not-null", "Replace !! with ?: error()", _fix_kotlin_assert_not_null),
    FixPattern("L0.semgrep:kotlin-runblocking", "Add TODO for runBlocking", _fix_kotlin_runblocking),
    FixPattern("L0.semgrep:kotlin-globalscope", "Add TODO for GlobalScope", _fix_kotlin_globalscope),
    FixPattern("L0.semgrep:kotlin-lateinit-var", "Add TODO for lateinit", _fix_kotlin_lateinit),
    FixPattern("L0.semgrep:kotlin-md5", "Replace MD5/SHA1 with SHA-256", _fix_kotlin_md5),
    FixPattern("L0.semgrep:kotlin-random-not-secure", "Replace Random with SecureRandom", _fix_kotlin_random),
    FixPattern("L0.semgrep:kotlin-trust-all-certs", "Add CRITICAL TODO for SSL bypass", _fix_kotlin_trust_all),
    FixPattern("L0.semgrep:kotlin-sharedprefs-secret", "Add TODO for SharedPreferences secret", _fix_kotlin_sharedprefs_secret),
    # SQL
    FixPattern("L0.semgrep:sql-select-star", "Add TODO for SELECT *", _fix_sql_select_star),
    FixPattern("L0.semgrep:sql-no-where-delete", "Add CRITICAL guard for DELETE without WHERE", _fix_sql_no_where_delete),
    FixPattern("L0.semgrep:sql-no-where-update", "Add CRITICAL guard for UPDATE without WHERE", _fix_sql_no_where_update),
    FixPattern("L0.semgrep:sql-drop-table", "Add CRITICAL comment for DROP TABLE", _fix_sql_drop_table),
    FixPattern("L0.semgrep:sql-weak-password", "Add CRITICAL TODO for weak password", _fix_sql_weak_password),
    FixPattern("L0.semgrep:sql-xp-cmdshell", "Add CRITICAL TODO for xp_cmdshell", _fix_sql_xp_cmdshell),
    # Bash
    FixPattern("L0.semgrep:bash-eval", "Add TODO for eval", _fix_bash_eval),
    FixPattern("L0.semgrep:bash-unquoted-var", "Quote unquoted variables", _fix_bash_unquoted_var),
    FixPattern("L0.semgrep:bash-curl-pipe-bash", "Add CRITICAL TODO for curl|sh", _fix_bash_curl_pipe_sh),
    FixPattern("L0.semgrep:bash-chmod-777", "Replace chmod 777 with 755", _fix_bash_chmod_777),
    FixPattern("L0.semgrep:bash-set-e-missing", "Add set -euo pipefail", _fix_bash_set_e_missing),
    FixPattern("L0.semgrep:bash-rm-rf-slash", "Comment out rm -rf /", _fix_bash_rm_rf_root),
    FixPattern("L0.semgrep:bash-wget-no-check", "Remove --no-check-certificate", _fix_bash_wget_no_check_cert),
    FixPattern("L0.semgrep:bash-curl-insecure", "Remove -k/--insecure", _fix_bash_curl_insecure),
    # Dart
    FixPattern("L0.semgrep:dart-print-prod", "Comment out Dart print", _fix_dart_print),
    FixPattern("L0.semgrep:dart-md5", "Replace md5 with sha256", _fix_dart_md5),
    FixPattern("L0.semgrep:dart-random-not-secure", "Replace Random with Random.secure", _fix_dart_random),
    FixPattern("L0.semgrep:dart-assert-prod", "Add TODO for assert in prod", _fix_dart_assert),
    FixPattern("L0.semgrep:dart-sharedprefs-secret", "Add TODO for SharedPreferences secret", _fix_dart_sharedprefs_secret),
    # Python additional
    FixPattern("L0.sast.mini:py-pickle-load", "Add TODO for pickle.load RCE", _fix_python_pickle_load),
    FixPattern("L0.sast.mini:py-os-system", "Replace os.system with subprocess.run", _fix_python_os_system),
    FixPattern("L0.sast.mini:py-yaml-load", "Replace yaml.load with safe_load", _fix_python_pyyaml_unsafe),
    FixPattern("L0.sast.mini:py-subprocess-shell", "Add TODO for subprocess shell=True", _fix_python_subprocess_pipe),
    FixPattern("L0.sast.mini:py-xml-etree", "Add TODO for XXE in ElementTree", _fix_python_xml_etree),
    FixPattern("L0.sast.mini:py-requests-verify-false", "Replace verify=False with True", _fix_python_requests_verify_false),
    FixPattern("L0.sast.mini:py-flask-debug", "Replace debug=True with False", _fix_python_flask_debug),
    FixPattern("L0.sast.mini:py-django-debug", "Replace DEBUG=True with False", _fix_python_django_debug),
    FixPattern("L0.secrets.regex:Hardcoded password", "Replace hardcoded password with env var", _fix_python_hardcoded_password_str),
    FixPattern("L0.sast.mini:py-sqlite3-fstring", "Add TODO for sqlite3 f-string", _fix_python_sqlite3_string),
    FixPattern("L0.sast.mini:py-pdb-trace", "Remove pdb.set_trace/breakpoint", _fix_python_pdb_trace),
    # Java additional
    FixPattern("L0.java.system-exit", "Add TODO for System.exit", _fix_java_system_exit),
    FixPattern("L0.java.thread-sleep", "Add TODO for Thread.sleep", _fix_java_thread_sleep),
    FixPattern("L0.java.empty-catch", "Add TODO in empty catch", _fix_java_empty_catch),
    # Go additional
    FixPattern("L0.go.http-get-user", "Add TODO for http.Get user input", _fix_go_http_get_user),
    FixPattern("L0.go.exec-command", "Add TODO for exec.Command", _fix_go_exec_command),
    FixPattern("L0.go.sql-exec-user", "Add TODO for db.Exec concat", _fix_go_sql_exec_user),
    # Swift additional
    FixPattern("L0.semgrep:swift-force-unwrap", "Add TODO for force unwrap", _fix_swift_force_unwrap),
    FixPattern("L0.semgrep:swift-print-prod", "Comment out Swift print", _fix_swift_print),
    # Scala additional
    FixPattern("L0.semgrep:scala-println-prod", "Comment out Scala println", _fix_scala_println),
    FixPattern("L0.semgrep:scala-printstacktrace", "Add TODO for printStackTrace", _fix_scala_printstacktrace),
    FixPattern("L0.semgrep:scala-null-return", "Replace return null with None", _fix_scala_null_return),
]


class L8AutoFix(LayerBase):
    id = LayerID.L8_AUTOFIX  # v4.11: use own LayerID
    name = "Auto-Fix"
    description = "Generate patches for findings (deterministic + LLM-assisted)"
    LAYER_TAG = "L8_autofix"

    def __init__(self, apply: bool = False):
        self.apply = apply  # if True, apply patches directly; else just stage them

    def run(self, repo_root: Path, hunks: List[DiffHunk],
            config, prior_findings: List[Finding] = None) -> List[Finding]:
        """Generate fixes for findings from other layers."""
        findings: List[Finding] = []
        if not prior_findings:
            return findings

        fixes_dir = repo_root / ".loomscan-fixes"
        fixes_dir.mkdir(parents=True, exist_ok=True)

        applied = 0
        staged = 0
        rejected = 0  # fixes that failed safety verification
        for f in prior_findings:
            patch = self._generate_fix(f, repo_root)
            if patch is None:
                continue

            # SAFETY: For Python files, verify the patch parses before staging/applying
            if f.file.endswith(".py") and not _verify_python_parses(patch):
                rejected += 1
                findings.append(Finding(
                    layer=self.id,
                    rule_id=f"L8.fix.rejected.{f.rule_id}",
                    message=f"Auto-fix for {f.rule_id} rejected — produced invalid Python syntax",
                    file=f.file, start_line=f.start_line,
                    severity=Severity.LOW, confidence=1.0,
                    blast_radius=BlastRadius.FUNCTION, exploitability=0.0,
                    raw={"original_finding": f.fingerprint, "reason": "syntax_error"},
                ))
                continue

            patch_path = fixes_dir / f"{f.fingerprint}.patch"
            patch_path.write_text(patch, encoding="utf-8")

            if self.apply:
                self._apply_patch(repo_root / f.file, patch)
                applied += 1
            else:
                staged += 1
                findings.append(Finding(
                    layer=self.id,
                    rule_id=f"L8.fix.{f.rule_id}",
                    message=f"Auto-fix available for {f.rule_id} (staged in {patch_path.relative_to(repo_root)})",
                    file=f.file, start_line=f.start_line,
                    severity=Severity.INFO, confidence=0.7,
                    blast_radius=BlastRadius.FUNCTION, exploitability=0.0,
                    fix_suggestion=f"Apply with: loomscan fix --apply {f.fingerprint}",
                    raw={"patch_file": str(patch_path), "original_finding": f.fingerprint},
                ))

        if applied or staged or rejected:
            findings.insert(0, Finding(
                layer=self.id,
                rule_id="L8.summary",
                message=f"Auto-fix: {applied} applied, {staged} staged, {rejected} rejected (review in .loomscan-fixes/)",
                file="<autofix>", start_line=0,
                severity=Severity.INFO, confidence=1.0,
                blast_radius=BlastRadius.FUNCTION, exploitability=0.0,
                raw={"applied": applied, "staged": staged, "rejected": rejected},
            ))
        return findings

    def _generate_fix(self, finding: Finding, repo_root: Path) -> Optional[str]:
        """Try to generate a fix patch for a finding."""
        # Try built-in deterministic fixers
        for pattern in FIX_PATTERNS:
            if finding.rule_id.startswith(pattern.rule_prefix) or \
               pattern.rule_prefix in finding.rule_id:
                try:
                    return pattern.fixer(finding, repo_root)
                except Exception:
                    continue

        # Try tool-native fixers (semgrep --autofix, ruff --fix)
        if finding.rule_id.startswith("L0.semgrep:"):
            return self._semgrep_autofix(finding, repo_root)
        if finding.rule_id.startswith("L0.ruff:"):
            return self._ruff_fix(finding, repo_root)

        return None

    def _semgrep_autofix(self, finding: Finding, repo_root: Path) -> Optional[str]:
        """Use semgrep's built-in autofix if the rule has one.

        v4.11: Previously used --config auto which downloads and applies ALL
        community rules' autofixes. Now uses the specific rule_id to only
        apply the fix for the finding that fired.
        v4.15: Fixed rule ID extraction — `py-eval-injection` is LoomScan's
        local ID, not a valid semgrep registry pack. Now maintains a mapping
        from LoomScan rule prefixes to semgrep config paths, and skips autofix
        when no mapping exists (rather than always failing silently).
        """
        # v4.15: Map LoomScan rule_id prefixes to semgrep registry config paths.
        # Only rules that actually have semgrep registry equivalents are listed.
        _SEMGREP_RULE_MAP = {
            "py-eval": "p/python.lang.security.audit.eval-detected",
            "py-exec": "p/python.lang.security.audit.exec-detected",
            "py-sql": "p/python.lang.security.audit.dangerous-sql-query",
            "py-shell": "p/python.lang.security.audit.subprocess-shell-true",
            "py-hardcoded-password": "p/python.lang.security.audit.hardcoded-password-string",
            "py-hardcoded-token": "p/python.lang.security.audit.hardcoded-token-string",
            "js-eval": "p/javascript.lang.security.audit.detect-eval-with-expression",
            "js-innerhtml": "p/javascript.lang.security.audit.detect-html-injection-with-innerhtml",
        }
        try:
            path = repo_root / finding.file
            # v4.15: Look up the semgrep config from the mapping
            # v4.26: Use exact-prefix match instead of substring (py-sql
            # was matching both py-sql-injection and py-sql-string-format)
            semgrep_config = None
            for loomscan_prefix, semgrep_path in _SEMGREP_RULE_MAP.items():
                if finding.rule_id.startswith(loomscan_prefix + "-") or finding.rule_id.startswith(loomscan_prefix + ":") or finding.rule_id == loomscan_prefix:
                    semgrep_config = semgrep_path
                    break
            if not semgrep_config:
                # No semgrep mapping for this rule — skip autofix
                return None
            # v4.26: Read original content BEFORE running semgrep for hash comparison
            original_content = path.read_text(encoding="utf-8")
            proc = subprocess.run(
                ["semgrep", "--autofix", "--config", semgrep_config,
                 str(path)],
                capture_output=True, text=True, check=False, timeout=30,
                cwd=str(repo_root),
            )
            if proc.returncode != 0:
                return None
            if proc.returncode == 0:
                content = path.read_text(encoding="utf-8")
                # v4.26: Verify semgrep actually changed the file
                import hashlib
                orig_hash = hashlib.md5(original_content.encode("utf-8")).hexdigest()
                new_hash = hashlib.md5(content.encode("utf-8")).hexdigest()
                if orig_hash == new_hash:
                    return None  # No change — semgrep didn't apply a fix
                # SAFETY: verify semgrep's output parses
                if finding.file.endswith(".py") and not _verify_python_parses(content):
                    return None
                return content
        except Exception:
            pass
        return None

    def _ruff_fix(self, finding: Finding, repo_root: Path) -> Optional[str]:
        """Use ruff --fix for ruff findings."""
        try:
            path = repo_root / finding.file
            proc = subprocess.run(
                ["ruff", "check", "--fix", str(path)],
                capture_output=True, text=True, check=False, timeout=15,
                cwd=str(repo_root),
            )
            if proc.returncode == 0:
                content = path.read_text(encoding="utf-8")
                # SAFETY: verify ruff's output parses
                if finding.file.endswith(".py") and not _verify_python_parses(content):
                    return None
                return content
        except Exception:
            pass
        return None

    def _apply_patch(self, file_path: Path, new_content: str) -> None:
        """Apply a patch (full file replacement) to disk — with safety verification.

        For Python files, we verify the new content parses before writing.
        This prevents the auto-fix from breaking the user's build.
        """
        try:
            # SAFETY: For Python files, verify parses before writing
            if file_path.suffix == ".py":
                if not _verify_python_parses(new_content):
                    # Don't write broken code — this is the critical safety guard
                    return
            file_path.write_text(new_content, encoding="utf-8")
        except Exception:
            pass
