"""Auto-rule mining from git history.

The most valuable rules are the ones that catch YOUR bugs — not generic bugs
that might never occur in your codebase. This module mines your git history
for bug-fix commits and auto-generates Semgrep rules from the diff.

Pattern:
  1. Find commits with "fix", "bug", "patch", "CVE", "security" in message
  2. Diff the before/after code
  3. The "before" code (removed lines) is a bug pattern
  4. The "after" code (added lines) is the fix
  5. Generate a Semgrep rule that matches the "before" pattern
  6. Verify the rule catches the bug (run Semgrep against the old commit)
  7. Commit the rule to .loomscan-rules/mined/

This is "learning from your own mistakes" — every bug you've ever fixed
becomes a permanent rule that prevents the same bug from recurring.

This is the intelligent counter to "we can't write 5,000 rules overnight":
we don't write them — we mine them from the bugs you've already fixed.
"""
from __future__ import annotations

import ast
import hashlib
import json
import re
import subprocess
import textwrap
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Tuple, Optional, Dict, Set


# Commit message patterns that indicate a bug fix
BUG_FIX_PATTERNS = [
    r"\bfix(?:ed|es|ing)?\b",
    r"\bbug(?:gy|s)?\b",
    r"\bpatch(?:ed|ing)?\b",
    r"\bCVE-\d{4}-\d+\b",
    r"\bsecurity\b",
    r"\bvulnerab(?:le|ility)\b",
    r"\binject(?:ion|ed)\b",
    r"\boverflow\b",
    r"\bcrash(?:ed|es|ing)?\b",
    r"\bregress(?:ion|ed)\b",
    r"\bbreak(?:ing|s|ed)?\b",
    r"\bincorrect\b",
    r"\bwrong\b",
    r"\bbroken\b",
    r"\bdeadlock\b",
    r"\brace condition\b",
]


@dataclass
class MinedRule:
    """A rule mined from a git bug-fix commit."""
    rule_id: str
    commit_hash: str
    commit_message: str
    file: str
    bug_pattern: str  # the "before" code (removed lines)
    fix_pattern: str  # the "after" code (added lines)
    language: str
    semgrep_rule: str  # generated YAML
    verified: bool = False  # True if Semgrep confirmed it catches the bug


def find_bug_fix_commits(repo_root: Path, max_commits: int = 500) -> List[Tuple[str, str]]:
    """Find commits that look like bug fixes.

    Returns list of (commit_hash, commit_message).
    """
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo_root), "log", f"-n{max_commits}",
             "--pretty=format:%H|%s"],
            capture_output=True, text=True, check=False, timeout=30,
        )
    except Exception:
        return []

    results: List[Tuple[str, str]] = []
    for line in proc.stdout.splitlines():
        if "|" not in line:
            continue
        commit_hash, message = line.split("|", 1)
        message_lower = message.lower()
        if any(re.search(pat, message_lower) for pat in BUG_FIX_PATTERNS):
            results.append((commit_hash, message))
    return results


def get_commit_diff(repo_root: Path, commit_hash: str) -> str:
    """Get the unified diff for a commit."""
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo_root), "show", commit_hash, "--no-color",
             "--pretty=format:"],
            capture_output=True, text=True, check=False, timeout=15,
        )
        return proc.stdout
    except Exception:
        return ""


def extract_bug_fix_pairs(diff: str) -> List[Tuple[str, str, str]]:
    """Extract (file, removed_lines, added_lines) pairs from a diff.

    A "bug fix pair" is a contiguous block where lines were removed (the bug)
    and lines were added (the fix).
    """
    pairs: List[Tuple[str, str, str]] = []
    current_file = ""
    current_removed: List[str] = []
    current_added: List[str] = []

    def flush():
        nonlocal current_removed, current_added
        if current_removed and (current_added or current_removed):
            pairs.append((current_file, "\n".join(current_removed), "\n".join(current_added)))
        current_removed = []
        current_added = []

    for line in diff.splitlines():
        if line.startswith("+++ b/"):
            flush()
            current_file = line[6:]
        elif line.startswith("@@"):
            flush()
        elif line.startswith("-") and not line.startswith("---"):
            current_removed.append(line[1:])
        elif line.startswith("+") and not line.startswith("+++"):
            current_added.append(line[1:])
        else:
            # context line — flush the current pair
            flush()
    flush()
    return pairs


def detect_language(file_path: str) -> str:
    """Detect language from file extension."""
    ext = Path(file_path).suffix.lower()
    return {
        ".py": "python", ".js": "javascript", ".ts": "javascript",
        ".jsx": "javascript", ".tsx": "javascript",
        ".go": "go", ".java": "java",
        ".c": "c", ".cpp": "cpp", ".h": "c", ".hpp": "cpp",
    }.get(ext, "")


def generate_semgrep_rule(rule_id: str, bug_pattern: str, fix_pattern: str,
                           language: str, commit_hash: str,
                           commit_message: str) -> Optional[str]:
    """Generate a Semgrep rule YAML from a bug-fix pair.

    Strategy: extract the most "characteristic" line from the bug pattern
    (the one that differs most from the fix) and use it as the Semgrep pattern.
    """
    if not bug_pattern.strip():
        return None

    # Find lines that were removed but not added (the actual bug)
    bug_lines = [l.strip() for l in bug_pattern.splitlines() if l.strip()]
    fix_lines = [l.strip() for l in fix_pattern.splitlines() if l.strip()]

    if not bug_lines:
        return None

    # Pick the most distinctive bug line (longest, most different from fix)
    best_line = max(bug_lines, key=lambda l: (
        len(l) + (0 if any(l in fl for fl in fix_lines) else 20)
    ))

    # Skip lines that are too short or too generic
    if len(best_line) < 10:
        return None
    if best_line in ("{", "}", "(", ")", "return", "break", "continue", "pass"):
        return None

    # Generate metavariables for identifiers
    # Replace specific variable names with metavariables to generalize
    pattern = best_line
    # Replace string literals with metavariables
    pattern = re.sub(r'"[^"]*"', '"$X"', pattern)
    pattern = re.sub(r"'[^']*'", "'$X'", pattern)
    # Replace numbers with metavariables
    pattern = re.sub(r'\b\d+\b', '$N', pattern)

    # Escape for YAML
    rule_yaml = textwrap.dedent(f"""
      # Auto-mined from commit {commit_hash[:8]}: {commit_message[:80]}
      # Bug pattern (removed):
      # {bug_pattern.strip()[:200]}
      # Fix pattern (added):
      # {fix_pattern.strip()[:200]}
      rules:
        - id: {rule_id}
          pattern: {pattern}
          message: |
            Possible bug (mined from commit {commit_hash[:8]}):
            {commit_message[:100]}
          languages: [{language}]
          severity: WARNING
          metadata:
            source: git-mined
            commit: {commit_hash}
            original_message: {commit_message[:200]}
    """).strip() + "\n"
    return rule_yaml


def verify_rule(repo_root: Path, rule_yaml: str, old_commit: str,
                 file_path: str) -> bool:
    """Verify a mined rule catches the bug by running Semgrep on the old commit.

    Returns True if the rule matches in the old (buggy) version.
    """
    if not shutil.which("semgrep"):
        return False  # can't verify without semgrep

    # Get the old version of the file
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo_root), "show", f"{old_commit}~1:{file_path}"],
            capture_output=True, text=True, check=False, timeout=10,
        )
        if proc.returncode != 0:
            return False
        old_content = proc.stdout
    except Exception:
        return False

    # Write old content to a temp file
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=Path(file_path).suffix,
                                      delete=False, encoding="utf-8") as f:
        f.write(old_content)
        temp_path = Path(f.name)

    # Write rule to a temp file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yml",
                                      delete=False, encoding="utf-8") as f:
        f.write(rule_yaml)
        rule_path = Path(f.name)

    try:
        proc = subprocess.run(
            ["semgrep", "--config", str(rule_path), "--json", str(temp_path)],
            capture_output=True, text=True, check=False, timeout=30,
        )
        data = json.loads(proc.stdout or "{}")
        results = data.get("results", [])
        return len(results) > 0
    except Exception:
        return False
    finally:
        temp_path.unlink(missing_ok=True)
        rule_path.unlink(missing_ok=True)


import shutil


def mine_rules_from_history(repo_root: Path,
                             max_commits: int = 500,
                             verify: bool = True) -> List[MinedRule]:
    """End-to-end: mine rules from git history.

    Args:
        repo_root: path to the git repo
        max_commits: max commits to scan
        verify: if True, verify each rule with Semgrep before keeping it

    Returns:
        List of mined (and optionally verified) rules.
    """
    bug_fixes = find_bug_fix_commits(repo_root, max_commits)
    mined: List[MinedRule] = []

    for commit_hash, message in bug_fixes[:100]:  # cap at 100 commits
        diff = get_commit_diff(repo_root, commit_hash)
        if not diff:
            continue

        pairs = extract_bug_fix_pairs(diff)
        for file_path, bug_pattern, fix_pattern in pairs:
            language = detect_language(file_path)
            if not language:
                continue

            rule_id = f"mined-{commit_hash[:8]}-{hashlib.md5(bug_pattern.encode()).hexdigest()[:8]}"
            rule_yaml = generate_semgrep_rule(
                rule_id, bug_pattern, fix_pattern, language,
                commit_hash, message,
            )
            if not rule_yaml:
                continue

            verified = False
            if verify:
                verified = verify_rule(repo_root, rule_yaml, commit_hash, file_path)

            # only keep verified rules (or all if verify=False)
            if verify and not verified:
                continue

            mined.append(MinedRule(
                rule_id=rule_id,
                commit_hash=commit_hash,
                commit_message=message,
                file=file_path,
                bug_pattern=bug_pattern,
                fix_pattern=fix_pattern,
                language=language,
                semgrep_rule=rule_yaml,
                verified=verified,
            ))

    return mined


def save_mined_rules(rules: List[MinedRule], dest_dir: Path) -> List[Path]:
    """Save mined rules to .loomscan-rules/mined/."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    saved: List[Path] = []
    for rule in rules:
        path = dest_dir / f"{rule.rule_id}.yml"
        path.write_text(rule.semgrep_rule, encoding="utf-8")
        saved.append(path)
    return saved
