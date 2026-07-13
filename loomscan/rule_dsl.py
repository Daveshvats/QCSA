r"""Rule authoring DSL — a YAML-like format for writing custom detection rules.

Example rule file:

    rules:
      - id: PY-NO-ASSERT-IN-PROD
        message: assert() removed with -O; use raise
        severity: medium
        cwe: CWE-617
        languages: [python]
        pattern: ^\s*assert\s+\w

    tests:
      - rule: PY-NO-ASSERT-IN-PROD
        snippets:
          - code: "assert x"
            should_match: true
          - code: "x = 1"
            should_match: false

The DSL supports `$META` (matches identifier-like tokens, captures as meta)
and `...` (matches any run of characters on the same line).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# =============================================================================
# Data model
# =============================================================================

@dataclass
class RuleFilter:
    """Filter constraints for a rule (which files it applies to)."""
    languages: List[str] = field(default_factory=list)
    paths_include: List[str] = field(default_factory=list)
    paths_exclude: List[str] = field(default_factory=list)


@dataclass
class Rule:
    """A single detection rule."""
    id: str
    message: str = ""
    severity: str = "medium"
    cwe: str = ""
    pattern: str = ""
    regex: Optional["re.Pattern"] = None
    filters: RuleFilter = field(default_factory=RuleFilter)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def matches_file(self, file_path: Path) -> bool:
        path_str = str(file_path)
        for ex in self.filters.paths_exclude:
            if ex in path_str:
                return False
        if self.filters.paths_include and not any(
            inc in path_str for inc in self.filters.paths_include
        ):
            return False
        if self.filters.languages:
            ext = file_path.suffix.lower().lstrip(".")
            lang_map = {"py": "python", "js": "javascript", "jsx": "javascript",
                        "ts": "javascript", "tsx": "javascript", "go": "go",
                        "java": "java", "c": "cpp", "cpp": "cpp"}
            lang = lang_map.get(ext, "")
            if lang not in self.filters.languages and ext not in self.filters.languages:
                return False
        return True

    def find_in(self, source: str) -> List["RuleFinding"]:
        if not self.regex:
            return []
        out: List[RuleFinding] = []
        for i, line in enumerate(source.splitlines(), 1):
            m = self.regex.search(line)
            if m:
                out.append(RuleFinding(
                    rule_id=self.id, line=i, column=m.start() + 1,
                    match=m.group(0), message=self.message,
                    severity=self.severity, cwe=self.cwe,
                    metadata=m.groupdict() or {}))
        return out


@dataclass
class RuleFinding:
    rule_id: str
    line: int
    column: int
    match: str
    message: str
    severity: str = "medium"
    cwe: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RuleTestCase:
    rule_id: str
    code: str
    should_match: bool
    description: str = ""


@dataclass
class RuleTestResult:
    rule_id: str
    passed: bool
    expected: bool
    actual: bool
    code: str
    description: str = ""


# =============================================================================
# YAML-like parser (no PyYAML dependency for simple structures)
# =============================================================================

def parse_rule(text: str) -> List[Rule]:
    """Parse a YAML-like rules file into a list of Rule objects.

    Supports the subset we need: top-level `rules:` and `tests:` blocks with
    indented `- id: ...` items and `key: value` pairs. Lists use `[a, b]`.
    """
    rules: List[Rule] = []
    lines = text.splitlines()
    i = 0
    in_rules_block = False
    current: Optional[Rule] = None
    while i < len(lines):
        raw = lines[i]
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        # top-level key
        if not line.startswith(" ") and not line.startswith("\t"):
            in_rules_block = stripped.rstrip(":") == "rules"
            if current:
                _finalize(current)
                rules.append(current)
                current = None
            i += 1
            continue
        # new rule entry
        if stripped.startswith("- "):
            if current:
                _finalize(current)
                rules.append(current)
            current = Rule(id="")
            content = stripped[2:].strip()
            if content:
                _apply_kv(current, content)
            i += 1
            continue
        # continuation key
        if current and ":" in stripped:
            _apply_kv(current, stripped)
        i += 1
    if current:
        _finalize(current)
        rules.append(current)
    return [r for r in rules if r.id]


def _apply_kv(rule: Rule, kv: str) -> None:
    if ":" not in kv:
        return
    key, _, value = kv.partition(":")
    key = key.strip()
    value = value.strip()
    if key == "id":
        rule.id = value
    elif key == "message":
        rule.message = value
    elif key == "severity":
        rule.severity = value
    elif key == "cwe":
        rule.cwe = value
    elif key == "pattern":
        rule.pattern = value
    elif key == "languages":
        rule.filters.languages = [v.strip().strip("'\"") for v in value.strip("[]").split(",") if v.strip()]
    elif key == "paths_include" or key == "include":
        rule.filters.paths_include = [v.strip().strip("'\"") for v in value.strip("[]").split(",") if v.strip()]
    elif key == "paths_exclude" or key == "exclude":
        rule.filters.paths_exclude = [v.strip().strip("'\"") for v in value.strip("[]").split(",") if v.strip()]


def _finalize(rule: Rule) -> None:
    if rule.pattern and not rule.regex:
        try:
            rule.regex = _compile_pattern(rule.pattern)
        except re.error:
            rule.regex = None


def _compile_pattern(pattern: str) -> "re.Pattern":
    r"""Compile a DSL pattern into a regex.

    Replaces:
      $META   → (?P<meta_N>\w+)
      ...     → .*?
      $IDENT  → (?P<ident>\w+)
      $STRING → (?P<string>['"][^'"]*['"])
    """
    out = pattern
    # $STRING first (more specific)
    out = re.sub(r"\$STRING", r"""['\"][^'\"]*['\"]""", out)
    out = re.sub(r"\$IDENT", r"\w+", out)
    # numbered $META captures
    counter = [0]
    def _meta(m):
        counter[0] += 1
        return f"(?P<meta_{counter[0]}>\\w+)"
    out = re.sub(r"\$META", _meta, out)
    out = out.replace("...", ".*?")
    return re.compile(out)


# =============================================================================
# Rule matcher
# =============================================================================

class RuleMatcher:
    """Run a set of rules against a file."""

    def __init__(self, rules: List[Rule]) -> None:
        self.rules = [r for r in rules if r.regex]

    def match_file(self, file_path: Path) -> List[RuleFinding]:
        if not file_path.exists():
            return []
        try:
            source = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return []
        out: List[RuleFinding] = []
        for rule in self.rules:
            if not rule.matches_file(file_path):
                continue
            out.extend(rule.find_in(source))
        return out


# =============================================================================
# Rule tester
# =============================================================================

class RuleTester:
    """Run a set of test cases against the corresponding rules."""

    def __init__(self, rules: List[Rule]) -> None:
        self.rules_by_id = {r.id: r for r in rules}

    def run(self, test_cases: List[RuleTestCase]) -> List[RuleTestResult]:
        out: List[RuleTestResult] = []
        for tc in test_cases:
            rule = self.rules_by_id.get(tc.rule_id)
            if not rule or not rule.regex:
                out.append(RuleTestResult(
                    rule_id=tc.rule_id, passed=False,
                    expected=tc.should_match, actual=False,
                    code=tc.code, description=tc.description or "rule not found"))
                continue
            matched = bool(rule.regex.search(tc.code))
            out.append(RuleTestResult(
                rule_id=tc.rule_id, passed=(matched == tc.should_match),
                expected=tc.should_match, actual=matched,
                code=tc.code, description=tc.description))
        return out


# =============================================================================
# Rule linter — detect overly-broad rules
# =============================================================================

class RuleLinter:
    """Detect rules that would produce too many false positives."""

    BROAD_PATTERNS: List[Tuple[str, str]] = [
        (r"^\.\*\??$", "matches everything — too broad"),
        (r"^\.\*\??\$?$", "wildcard-only pattern — too broad"),
        (r"^[a-z_]\w*$", "matches any single identifier — too broad"),
    ]

    def lint(self, rules: List[Rule]) -> List[Tuple[str, str]]:
        out: List[Tuple[str, str]] = []
        for rule in rules:
            if not rule.pattern:
                out.append((rule.id, "rule has no pattern"))
                continue
            for broad_re, reason in self.BROAD_PATTERNS:
                if re.match(broad_re, rule.pattern):
                    out.append((rule.id, reason))
                    break
            if len(rule.pattern) < 4 and not rule.pattern.startswith("\\"):
                out.append((rule.id, f"pattern '{rule.pattern}' is very short — likely broad"))
        return out


# =============================================================================
# File loading
# =============================================================================

def load_rules_file(path: Path) -> List[Rule]:
    """Load rules from a YAML-like file."""
    try:
        text = path.read_text(encoding="utf-8")
    except Exception:
        return []
    return parse_rule(text)


def load_rules_dir(dir_path: Path) -> List[Rule]:
    """Load all .yml/.yaml rule files from a directory."""
    out: List[Rule] = []
    if not dir_path.exists():
        return out
    for path in dir_path.rglob("*"):
        if path.suffix.lower() in {".yml", ".yaml"} and path.is_file():
            out.extend(load_rules_file(path))
    return out
