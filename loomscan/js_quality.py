"""JS code quality analyzer — cyclomatic complexity, toxicity, Halstead,
nesting depth, parameter count, and file health grading.

Concise regex-based implementation that works on .js/.jsx/.ts/.tsx/.mjs
without requiring a JS parser. Numbers are approximate but useful for
relative ranking.
"""
from __future__ import annotations
from .text_utils import extract_block as _extract_block

import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# =============================================================================
# Data model
# =============================================================================

@dataclass
class FunctionMetrics:
    file: str
    function: str
    line: int
    cyclomatic_complexity: int = 1
    nesting_depth: int = 0
    param_count: int = 0
    loc: int = 0
    halstead_volume: float = 0.0
    halstead_difficulty: float = 0.0
    toxicity: float = 0.0           # 0..100
    grade: str = "A"                # A..F


@dataclass
class FileHealthReport:
    file: str
    functions: List[FunctionMetrics] = field(default_factory=list)
    avg_complexity: float = 0.0
    avg_toxicity: float = 0.0
    max_toxicity: float = 0.0
    total_loc: int = 0
    grade: str = "A"


# =============================================================================
# Function extraction
# =============================================================================

_FUNC_RE = re.compile(
    r"(?:async\s+)?function\s+(?P<name>\w+)\s*\((?P<args>[^)]*)\)\s*\{"
    r"|(?:const|let|var)\s+(?P<name2>\w+)\s*=\s*(?:async\s*)?\((?P<args2>[^)]*)\)\s*=>\s*(?:\{|(?P<expr>[^\n;]+))",
    re.MULTILINE)




# =============================================================================
# Metric computation
# =============================================================================

_CC_TOKENS = re.compile(
    r"\b(?:if|else if|else|for|while|do|case|catch|&&|\|\||\?\s*[^:]*(?=:))\b"
)
_NEST_OPEN = re.compile(r"\{|\[|\(")
_NEST_CLOSE = re.compile(r"\}|\]|\)")
_HALSTEAD_OPS = re.compile(
    r"\+|\-|\*|/|%|=|==|!=|===|!==|<|>|<=|>=|&&|\|\||!|&|\||\^|<<|>>|\?|:|"
    r"\+\+|\-\-|\+=|\-=|\*=|/=|%=|\.|\bnew\b|\btypeof\b|\binstanceof\b|\bin\b"
)
_HALSTEAD_OPND = re.compile(r"\b[a-zA-Z_$][a-zA-Z0-9_$]*\b|\b\d+(?:\.\d+)?\b")


def _cyclomatic_complexity(body: str) -> int:
    return 1 + len(_CC_TOKENS.findall(body))


def _nesting_depth(body: str) -> int:
    depth = 0
    max_depth = 0
    for c in body:
        if c in "{[(":
            depth += 1
            max_depth = max(max_depth, depth)
        elif c in "}])":
            depth -= 1
    return max_depth


def _halstead(body: str) -> Tuple[float, float]:
    operators = _HALSTEAD_OPS.findall(body)
    operands = _HALSTEAD_OPND.findall(body)
    n1 = len(set(operators))
    n2 = len(set(operands))
    N1 = len(operators)
    N2 = len(operands)
    if n1 == 0 or n2 == 0 or N1 == 0 or N2 == 0:
        return 0.0, 0.0
    vocab = n1 + n2
    length = N1 + N2
    volume = length * math.log2(max(vocab, 2))
    difficulty = (n1 / 2.0) * (N2 / max(n2, 1))
    return volume, difficulty


def _toxicity(cc: int, nesting: int, params: int, halstead_vol: float,
              halstead_diff: float, loc: int) -> float:
    """Compute a 0-100 toxicity score.

    Heuristic blend of cyclomatic complexity, nesting, parameter count,
    Halstead difficulty, and length.
    """
    cc_score = min(40, max(0, (cc - 5) * 4))           # CC > 5 starts to hurt
    nest_score = min(25, nesting * 6)
    param_score = min(15, max(0, (params - 3) * 4))
    halstead_score = min(15, halstead_diff / 4.0)
    loc_score = min(5, max(0, (loc - 50) / 10.0))
    return round(min(100.0, cc_score + nest_score + param_score + halstead_score + loc_score), 1)


def _grade(toxicity: float) -> str:
    if toxicity < 10: return "A"
    if toxicity < 25: return "B"
    if toxicity < 45: return "C"
    if toxicity < 65: return "D"
    if toxicity < 85: return "E"
    return "F"


# =============================================================================
# Analyzers
# =============================================================================

def analyze_file_js_quality(file_path: Path) -> FileHealthReport:
    """Analyze one JS/TS file."""
    report = FileHealthReport(file=str(file_path))
    if not file_path.exists():
        return report
    if file_path.suffix.lower() not in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
        return report
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return report
    report.total_loc = source.count("\n") + 1
    for m in _FUNC_RE.finditer(source):
        name = m.group("name") or m.group("name2") or "<anon>"
        args_str = m.group("args") or m.group("args2") or ""
        line = source[:m.start()].count("\n") + 1
        # body: brace block or single-expression arrow
        body = ""
        if m.group("expr"):
            body = m.group("expr")
        else:
            body = _extract_block(source, m.end())
        cc = _cyclomatic_complexity(body)
        nesting = _nesting_depth(body)
        params = [a for a in re.split(r",", args_str) if a.strip()]
        vol, diff = _halstead(body)
        loc = body.count("\n") + 1
        tox = _toxicity(cc, nesting, len(params), vol, diff, loc)
        report.functions.append(FunctionMetrics(
            file=str(file_path), function=name, line=line,
            cyclomatic_complexity=cc, nesting_depth=nesting,
            param_count=len(params), loc=loc,
            halstead_volume=round(vol, 1), halstead_difficulty=round(diff, 1),
            toxicity=tox, grade=_grade(tox)))
    if report.functions:
        report.avg_complexity = round(
            sum(f.cyclomatic_complexity for f in report.functions) / len(report.functions), 2)
        report.avg_toxicity = round(
            sum(f.toxicity for f in report.functions) / len(report.functions), 2)
        report.max_toxicity = max(f.toxicity for f in report.functions)
        report.grade = _grade(report.avg_toxicity)
    return report


def analyze_repo_js_quality(repo_root: Path) -> List[FileHealthReport]:
    """Walk a repo and analyze every JS/TS file. Returns per-file reports."""
    out: List[FileHealthReport] = []
    skip = {"node_modules", ".git", "dist", "build", ".next", "vendor"}
    for path in repo_root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
            continue
        if any(s in str(path) for s in skip):
            continue
        out.append(analyze_file_js_quality(path))
    return out


def print_js_quality_report(reports: List[FileHealthReport]) -> str:
    """Render a human-readable summary."""
    lines = [f"{'File':<60} {'Grade':<6} {'AvgCC':<7} {'AvgTox':<7} {'MaxTox':<7} {'LOC':<6} {'Funcs'}"]
    lines.append("-" * 110)
    for r in sorted(reports, key=lambda x: x.avg_toxicity, reverse=True):
        if not r.functions:
            continue
        lines.append(f"{r.file[-60:]:<60} {r.grade:<6} {r.avg_complexity:<7} "
                     f"{r.avg_toxicity:<7} {r.max_toxicity:<7} {r.total_loc:<6} {len(r.functions)}")
    return "\n".join(lines)
