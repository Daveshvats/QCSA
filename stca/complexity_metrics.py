"""Halstead complexity metrics + code toxicity scoring.

Inspired by:
  - codehawk-cli: Halstead metrics (difficulty, effort, volume, vocabulary)
  - nocuous: code toxicity (composite score per function)

Halstead metrics measure the "complexity" of code based on operators and
operands. Unlike cyclomatic complexity (which counts branches), Halstead
measures the "information content" of code.

Code toxicity combines multiple signals into a single "toxicity score" (0-100):
  - Function length (>50 lines = toxic)
  - Cyclomatic complexity (>10 = toxic)
  - Nesting depth (>4 = toxic)
  - Parameter count (>5 = toxic)
  - Halstead difficulty (>20 = toxic)
  - Return statement count (>3 = toxic)

A function with toxicity >50 is "toxic" and likely to contain bugs.
"""
from __future__ import annotations

import ast
import math
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# Halstead operator keywords in Python
PY_OPERATORS = {
    "and", "or", "not", "in", "not in", "is", "is not",
    "+", "-", "*", "/", "//", "%", "**",
    "<<", ">>", "&", "|", "^", "~",
    "==", "!=", "<", ">", "<=", ">=",
    "=", "+=", "-=", "*=", "/=", "//=", "%=", "**=", "&=", "|=", "^=", "<<=", ">>=",
    "lambda", "if", "else", "elif", "for", "while",
    "return", "yield", "break", "continue",
    "import", "from", "as", "with", "try", "except", "finally", "raise",
    "del", "global", "nonlocal", "assert", "pass",
}


@dataclass
class HalsteadMetrics:
    """Halstead complexity metrics for a function."""
    n1: int = 0  # distinct operators
    n2: int = 0  # distinct operands
    N1: int = 0  # total operators
    N2: int = 0  # total operands

    @property
    def vocabulary(self) -> int:
        """Program vocabulary: n1 + n2"""
        return self.n1 + self.n2

    @property
    def length(self) -> int:
        """Program length: N1 + N2"""
        return self.N1 + self.N2

    @property
    def volume(self) -> float:
        """Volume: V = N * log2(n) where N = N1+N2, n = n1+n2"""
        n = self.vocabulary
        N = self.length
        if n == 0:
            return 0.0
        return N * math.log2(n)

    @property
    def difficulty(self) -> float:
        """Difficulty: D = (n1/2) * (N2/n2)"""
        if self.n2 == 0:
            return 0.0
        return (self.n1 / 2) * (self.N2 / self.n2)

    @property
    def effort(self) -> float:
        """Effort: E = D * V"""
        return self.difficulty * self.volume

    @property
    def time(self) -> float:
        """Estimated time to understand: T = E / 18 (seconds)"""
        return self.effort / 18

    @property
    def bugs(self) -> float:
        """Estimated number of bugs: B = V / 3000"""
        return self.volume / 3000


@dataclass
class ToxicityReport:
    """Code toxicity report for a function."""
    function: str
    file: str
    line: int
    toxicity_score: float  # 0-100
    risk_level: str  # 'clean', 'low', 'medium', 'high', 'toxic'
    factors: Dict[str, float] = field(default_factory=dict)  # factor_name → contribution
    halstead: Optional[HalsteadMetrics] = None
    cyclomatic_complexity: int = 0
    nesting_depth: int = 0
    line_count: int = 0
    param_count: int = 0
    return_count: int = 0


def compute_halstead(func_node: ast.FunctionDef) -> HalsteadMetrics:
    """Compute Halstead metrics for a Python function."""
    operators: List[str] = []
    operands: List[str] = []

    class HalsteadVisitor(ast.NodeVisitor):
        def visit_BinOp(self, node):
            operators.append(type(node.op).__name__)
            self.generic_visit(node)

        def visit_UnaryOp(self, node):
            operators.append(type(node.op).__name__)
            self.generic_visit(node)

        def visit_Compare(self, node):
            for op in node.ops:
                operators.append(type(op).__name__)
            self.generic_visit(node)

        def visit_BoolOp(self, node):
            operators.append(type(node.op).__name__)
            self.generic_visit(node)

        def visit_Assign(self, node):
            operators.append("=")
            self.generic_visit(node)

        def visit_AugAssign(self, node):
            operators.append(type(node.op).__name__ + "=")
            self.generic_visit(node)

        def visit_Name(self, node):
            operands.append(node.id)

        def visit_Constant(self, node):
            operands.append(repr(node.value))

        def visit_Call(self, node):
            # v4.8: Don't recurse into node.func to avoid double-counting.
            # Previously, visit_Call appended func.attr, then generic_visit
            # recursed into node.func (the Attribute), and visit_Attribute
            # appended attr again — N2 was roughly 2× too high.
            if isinstance(node.func, ast.Name):
                operands.append(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                operands.append(node.func.attr)
            # Only visit args, NOT node.func (which we already handled above)
            for arg in node.args:
                self.visit(arg)
            for kw in node.keywords:
                self.visit(kw.value)

        def visit_Attribute(self, node):
            # v4.8: Only count attributes that aren't part of a Call
            # (Call.visit handles its own func attribute). This prevents
            # the double-count where foo.bar() counts "bar" twice.
            operands.append(node.attr)
            self.generic_visit(node)

        def visit_If(self, node):
            operators.append("if")
            self.generic_visit(node)

        def visit_For(self, node):
            operators.append("for")
            self.generic_visit(node)

        def visit_While(self, node):
            operators.append("while")
            self.generic_visit(node)

        def visit_Return(self, node):
            operators.append("return")
            self.generic_visit(node)

        def visit_Lambda(self, node):
            operators.append("lambda")
            self.generic_visit(node)

    visitor = HalsteadVisitor()
    visitor.visit(func_node)

    op_counter = Counter(operators)
    operand_counter = Counter(operands)

    return HalsteadMetrics(
        n1=len(op_counter),
        n2=len(operand_counter),
        N1=len(operators),
        N2=len(operands),
    )


def compute_cyclomatic_complexity(func_node: ast.FunctionDef) -> int:
    """Compute cyclomatic complexity (McCabe's formula)."""
    cc = 1
    for node in ast.walk(func_node):
        if isinstance(node, (ast.If, ast.IfExp)):
            cc += 1
        elif isinstance(node, (ast.For, ast.While, ast.AsyncFor)):
            cc += 1
        elif isinstance(node, ast.ExceptHandler):
            cc += 1
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            cc += 1
        elif isinstance(node, ast.BoolOp):
            cc += len(node.values) - 1
        elif isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            cc += 1
    return cc


def compute_nesting_depth(func_node: ast.FunctionDef) -> int:
    """Compute maximum nesting depth of a function."""
    def _depth(node, current=0):
        max_d = current
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.If, ast.For, ast.While, ast.With,
                                   ast.Try, ast.ExceptHandler)):
                d = _depth(child, current + 1)
                if d > max_d:
                    max_d = d
            else:
                d = _depth(child, current)
                if d > max_d:
                    max_d = d
        return max_d
    return _depth(func_node)


def compute_toxicity(func_node: ast.FunctionDef, file: str) -> ToxicityReport:
    """Compute the toxicity score for a function.

    Score ranges from 0 (clean) to 100 (extremely toxic).
    Each factor contributes a weighted portion of the score.
    """
    halstead = compute_halstead(func_node)
    cc = compute_cyclomatic_complexity(func_node)
    nesting = compute_nesting_depth(func_node)

    # Count lines
    line_count = func_node.end_lineno - func_node.lineno + 1 if hasattr(func_node, 'end_lineno') else 0

    # Count parameters
    param_count = len(func_node.args.args) + len(func_node.args.kwonlyargs)

    # Count return statements
    return_count = sum(1 for n in ast.walk(func_node) if isinstance(n, ast.Return))

    # Calculate toxicity factors (each contributes 0-20 points, max 100)
    factors: Dict[str, float] = {}

    # Factor 1: Line count (>50 lines = 20 points)
    factors["length"] = min(20, max(0, (line_count - 20) / 30 * 20))

    # Factor 2: Cyclomatic complexity (>10 = 20 points)
    factors["complexity"] = min(20, max(0, (cc - 5) / 10 * 20))

    # Factor 3: Nesting depth (>4 = 20 points)
    factors["nesting"] = min(20, max(0, (nesting - 3) / 3 * 20))

    # Factor 4: Parameter count (>5 = 15 points)
    factors["params"] = min(15, max(0, (param_count - 3) / 5 * 15))

    # Factor 5: Halstead difficulty (>20 = 15 points)
    factors["halstead"] = min(15, max(0, (halstead.difficulty - 10) / 15 * 15))

    # Factor 6: Return count (>3 = 10 points)
    factors["returns"] = min(10, max(0, (return_count - 2) / 5 * 10))

    total = sum(factors.values())
    total = min(100, total)

    if total >= 70:
        risk = "toxic"
    elif total >= 50:
        risk = "high"
    elif total >= 30:
        risk = "medium"
    elif total >= 15:
        risk = "low"
    else:
        risk = "clean"

    return ToxicityReport(
        function=func_node.name,
        file=file,
        line=func_node.lineno,
        toxicity_score=round(total, 1),
        risk_level=risk,
        factors={k: round(v, 1) for k, v in factors.items()},
        halstead=halstead,
        cyclomatic_complexity=cc,
        nesting_depth=nesting,
        line_count=line_count,
        param_count=param_count,
        return_count=return_count,
    )


def analyze_file_toxicity(file_path: Path, repo_root: Path = None) -> List[ToxicityReport]:
    """Analyze all functions in a Python file for toxicity."""
    if not file_path.exists() or file_path.suffix != ".py":
        return []
    try:
        source = file_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except Exception:
        return []

    rel = str(file_path.relative_to(repo_root)) if repo_root else str(file_path)
    reports: List[ToxicityReport] = []

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name.startswith("_"):
                continue
            reports.append(compute_toxicity(node, rel))

    return reports


def analyze_repo_toxicity(repo_root: Path, max_files: int = 100) -> List[ToxicityReport]:
    """Analyze all Python files for toxicity."""
    skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules",
                 ".stca-cache", ".stca-reports", ".stca-fixes", "build", "dist"}
    reports: List[ToxicityReport] = []
    count = 0
    for p in repo_root.rglob("*.py"):
        if any(part in skip_dirs for part in p.parts):
            continue
        reports.extend(analyze_file_toxicity(p, repo_root))
        count += 1
        if count >= max_files:
            break
    return reports


def toxicity_stats(reports: List[ToxicityReport]) -> dict:
    """Return toxicity statistics."""
    from collections import Counter
    by_risk = Counter(r.risk_level for r in reports)
    avg_score = sum(r.toxicity_score for r in reports) / len(reports) if reports else 0
    toxic_functions = [r for r in reports if r.risk_level in ("toxic", "high")]
    return {
        "total_functions": len(reports),
        "average_score": round(avg_score, 1),
        "by_risk": dict(by_risk),
        "toxic_count": len(toxic_functions),
        "top_toxic": [
            {"function": r.function, "file": r.file, "line": r.line,
             "score": r.toxicity_score, "risk": r.risk_level}
            for r in sorted(reports, key=lambda x: x.toxicity_score, reverse=True)[:10]
        ],
    }
