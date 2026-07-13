"""L0d — Behavioral Code Analysis (CodeScene-inspired).

CodeScene's insight: behavioral analysis of git history reveals where bugs
actually cluster. Files that are:
  - Frequently changed (high churn)
  - High complexity (cyclomatic)
  - Touched by many authors
...are 6x more likely to contain bugs than the codebase average.

This layer:
  - Computes file churn from `git log --since="3 months ago"`
  - Computes cyclomatic complexity via AST
  - Flags "hotspot" files (high churn × high complexity)
  - Detects trend: files whose complexity is growing
  - Detects "knowledge drift" (files where the original author has stopped
    touching them — high bus factor risk)

Where L0 catches bugs *in* the code, L0d catches *risk patterns* around the code.
"""
from __future__ import annotations

import ast
import subprocess
import math
from collections import defaultdict
from pathlib import Path
from typing import List, Dict, Tuple

from .base import LayerBase
from ..models import Finding, DiffHunk, LayerID, Severity, BlastRadius


class L0dBehavioral(LayerBase):
    id = LayerID.L0D_BEHAVIORAL  # v4.11: use own LayerID
    name = "Behavioral Analysis"
    description = "CodeScene-style hotspot detection, complexity trends, knowledge drift"
    LAYER_TAG = "L0d_behavioral"

    CHURN_WINDOW_DAYS = 90
    HOTSPOT_CHURN_THRESHOLD = 10    # commits in last 90 days
    HOTSPOT_COMPLEXITY_THRESHOLD = 15  # cyclomatic complexity
    HIGH_COMPLEXITY_THRESHOLD = 20
    KNOWLEDGE_DRIFT_THRESHOLD = 0.4  # original author contribution dropped below 40%

    def run(self, repo_root: Path, hunks: List[DiffHunk],
            config) -> List[Finding]:
        findings: List[Finding] = []

        files_in_diff = {h.file for h in hunks}
        if not files_in_diff:
            return findings

        # 1. Hotspot detection
        findings += self._detect_hotspots(repo_root, files_in_diff)

        # 2. High complexity
        findings += self._detect_high_complexity(repo_root, files_in_diff)

        # 3. Knowledge drift
        findings += self._detect_knowledge_drift(repo_root, files_in_diff)

        # 4. Growing complexity (trend)
        findings += self._detect_growing_complexity(repo_root, files_in_diff)

        for f in findings:
            if not f.rule_id.startswith("L0d"):
                f.rule_id = f"L0d.{f.rule_id}"

        return findings

    def _git_log(self, repo_root: Path, args: list) -> str:
        try:
            proc = subprocess.run(
                ["git", "-C", str(repo_root), "log", *args],
                capture_output=True, text=True, check=False, timeout=15,
            )
            return proc.stdout
        except Exception:
            return ""

    def _detect_hotspots(self, repo_root: Path, files: set) -> List[Finding]:
        """Files with high churn × high complexity = hotspots."""
        findings: List[Finding] = []
        # get churn count per file in last 90 days
        log_output = self._git_log(repo_root, [
            f"--since={self.CHURN_WINDOW_DAYS} days ago",
            "--name-only", "--pretty=format:",
        ])
        churn_counts: Dict[str, int] = defaultdict(int)
        for line in log_output.splitlines():
            line = line.strip()
            if line:
                churn_counts[line] += 1

        for f in files:
            churn = churn_counts.get(f, 0)
            if churn < self.HOTSPOT_CHURN_THRESHOLD:
                continue
            complexity = self._cyclomatic_complexity(repo_root / f)
            if complexity >= self.HOTSPOT_COMPLEXITY_THRESHOLD:
                findings.append(Finding(
                    layer=self.id,
                    rule_id="L0d.hotspot",
                    message=f"Hotspot file: {churn} commits in {self.CHURN_WINDOW_DAYS}d × complexity {complexity} — 6x bug risk (CodeScene pattern)",
                    file=f, start_line=1,
                    severity=Severity.MEDIUM, confidence=0.7,
                    blast_radius=BlastRadius.MODULE, exploitability=0.1,
                    cwe="CWE-1058",  # reliance on third-party/component
                    fix_suggestion="Refactor this file — split into smaller modules, add tests before changes",
                    raw={"churn": churn, "complexity": complexity},
                ))
        return findings

    def _detect_high_complexity(self, repo_root: Path, files: set) -> List[Finding]:
        """Flag individual functions with high cyclomatic complexity."""
        findings: List[Finding] = []
        for f in files:
            if not f.endswith(".py"):
                continue
            path = repo_root / f
            if not path.exists():
                continue
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"))
            except Exception:
                continue
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    cc = self._function_complexity(node)
                    if cc >= self.HIGH_COMPLEXITY_THRESHOLD:
                        findings.append(Finding(
                            layer=self.id,
                            rule_id="L0d.high_complexity",
                            message=f"High cyclomatic complexity: {node.name}() has CC={cc} (threshold {self.HIGH_COMPLEXITY_THRESHOLD})",
                            file=f, start_line=node.lineno,
                            severity=Severity.MEDIUM, confidence=0.85,
                            blast_radius=BlastRadius.FUNCTION, exploitability=0.0,
                            cwe="CWE-1058",
                            fix_suggestion="Break into smaller functions. Aim for CC<10.",
                            raw={"function": node.name, "complexity": cc},
                        ))
        return findings

    def _detect_knowledge_drift(self, repo_root: Path, files: set) -> List[Finding]:
        """Files where the original author no longer contributes — bus factor risk."""
        findings: List[Finding] = []
        for f in files:
            # Get author counts for this file
            log_output = self._git_log(repo_root, [
                "--follow", "--pretty=format:%an", "--", f
            ])
            authors = [a.strip() for a in log_output.splitlines() if a.strip()]
            if len(authors) < 5:
                continue
            original_author = authors[-1]  # earliest
            total = len(authors)
            original_count = authors.count(original_author)
            ratio = original_count / total
            if ratio < self.KNOWLEDGE_DRIFT_THRESHOLD and total > 8:
                findings.append(Finding(
                    layer=self.id,
                    rule_id="L0d.knowledge_drift",
                    message=f"Knowledge drift: original author '{original_author}' contributed {ratio:.0%} of {total} changes — bus factor risk",
                    file=f, start_line=1,
                    severity=Severity.LOW, confidence=0.6,
                    blast_radius=BlastRadius.MODULE, exploitability=0.0,
                    cwe="CWE-1058",
                    fix_suggestion="Pair-program changes to this file; document architecture decisions",
                    raw={"original_author": original_author, "ratio": ratio, "total_commits": total},
                ))
        return findings

    def _detect_growing_complexity(self, repo_root: Path, files: set) -> List[Finding]:
        """Files whose complexity has grown over time (last 6 months vs prior)."""
        findings: List[Finding] = []
        for f in files:
            if not f.endswith(".py"):
                continue
            # Get the file's content 6 months ago vs now
            try:
                old_proc = subprocess.run(
                    ["git", "-C", str(repo_root), "show", f"HEAD~30:{f}"],
                    capture_output=True, text=True, check=False, timeout=10,
                )
                if old_proc.returncode != 0:
                    continue
                old_tree = ast.parse(old_proc.stdout)
                old_cc = sum(self._function_complexity(n) for n in ast.walk(old_tree)
                             if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)))
            except Exception:
                continue
            new_cc = self._cyclomatic_complexity(repo_root / f)
            if old_cc > 0 and new_cc > old_cc * 1.5:  # 50% growth
                findings.append(Finding(
                    layer=self.id,
                    rule_id="L0d.growing_complexity",
                    message=f"Complexity growing: was CC={old_cc}, now CC={new_cc} (+{int((new_cc/old_cc - 1)*100)}%)",
                    file=f, start_line=1,
                    severity=Severity.LOW, confidence=0.65,
                    blast_radius=BlastRadius.MODULE, exploitability=0.0,
                    cwe="CWE-1058",
                    fix_suggestion="Refactor before adding more features — pay down technical debt",
                    raw={"old_complexity": old_cc, "new_complexity": new_cc},
                ))
        return findings

    def _cyclomatic_complexity(self, path: Path) -> int:
        """Sum of function complexities in a file."""
        if not path.exists() or not path.suffix == ".py":
            return 0
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
            return sum(self._function_complexity(n) for n in ast.walk(tree)
                       if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)))
        except Exception:
            return 0

    @staticmethod
    def _function_complexity(node: ast.AST) -> int:
        """Cyclomatic complexity of a single function. McCabe's formula."""
        cc = 1
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.IfExp)):
                cc += 1
            elif isinstance(child, (ast.For, ast.While, ast.AsyncFor)):
                cc += 1
            elif isinstance(child, ast.ExceptHandler):
                cc += 1
            elif isinstance(child, (ast.With, ast.AsyncWith)):
                cc += 1
            elif isinstance(child, ast.BoolOp):
                cc += len(child.values) - 1
            elif isinstance(child, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                cc += 1
        return cc
