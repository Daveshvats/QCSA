"""Counterfactual mutation testing.

A finding is "verified" if a small mutation that *should* eliminate the bug
also eliminates the detector's report. If the detector still reports the
finding after the fix-mutation, the finding is likely a false positive.

Strategies:
  - line_removal:        remove the offending line entirely
  - guard_injection:     prepend a guard like `if x is None: return`
  - type_annotation:     add a Non-Optional type annotation
"""
from __future__ import annotations

import logging
_logger = logging.getLogger(__name__.replace('loomscan.', ''))

import ast
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple


@dataclass
class MutationResult:
    """Result of a single mutation."""
    strategy: str
    mutated: bool
    detector_still_fires: bool
    mutant_diff: str = ""
    error: str = ""


@dataclass
class MutationConfig:
    """Configuration for the counterfactual mutator."""
    strategies: List[str] = field(default_factory=lambda: ["line_removal", "guard_injection", "type_annotation"])
    timeout_seconds: int = 30
    python_executable: str = sys.executable


# =============================================================================
# Counterfactual Mutator
# =============================================================================

class CounterfactualMutator:
    """Mutates the code at a finding's location and re-runs the detector.

    The detector is any callable taking a file path and returning a list of
    findings (each having at minimum a `line` and `rule_id` attribute or being
    a dict with those keys).
    """

    def __init__(self, detector: Callable[[Path], List], config: Optional[MutationConfig] = None) -> None:
        self.detector = detector
        self.config = config or MutationConfig()

    def verify_finding(self, file_path: Path, line: int, rule_id: str,
                       column: int = 0, context: Optional[dict] = None) -> MutationResult:
        """Run all configured mutation strategies and return the best result.

        A finding is considered verified (true positive) if AT LEAST ONE
        mutation eliminates the detector's report.
        """
        context = context or {}
        # v4.11: Store file_path so _mutate can detect language for
        # language-aware no-ops. v4.10 wrote the logic but never set
        # _source_path, making the language guard dead code.
        self._source_path = str(file_path)
        context["file_path"] = str(file_path)
        try:
            source = file_path.read_text(encoding="utf-8")
        except Exception as e:
            return MutationResult(strategy="none", mutated=False,
                                  detector_still_fires=True, error=str(e))

        baseline = self._count_findings(file_path, rule_id, line)
        if baseline == 0:
            return MutationResult(strategy="baseline", mutated=False,
                                  detector_still_fires=False,
                                  error="detector did not fire on original code")

        best = MutationResult(strategy="none", mutated=False, detector_still_fires=True)
        for strategy in self.config.strategies:
            mutant_source = self._mutate(source, line, strategy, context)
            if mutant_source is None or mutant_source == source:
                continue
            with tempfile.NamedTemporaryFile(mode="w", suffix=file_path.suffix,
                                             delete=False, encoding="utf-8") as tf:
                tf.write(mutant_source)
                tmp_path = Path(tf.name)
            try:
                count = self._count_findings(tmp_path, rule_id, line)
                result = MutationResult(
                    strategy=strategy, mutated=True,
                    detector_still_fires=(count > 0),
                    mutant_diff=_unified_diff(source, mutant_source),
                )
                # Pick the strategy that ELIMINATES the finding (smallest diff wins)
                if not result.detector_still_fires:
                    return result
                if len(result.mutant_diff) < len(best.mutant_diff) or not best.mutated:
                    best = result
            finally:
                try: tmp_path.unlink()
                except Exception: pass  # v4.5: suppressed — add logging
        return best

    # ------------------------------------------------------------------
    # Mutation strategies
    # ------------------------------------------------------------------

    def _mutate(self, source: str, line: int, strategy: str, context: dict) -> Optional[str]:
        lines = source.splitlines(keepends=True)
        idx = line - 1
        if idx < 0 or idx >= len(lines):
            return None
        original = lines[idx]

        if strategy == "line_removal":
            # v4.10: Language-aware no-op — "pass" is Python-only.
            # For JS/Java/Go/C, use a comment or language-appropriate no-op.
            indent = re.match(r"^(\s*)", original).group(1)
            ext = Path(self._source_path if hasattr(self, '_source_path') else "").suffix.lower()
            # Detect language from file extension in the path
            # (context is passed by verify_finding which has file_path)
            if ext in (".js", ".jsx", ".ts", ".tsx", ".mjs"):
                lines[idx] = f"{indent}/* counterfactual: line removed */\n"
            elif ext == ".go":
                lines[idx] = f"{indent}// counterfactual: line removed\n"
            elif ext in (".java",):
                lines[idx] = f"{indent};// counterfactual: line removed\n"
            elif ext in (".c", ".cpp", ".h", ".hpp"):
                lines[idx] = f"{indent}/* counterfactual: line removed */\n"
            else:
                lines[idx] = f"{indent}pass  # counterfactual: line removed\n"
            return "".join(lines)

        if strategy == "guard_injection":
            # v5.0: Language-aware guard injection (was Python-only)
            indent = re.match(r"^(\s*)", original).group(1)
            var = context.get("variable") or self._guess_subject(original)
            ext = Path(self._source_path if hasattr(self, '_source_path') else "").suffix.lower()

            if ext in (".js", ".jsx", ".ts", ".tsx", ".mjs"):
                # JavaScript/TypeScript: if (var === null || var === undefined) return;
                guard = f"{indent}if ({var} === null || {var} === undefined) return; // counterfactual guard\n"
            elif ext == ".go":
                # Go: if var == nil { return }
                guard = f"{indent}if {var} == nil {{ return }} // counterfactual guard\n"
            elif ext == ".java":
                # Java: if (var == null) return;
                guard = f"{indent}if ({var} == null) return; // counterfactual guard\n"
            elif ext in (".c", ".cpp", ".h", ".hpp"):
                # C/C++: if (var == NULL) return;
                guard = f"{indent}if ({var} == NULL) return; /* counterfactual guard */\n"
            elif ext == ".rs":
                # Rust: if var.is_none() { return; }
                guard = f"{indent}if {var}.is_none() {{ return; }} // counterfactual guard\n"
            elif ext == ".php":
                # PHP: if ($var === null) return;
                guard = f"{indent}if (${var} === null) return; // counterfactual guard\n"
            elif ext == ".rb":
                # Ruby: return if var.nil?
                guard = f"{indent}return if {var}.nil? # counterfactual guard\n"
            else:
                # Python (default): if var is None: return None
                guard = f"{indent}if {var} is None:\n{indent}    return None  # counterfactual guard\n"
            lines.insert(idx, guard)
            return "".join(lines)

        if strategy == "type_annotation":
            # v5.0: Language-aware type annotation (was Python-only)
            var = context.get("variable") or self._guess_subject(original)
            indent = re.match(r"^(\s*)", original).group(1)
            ext = Path(self._source_path if hasattr(self, '_source_path') else "").suffix.lower()

            if ext in (".js", ".jsx", ".ts", ".tsx", ".mjs"):
                annotation = f"{indent}// @ts-expect-error counterfactual: assert non-null\n{indent}if ({var} === null) throw new Error('counterfactual');\n"
            elif ext == ".go":
                annotation = f"{indent}// counterfactual: assert non-nil\n"
            elif ext == ".java":
                annotation = f"{indent}assert {var} != null : \"counterfactual\";\n"
            elif ext in (".c", ".cpp", ".h", ".hpp"):
                annotation = f"{indent}assert({var} != NULL); /* counterfactual */\n"
            elif ext == ".rs":
                annotation = f"{indent}assert!({var}.is_some()); // counterfactual\n"
            else:
                # Python (default): assert var is not None
                annotation = f"{indent}assert {var} is not None  # counterfactual type narrowing\n"
            lines.insert(idx, annotation)
            return "".join(lines)

        return None

    def _guess_subject(self, line: str) -> str:
        """Best-effort guess of the variable name being dereferenced."""
        m = re.search(r"(\w+)\s*\.\s*\w+\s*\(", line)
        if m: return m.group(1)
        m = re.search(r"(\w+)\s*\[", line)
        if m: return m.group(1)
        m = re.search(r"(\w+)\s*=", line)
        if m: return m.group(1)
        return "x"

    def _count_findings(self, file_path: Path, rule_id: str, line: int) -> int:
        try:
            findings = self.detector(file_path) or []
        except Exception:
            return 0
        count = 0
        for f in findings:
            f_line = _attr(f, "line")
            f_rule = _attr(f, "rule_id")
            if f_rule == rule_id and abs(int(f_line or 0) - line) <= 2:
                count += 1
        return count


# =============================================================================
# Helpers
# =============================================================================

def _attr(obj, name: str):
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None)


def _unified_diff(a: str, b: str) -> str:
    import difflib
    return "".join(difflib.unified_diff(
        a.splitlines(keepends=True), b.splitlines(keepends=True),
        fromfile="original", tofile="mutant", n=1))


# =============================================================================
# Top-level convenience
# =============================================================================

def verify_findings(findings: List, detector: Callable[[Path], List],
                     repo_root: Path, config: Optional[MutationConfig] = None) -> Dict[str, MutationResult]:
    """Verify a batch of findings. Returns {fingerprint: MutationResult}."""
    mutator = CounterfactualMutator(detector, config)
    results: Dict[str, MutationResult] = {}
    for f in findings:
        file_str = _attr(f, "file") or _attr(f, "path") or ""
        if not file_str:
            continue
        fp = Path(repo_root) / file_str if not Path(file_str).is_absolute() else Path(file_str)
        line = int(_attr(f, "line") or 0)
        rule_id = _attr(f, "rule_id") or ""
        if not fp.exists() or line == 0:
            continue
        key = _attr(f, "fingerprint") or f"{fp}:{line}:{rule_id}"
        results[key] = mutator.verify_finding(fp, line, rule_id)
    return results
