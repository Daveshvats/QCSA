"""Core data models for findings, decisions, and pipeline state."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional, Dict, Any, List, Tuple
from pathlib import Path
from hashlib import sha256
import json


class Severity(str, Enum):
    """Fuzzy severity levels. We keep them as enums for stable serialization,
    but the IT2-FIS will treat the boundaries as fuzzy (e.g., a finding at 0.6
    confidence that's nominally 'high' partially belongs to 'medium' too)."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @classmethod
    def from_score(cls, score: float) -> "Severity":
        """Map a 0-1 severity score to a discrete level."""
        if score >= 0.85: return cls.CRITICAL
        if score >= 0.65: return cls.HIGH
        if score >= 0.40: return cls.MEDIUM
        if score >= 0.20: return cls.LOW
        return cls.INFO


class Category(str, Enum):
    """Finding category — the TYPE of issue (independent of severity).

    Inspired by lintr's two-axis taxonomy (severity × category). This lets
    users filter by "show me all security issues" regardless of severity.
    """
    SECURITY = "security"          # vulnerabilities, injection, auth
    CORRECTNESS = "correctness"    # bugs that produce wrong output
    PERFORMANCE = "performance"    # slow code, resource leaks
    MAINTAINABILITY = "maintainability"  # complexity, duplication, dead code
    STYLE = "style"                # formatting, naming, consistency
    RELIABILITY = "reliability"    # None checks, error handling, edge cases
    SUPPLY_CHAIN = "supply_chain"  # dependency CVEs, EOL, typosquats
    INFRASTRUCTURE = "infrastructure"  # IaC misconfigs
    BEHAVIORAL = "behavioral"      # hotspots, churn, commit risk
    CONCURRENCY = "concurrency"    # races, deadlocks, async issues


class BlastRadius(str, Enum):
    """How wide an impact the bug has."""
    FUNCTION = "function"
    MODULE = "module"
    SYSTEM = "system"


class Decision(str, Enum):
    """The aggregator's final call on a finding (or the whole diff)."""
    BLOCK = "block"
    WARN = "warn"
    PASS = "pass"
    UNCERTAIN = "uncertain"  # triggers the optional LLM tie-breaker


class LayerID(str, Enum):
    L0_FAST = "L0_fast"
    L0B_SUPPLY_CHAIN = "L0b_supply_chain"
    # v4.11: Add missing LayerIDs so layers don't borrow L0_FAST.
    # Previously L0c/L0d/L0e/L0f/L8 all hardcoded id = LayerID.L0_FAST,
    # collapsing per-layer reliability scoring.
    L0C_DEPENDENCIES = "L0c_dependencies"
    L0D_BEHAVIORAL = "L0d_behavioral"
    L0E_IAC = "L0e_iac"
    L0F_COMMIT_RISK = "L0f_commit_risk"
    L1_PROPERTY = "L1_property"
    L2_MUTATION = "L2_test_coverage"  # v4.15: value renamed, keeping enum name for compat
    L3_INVARIANTS = "L3_invariants"
    L4_FUZZ = "L4_fuzz"
    L5_POLICY = "L5_policy"
    L6_SYMBOLIC = "L6_symbolic"
    L7_SIMULATION = "L7_simulation"
    L8_AUTOFIX = "L8_autofix"


@dataclass
class Finding:
    """A single issue reported by any layer of the pipeline."""
    layer: LayerID
    rule_id: str                      # e.g. "semgrep:python.lang.security.X"
    message: str
    file: str
    start_line: int
    end_line: int = 0
    severity: Severity = Severity.MEDIUM
    confidence: float = 0.5           # 0..1, the layer's own self-reported confidence
    blast_radius: BlastRadius = BlastRadius.FUNCTION
    exploitability: float = 0.0       # 0..1, how directly an attacker can trigger it
    category: Category = Category.CORRECTNESS  # type of issue (security, correctness, etc.)
    cwe: Optional[str] = None         # e.g. "CWE-89"
    fix_suggestion: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)
    # v4.3: Engine field for per-detector identification within L0_FAST.
    # The precision engine's corroboration logic skips same-layer findings,
    # which means ~15 detectors all using L0_FAST can never be deduped or
    # corroborated. The engine field lets precision.py group findings by
    # (layer, engine) instead of just layer, so same-concept findings from
    # different detectors (e.g., typestate.py vs v4_restored.py) can be
    # recognized as duplicates even when they share L0_FAST.
    engine: str = ""

    @property
    def fingerprint(self) -> str:
        """Stable ID for deduplication and feedback tracking."""
        h = sha256(f"{self.layer}|{self.rule_id}|{self.file}:{self.start_line}|{self.message}"
                   .encode("utf-8")).hexdigest()[:16]
        return h

    def severity_score(self) -> float:
        """Convert severity enum to a 0..1 score for the FIS."""
        return {
            Severity.CRITICAL: 0.95,
            Severity.HIGH: 0.75,
            Severity.MEDIUM: 0.50,
            Severity.LOW: 0.30,
            Severity.INFO: 0.10,
        }[self.severity]

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["layer"] = self.layer.value
        d["severity"] = self.severity.value
        d["category"] = self.category.value if hasattr(self.category, 'value') else self.category
        d["blast_radius"] = self.blast_radius.value
        d["fingerprint"] = self.fingerprint
        return d


@dataclass
class AggregatedDecision:
    """The IT2-FIS output for a single finding (or the diff as a whole)."""
    decision: Decision
    confidence_interval: Tuple[float, float]   # (lower, upper) — type-2 footprint of uncertainty
    contributing_signals: Dict[str, Any] = field(default_factory=dict)
    reasoning: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.decision.value,
            "confidence_interval": list(self.confidence_interval),
            "contributing_signals": self.contributing_signals,
            "reasoning": self.reasoning,
        }


@dataclass
class DiffHunk:
    """A single changed region in a single file."""
    file: str
    start_line: int
    end_line: int
    added_lines: List[str] = field(default_factory=list)
    removed_lines: List[str] = field(default_factory=list)
    function_name: Optional[str] = None    # tree-sitter resolved
    function_body: Optional[str] = None

    @property
    def fingerprint(self) -> str:
        h = sha256(f"{self.file}:{self.start_line}-{self.end_line}".encode()).hexdigest()[:12]
        return h


@dataclass
class PipelineResult:
    """Everything the orchestrator produces in one run."""
    findings: List[Finding] = field(default_factory=list)
    decisions: List[AggregatedDecision] = field(default_factory=list)
    diff_hunks: List[DiffHunk] = field(default_factory=list)
    layer_timings: Dict[str, float] = field(default_factory=dict)
    layers_run: List[str] = field(default_factory=list)
    llm_invoked: bool = False
    final_decision: Decision = Decision.PASS
    suppressed_count: int = 0
    # v4.11: Persist suppressed findings so reviewers can audit what was hidden.
    # Previously only suppressed_count was stored — the actual findings were discarded.
    suppressed_findings: List[tuple] = field(default_factory=list)  # List[Tuple[Finding, Suppression]]
    autofix_count: int = 0
    precision_stats: Dict[str, Any] = field(default_factory=dict)
    baselined_count: int = 0
    issue_store_stats: Dict[str, Any] = field(default_factory=dict)
    # v3.1+: scanner health tracking — surfaces previously-silent failures
    scanner_health: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def scanner_error_count(self) -> int:
        """Number of scanners that failed during this run."""
        return sum(1 for e in self.scanner_health if e.get("level") == "warning")

    @property
    def has_scanner_errors(self) -> bool:
        """True if any scanner failed during this run."""
        return self.scanner_error_count > 0

    def to_dict(self) -> Dict[str, Any]:
        # v4.14: Include suppressed_findings so reviewers can audit
        # what was hidden. v4.11 populated the field but v4.13 still
        # didn't serialize it.
        suppressed_serialized = []
        for item in self.suppressed_findings:
            if isinstance(item, tuple) and len(item) == 2:
                f, sup = item
                suppressed_serialized.append({
                    "finding": f.to_dict() if hasattr(f, 'to_dict') else str(f),
                    "suppression": {"file": sup.file, "line": sup.line,
                                    "rule_id": sup.rule_id, "reason": sup.reason}
                                    if hasattr(sup, 'file') else str(sup),
                })
        return {
            "findings": [f.to_dict() for f in self.findings],
            "decisions": [d.to_dict() for d in self.decisions],
            "diff_hunks": [
                {"file": h.file, "start": h.start_line, "end": h.end_line,
                 "function": h.function_name}
                for h in self.diff_hunks
            ],
            "layer_timings": self.layer_timings,
            "layers_run": self.layers_run,
            "llm_invoked": self.llm_invoked,
            "final_decision": self.final_decision.value,
            "suppressed_count": self.suppressed_count,
            "suppressed_findings": suppressed_serialized,  # v4.14
            "autofix_count": self.autofix_count,
            "precision_stats": self.precision_stats,
            "baselined_count": self.baselined_count,
            "issue_store_stats": self.issue_store_stats,
            "scanner_health": self.scanner_health,
            "scanner_error_count": self.scanner_error_count,
        }

    def to_json(self, path: Path) -> None:
        path.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")


@dataclass
class LayerStats:
    """Per-layer precision/recall tracking for the feedback loop."""
    layer: str
    true_positives: int = 0
    false_positives: int = 0
    bugs_missed: int = 0

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.bugs_missed
        return self.true_positives / denom if denom else 0.0

    @property
    def reliability_score(self) -> float:
        """0..1 score fed into the IT2-FIS as the 'source reliability' signal."""
        p, r = self.precision, self.recall
        if p == 0 and r == 0:
            return 0.5  # no data yet — neutral prior
        return 0.5 * (p + r)
