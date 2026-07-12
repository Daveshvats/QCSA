"""The orchestrator — runs layers in parallel, aggregates via IT2-FIS,
optionally invokes the LLM tie-breaker, produces a PipelineResult.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional, List
import os
import time
import json
import logging
import traceback as _tb

logger = logging.getLogger("stca.orchestrator")


def _max_files(default: int) -> int:
    """Return the effective per-engine file cap.

    v4.33: Reads STCA_MAX_FILES_OVERRIDE (set by `stca check --max-files N`).
    - If the env var is set to a positive integer N, return N (overrides default).
    - If the env var is set to "0", return a very large number (unlimited).
    - Otherwise return the engine-specific default.

    This is the single chokepoint that all max_files= call sites funnel
    through, so the override actually takes effect (v4.32 set the env var
    but no engine read it).
    """
    override = os.environ.get("STCA_MAX_FILES_OVERRIDE")
    if override:
        try:
            n = int(override)
            if n == 0:
                # 0 = unlimited — use a large sentinel instead of float('inf')
                # because some downstream APIs expect int.
                return 10_000_000
            if n > 0:
                return n
        except ValueError:
            pass
    return default

from .config import STCAConfig, find_config
from .diff_slicer import slice_diff
from .models import (
    PipelineResult, Finding, AggregatedDecision, Decision, LayerID, DiffHunk,
    Severity, BlastRadius,
)
from .layers import ALL_LAYERS
from .layers.l0b_supply_chain import L0bSupplyChain
from .layers.l0c_dependencies import L0cDependencies
from .layers.l0d_behavioral import L0dBehavioral
from .layers.l0e_iac import L0eIaC
from .layers.l0f_commit_risk import L0fCommitRisk
from .layers.l8_autofix import L8AutoFix
from .brain.aggregator import Aggregator
from .llm.client import LLMClient
from .llm.prm import PRMScorer
from .feedback.stats import StatsTracker
from .cache import ResultCache
from .suppressions import filter_suppressed
from .taint_cross_file import track_taint_for_files, track_taint_cross_file
from .cpg import build_cpg_for_repo, build_cpg_for_repo_multi
from .cpg_queries import (query_unsanitized_taint_flows, query_unused_variables,
                           query_dangerous_patterns_in_auth, query_function_complexity,
                           query_def_use_chains, query_cross_function_taint)
from .typestate import analyze_typestate
from .metamorphic import run_metamorphic_tests
from .differential import run_differential_tests
from .hotspots import HotspotManager
from .pysa_integration import PysaIntegration, get_pysa_findings_or_fallback
from .advanced_secrets import detect_secrets_advanced
from .coverage import find_coverage_report, track_coverage_history, CoverageReport
from .audit import AuditLogger
from .precision import (apply_precision_pipeline, FPLearner, ConfidenceCalibrator,
                         apply_corroboration)
from .bug_seeds import boost_finding_confidence, cross_reference_finding
from .baseline import Baseline
from .strictness import get_level, filter_findings_by_strictness, should_block
from .nullness import NullnessAnalyzer
from .issue_store import IssueStore
from .consistency import check_all_consistencies
from .models import Category
from .version_vuln_checks import scan_version_vuln_checks
from .contracts import extract_all_contracts, check_preconditions_at_call_sites
from .flawfinder_db import scan_repo_dangerous_functions
from .malicious_patterns import scan_repo_malicious_patterns, scan_malicious_patterns
from .pii_detection import scan_repo_pii, scan_pii
from .root_cause import find_root_causes, rca_stats
from .impact_analysis import ImpactAnalyzer
from .architecture import ArchitectureEnforcer
from .doc_audit import audit_repo
from .html_scanner import scan_html_config
from .js_cpg import JavaScriptCPG, scan_js_taint_flows
from .js_pattern_scanner import scan_repo_js_patterns


class Orchestrator:
    """Runs the full pipeline on a git diff."""

    def __init__(self, repo_root: Path, config: Optional[STCAConfig] = None,
                 strictness: int = None, use_baseline: bool = False):
        self.repo_root = repo_root
        self.config = config or STCAConfig.from_file(find_config(repo_root))
        self.stats_path = repo_root / self.config.stats_file
        self.aggregator = Aggregator(self.stats_path)
        self.cache = ResultCache(repo_root)
        self.hotspots = HotspotManager(repo_root)
        self.audit = AuditLogger(repo_root)
        # v4.13: Pass learn_mode from config so users can opt out of
        # the side-effect-on-every-run behavior.
        self.fp_learner = FPLearner(repo_root,
                                     learn_mode=self.config.brain.get("fp_learn_mode", True))
        self.calibrator = ConfidenceCalibrator(repo_root)
        self.baseline = Baseline(repo_root)
        self.issue_store = IssueStore(repo_root)
        self.nullness = NullnessAnalyzer()
        # strictness level (from CLI or config)
        self.strictness = strictness or self.config.layers.get("__strictness__", {}).get("level", 5)
        self.use_baseline = use_baseline
        self.llm: Optional[LLMClient] = None
        self.prm = PRMScorer()
        if self.config.llm.get("enabled"):
            self.llm = LLMClient(
                endpoint=self.config.llm.get("endpoint", "http://localhost:11434"),
                model=self.config.llm.get("model", "qwen3-coder-1.5b"),
            )
        # v4.10: Wire BayesianSecondOpinion as an opt-in deterministic second
        # opinion for UNCERTAIN/WARN findings. Runs BEFORE the LLM tie-breaker
        # (free, no I/O) and can promote UNCERTAIN→WARN or demote WARN→PASS.
        # v4.10 FIX: Use top-level config.brain dict (v4.9 used config.layers
        # which could never open the gate — STCAConfig.layers is Dict[str, LayerConfig],
        # not a plain dict with arbitrary keys).
        self.bayesian = None
        if self.config.brain.get("enable_bayesian", False):
            try:
                from .brain.bayesian import BayesianSecondOpinion
                self.bayesian = BayesianSecondOpinion()
                logger.info("BayesianSecondOpinion enabled — deterministic second opinion active")
            except Exception as e:
                logger.warning("BayesianSecondOpinion not available: %s", e)

        # v4.10: Wire ProjectTuner for per-rule confidence tuning
        self.project_tuner = None
        if self.config.brain.get("enable_project_tuner", False):
            try:
                from .brain.project_tuner import ProjectTuner, FeedbackStore
                tuner_path = self.repo_root / ".stca-project-tuner.json"
                store = FeedbackStore(tuner_path)
                self.project_tuner = ProjectTuner(store)
                self.project_tuner.refresh()
                logger.info("ProjectTuner enabled — per-rule confidence tuning active")
            except Exception as e:
                logger.warning("ProjectTuner not available: %s", e)
        # v3.1+ scanner health tracking
        self._scanner_health: List[dict] = []
        self._scanner_warnings: List[dict] = []  # v4.24: separate warnings from errors
        self._strict_scanners: bool = False

    def _scanner_error(self, scanner_name: str, exc: BaseException,
                        level: str = "warning", exc_info: bool = False) -> None:
        """Record a scanner failure to _scanner_health and log it."""
        entry = {
            "scanner": scanner_name,
            "level": level,
            "error": f"{type(exc).__name__}: {exc}",
            "error_type": type(exc).__name__,
            "traceback": "",
        }
        if exc_info:
            entry["traceback"] = "".join(_tb.format_exception(type(exc), exc, exc.__traceback__))
        # v4.24: Warnings go to separate list so they don't inflate scanner_error_count
        if level == "warning":
            self._scanner_warnings.append(entry)
            logger.warning("Scanner %s: %s", scanner_name, entry["error"])
        else:
            self._scanner_health.append(entry)
            logger.debug("Scanner %s skipped: %s", scanner_name, entry["error"])

    # v4.4: Engine-name mapping for the L0_FAST corroboration fix.
    # The precision engine's corroboration logic now uses (layer, engine)
    # instead of just layer, but this only works if engine= is set on
    # each Finding. Rather than editing 29 call sites individually, we
    # post-process all findings before returning, setting engine= based
    # on the rule_id prefix. This is a single-point fix that covers all
    # current and future detectors.
    _ENGINE_MAP = {
        "L0.bl.": "multi_language_bl",
        "L0.v4.": "v4_restored",
        "L0.v42.": "multi_language_advanced",
        "L0.cq.": "code_quality",
        "L0.ast.": "tree_sitter_analyzer",
        "L0.state.": "state_machine",
        "L0.crypto.": "crypto_audit",
        "L0.idor.": "modern_attacks",
        "L0.jspattern.": "js_pattern_scanner",
        "L0.pii.": "pii_detection",
        "L0.auth.": "business_logic",
        "L0.sast.": "baseline",
        "L0.nullness.": "nullness",
        "L0.secrets.": "advanced_secrets",
        "L0.entropy_secret.": "advanced_secrets",
        "L0.doc_audit.": "doc_audit",
        "L0f.": "commit_risk",
        "L0e.": "iac_scanner",
        "L0b.": "supply_chain",
        "L0c.": "dependency_check",
        "L0d.": "behavioral",
        "L0.contracts.": "contracts",
        "L0.malicious.": "malicious_patterns",
        "L0.flawfinder.": "flawfinder_db",
        "L0.architecture.": "architecture",
        "L0.html.": "html_scanner",
        "L0.js_taint.": "js_cpg",
        "L0.js_pattern.": "js_pattern_scanner",
        "L0.cross_file.": "taint_cross_file",
        "L0.typestate.": "typestate",
        "L0.metamorphic.": "metamorphic",
        "L0.cpg.": "cpg_queries",
    }

    def _apply_counterfactual(self, result: PipelineResult) -> None:
        """v4.11: Counterfactual verification — shared by run() and run_full().

        v4.8 fixed the inversion (verified TPs were being downgraded).
        v4.9 regressed by only calling it from run_full(). v4.10 extracts
        it into a shared helper called from both paths.
        v4.11: Apply boost/downgrade for ALL strategies (not just line_removal),
        lower the confidence threshold to 0.5 (medium-confidence TPs need
        boosts most), and raise the cap to 500.

        When the detector STOPS firing after any mutation, that means the
        finding is a TRUE POSITIVE — boost confidence +0.15.
        When the detector STILL fires, the finding may be a FALSE POSITIVE
        — downgrade confidence -0.2.
        """
        try:
            from .counterfactual import CounterfactualMutator
            # v4.11: Lower threshold from 0.7 to 0.5 and raise cap from 200 to 500
            high_conf_findings = [f for f in result.findings if f.confidence >= 0.5]
            for finding in high_conf_findings[:500]:
                try:
                    file_path = self.repo_root / finding.file
                    if not file_path.exists():
                        continue
                    def _detector(p: Path, _f=finding) -> List:
                        return self._quick_recheck(p, _f) or []
                    mutator = CounterfactualMutator(_detector)
                    result_mut = mutator.verify_finding(
                        file_path, finding.start_line, finding.rule_id
                    )
                    # v4.11: Apply for ALL strategies, not just line_removal
                    if result_mut.mutated:
                        if not result_mut.detector_still_fires:
                            # Finding disappeared after mutation → TRUE POSITIVE
                            finding.confidence = min(finding.confidence + 0.15, 0.99)
                        else:
                            # Finding still fires → possible FALSE POSITIVE
                            finding.confidence = max(finding.confidence - 0.2, 0.1)
                except Exception as e:
                    self._scanner_error("counterfactual", e)
        except Exception as e:
            self._scanner_error("counterfactual", e)

    def _apply_bayesian_second_opinion(self, result: PipelineResult) -> None:
        """v4.10: Apply BayesianSecondOpinion to UNCERTAIN/WARN findings.

        Runs after FIS aggregation, before LLM tie-breaker. The BBN can:
        - Promote UNCERTAIN→WARN (evidence supports warning)
        - Demote WARN→PASS (evidence suggests false positive)
        - Never overrule a FIS BLOCK (safety constraint)

        v4.9 had 6 API bugs that made this permanently inert. v4.10 fixes
        all 6: correct import (BBNEvidence not Evidence), correct field
        (fis_score not severity), correct method (evaluate not aggregate),
        correct return type conversion (BBNResult→AggregatedDecision),
        correct FP history call (suppression_rate not get_fp_rate),
        and correct config gate (top-level brain dict not layers.brain).
        """
        if not self.bayesian:
            return
        try:
            from .brain.bayesian import BBNEvidence
            for i, (finding, decision) in enumerate(zip(result.findings, result.decisions)):
                if decision.decision == Decision.BLOCK:
                    continue  # never override BLOCK
                if decision.decision not in (Decision.UNCERTAIN, Decision.WARN):
                    continue
                # Build evidence from the finding + decision
                # v4.10: Use fis_score from the decision's midpoint
                fis_score = 0.5
                if hasattr(decision, 'confidence_interval') and decision.confidence_interval:
                    fis_score = sum(decision.confidence_interval) / len(decision.confidence_interval)
                # v4.10: Use suppression_rate (actual FPLearner method)
                fp_history = 0.0
                try:
                    fp_history = self.fp_learner.suppression_rate(finding.rule_id, finding.file)
                except Exception:
                    pass
                evidence = BBNEvidence(
                    fis_score=fis_score,
                    confidence=finding.confidence,
                    exploitability=finding.exploitability,
                    reliability=self.aggregator.get_reliability(finding.layer.value),
                    fp_history=fp_history,
                    corroboration=0.5,  # neutral
                    test_exclusion=0.0,
                )
                # v4.10: Use evaluate() not aggregate()
                bbn_result = self.bayesian.evaluate(evidence)
                if bbn_result and bbn_result.decision != decision.decision:
                    # v4.10: Convert BBNResult to AggregatedDecision
                    result.decisions[i] = AggregatedDecision(
                        decision=bbn_result.decision,
                        confidence_interval=(bbn_result.confidence * 0.9, bbn_result.confidence),
                        contributing_signals={
                            "bbn_p_block": bbn_result.p_block,
                            "bbn_p_warn": bbn_result.p_warn,
                            "bbn_p_pass": bbn_result.p_pass,
                            "fis_score": fis_score,
                        },
                        reasoning=f"BBN second opinion: P(block)={bbn_result.p_block:.2f} "
                                  f"P(warn)={bbn_result.p_warn:.2f} P(pass)={bbn_result.p_pass:.2f} "
                                  f"→ {bbn_result.decision.value}",
                    )
        except Exception as e:
            self._scanner_error("bayesian_second_opinion", e)

    def _tag_engines(self, findings: List[Finding]) -> List[Finding]:
        """Set engine= on each finding based on rule_id prefix.

        v4.4: This is the fix Claude identified as 'built correctly but not
        connected to production.' The engine field was added in v4.3 but
        none of the 29 call sites set it. This post-processing step sets
        engine= for all findings in one place, enabling the precision
        engine's corroboration logic to distinguish same-layer findings
        from different detectors.
        """
        for f in findings:
            if f.engine:
                continue  # already set
            for prefix, engine in self._ENGINE_MAP.items():
                if prefix in f.rule_id:
                    f.engine = engine
                    break
            if not f.engine:
                f.engine = "orchestrator"
        return findings

    def run_full(self) -> PipelineResult:
        """Run the pipeline on ALL source files (not just diff).

        This is the full-repo scan mode. It discovers all source files and
        treats them as "changed" so every layer runs on every file.
        """
        # Reset scanner health for this run
        self._scanner_health = []
        self._scanner_warnings = []  # v4.26: Reset warnings too (was only in __init__)
        # v4.6: Reset skipped-file tracking so we can surface "N TypeScript
        # files skipped" warnings in the report
        try:
            from .normalized_ast import reset_skipped_file_stats
            reset_skipped_file_stats()
        except ImportError:
            pass
        self.audit.log("check_run", {"mode": "full"})

        result = PipelineResult()
        t0 = time.perf_counter()

        # Discover ALL source files and create synthetic diff hunks
        skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules",
                     ".stca-cache", ".stca-reports", ".stca-fixes", "build",
                     "dist", ".pytest_cache", "coverage"}
        source_extensions = {".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".java",
                             ".c", ".cpp", ".cc", ".h", ".hpp", ".hxx",
                             ".tf", ".yaml", ".yml", ".json", ".env",
                             ".dockerfile", ".sh", ".cfg", ".ini", ".conf"}

        all_hunks: List[DiffHunk] = []
        for p in self.repo_root.rglob("*"):
            if not p.is_file():
                continue
            if any(part in skip_dirs for part in p.parts):
                continue
            if p.suffix.lower() in source_extensions or p.name.lower().startswith("dockerfile"):
                rel = str(p.relative_to(self.repo_root))
                all_hunks.append(DiffHunk(
                    file=rel, start_line=1, end_line=9999,
                    added_lines=[], removed_lines=[],
                ))

        result.diff_hunks = all_hunks

        if not all_hunks:
            return result

        # Run the same layer pipeline as run(), but with all files
        enabled_layers = []
        for layer_cls in ALL_LAYERS:
            layer_cfg = self.config.layers.get(layer_cls.id.value)
            if layer_cfg and layer_cfg.enabled:
                if layer_cls.id in (LayerID.L6_SYMBOLIC, LayerID.L7_SIMULATION):
                    if not any(self.config.is_critical_path(h.file) for h in all_hunks) and \
                       not any(self.config.is_concurrency_path(h.file) for h in all_hunks):
                        continue
                enabled_layers.append(layer_cls())

        enabled_layers.append(L0bSupplyChain())
        enabled_layers.append(L0cDependencies())
        enabled_layers.append(L0dBehavioral())
        if any(self._is_iac_file(h.file) for h in all_hunks) or self._has_any_iac_files():
            enabled_layers.append(L0eIaC())
        enabled_layers.append(L0fCommitRisk())

        with ThreadPoolExecutor(max_workers=4) as executor:
            future_to_layer = {
                executor.submit(self._run_layer_cached, layer, all_hunks): layer
                for layer in enabled_layers
            }
            for future in as_completed(future_to_layer):
                layer = future_to_layer[future]
                try:
                    # v4.8: Enforce layer timeout — LayerConfig.timeout_seconds
                    # was defined but never enforced. A hanging subprocess
                    # (e.g. semgrep on a pathological file) would hang the
                    # whole pipeline indefinitely.
                    findings, elapsed = future.result(timeout=300)
                except TimeoutError:
                    findings = [Finding(
                        layer=getattr(layer, 'id', LayerID.L0_FAST),
                        rule_id=f"{layer.name}.timeout",
                        message=f"Layer {layer.name} timed out after 300s — skipped",
                        file="<pipeline>", start_line=0,
                        severity=Severity.LOW, confidence=1.0,
                    )]
                    elapsed = 300.0
                    self._scanner_error(layer.name, TimeoutError(f"{layer.name} timed out"))
                except Exception as e:
                    findings = [Finding(
                        layer=getattr(layer, 'id', LayerID.L0_FAST),
                        rule_id=f"{layer.name}.internal_error",
                        message=f"Layer crashed: {type(e).__name__}: {e}",
                        file="<pipeline>", start_line=0,
                    )]
                    elapsed = 0.0
                result.findings.extend(findings)
                result.layer_timings[layer.name] = elapsed
                result.layers_run.append(layer.name)

        # Dedupe — v2.9: normalized dedup that strips L0.{category}. prefix
        # so the same finding from multiple scanners (crypto/concurrency/auth/etc)
        # collapses into one
        seen = set()
        unique_findings: List[Finding] = []
        for f in result.findings:
            # Normalize rule_id for dedup: strip "L0.{category}." prefix
            normalized_rule = f.rule_id
            parts = f.rule_id.split(".")
            if len(parts) > 2 and parts[0] == "L0" and parts[1] in (
                "state", "concurrency", "crypto", "modern", "idor", "cq", "biz",
                "auth", "ast", "taint", "bl", "v4"
            ):
                normalized_rule = ".".join(parts[2:])
            # Also normalize file path (remove any leading ./)
            normalized_file = f.file.lstrip("./")
            dedup_key = (normalized_rule, normalized_file, f.start_line)
            if dedup_key not in seen:
                seen.add(dedup_key)
                unique_findings.append(f)
        result.findings = unique_findings

        # Advanced detection
        result.findings += self._run_cross_file_taint_tracking_with_pysa(all_hunks)
        result.findings += self._run_advanced_secret_detection(all_hunks)
        result.findings += self._run_hotspot_detection(all_hunks)
        result.findings += self._run_typestate_analysis(all_hunks)
        result.findings += self._run_cpg_queries(all_hunks)
        result.findings += self._run_knowledge_graph_analysis(all_hunks)
        result.findings += self._run_spec_mining(all_hunks)  # v4.38
        result.findings += self._run_advanced_research_engines()
        result.findings += self._run_metamorphic_tests(all_hunks)
        result.findings += self._run_differential_tests(all_hunks)
        result.findings += self._run_coverage_checks(all_hunks)
        result.findings += self._run_nullness_analysis(all_hunks)
        result.findings += self._run_consistency_checks()
        result.findings += self._run_missing_patch_detection()
        result.findings += self._run_malicious_pattern_detection(all_hunks)
        result.findings += self._run_flawfinder_scan()
        result.findings += self._run_contract_verification(all_hunks)
        result.findings += self._run_pii_detection(all_hunks)
        result.findings += self._run_architecture_check()
        result.findings += self._run_doc_audit()
        result.findings += self._run_html_config_scan()
        result.findings += self._run_js_taint_tracking()
        result.findings += self._run_js_pattern_scan()

        # v2 analyzers (multi-lang, code quality, config, IaC, supply chain, AST)
        result.findings += self._run_v2_analyzers()

        # Suppression filter
        kept, suppressed = filter_suppressed(result.findings, self.repo_root)
        result.findings = kept
        result.suppressed_count = len(suppressed)
        result.suppressed_findings = suppressed  # v4.11: persist for audit

        # Bug-seed boost
        for f in result.findings:
            new_conf, seed_name = boost_finding_confidence(f)
            if seed_name:
                f.confidence = new_conf
                if not f.raw:
                    f.raw = {}
                f.raw["bug_seed"] = seed_name

        # v4.24: Tag engines BEFORE precision pipeline (unblocks corroboration)
        result.findings = self._tag_engines(result.findings)

        # Precision pipeline
        result.findings, precision_stats = apply_precision_pipeline(
            result.findings, self.repo_root, self.fp_learner, self.calibrator
        )
        result.precision_stats = precision_stats

        # v4.10: Counterfactual verification — extracted to shared helper
        # so both run() and run_full() get the fix. v4.9 regressed by only
        # having it in run_full().
        self._apply_counterfactual(result)

        # v2.9: Final normalized dedup — collapse cross-scanner duplicates
        seen = set()
        unique_findings: List[Finding] = []
        for f in result.findings:
            normalized_rule = f.rule_id
            parts = f.rule_id.split(".")
            if len(parts) > 2 and parts[0] == "L0" and parts[1] in (
                "state", "concurrency", "crypto", "modern", "idor", "cq", "biz",
                "auth", "ast", "taint", "bl", "v4"
            ):
                normalized_rule = ".".join(parts[2:])
            normalized_file = f.file.lstrip("./")
            dedup_key = (normalized_rule, normalized_file, f.start_line)
            if dedup_key not in seen:
                seen.add(dedup_key)
                unique_findings.append(f)
        result.findings = unique_findings

        # Strictness filter
        result.findings = filter_findings_by_strictness(result.findings, self.strictness)

        # v4.10: Apply ProjectTuner per-rule confidence adjustment before FIS
        if self.project_tuner:
            for f in result.findings:
                mult = self.project_tuner.get_confidence_multiplier(f.rule_id)
                if mult != 1.0:
                    f.confidence = max(0.0, min(1.0, f.confidence * mult))
                if self.project_tuner.is_suppressed(f.rule_id):
                    f.confidence = 0.0  # v4.14: will be filtered below

        # v4.14 BUG #8 FIX: Actually filter confidence=0 findings.
        # Previously set confidence=0 but nothing filtered them.
        result.findings = [f for f in result.findings if f.confidence > 0.0]

        # FIS aggregation
        result.decisions, result.final_decision = self.aggregator.aggregate(result.findings)
        # v4.9: Apply Bayesian second opinion (opt-in, before LLM tie-breaker)
        self._apply_bayesian_second_opinion(result)

        # v4.14 BUG #4 FIX: Add LLM tie-breaker to run_full() too
        # (was only in run(), causing stca check and stca check --full to diverge)
        if self.llm and self.config.llm.get("only_on_uncertain", True):
            for i, (finding, decision) in enumerate(zip(result.findings, result.decisions)):
                if decision.decision == Decision.UNCERTAIN:
                    llm_decision = self._llm_tie_break(finding)
                    if llm_decision:
                        result.decisions[i] = llm_decision

        # v4.14: Add baseline filtering to run_full() too
        if self.use_baseline and self.baseline.exists():
            result.findings, baselined = self.baseline.filter_new(result.findings)
            result.baselined_count = len(baselined)

        # Auto-fix
        fixable_findings = [f for f in result.findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        if fixable_findings:
            # v4.8: Wrap L8AutoFix in try/except so a fix-write crash
            # doesn't lose all results after analysis is complete.
            try:
                autofix = L8AutoFix(apply=False)
                fix_findings = autofix.run(self.repo_root, all_hunks, self.config,
                                            prior_findings=fixable_findings)
                result.findings.extend(fix_findings)
            except Exception as e:
                self._scanner_error("l8_autofix", e)

        # Store in issue store
        try:
            new_count, recurring_count = self.issue_store.upsert_findings(result.findings)
            result.issue_store_stats = {
                "new": new_count, "recurring": recurring_count,
                "total_in_store": self.issue_store.stats()["total_issues"],
            }
        except Exception as e:
            self._scanner_error("issue_store", e)

        # v4.24: _tag_engines already called above (before precision pipeline)

        # Surface scanner failures in the result
        result.scanner_health = list(self._scanner_health)
        # v4.24: Also include warnings in a separate field (not in scanner_health)
        if hasattr(self, '_scanner_warnings') and self._scanner_warnings:
            result.scanner_warnings = list(self._scanner_warnings)

        # v4.6: Surface skipped files due to missing language support
        # v4.24: These go to scanner_warnings, not scanner_health
        try:
            from .normalized_ast import get_skipped_file_stats
            skipped = get_skipped_file_stats()
            for lang, count in skipped.items():
                if not hasattr(result, 'scanner_warnings'):
                    result.scanner_warnings = []
                result.scanner_warnings.append({
                    "scanner": "normalized_ast",
                    "level": "warning",
                    "error": f"{count} {lang} file(s) skipped — tree_sitter_{lang} not installed. "
                             f"Install with: pip install tree_sitter_{lang}",
                    "error_type": "UnsupportedLanguage",
                    "traceback": "",
                })
        except ImportError:
            pass

        # v4.10: Surface supply-chain tool_missing findings as warnings
        # v4.24: Go to scanner_warnings, not scanner_health
        for f in result.findings:
            if "tool_missing" in f.rule_id:
                if not hasattr(result, 'scanner_warnings'):
                    result.scanner_warnings = []
                result.scanner_warnings.append({
                    "scanner": f.rule_id,
                    "level": "warning",
                    "error": f.message,
                    "error_type": "ToolMissing",
                    "traceback": "",
                })
        self._save_reports(result)
        result.layer_timings["__total__"] = time.perf_counter() - t0
        return result

    def run(self, base: str = "HEAD", staged: bool = False) -> PipelineResult:

        result = PipelineResult()
        t0 = time.perf_counter()
        # v4.26: Reset scanner health AND warnings for this run
        self._scanner_health = []
        self._scanner_warnings = []

        # Step 1: slice the diff
        result.diff_hunks = slice_diff(self.repo_root, base=base, staged=staged)
        if not result.diff_hunks:
            # clean diff — still run supply chain checks (they're diff-independent)
            enabled_layers = [L0bSupplyChain(), L0cDependencies()]
            for layer in enabled_layers:
                findings, elapsed = layer.time_run(self.repo_root, [], self.config)
                result.findings.extend(findings)
                result.layer_timings[layer.name] = elapsed
                result.layers_run.append(layer.name)
            result.decisions, result.final_decision = self.aggregator.aggregate(result.findings)
            self._apply_bayesian_second_opinion(result)
            self._save_reports(result)
            return result

        # Step 2: instantiate enabled layers
        enabled_layers = []
        for layer_cls in ALL_LAYERS:
            layer_cfg = self.config.layers.get(layer_cls.id.value)
            if layer_cfg and layer_cfg.enabled:
                # force-enable L6 for critical paths, L7 for concurrency paths
                if layer_cls.id in (LayerID.L6_SYMBOLIC, LayerID.L7_SIMULATION):
                    if not any(self.config.is_critical_path(h.file) for h in result.diff_hunks) and \
                       not any(self.config.is_concurrency_path(h.file) for h in result.diff_hunks):
                        continue
                enabled_layers.append(layer_cls())

        # Always include L0b (supply chain) and L0c (dependency health) — they're fast
        enabled_layers.append(L0bSupplyChain())
        enabled_layers.append(L0cDependencies())
        # Behavioral analysis (hotspots, complexity) — fast
        enabled_layers.append(L0dBehavioral())
        # IaC scanning — only if IaC files present
        if any(self._is_iac_file(h.file) for h in result.diff_hunks) or \
           self._has_any_iac_files():
            enabled_layers.append(L0eIaC())
        # Commit risk — always (very fast)
        enabled_layers.append(L0fCommitRisk())

        # Step 3: run layers in parallel (with caching)
        with ThreadPoolExecutor(max_workers=4) as executor:
            future_to_layer = {
                executor.submit(self._run_layer_cached, layer, result.diff_hunks): layer
                for layer in enabled_layers
            }
            for future in as_completed(future_to_layer):
                layer = future_to_layer[future]
                try:
                    # v4.8: Enforce layer timeout — LayerConfig.timeout_seconds
                    # was defined but never enforced. A hanging subprocess
                    # (e.g. semgrep on a pathological file) would hang the
                    # whole pipeline indefinitely.
                    findings, elapsed = future.result(timeout=300)
                except TimeoutError:
                    findings = [Finding(
                        layer=getattr(layer, 'id', LayerID.L0_FAST),
                        rule_id=f"{layer.name}.timeout",
                        message=f"Layer {layer.name} timed out after 300s — skipped",
                        file="<pipeline>", start_line=0,
                        severity=Severity.LOW, confidence=1.0,
                    )]
                    elapsed = 300.0
                    self._scanner_error(layer.name, TimeoutError(f"{layer.name} timed out"))
                except Exception as e:
                    findings = [Finding(
                        layer=getattr(layer, 'id', LayerID.L0_FAST),
                        rule_id=f"{layer.name}.internal_error",
                        message=f"Layer crashed: {type(e).__name__}: {e}",
                        file="<pipeline>", start_line=0,
                    )]
                    elapsed = 0.0
                result.findings.extend(findings)
                result.layer_timings[layer.name] = elapsed
                result.layers_run.append(layer.name)

        # Step 4: dedupe findings by fingerprint
        seen = set()
        unique_findings: List[Finding] = []
        for f in result.findings:
            if f.fingerprint not in seen:
                seen.add(f.fingerprint)
                unique_findings.append(f)
        result.findings = unique_findings

        # Step 4b: add cross-file taint tracking (CPG-based, with Pysa fallback)
        result.findings += self._run_cross_file_taint_tracking_with_pysa(result.diff_hunks)

        # Step 4b2: advanced secret detection (TruffleHog + entropy)
        result.findings += self._run_advanced_secret_detection(result.diff_hunks)

        # Step 4b3: security hotspot detection (SonarQube-style, with review workflow)
        result.findings += self._run_hotspot_detection(result.diff_hunks)

        # Step 4c: add typestate analysis (state machine violations)
        result.findings += self._run_typestate_analysis(result.diff_hunks)

        # Step 4d: add CPG queries (Joern-style pattern queries)
        result.findings += self._run_cpg_queries(result.diff_hunks)
        result.findings += self._run_knowledge_graph_analysis(result.diff_hunks)
        result.findings += self._run_spec_mining(result.diff_hunks)  # v4.38
        result.findings += self._run_advanced_research_engines()

        # Step 4e: add metamorphic testing (oracle-free bug detection)
        if self.config.layers.get("L1_property") and \
           self.config.layers["L1_property"].enabled:
            result.findings += self._run_metamorphic_tests(result.diff_hunks)

        # Step 4f: add differential testing (refactor verification)
        result.findings += self._run_differential_tests(result.diff_hunks)

        # Step 4g: coverage integration (track coverage drops on changed files)
        result.findings += self._run_coverage_checks(result.diff_hunks)

        # Step 4g2: multi-language business logic detection (v4: all languages)
        try:
            from .multi_language_bl import detect_repo as detect_bl_multi
            bl_sev_map = {"high": Severity.HIGH, "medium": Severity.MEDIUM,
                          "low": Severity.LOW, "critical": Severity.CRITICAL}
            for blf in detect_bl_multi(self.repo_root, max_files=_max_files(200)):
                result.findings.append(Finding(
                    layer=LayerID.L0_FAST, rule_id=f"L0.bl.{blf.rule_id}",
                    message=blf.description, file=blf.file, start_line=blf.line,
                    severity=bl_sev_map.get(blf.severity, Severity.MEDIUM), confidence=0.8,
                    blast_radius=BlastRadius.SYSTEM if "AUTH" in blf.rule_id or "REENTRANCY" in blf.rule_id else BlastRadius.FUNCTION,
                    exploitability=0.7 if "AUTH" in blf.rule_id else 0.5,
                    category=Category.SECURITY if "AUTH" in blf.rule_id or "REENTRANCY" in blf.rule_id else Category.CORRECTNESS,
                    cwe=blf.cwe, fix_suggestion=blf.fix,
                    raw={"language": blf.language, "function": blf.function}))
        except Exception as e:
            self._scanner_error("run", e)

        # Step 4h: filter suppressed findings (inline `# stca: ignore`)
        kept, suppressed = filter_suppressed(result.findings, self.repo_root)
        result.findings = kept
        result.suppressed_count = len(suppressed)
        result.suppressed_findings = suppressed  # v4.11: persist for audit

        # Step 4i: bug-seed cross-reference — boost confidence for known CWE patterns
        for f in result.findings:
            new_conf, seed_name = boost_finding_confidence(f)
            if seed_name:
                f.confidence = new_conf
                if not f.raw:
                    f.raw = {}
                f.raw["bug_seed"] = seed_name

        # v4.24: Tag engines BEFORE precision pipeline (same fix as run_full)
        result.findings = self._tag_engines(result.findings)

        # Step 4j: precision pipeline — corroboration + FP learning + calibration
        result.findings, precision_stats = apply_precision_pipeline(
            result.findings, self.repo_root, self.fp_learner, self.calibrator
        )
        result.precision_stats = precision_stats

        # v4.10: Counterfactual verification — now in run() too (was only in run_full)
        self._apply_counterfactual(result)

        # Step 4k: nullness analysis (NilAway-inspired) — None dereference detection
        result.findings += self._run_nullness_analysis(result.diff_hunks)

        # Step 4l: consistency checker (credo-inspired) — inconsistent patterns
        result.findings += self._run_consistency_checks()

        # Step 4k2: missing-patch detection (Vanir-inspired) — unpatched CVEs
        result.findings += self._run_missing_patch_detection()

        # Step 4k3: malicious package pattern detection (aura-inspired)
        result.findings += self._run_malicious_pattern_detection(result.diff_hunks)

        # Step 4k4: C/C++ dangerous function database (flawfinder-inspired)
        result.findings += self._run_flawfinder_scan()

        # Step 4l2: contract verification (deal-inspired) — check @pre/@post
        result.findings += self._run_contract_verification(result.diff_hunks)

        # Step 4l3: PII detection (pii-shield-inspired)
        result.findings += self._run_pii_detection(result.diff_hunks)

        # Step 4l4: architecture enforcement (rev-dep-inspired)
        result.findings += self._run_architecture_check()

        # Step 4l5: documentation audit (valknut-inspired)
        result.findings += self._run_doc_audit()

        # v4.8: Unify run() and run_full() — these scanners were missing from run(),
        # causing stca check and stca check --full to produce different results.
        result.findings += self._run_html_config_scan()
        result.findings += self._run_js_taint_tracking()
        result.findings += self._run_js_pattern_scan()
        result.findings += self._run_v2_analyzers()

        # Step 4m: strictness filtering (PHPStan-inspired) — only report at configured level
        result.findings = filter_findings_by_strictness(result.findings, self.strictness)

        # v4.14 BUG #4 FIX: Apply ProjectTuner in run() too (was only in run_full).
        # This was one of 5 divergences between stca check and stca check --full.
        if self.project_tuner:
            for f in result.findings:
                mult = self.project_tuner.get_confidence_multiplier(f.rule_id)
                if mult != 1.0:
                    f.confidence = max(0.0, min(1.0, f.confidence * mult))
                if self.project_tuner.is_suppressed(f.rule_id):
                    f.confidence = 0.0
            result.findings = [f for f in result.findings if f.confidence > 0.0]

        # Step 4n: baseline filtering (detekt-inspired) — only flag NEW issues
        if self.use_baseline and self.baseline.exists():
            result.findings, baselined = self.baseline.filter_new(result.findings)
            result.baselined_count = len(baselined)

        # Step 4o: store findings in issue store (CodeChecker-inspired) + trend tracking
        try:
            new_count, recurring_count = self.issue_store.upsert_findings(result.findings)
            result.issue_store_stats = {
                "new": new_count, "recurring": recurring_count,
                "total_in_store": self.issue_store.stats()["total_issues"],
            }
        except Exception as e:
            self._scanner_error("run", e)

        # Step 5: aggregate via IT2-FIS
        result.decisions, result.final_decision = self.aggregator.aggregate(result.findings)
        # v4.9: Apply Bayesian second opinion (opt-in, before LLM tie-breaker)
        self._apply_bayesian_second_opinion(result)

        # Step 6: optional LLM tie-breaker for UNCERTAIN findings
        if self.llm and self.config.llm.get("only_on_uncertain", True):
            for i, (finding, decision) in enumerate(zip(result.findings, result.decisions)):
                if decision.decision == Decision.UNCERTAIN:
                    llm_decision = self._llm_tie_break(finding)
                    if llm_decision:
                        result.decisions[i] = llm_decision
                        result.llm_invoked = True
            # recompute final decision
            from .models import Decision as D
            priority = {D.BLOCK: 4, D.WARN: 3, D.UNCERTAIN: 2, D.PASS: 1}
            if result.decisions:
                result.final_decision = max(
                    result.decisions, key=lambda d: priority[d.decision]
                ).decision

        # Step 6b: auto-fix — generate patches for HIGH/CRITICAL findings
        fixable_findings = [f for f in result.findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        if fixable_findings:
            try:
                autofix = L8AutoFix(apply=False)
                fix_findings = autofix.run(self.repo_root, result.diff_hunks, self.config,
                                            prior_findings=fixable_findings)
                result.findings.extend(fix_findings)
            except Exception as e:
                self._scanner_error("l8_autofix", e)

        # Step 7: persist reports
        # v4.24: _tag_engines already called above (before precision pipeline)
        result.scanner_health = list(self._scanner_health)
        self._save_reports(result)

        result.layer_timings["__total__"] = time.perf_counter() - t0
        return result

    def _run_layer_cached(self, layer, hunks: List[DiffHunk]) -> tuple:
        """Run a layer with function-level result caching."""
        import time as _time
        t0 = _time.perf_counter()

        cached_findings: List[Finding] = []
        uncached_hunks: List[DiffHunk] = []

        for hunk in hunks:
            if hunk.function_body:
                cached = self.cache.get(layer.name, hunk.function_body)
                if cached is not None:
                    for f_dict in cached:
                        try:
                            cached_findings.append(Finding(
                                layer=LayerID(f_dict["layer"]) if f_dict["layer"] in [l.value for l in LayerID] else LayerID.L0_FAST,
                                rule_id=f_dict["rule_id"],
                                message=f_dict["message"],
                                file=f_dict["file"],
                                start_line=f_dict["start_line"],
                                end_line=f_dict.get("end_line", 0),
                                severity=Severity(f_dict["severity"]),
                                confidence=f_dict["confidence"],
                                blast_radius=BlastRadius(f_dict["blast_radius"]),
                                exploitability=f_dict["exploitability"],
                                cwe=f_dict.get("cwe"),
                                fix_suggestion=f_dict.get("fix_suggestion"),
                                raw=f_dict.get("raw", {}),
                            ))
                        except Exception:
                            continue
                    continue
            uncached_hunks.append(hunk)

        if uncached_hunks or not cached_findings:
            new_findings, _ = layer.time_run(self.repo_root, hunks if not cached_findings else uncached_hunks, self.config)
        else:
            new_findings = []

        cacheable_layers = {"Fast Hooks", "Property Tests", "Invariant Checks", "Policy Checks"}
        if layer.name in cacheable_layers:
            for hunk in uncached_hunks:
                if hunk.function_body:
                    func_findings = [f for f in new_findings if f.file == hunk.file
                                     and hunk.start_line <= f.start_line <= hunk.end_line]
                    self.cache.put(layer.name, hunk.function_body,
                                   [f.to_dict() for f in func_findings])

        elapsed = _time.perf_counter() - t0
        return cached_findings + new_findings, elapsed

    def _run_nullness_analysis(self, hunks: List[DiffHunk]) -> List[Finding]:
        """Run sound nullness analysis (NilAway-inspired) on changed Python files."""
        findings: List[Finding] = []
        seen_files: set = set()
        for hunk in hunks:
            if not hunk.file.endswith(".py") or hunk.file in seen_files:
                continue
            seen_files.add(hunk.file)
            file_path = self.repo_root / hunk.file
            if not file_path.exists():
                continue
            issues = self.nullness.analyze_file(file_path, self.repo_root)
            for issue in issues:
                findings.append(Finding(
                    layer=LayerID.L0_FAST,
                    rule_id="L0.nullness.dereference",
                    message=f"Possible None dereference: {issue.reason}",
                    file=issue.file, start_line=issue.line,
                    severity=Severity.HIGH, confidence=issue.confidence,
                    blast_radius=BlastRadius.FUNCTION, exploitability=0.2,
                    category=Category.RELIABILITY,
                    cwe="CWE-476",  # NULL Pointer Dereference
                    fix_suggestion=f"Add a None check before using '{issue.variable}': `if {issue.variable} is not None: ...`",
                    raw={"variable": issue.variable, "reason": issue.reason,
                         "context": issue.context},
                ))
        return findings

    def _run_consistency_checks(self) -> List[Finding]:
        """Run consistency checks (credo-inspired) across the codebase."""
        findings: List[Finding] = []
        inconsistencies = check_all_consistencies(self.repo_root, max_files=_max_files(50))
        for inc in inconsistencies:
            findings.append(Finding(
                layer=LayerID.L0_FAST,
                rule_id=f"L0.consistency.{inc.category}",
                message=f"Inconsistency ({inc.category}): {inc.description}",
                file="<codebase>", start_line=0,
                severity=Severity.LOW, confidence=0.7,
                blast_radius=BlastRadius.MODULE, exploitability=0.0,
                category=Category.STYLE,
                fix_suggestion=inc.recommendation,
                raw={"pattern_a": inc.pattern_a, "pattern_b": inc.pattern_b,
                     "files_a": inc.files_using_a[:5], "files_b": inc.files_using_b[:5]},
            ))
        return findings

    def _run_missing_patch_detection(self) -> List[Finding]:
        """Run missing-patch detection (Vanir-inspired)."""
        findings: List[Finding] = []
        try:
            missing = scan_version_vuln_checks(self.repo_root, max_files=_max_files(100))
            for m in missing:
                sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                           "medium": Severity.MEDIUM, "low": Severity.LOW}
                findings.append(Finding(
                    layer=LayerID.L0_FAST,
                    rule_id=f"L0.missing_patch.{m.cve}",
                    message=f"Missing security patch {m.cve} ({m.package}): {m.description}",
                    file=m.file, start_line=m.line,
                    severity=sev_map.get(m.severity, Severity.MEDIUM),
                    confidence=0.9,
                    blast_radius=BlastRadius.SYSTEM, exploitability=0.8,
                    category=Category.SECURITY,
                    cwe=m.cve,
                    fix_suggestion=f"Update {m.package} — see {m.fix_url}",
                    raw={"cve": m.cve, "package": m.package,
                         "vulnerable_snippet": m.vulnerable_snippet},
                ))
        except Exception as e:
            self._scanner_error("missing_patch_detection", e)
        return findings

    def _run_malicious_pattern_detection(self, hunks: List[DiffHunk]) -> List[Finding]:
        """Run malicious package pattern detection (aura-inspired)."""
        findings: List[Finding] = []
        try:
            # scan changed Python files + setup.py
            files_to_scan: List[Path] = []
            for hunk in hunks:
                if hunk.file.endswith(".py"):
                    files_to_scan.append(self.repo_root / hunk.file)
            # always scan setup.py if it exists
            setup_py = self.repo_root / "setup.py"
            if setup_py.exists():
                files_to_scan.append(setup_py)

            for f in files_to_scan:
                if not f.exists():
                    continue
                hits = scan_malicious_patterns(f, self.repo_root)
                for h in hits:
                    sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                               "medium": Severity.MEDIUM, "low": Severity.LOW}
                    findings.append(Finding(
                        layer=LayerID.L0_FAST,
                        rule_id=f"L0.malicious.{h.pattern_type}",
                        message=f"Malicious pattern ({h.pattern_type}): {h.description} — {h.indicator}",
                        file=h.file, start_line=h.line,
                        severity=sev_map.get(h.severity, Severity.HIGH),
                        confidence=0.85,
                        blast_radius=BlastRadius.SYSTEM, exploitability=0.9,
                        category=Category.SECURITY,
                        cwe="CWE-506",  # embedded malicious code
                        fix_suggestion="Investigate this pattern — may indicate a malicious dependency",
                        raw={"pattern_type": h.pattern_type, "indicator": h.indicator,
                             "context": h.context},
                    ))
        except Exception as e:
            self._scanner_error("malicious_pattern_detection", e)
        return findings

    def _run_flawfinder_scan(self) -> List[Finding]:
        """Run C/C++ dangerous function scan (flawfinder-inspired)."""
        findings: List[Finding] = []
        try:
            hits = scan_repo_dangerous_functions(self.repo_root, max_files=_max_files(100))
            for h in hits:
                # map risk level 1-5 to severity
                sev_map = {5: Severity.CRITICAL, 4: Severity.HIGH,
                           3: Severity.MEDIUM, 2: Severity.LOW, 1: Severity.INFO}
                findings.append(Finding(
                    layer=LayerID.L0_FAST,
                    rule_id=f"L0.flawfinder.{h.function}",
                    message=f"Dangerous function {h.function}() [risk {h.risk_level}/5]: {h.explanation}",
                    file=h.file, start_line=h.line,
                    severity=sev_map.get(h.risk_level, Severity.MEDIUM),
                    confidence=0.95,  # flawfinder is very precise (exact function match)
                    blast_radius=BlastRadius.MODULE,
                    exploitability=0.8 if h.risk_level >= 4 else 0.5,
                    category=Category.SECURITY,
                    cwe=h.cwe,
                    fix_suggestion=h.safer_alternative,
                    raw={"function": h.function, "risk_level": h.risk_level,
                         "context": h.context},
                ))
        except Exception as e:
            self._scanner_error("flawfinder_scan", e)
        return findings

    def _run_contract_verification(self, hunks: List[DiffHunk]) -> List[Finding]:
        """Run design-by-contract verification (deal-inspired)."""
        findings: List[Finding] = []
        try:
            contracts = extract_all_contracts(self.repo_root, max_files=_max_files(50))
            if not contracts:
                return findings
            violations = check_preconditions_at_call_sites(contracts, self.repo_root)
            for v in violations:
                findings.append(Finding(
                    layer=LayerID.L0_FAST,
                    rule_id=f"L0.contract.{v.violation_type}",
                    message=f"Contract violation: {v.message} — {v.function}() called at {v.caller_file}:{v.caller_line} violates {v.contract_type}: {v.condition}",
                    file=v.caller_file or v.file, start_line=v.caller_line or v.line,
                    severity=Severity.HIGH, confidence=0.8,
                    blast_radius=BlastRadius.FUNCTION, exploitability=0.3,
                    category=Category.CORRECTNESS,
                    cwe="CWE-699",
                    fix_suggestion=f"Ensure the precondition is satisfied: {v.condition}",
                    raw={"function": v.function, "contract_type": v.contract_type,
                         "condition": v.condition},
                ))
        except Exception as e:
            self._scanner_error("contract_verification", e)
        return findings

    def _run_pii_detection(self, hunks: List[DiffHunk]) -> List[Finding]:
        """Run PII detection (pii-shield-inspired)."""
        findings: List[Finding] = []
        try:
            # scan changed files + all config files
            files_to_scan: List[Path] = []
            for hunk in hunks:
                file_path = self.repo_root / hunk.file
                if file_path.exists():
                    files_to_scan.append(file_path)
            # also scan common PII-containing files
            for pattern in ["**/*.csv", "**/*.json", "**/*.yaml", "**/*.yml", "**/*.txt", "**/*.env"]:
                for p in list(self.repo_root.glob(pattern))[:10]:
                    if p not in files_to_scan:
                        files_to_scan.append(p)

            for f in files_to_scan[:50]:
                detections = scan_pii(f, self.repo_root)
                for d in detections:
                    sev_map = {0.9: Severity.CRITICAL, 0.8: Severity.HIGH,
                               0.5: Severity.MEDIUM, 0.3: Severity.LOW}
                    sev = Severity.CRITICAL if d.confidence >= 0.85 else \
                          Severity.HIGH if d.confidence >= 0.7 else \
                          Severity.MEDIUM if d.confidence >= 0.4 else Severity.LOW
                    findings.append(Finding(
                        layer=LayerID.L0_FAST,
                        rule_id=f"L0.pii.{d.pii_type}",
                        message=f"PII detected ({d.pii_type}): {d.value_preview} — {d.context[:80]}",
                        file=d.file, start_line=d.line,
                        severity=sev, confidence=d.confidence,
                        blast_radius=BlastRadius.SYSTEM, exploitability=0.5,
                        category=Category.SECURITY,
                        cwe="CWE-359",  # exposure of private personal information
                        fix_suggestion="Remove PII from source code; store in secure data store with access controls",
                        raw={"pii_type": d.pii_type, "preview": d.value_preview},
                    ))
        except Exception as e:
            self._scanner_error("pii_detection", e)
        return findings

    def _run_architecture_check(self) -> List[Finding]:
        """Run architecture enforcement (rev-dep-inspired)."""
        findings: List[Finding] = []
        try:
            enforcer = ArchitectureEnforcer(self.repo_root)
            violations = enforcer.check_repo(max_files=_max_files(50))
            for v in violations:
                findings.append(Finding(
                    layer=LayerID.L0_FAST,
                    rule_id=f"L0.architecture.{v.violation}",
                    message=f"Architecture violation: {v.description}",
                    file=v.file, start_line=v.line,
                    severity=Severity.MEDIUM, confidence=0.7,
                    blast_radius=BlastRadius.MODULE, exploitability=0.0,
                    category=Category.MAINTAINABILITY,
                    cwe="CWE-1058",
                    fix_suggestion=f"Move the import to respect layer boundaries: {v.importing_layer} should not import from {v.imported_layer}",
                    raw={"importing_layer": v.importing_layer,
                         "imported_layer": v.imported_layer,
                         "imported_module": v.imported_module},
                ))
        except Exception as e:
            self._scanner_error("architecture_check", e)
        return findings

    def _run_doc_audit(self) -> List[Finding]:
        """Run documentation audit (valknut-inspired)."""
        findings: List[Finding] = []
        try:
            issues = audit_repo(self.repo_root, max_files=_max_files(50))
            for issue in issues:
                sev_map = {"medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO}
                findings.append(Finding(
                    layer=LayerID.L0_FAST,
                    rule_id=f"L0.doc_audit.{issue.issue_type}",
                    message=f"Doc audit: {issue.description}",
                    file=issue.file, start_line=issue.line,
                    severity=sev_map.get(issue.severity, Severity.INFO),
                    confidence=0.9,
                    blast_radius=BlastRadius.FUNCTION, exploitability=0.0,
                    category=Category.MAINTAINABILITY,
                    fix_suggestion="Add or update documentation",
                    raw={"issue_type": issue.issue_type, "name": issue.name},
                ))
        except Exception as e:
            self._scanner_error("doc_audit", e)
        return findings

    def _run_html_config_scan(self) -> List[Finding]:
        """Run HTML/config security scan (CSP, security headers, .env secrets)."""
        findings: List[Finding] = []
        try:
            issues = scan_html_config(self.repo_root)
            for issue in issues:
                sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                           "medium": Severity.MEDIUM, "low": Severity.LOW}
                findings.append(Finding(
                    layer=LayerID.L0_FAST,
                    rule_id=f"L0.html_scan.{issue.issue_type}",
                    message=f"HTML/config: {issue.description}",
                    file=issue.file, start_line=issue.line,
                    severity=sev_map.get(issue.severity, Severity.MEDIUM),
                    confidence=0.9,
                    blast_radius=BlastRadius.SYSTEM, exploitability=0.6,
                    category=Category.SECURITY,
                    cwe="CWE-693",
                    fix_suggestion=issue.fix,
                    raw={"issue_type": issue.issue_type},
                ))
        except Exception as e:
            self._scanner_error("html_config_scan", e)
        return findings

    def _run_js_taint_tracking(self) -> List[Finding]:
        """Run JavaScript CPG taint tracking (cross-file XSS/injection)."""
        findings: List[Finding] = []
        try:
            flows = scan_js_taint_flows(self.repo_root, max_files=_max_files(300))
            for flow in flows:
                sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                           "medium": Severity.MEDIUM}
                findings.append(Finding(
                    layer=LayerID.L0_FAST,
                    rule_id=f"L0.js_taint.{flow.sink_type}",
                    message=f"JS taint flow: {flow.source_type} → {flow.sink_type} ({'cross-file' if flow.cross_file else 'same-file'}) — {flow.source} reaches {flow.sink} (CWE {flow.cwe})",
                    file=flow.sink_file, start_line=flow.sink_line,
                    severity=sev_map.get(flow.severity, Severity.HIGH),
                    confidence=0.8,
                    blast_radius=BlastRadius.SYSTEM if flow.cross_file else BlastRadius.MODULE,
                    exploitability=0.85,
                    category=Category.SECURITY,
                    cwe=flow.cwe,
                    fix_suggestion=f"Sanitize {flow.source} before passing to {flow.sink}. Use DOMPurify.sanitize() or escapeHtml().",
                    raw={"source": flow.source, "source_type": flow.source_type,
                         "sink": flow.sink, "sink_type": flow.sink_type,
                         "cross_file": flow.cross_file,
                         "path": flow.path},
                ))
        except Exception as e:
            self._scanner_error("js_taint_tracking", e)
        return findings

    def _run_js_pattern_scan(self) -> List[Finding]:
        """Run dedicated JS pattern scanner (bypasses semgrep JSX limitations)."""
        findings: List[Finding] = []
        try:
            hits = scan_repo_js_patterns(self.repo_root, max_files=_max_files(500))
            for hit in hits:
                sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                           "medium": Severity.MEDIUM, "low": Severity.LOW,
                           "info": Severity.INFO, "warning": Severity.MEDIUM}
                findings.append(Finding(
                    layer=LayerID.L0_FAST,
                    rule_id=hit.rule_id,
                    message=hit.message,
                    file=hit.file, start_line=hit.line,
                    severity=sev_map.get(hit.severity, Severity.MEDIUM),
                    confidence=0.9,  # high confidence — exact pattern match
                    blast_radius=BlastRadius.MODULE, exploitability=0.7,
                    category=Category.SECURITY,
                    cwe=hit.cwe,
                    fix_suggestion=hit.fix,
                    raw={"context": hit.context, "pattern": hit.rule_id},
                ))
        except Exception as e:
            self._scanner_error("js_pattern_scan", e)
        return findings

    def _quick_recheck(self, file_path: Path, original_finding) -> List:
        """Quick re-check of a file for counterfactual mutation testing.

        Re-runs the relevant scanner on the mutated file and returns findings
        of the same rule_id. If no findings, the original was likely a TP.
        """
        results = []
        rule_id = original_finding.rule_id
        try:
            if "L0.crypto." in rule_id or "CRYPTO" in rule_id:
                from .multi_lang import scan_crypto_multi
                results = scan_crypto_multi(file_path, self.repo_root)
            elif "L0.auth." in rule_id or "AUTH" in rule_id:
                from .multi_lang import scan_auth_multi
                results = scan_auth_multi(file_path, self.repo_root)
            elif "L0.idor." in rule_id or "IDOR" in rule_id:
                from .multi_lang import scan_idor_multi
                results = scan_idor_multi(file_path, self.repo_root)
            elif "L0.concurrency." in rule_id or "CONC" in rule_id:
                from .multi_lang import scan_concurrency_multi
                results = scan_concurrency_multi(file_path, self.repo_root)
            elif "L0.cq." in rule_id or "CQ-" in rule_id:
                from .code_quality import analyze_code_quality
                results = analyze_code_quality(file_path, self.repo_root)
            else:
                # Generic: return empty (can't re-check unknown rule type)
                pass
        except Exception as e:
            self._scanner_error("quick_recheck", e)
        return results

    def _run_v2_analyzers(self) -> List[Finding]:
        """Run all v2 analyzers: multi-lang patterns, code quality, config, IaC, supply chain."""
        findings: List[Finding] = []
        sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                   "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO}

        # 1. Multi-language pattern scanners
        try:
            from .multi_lang import (scan_crypto_multi, scan_concurrency_multi, scan_auth_multi,
                                       scan_modern_multi, scan_idor_multi, scan_state_machine_multi, scan_repo_multi)
            for scanner, prefix in [(scan_crypto_multi,"crypto"),(scan_concurrency_multi,"concurrency"),
                                     (scan_auth_multi,"auth"),(scan_modern_multi,"modern"),
                                     (scan_idor_multi,"idor"),(scan_state_machine_multi,"state")]:
                try:
                    for lf in scan_repo_multi(self.repo_root, scanner, max_files=_max_files(400)):
                        findings.append(Finding(layer=LayerID.L0_FAST, rule_id=f"L0.{prefix}.{lf.rule_id}",
                            message=lf.description, file=lf.file, start_line=lf.line,
                            severity=sev_map.get(lf.severity, Severity.MEDIUM), confidence=lf.confidence,
                            blast_radius=BlastRadius.SYSTEM, exploitability=0.8, category=Category.SECURITY,
                            cwe=lf.cwe, fix_suggestion=lf.fix))
                except Exception as e:
                    self._scanner_error("v2_analyzers", e)
        except Exception as e:
            self._scanner_error("v2_analyzers", e)
        # 2. Code quality
        try:
            from .code_quality import analyze_repo_code_quality
            cq_cat = {"maintainability":Category.MAINTAINABILITY,"performance":Category.PERFORMANCE,
                      "correctness":Category.CORRECTNESS,"ux":Category.MAINTAINABILITY,
                      "concurrency":Category.CONCURRENCY,"security":Category.SECURITY}
            for issue in analyze_repo_code_quality(self.repo_root, max_files=_max_files(400)):
                findings.append(Finding(layer=LayerID.L0_FAST, rule_id=f"L0.cq.{issue.rule_id}",
                    message=issue.description, file=issue.file, start_line=issue.line,
                    severity=sev_map.get(issue.severity, Severity.LOW), confidence=issue.confidence,
                    blast_radius=BlastRadius.FUNCTION if issue.category=="maintainability" else BlastRadius.MODULE,
                    exploitability=0.3 if issue.category=="maintainability" else 0.5,
                    category=cq_cat.get(issue.category, Category.MAINTAINABILITY), cwe=issue.cwe, fix_suggestion=issue.fix))
        except Exception as e:
            self._scanner_error("v2_analyzers", e)
        # 3. Config scanner
        try:
            from .config_scanner import scan_repo_configs
            for issue in scan_repo_configs(self.repo_root, max_files=_max_files(50)):
                findings.append(Finding(layer=LayerID.L0_FAST, rule_id=issue.rule_id,
                    message=issue.description, file=issue.file, start_line=issue.line,
                    severity=sev_map.get(issue.severity, Severity.MEDIUM), confidence=issue.confidence,
                    blast_radius=BlastRadius.SYSTEM, exploitability=0.9, category=Category.SECURITY,
                    cwe=issue.cwe, fix_suggestion=issue.fix))
        except Exception as e:
            self._scanner_error("v2_analyzers", e)
        # 4. IaC scanner
        try:
            from .iac_scanner import scan_iac
            for issue in scan_iac(self.repo_root, max_files=_max_files(80)):
                findings.append(Finding(layer=LayerID.L0_FAST, rule_id=issue.rule_id,
                    message=issue.description, file=issue.file, start_line=issue.line,
                    severity=sev_map.get(issue.severity, Severity.HIGH), confidence=issue.confidence,
                    blast_radius=BlastRadius.SYSTEM, exploitability=0.7, category=Category.SECURITY,
                    cwe=issue.cwe, fix_suggestion=issue.fix))
        except Exception as e:
            self._scanner_error("v2_analyzers", e)
        # 5. Supply chain (typosquats + Maven CVEs)
        try:
            from .supply_chain import analyze_supply_chain
            sc_findings, _sbom = analyze_supply_chain(self.repo_root)
            for issue in sc_findings:
                rule_id = f"L0b.sc.{issue.kind}"
                if issue.kind == "maven_cve": rule_id = f"L0b.sc.{issue.kind}.{issue.cve or issue.package}"
                findings.append(Finding(layer=LayerID.L0B_SUPPLY_CHAIN, rule_id=rule_id,
                    message=issue.description, file=f"{issue.package}@{issue.version}", start_line=1,
                    severity=sev_map.get(issue.severity, Severity.MEDIUM), confidence=issue.confidence,
                    blast_radius=BlastRadius.SYSTEM, exploitability=0.5, category=Category.SUPPLY_CHAIN,
                    cwe="CWE-1357", fix_suggestion=issue.fix))
        except Exception as e:
            self._scanner_error("v2_analyzers", e)
        # 6. Tree-sitter AST
        try:
            from .tree_sitter_analyzer import analyze_repo_with_ast
            for issue in analyze_repo_with_ast(self.repo_root, max_files=_max_files(150)):
                ast_cat = {"correctness":Category.CORRECTNESS,"maintainability":Category.MAINTAINABILITY,"security":Category.SECURITY}
                findings.append(Finding(layer=LayerID.L0_FAST, rule_id=f"L0.ast.{issue.rule_id}",
                    message=issue.description, file=issue.file, start_line=issue.line,
                    severity=sev_map.get(issue.severity, Severity.LOW), confidence=issue.confidence,
                    blast_radius=BlastRadius.FUNCTION, exploitability=0.4,
                    category=ast_cat.get(issue.category, Category.MAINTAINABILITY), cwe=issue.cwe, fix_suggestion=issue.fix))
        except Exception as e:
            self._scanner_error("v2_analyzers", e)
        # 7. Multi-language business logic detection (v4: all languages)
        try:
            from .multi_language_bl import detect_repo as detect_bl_multi
            for blf in detect_bl_multi(self.repo_root, max_files=_max_files(300)):
                bl_sev = {"high": Severity.HIGH, "medium": Severity.MEDIUM,
                          "low": Severity.LOW, "critical": Severity.CRITICAL}
                findings.append(Finding(layer=LayerID.L0_FAST, rule_id=f"L0.bl.{blf.rule_id}",
                    message=blf.description, file=blf.file, start_line=blf.line,
                    severity=bl_sev.get(blf.severity, Severity.MEDIUM), confidence=0.8,
                    blast_radius=BlastRadius.SYSTEM if "AUTH" in blf.rule_id or "REENTRANCY" in blf.rule_id else BlastRadius.FUNCTION,
                    exploitability=0.7 if "AUTH" in blf.rule_id else 0.5,
                    category=Category.SECURITY if "AUTH" in blf.rule_id or "REENTRANCY" in blf.rule_id else Category.CORRECTNESS,
                    cwe=blf.cwe, fix_suggestion=blf.fix,
                    raw={"language": blf.language, "function": blf.function}))
        except Exception as e:
            self._scanner_error("v2_analyzers", e)

        # 8. v4 restored: expanded rules + codebase understanding + semantic BL + nullness + state machines + typestate
        try:
            from .v4_restored import analyze_all as v4_analyze
            v4_sev = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO}
            for uf in v4_analyze(self.repo_root):
                findings.append(Finding(
                    layer=LayerID.L0_FAST, rule_id=f"L0.v4.{uf.rule_id}",
                    message=uf.description, file=uf.file, start_line=uf.line,
                    severity=v4_sev.get(uf.severity, Severity.LOW), confidence=0.75,
                    blast_radius=BlastRadius.SYSTEM if "AUTH" in uf.rule_id or "CRITICAL" in uf.severity.upper() else BlastRadius.FUNCTION,
                    exploitability=0.7 if "AUTH" in uf.rule_id or "INJECTION" in uf.rule_id else 0.4,
                    category=Category.SECURITY if uf.category in ("security", "nullness", "typestate") else Category.CORRECTNESS if uf.category in ("behavioral", "state_machine", "spec_mining", "api_mismatch") else Category.MAINTAINABILITY,
                    cwe=uf.cwe, fix_suggestion=uf.suggestion,
                    raw={"language": uf.language, "function": uf.function, "category": uf.category}))
        except Exception as e:
            self._scanner_error("v2_analyzers", e)

        return findings

    def _run_cross_file_taint_tracking_with_pysa(self, hunks: List[DiffHunk]) -> List[Finding]:
        """Run Pysa first (production-grade, Meta OSS); fall back to CPG taint tracker."""
        py_hunks = [h for h in hunks if h.file.endswith(".py")]
        if not py_hunks:
            return []

        # try Pysa first
        pysa = PysaIntegration(self.repo_root)
        if pysa.is_available():
            files = [self.repo_root / h.file for h in py_hunks]
            pysa_findings = pysa.run(files)
            if pysa_findings:
                self.audit.log("pysa_run", {"findings": len(pysa_findings)})
                return pysa_findings
            # v4.8: Pysa found nothing — DON'T trust it blindly. Pysa can
            # return 0 findings due to misconfiguration (missing taint models,
            # wrong .pyre_configuration, analysis timeout). Fall through to
            # the CPG taint tracker as a safety net.
            self.audit.log("pysa_zero_findings", {"note": "falling back to CPG"})

        # v4.8: Always run CPG fallback (previously only ran if pysa wasn't available)
        return self._run_cross_file_taint_tracking(hunks)

    def _run_advanced_secret_detection(self, hunks: List[DiffHunk]) -> List[Finding]:
        """Run TruffleHog + entropy-based secret detection on changed files."""
        files = []
        for hunk in hunks:
            file_path = self.repo_root / hunk.file
            if file_path.exists() and file_path.suffix in (".py", ".js", ".ts", ".jsx",
                                                            ".tsx", ".go", ".java", ".c",
                                                            ".cpp", ".h", ".yml", ".yaml",
                                                            ".json", ".env", ".txt", ".sh",
                                                            ".tf", ".cfg", ".conf", ".ini"):
                files.append(file_path)

        if not files:
            return []

        findings = detect_secrets_advanced(self.repo_root, files, scan_history=False)
        if findings:
            self.audit.log("secrets_detected", {"count": len(findings)})
        return findings

    def _run_hotspot_detection(self, hunks: List[DiffHunk]) -> List[Finding]:
        """Detect security hotspots (SonarQube-style, with review workflow)."""
        files = [self.repo_root / h.file for h in hunks if h.file.endswith((".py", ".js", ".ts", ".go", ".java"))]
        if not files:
            return []

        new_hotspots = self.hotspots.detect_hotspots(files)
        decayed = self.hotspots.get_decayed_hotspots()

        findings: List[Finding] = []
        for h in new_hotspots:
            findings.append(Finding(
                layer=LayerID.L0_FAST,
                rule_id=f"L0.hotspot.{h.category}",
                message=f"Security hotspot ({h.category}): {h.description}",
                file=h.file, start_line=h.line,
                severity=Severity.MEDIUM, confidence=0.6,
                blast_radius=BlastRadius.FUNCTION, exploitability=0.3,
                cwe="CWE-863",
                fix_suggestion=f"Review this hotspot: `stca hotspot review {h.id} safe|confirmed`",
                raw={"hotspot_id": h.id, "category": h.category},
            ))
        for h in decayed:
            findings.append(Finding(
                layer=LayerID.L0_FAST,
                rule_id=f"L0.hotspot.decayed.{h.category}",
                message=f"Hotspot needs re-review (marked safe 90+ days ago): {h.description}",
                file=h.file, start_line=h.line,
                severity=Severity.LOW, confidence=0.5,
                blast_radius=BlastRadius.FUNCTION, exploitability=0.2,
                cwe="CWE-863",
                fix_suggestion=f"Re-review: `stca hotspot review {h.id} safe|confirmed`",
                raw={"hotspot_id": h.id, "category": h.category, "decay": True},
            ))
        return findings

    def _run_coverage_checks(self, hunks: List[DiffHunk]) -> List[Finding]:
        """Check coverage for changed files; flag drops and low coverage."""
        report = find_coverage_report(self.repo_root)
        if not report:
            return []

        # track coverage history (writes to .stca-coverage-history.json)
        drops = track_coverage_history(self.repo_root, report)

        findings: List[Finding] = []
        for hunk in hunks:
            # find coverage for this file
            fc = report.files.get(hunk.file) or report.files.get(hunk.file.replace("/", "."))
            if not fc:
                continue
            # flag if coverage is <50% on a changed file
            if fc.line_rate < 0.5:
                findings.append(Finding(
                    layer=LayerID.L1_PROPERTY,
                    rule_id="L1.coverage.low",
                    message=f"Low coverage on changed file: {hunk.file} has {fc.line_rate*100:.0f}% line coverage",
                    file=hunk.file, start_line=0,
                    severity=Severity.MEDIUM, confidence=0.8,
                    blast_radius=BlastRadius.FUNCTION, exploitability=0.1,
                    cwe="CWE-1058",
                    fix_suggestion="Add tests for the changed code before merging",
                    raw={"line_rate": fc.line_rate, "branch_rate": fc.branch_rate},
                ))

        # flag coverage drops
        for file, drop in drops.items():
            findings.append(Finding(
                layer=LayerID.L1_PROPERTY,
                rule_id="L1.coverage.drop",
                message=f"Coverage dropped {drop*100:.0f}% in {file} — tests may have been removed or skipped",
                file=file, start_line=0,
                severity=Severity.HIGH, confidence=0.85,
                blast_radius=BlastRadius.FUNCTION, exploitability=0.0,
                cwe="CWE-1058",
                fix_suggestion="Restore the removed tests or add new ones for the changed code",
                raw={"drop": drop, "previous_rate": report.files.get(file, type("obj", (), {"line_rate": 0})).line_rate + drop},
            ))
        return findings

    def _run_cross_file_taint_tracking(self, hunks: List[DiffHunk]) -> List[Finding]:
        """Run CPG-based cross-file taint tracking on changed Python files.

        Replaces the old single-file taint tracker. This catches flows that
        span function calls and file boundaries — what CodeQL catches.
        """
        findings: List[Finding] = []
        # v4.32: Removed .py filter — multi-lang CPG supports all languages
        if not hunks:
            return findings

        try:
            # build CPG for the whole repo (cached after first build)
            cpg = build_cpg_for_repo_multi(self.repo_root)
            if not cpg.nodes:
                return findings
            flows = track_taint_cross_file(cpg)
            for flow in flows:
                # only report flows that touch a changed file
                # v4.33: was `py_hunks` (NameError after v4.32 removed the .py filter)
                if not any(flow.sink_file == h.file for h in hunks):
                    continue
                findings.append(Finding(
                    layer=LayerID.L0_FAST,
                    rule_id=f"L0.cpg_taint.{flow.sink}",
                    message=f"Cross-file taint flow: {flow.source} → {flow.sink}() in {flow.sink_function}() (CWE {flow.cwe}){' [cross-file]' if flow.cross_file else ''}",
                    file=flow.sink_file, start_line=flow.sink_line,
                    severity=Severity.CRITICAL if flow.cross_file else Severity.HIGH,
                    confidence=0.85,
                    blast_radius=BlastRadius.SYSTEM if flow.cross_file else BlastRadius.MODULE,
                    exploitability=0.9 if flow.cross_file else 0.75,
                    cwe=flow.cwe,
                    fix_suggestion=f"Sanitize input before passing to {flow.sink}()",
                    raw={"source": flow.source, "sink": flow.sink,
                         "cross_file": flow.cross_file,
                         "intermediate_functions": flow.intermediate_functions},
                ))
        except Exception as e:
            findings.append(Finding(
                layer=LayerID.L0_FAST,
                rule_id="L0.cpg_taint.error",
                message=f"CPG taint tracking failed: {e}",
                file="<pipeline>", start_line=0,
                severity=Severity.INFO, confidence=1.0,
            ))
        return findings

    def _run_typestate_analysis(self, hunks: List[DiffHunk]) -> List[Finding]:
        """Run typestate analysis on changed files (all languages, not just Python).

        v4.30: Removed .py filter — now runs on all supported languages.
        Also calls detect_typestate_multi from v4_restored for multi-lang typestate.
        """
        findings: List[Finding] = []
        seen_files: set = set()
        for hunk in hunks:
            if hunk.file in seen_files:
                continue
            seen_files.add(hunk.file)
            file_path = self.repo_root / hunk.file
            if not file_path.exists():
                continue
            # v4.30: Run Python typestate (original engine)
            if hunk.file.endswith(".py"):
                violations = analyze_typestate(file_path)
                for v in violations:
                    if not any(h.file == v.file and h.start_line <= v.line <= h.end_line for h in hunks):
                        continue
                    findings.append(Finding(
                        layer=LayerID.L0_FAST,
                        rule_id=f"L0.typestate.{v.violation}",
                        message=f"Typestate violation: {v.description}",
                        file=v.file, start_line=v.line,
                        severity=Severity.HIGH, confidence=0.8,
                        blast_radius=BlastRadius.MODULE, exploitability=0.5,
                        cwe=v.cwe,
                        fix_suggestion=f"Ensure proper state machine: {v.description}",
                        raw={"object": v.object_name, "protocol": v.protocol, "violation": v.violation},
                    ))
            # v4.30: Run multi-lang typestate via NormalizedNode
            try:
                from .v4_restored import detect_typestate_multi
                from .normalized_ast import parse_file, get_language
                lang = get_language(file_path)
                if lang != "unknown":
                    tree = parse_file(file_path)
                    if tree:
                        for uf in detect_typestate_multi(tree):
                            if not any(h.file == uf.file and h.start_line <= uf.line <= h.end_line for h in hunks):
                                continue
                            findings.append(Finding(
                                layer=LayerID.L0_FAST,
                                rule_id=f"L0.typestate_multi.{uf.rule_id}",
                                message=uf.description,
                                file=uf.file, start_line=uf.line,
                                severity=Severity.HIGH if uf.severity == "critical" else Severity.MEDIUM,
                                confidence=0.75,
                                blast_radius=BlastRadius.MODULE, exploitability=0.5,
                                cwe=uf.cwe,
                                fix_suggestion=uf.suggestion,
                                raw={"language": uf.language, "function": uf.function},
                            ))
            except Exception as e:
                self._scanner_error("typestate_multi", e)
        return findings

    def _run_advanced_research_engines(self) -> List[Finding]:
        """v4.24: Wire all previously-dead-code research engines."""
        findings: List[Finding] = []
        sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                   "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO}

        # 1. Counterexamples (Z3-based)
        try:
            from .counterexamples import generate_counterexamples_for_file
            py_files = [p for p in self.repo_root.rglob("*.py")
                        if not any(d in p.parts for d in (".git", "__pycache__", ".venv", "venv", "node_modules", ".stca-cache", "build", "dist", "tests", "test"))
                        and p.stat().st_size < 50000]
            for py_file in py_files[:30]:
                try:
                    for ce in generate_counterexamples_for_file(py_file):
                        findings.append(Finding(layer=LayerID.L3_INVARIANTS, rule_id=f"L3.counterexample.{ce.invariant}",
                            message=ce.description, file=ce.file, start_line=ce.line,
                            severity=sev_map.get(ce.severity, Severity.MEDIUM), confidence=0.7,
                            blast_radius=BlastRadius.FUNCTION, exploitability=0.5,
                            category=Category.CORRECTNESS, cwe="CWE-839",
                            fix_suggestion=ce.suggestion, raw={"invariant": ce.invariant, "function": ce.function}))
                except Exception: pass
        except Exception as e: self._scanner_error("advanced_engines.counterexamples", e)

        # 2. Concurrency
        try:
            from .concurrency import analyze_repo_concurrency
            for issue in analyze_repo_concurrency(self.repo_root):
                findings.append(Finding(layer=LayerID.L0_FAST, rule_id=f"L0.concurrency.{issue.rule_id}",
                    message=issue.description, file=issue.file, start_line=issue.line,
                    severity=sev_map.get(issue.severity, Severity.MEDIUM), confidence=issue.confidence,
                    blast_radius=BlastRadius.MODULE, exploitability=0.6,
                    category=Category.CONCURRENCY, cwe=issue.cwe, fix_suggestion=issue.fix, raw={"language": issue.language}))
        except Exception as e: self._scanner_error("advanced_engines.concurrency", e)

        # 3. Dead code
        try:
            from .deadcode import DeadCodeAnalyzer
            analyzer = DeadCodeAnalyzer(self.repo_root)
            analyzer.discover_functions(max_files=_max_files(200))
            analyzer.load_trace()
            for fi in analyzer.get_dead_code():
                findings.append(Finding(layer=LayerID.L0_FAST, rule_id="L0.deadcode.unused_function",
                    message=f"Dead code: function '{fi.name}' is never called", file=fi.file, start_line=fi.line,
                    severity=Severity.LOW, confidence=0.7, blast_radius=BlastRadius.FUNCTION,
                    exploitability=0.0, category=Category.MAINTAINABILITY, cwe="CWE-1164",
                    fix_suggestion="Remove the unused function or add a caller", raw={"function": fi.name}))
        except Exception as e: self._scanner_error("advanced_engines.deadcode", e)

        # 4. Duplication
        try:
            from .duplication import find_duplicates
            for dup in find_duplicates(self.repo_root, min_tokens=50):
                findings.append(Finding(layer=LayerID.L0_FAST, rule_id="L0.duplication.code_clone",
                    message=f"Code duplication: {dup.length} tokens in {dup.file_a} (L{dup.start_a}) and {dup.file_b} (L{dup.start_b})",
                    file=dup.file_a, start_line=dup.start_a, severity=Severity.LOW, confidence=0.8,
                    blast_radius=BlastRadius.MODULE, exploitability=0.0, category=Category.MAINTAINABILITY,
                    cwe="CWE-1047", fix_suggestion="Extract duplicated code into a shared function",
                    raw={"file_a": dup.file_a, "start_a": dup.start_a, "file_b": dup.file_b, "start_b": dup.start_b, "length": dup.length}))
        except Exception as e: self._scanner_error("advanced_engines.duplication", e)

        # 5. Runtime verification
        try:
            from .runtime_verification import find_invariant_annotations
            py_files = [p for p in self.repo_root.rglob("*.py") if not any(d in p.parts for d in (".git", "__pycache__", ".venv", "venv", "node_modules", ".stca-cache", "build", "dist"))]
            for py_file in py_files[:100]:
                try:
                    for inv in find_invariant_annotations(py_file):
                        # v4.30: Convert to Finding (was audit.log only — invisible to users)
                        findings.append(Finding(
                            layer=LayerID.L3_INVARIANTS,
                            rule_id="L3.runtime_invariant",
                            message=f"Runtime invariant: {inv.get('expression', '')}",
                            file=str(py_file.relative_to(self.repo_root)),
                            start_line=inv.get("line", 0),
                            severity=Severity.LOW,
                            confidence=0.6,
                            blast_radius=BlastRadius.FUNCTION,
                            exploitability=0.2,
                            category=Category.CORRECTNESS,
                            cwe="CWE-839",
                            fix_suggestion="Verify invariant holds for all inputs",
                            raw={"expression": inv.get("expression", ""),
                                 "function": inv.get("function", "")}))
                except Exception: pass
        except Exception as e: self._scanner_error("advanced_engines.runtime_verification", e)

        # 6. Knowledge base stats
        try:
            from .knowledge_base import knowledge_stats
            self.audit.log("knowledge_base_stats", knowledge_stats())
        except Exception as e: self._scanner_error("advanced_engines.knowledge_base", e)

        # 7. Impact analysis
        try:
            from .impact_analysis import ImpactAnalyzer
            analyzer = ImpactAnalyzer(self.repo_root)
            n_funcs = analyzer.build_call_graph(max_files=_max_files(200))
            self.audit.log("impact_graph_built", {"nodes": n_funcs, "edges": sum(len(v) for v in analyzer.call_graph.values())})
        except Exception as e: self._scanner_error("advanced_engines.impact_analysis", e)

        # 8. Root cause clustering
        try:
            from .root_cause import find_root_causes, rca_stats
            clusters = find_root_causes(findings)
            if clusters:
                self.audit.log("root_cause_clusters", rca_stats(clusters))
                if not hasattr(self, "_root_cause_clusters"): self._root_cause_clusters = []
                self._root_cause_clusters.extend(clusters)
        except Exception as e: self._scanner_error("advanced_engines.root_cause", e)

        # 9. v4.24: Wire multi_language_advanced.analyze_repo_advanced
        try:
            from .multi_language_advanced import analyze_repo_advanced
            for sf in analyze_repo_advanced(self.repo_root, max_files=_max_files(50)):
                findings.append(Finding(layer=LayerID.L3_INVARIANTS, rule_id=f"L3.symbolic.{sf.rule_id}",
                    message=sf.description, file=sf.file, start_line=sf.line,
                    severity=sev_map.get(sf.severity, Severity.MEDIUM), confidence=0.7,
                    blast_radius=BlastRadius.FUNCTION, exploitability=0.5,
                    category=Category.CORRECTNESS, cwe="CWE-839",
                    fix_suggestion="Fix the invariant violation",
                    raw={"language": sf.language, "function": sf.function, "counterexample": sf.counterexample}))
        except Exception as e: self._scanner_error("advanced_engines.multi_language_advanced", e)

        # 10. v4.24: Wire dynamic_invariants
        try:
            from .dynamic_invariants import run_dynamic_invariant_inference
            py_files = [p for p in self.repo_root.rglob("*.py")
                        if not any(d in p.parts for d in (".git", "__pycache__", ".venv", "venv", "node_modules", ".stca-cache", "build", "dist", "tests", "test"))
                        and p.stat().st_size < 50000]
            for py_file in py_files[:30]:
                try:
                    for inv in run_dynamic_invariant_inference(py_file):
                        findings.append(Finding(layer=LayerID.L3_INVARIANTS,
                            rule_id=f"L3.dynamic_invariant.{inv.get('invariant', 'unknown')}",
                            message=f"Dynamic invariant: {inv.get('invariant', '')}",
                            file=str(py_file.relative_to(self.repo_root)),
                            start_line=inv.get("line", 0),
                            severity=Severity.LOW, confidence=0.6,
                            blast_radius=BlastRadius.FUNCTION, exploitability=0.3,
                            category=Category.CORRECTNESS, cwe="CWE-839",
                            fix_suggestion="Verify invariant holds", raw={"invariant": inv.get("invariant", ""), "function": inv.get("function", "")}))
                except Exception: pass
        except Exception as e: self._scanner_error("advanced_engines.dynamic_invariants", e)

        # 11. v4.24: Wire llm_verify (only if LLM client available)
        try:
            from .llm_verify import llm_verify_function
            from .llm.client import LLMClient
            try: llm_client = LLMClient()
            except Exception: llm_client = None
            if llm_client is not None:
                import ast as pyast
                py_files = [p for p in self.repo_root.rglob("*.py")
                            if not any(d in p.parts for d in (".git", "__pycache__", ".venv", "venv", "node_modules", ".stca-cache", "build", "dist", "tests", "test"))
                            and p.stat().st_size < 30000]
                for py_file in py_files[:10]:
                    try:
                        source = py_file.read_text(encoding="utf-8", errors="replace")
                        tree = pyast.parse(source)
                        for node in pyast.walk(tree):
                            if not isinstance(node, (pyast.FunctionDef, pyast.AsyncFunctionDef)): continue
                            try:
                                func_body = pyast.unparse(node)
                                for vb in llm_verify_function(py_file, node.name, func_body, llm_client=llm_client, repo_root=self.repo_root):
                                    findings.append(Finding(layer=LayerID.L0_FAST,
                                        rule_id=f"L0.llm_verify.{vb.hypothesis.bug_type}",
                                        message=vb.description, file=str(py_file.relative_to(self.repo_root)),
                                        start_line=node.lineno, severity=Severity.HIGH, confidence=0.85,
                                        blast_radius=BlastRadius.FUNCTION, exploitability=0.8,
                                        category=Category.SECURITY, cwe=vb.hypothesis.cwe,
                                        fix_suggestion=vb.hypothesis.fix, raw={"function": node.name}))
                            except Exception: pass
                    except Exception: pass
        except Exception as e: self._scanner_error("advanced_engines.llm_verify", e)

        # 12. v4.25: Wire InterproceduralTaintAnalyzer (was 1240 lines of dead code)
        # v4.26: Use public analyze_repo() instead of private _analyze_file() —
        # analyze_repo does 3 steps (call graph → discover sources → loop),
        # so custom source wrappers are detected, not just LANGUAGE_KNOWLEDGE.
        try:
            from .interprocedural import InterproceduralTaintAnalyzer
            analyzer = InterproceduralTaintAnalyzer("python")
            for flow in analyzer.analyze_repo(self.repo_root, max_files=_max_files(200)):
                findings.append(Finding(
                    layer=LayerID.L0_FAST,
                    rule_id=f"L0.interproc_taint.{flow.sink_function}",
                    message=f"Interprocedural taint: {flow.source_param} -> {flow.sink_function} "
                            f"({flow.sink_type}) at L{flow.sink_line}",
                    file=flow.source_file,
                    start_line=flow.sink_line,
                    severity=Severity.HIGH if flow.interprocedural else Severity.MEDIUM,
                    confidence=0.8,
                    blast_radius=BlastRadius.FUNCTION if not flow.interprocedural else BlastRadius.MODULE,
                    exploitability=0.7,
                    category=Category.SECURITY,
                    cwe=f"CWE-{flow.sink_type[:2]}" if flow.sink_type else "",
                    fix_suggestion=f"Sanitize input before passing to {flow.sink_function}",
                    raw={"source_param": flow.source_param,
                         "sink_function": flow.sink_function,
                         "sink_type": flow.sink_type,
                         "interprocedural": flow.interprocedural,
                         "context_signature": getattr(flow, 'context_signature', ''),
                         "caller_function": getattr(flow, 'caller_function', '')}))
        except Exception as e: self._scanner_error("advanced_engines.interprocedural", e)

        return findings

    def _run_knowledge_graph_analysis(self, hunks: List[DiffHunk]) -> List[Finding]:
        """v4.24: Build knowledge graph and run impact analysis."""
        findings: List[Finding] = []
        try:
            from .knowledge_graph import KnowledgeGraphBuilder, DiffImpactAnalyzer
            builder = KnowledgeGraphBuilder(self.repo_root)
            graph = builder.build(max_files=_max_files(200))
            analyzer = DiffImpactAnalyzer(graph)
            changed_files = list({h.file for h in hunks})
            if not changed_files: return findings
            impact = analyzer.analyze_changed_files(changed_files)
            blast_radius = impact["total_blast_radius"]
            if blast_radius > 10:
                affected_funcs = impact.get("transitively_affected", [])
                findings.append(Finding(layer=LayerID.L0_FAST, rule_id="L0.kg.high_impact_change",
                    message=f"High-impact change: {len(changed_files)} file(s) affect {blast_radius} functions. Top: {', '.join(affected_funcs[:5])}",
                    file=changed_files[0] if changed_files else "", start_line=1,
                    severity=Severity.MEDIUM, confidence=0.7, blast_radius=BlastRadius.SYSTEM,
                    exploitability=0.0, category=Category.MAINTAINABILITY, cwe="",
                    fix_suggestion="Review all affected functions", raw={"blast_radius": blast_radius, "by_layer": impact.get("by_layer", {}), "changed_files": changed_files, "graph_stats": graph.stats()}))
            self.audit.log("knowledge_graph_built", graph.stats())
        except Exception as e: self._scanner_error("knowledge_graph", e)
        return findings

    def _run_cpg_queries(self, hunks: List[DiffHunk]) -> List[Finding]:
        """Run Joern-style CPG pattern queries."""
        findings: List[Finding] = []
        # v4.32: Removed .py filter — multi-lang CPG supports all languages
        if not hunks:
            return findings
        try:
            cpg = build_cpg_for_repo_multi(self.repo_root)
            if not cpg.nodes:
                return findings

            # query 1: unsanitized taint flows
            for result in query_unsanitized_taint_flows(cpg):
                findings.append(Finding(
                    layer=LayerID.L0_FAST,
                    rule_id="L0.cpg_query.unsanitized_taint",
                    message=f"CPG query: {result.description}",
                    file=result.file, start_line=result.line,
                    severity=Severity.HIGH, confidence=0.85,
                    blast_radius=BlastRadius.MODULE, exploitability=0.8,
                    cwe="CWE-20",
                    raw=result.raw or {},
                ))

            # query 2: dangerous patterns in auth code
            for result in query_dangerous_patterns_in_auth(cpg):
                findings.append(Finding(
                    layer=LayerID.L0_FAST,
                    rule_id="L0.cpg_query.auth_dangerous",
                    message=f"CPG query: {result.description}",
                    file=result.file, start_line=result.line,
                    severity=Severity.CRITICAL, confidence=0.9,
                    blast_radius=BlastRadius.SYSTEM, exploitability=0.95,
                    cwe="CWE-863",
                    raw=result.raw or {},
                ))

            # query 3: high-complexity functions
            for result in query_function_complexity(cpg, threshold=15):
                findings.append(Finding(
                    layer=LayerID.L0_FAST,
                    rule_id="L0.cpg_query.high_complexity",
                    message=f"CPG query: {result.description}",
                    file=result.file, start_line=result.line,
                    severity=Severity.LOW, confidence=0.85,
                    blast_radius=BlastRadius.FUNCTION, exploitability=0.0,
                    cwe="CWE-1058",
                    raw=result.raw or {},
                ))

            # v4.42: query 4: def-use chains (CodeQL-style dataflow)
            for result in query_def_use_chains(cpg):
                sev = Severity.LOW
                cwe = result.cwe or ""
                if "dead_store" in (result.raw or {}).get("kind", ""):
                    sev = Severity.MEDIUM
                findings.append(Finding(
                    layer=LayerID.L0_FAST,
                    rule_id="L0.cpg_query.def_use_chain",
                    message=f"CPG query: {result.description}",
                    file=result.file, start_line=result.line,
                    severity=sev, confidence=0.7,
                    blast_radius=BlastRadius.FUNCTION, exploitability=0.0,
                    cwe=cwe,
                    raw=result.raw or {},
                ))

            # v4.42: query 5: cross-function taint (CodeQL-style interprocedural)
            for result in query_cross_function_taint(cpg):
                findings.append(Finding(
                    layer=LayerID.L0_FAST,
                    rule_id="L0.cpg_query.cross_function_taint",
                    message=f"CPG query: {result.description}",
                    file=result.file, start_line=result.line,
                    severity=Severity.HIGH, confidence=0.75,
                    blast_radius=BlastRadius.MODULE, exploitability=0.7,
                    cwe=result.cwe or "CWE-89",
                    raw=result.raw or {},
                ))
        except Exception as e:
            self._scanner_error("cpg_queries", e)
        return findings

    def _run_spec_mining(self, hunks: List[DiffHunk]) -> List[Finding]:
        """v4.38: Run spec mining — mine API patterns and check for violations.

        This is the next auto-derivation path after rule_miner.py. Instead of
        mining rules from bug-fix commits, spec_mining mines API usage patterns
        (e.g., "open() is always followed by close()") and reports violations
        (e.g., "open() without close() — resource leak").
        """
        findings: List[Finding] = []
        if not hunks:
            return findings
        try:
            from .spec_mining import mine_and_check
            patterns, violations = mine_and_check(self.repo_root, min_confidence=0.3)
            if patterns:
                self.audit.log("spec_patterns_mined", {
                    "total_patterns": sum(len(v) for v in patterns.values()),
                    "apis_covered": list(patterns.keys())[:10],
                })
            for v in violations[:20]:  # cap at 20 to avoid flooding
                findings.append(Finding(
                    layer=LayerID.L0_FAST,
                    rule_id=f"L0.spec.{v.object_type}.violation",
                    message=f"Spec violation: {v.description}",
                    file=v.file, start_line=v.line,
                    severity=Severity.MEDIUM, confidence=0.6,
                    blast_radius=BlastRadius.FUNCTION, exploitability=0.0,
                    category=Category.CORRECTNESS, cwe="CWE-440",
                    fix_suggestion=f"Follow pattern: {v.expected_pattern}",
                    raw={"pattern": v.object_type,
                         "expected": v.expected_pattern,
                         "actual": list(v.actual_sequence)},
                ))
        except Exception as e:
            self._scanner_error("spec_mining", e)
        return findings

    def _run_metamorphic_tests(self, hunks: List[DiffHunk]) -> List[Finding]:
        """Run metamorphic tests on changed Python files (oracle-free bug detection)."""
        findings: List[Finding] = []
        seen_files: set = set()
        for hunk in hunks:
            if not hunk.file.endswith(".py") or hunk.file in seen_files:
                continue
            seen_files.add(hunk.file)
            file_path = self.repo_root / hunk.file
            if not file_path.exists():
                continue
            violations = run_metamorphic_tests(file_path, self.repo_root)
            for v in violations:
                findings.append(Finding(
                    layer=LayerID.L1_PROPERTY,
                    rule_id=f"L1.metamorphic.{v.relation}",
                    message=f"Metamorphic violation in {v.function}(): {v.relation} — {v.description}",
                    file=v.file, start_line=0,
                    severity=Severity.HIGH, confidence=0.7,
                    blast_radius=BlastRadius.FUNCTION, exploitability=0.2,
                    cwe="CWE-838",  # improper neutralization
                    raw={"function": v.function, "relation": v.relation,
                         "input_summary": v.input_summary},
                ))
        return findings

    def _run_differential_tests(self, hunks: List[DiffHunk]) -> List[Finding]:
        """Run differential tests on changed Python files (refactor verification)."""
        findings: List[Finding] = []
        seen_files: set = set()
        for hunk in hunks:
            if not hunk.file.endswith(".py") or hunk.file in seen_files:
                continue
            seen_files.add(hunk.file)
            file_path = self.repo_root / hunk.file
            if not file_path.exists():
                continue
            bugs = run_differential_tests(file_path, self.repo_root)
            for b in bugs:
                findings.append(Finding(
                    layer=LayerID.L1_PROPERTY,
                    rule_id="L1.differential",
                    message=f"Differential bug: {b.function_a}() vs {b.function_b}() disagree on input — {b.input_summary[:100]}",
                    file=b.file, start_line=0,
                    severity=Severity.HIGH, confidence=0.85,
                    blast_radius=BlastRadius.FUNCTION, exploitability=0.3,
                    cwe="CWE-838",
                    raw={"function_a": b.function_a, "function_b": b.function_b,
                         "output_a": b.output_a, "output_b": b.output_b},
                ))
        return findings

    def _is_iac_file(self, file_path: str) -> bool:
        """Check if a file is an IaC file (Dockerfile, K8s, Terraform, etc.)."""
        from pathlib import Path
        p = Path(file_path)
        name = p.name.lower()
        if name.startswith("dockerfile") or name.endswith(".dockerfile"):
            return True
        if p.suffix in (".tf", ".tfvars"):
            return True
        if file_path.startswith(".github/workflows/") and p.suffix in (".yml", ".yaml"):
            return True
        if any(x in file_path.lower() for x in ["k8s", "kubernetes", "manifest", "deploy"]):
            if p.suffix in (".yaml", ".yml"):
                return True
        return False

    def _has_any_iac_files(self) -> bool:
        """Quick check: does the repo have any IaC files at all?"""
        from pathlib import Path
        for pattern in ["**/Dockerfile*", "**/*.tf", ".github/workflows/*.yml"]:
            try:
                if any(Path(self.repo_root).glob(pattern)):
                    return True
            except Exception:
                continue
        return False

    def _llm_tie_break(self, finding: Finding) -> Optional[AggregatedDecision]:
        """Invoke the LLM tie-breaker for an uncertain finding, gated by PRM."""
        if not self.llm or not self.llm.is_available():
            return None

        finding_summary = (
            f"[{finding.layer.value}] {finding.rule_id}: {finding.message} "
            f"(severity={finding.severity.value}, confidence={finding.confidence:.0%})"
        )
        # v4.8: Actually populate function_body from the finding's file.
        # Previously `for hunk in []: pass` was a no-op, so function_body
        # was always empty, PRM grounding was always 0, and most LLM
        # verdicts were discarded as untrusted.
        function_body = ""
        try:
            file_path = self.repo_root / finding.file
            if file_path.exists():
                source = file_path.read_text(encoding="utf-8", errors="replace")
                lines = source.splitlines()
                # Extract ±5 lines around the finding for context
                start = max(0, finding.start_line - 6)
                end = min(len(lines), finding.start_line + 5)
                function_body = "\n".join(lines[start:end])
        except Exception:
            pass
        # Also use raw if available (for additional context)
        raw_body = finding.raw.get("function_body", "") or finding.raw.get("line", "")
        if raw_body and not function_body:
            function_body = str(raw_body)

        response = self.llm.review_finding(finding_summary, function_body)
        if not response:
            return None

        prm_result = self.prm.score_reasoning(response, function_body)
        threshold = float(self.config.llm.get("prm_threshold", 0.6))
        if not prm_result["verdict_trusted"] or prm_result["overall_prm_score"] < threshold:
            # PRM says LLM is hallucinating — drop the LLM input, keep UNCERTAIN
            return AggregatedDecision(
                decision=Decision.UNCERTAIN,
                confidence_interval=(0.4, 0.6),
                contributing_signals={"llm_prm_score": prm_result["overall_prm_score"],
                                      "llm_verdict": response.get("verdict", "uncertain"),
                                      "prm_trusted": False},
                reasoning=f"LLM tie-breaker invoked but PRM score {prm_result['overall_prm_score']:.2f} < threshold {threshold} — LLM input discarded",
            )

        # PRM trusts the LLM — convert verdict to decision
        verdict = response.get("verdict", "uncertain")
        llm_conf = float(response.get("confidence", 0.5))
        if verdict == "confirmed":
            new_decision = Decision.WARN if llm_conf < 0.7 else Decision.BLOCK
        elif verdict == "false_positive":
            new_decision = Decision.PASS
        else:
            new_decision = Decision.WARN

        return AggregatedDecision(
            decision=new_decision,
            confidence_interval=(llm_conf * 0.9, llm_conf),
            contributing_signals={
                "llm_verdict": verdict,
                "llm_confidence": llm_conf,
                "llm_prm_score": prm_result["overall_prm_score"],
                "suggested_fix": response.get("suggested_fix"),
            },
            reasoning=f"LLM tie-breaker (PRM score {prm_result['overall_prm_score']:.2f}): verdict={verdict}, confidence={llm_conf:.2f} → {new_decision.value}",
        )

    def _save_reports(self, result: PipelineResult) -> None:
        """Persist JSON, SARIF, and HTML reports."""
        from .report.sarif import save_sarif
        from .report.html import save_html

        report_dir = self.repo_root / self.config.report_dir
        report_dir.mkdir(parents=True, exist_ok=True)

        # JSON
        result.to_json(report_dir / "result.json")

        # SARIF
        save_sarif(result, self.repo_root, report_dir / "result.sarif")

        # HTML
        save_html(result, self.repo_root, report_dir / "report.html")
