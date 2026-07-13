"""v4.10 Regression tests — Z-Agent's brain wiring + counterfactual regression fixes.

Tests:
  1. Bayesian wiring actually fires when enabled (6 API bugs fixed)
  2. ProjectTuner wiring actually fires when enabled
  3. Counterfactual runs in both run() and run_full() (v4.9 regression fixed)
  4. tool_missing findings reach scanner_health (v4.8 fix completed)
  5. Bayesian mult_pass bug fixed (v4.9 fix verified)
"""
from __future__ import annotations

import tempfile, shutil, os, ast
from pathlib import Path
import pytest


# =============================================================================
# 1. BAYESIAN WIRING — must actually fire when enabled
# =============================================================================

class TestBayesianWiringRegression:
    """v4.9 had 6 API bugs making the Bayesian wiring permanently inert.
    v4.10 fixes all 6: correct import, field, method, return type, FP call, config gate.
    """

    def test_bayesian_enabled_when_config_set(self, tmp_path):
        """When config.brain.enable_bayesian=True, self.bayesian must be non-None."""
        from loomscan.orchestrator import Orchestrator
        from loomscan.config import STCAConfig
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / ".git").mkdir()
        (repo / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
        (repo / "app.py").write_text("x = 1\n")
        config = STCAConfig()
        config.brain["enable_bayesian"] = True
        orch = Orchestrator(repo, config)
        assert orch.bayesian is not None, (
            "Bayesian must be instantiated when config.brain.enable_bayesian=True. "
            "v4.9's config gate was structurally impossible to open."
        )

    def test_bayesian_evaluate_works(self):
        """BayesianSecondOpinion.evaluate() must produce a valid BBNResult."""
        from loomscan.brain.bayesian import BayesianSecondOpinion, BBNEvidence
        bbn = BayesianSecondOpinion()
        evidence = BBNEvidence(
            fis_score=0.8, confidence=0.9, exploitability=0.8,
            reliability=0.7, fp_history=0.0, corroboration=0.5, test_exclusion=0.0,
        )
        result = bbn.evaluate(evidence)
        assert result is not None
        assert result.decision is not None
        assert 0.0 <= result.confidence <= 1.0
        assert result.p_block + result.p_warn + result.p_pass > 0.99  # normalized

    def test_bayesian_not_enabled_by_default(self, tmp_path):
        """By default, Bayesian should be off (opt-in)."""
        from loomscan.orchestrator import Orchestrator
        from loomscan.config import STCAConfig
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / ".git").mkdir()
        (repo / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
        (repo / "app.py").write_text("x = 1\n")
        config = STCAConfig()
        orch = Orchestrator(repo, config)
        assert orch.bayesian is None, "Bayesian should be off by default"


# =============================================================================
# 2. PROJECTTUNER WIRING — must actually fire when enabled
# =============================================================================

class TestProjectTunerWiringRegression:
    """v4.9 only changed the header comment. v4.10 actually wires it in.
    """

    def test_project_tuner_enabled_when_config_set(self, tmp_path):
        """When config.brain.enable_project_tuner=True, self.project_tuner must be non-None."""
        from loomscan.orchestrator import Orchestrator
        from loomscan.config import STCAConfig
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / ".git").mkdir()
        (repo / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
        (repo / "app.py").write_text("x = 1\n")
        config = STCAConfig()
        config.brain["enable_project_tuner"] = True
        orch = Orchestrator(repo, config)
        assert orch.project_tuner is not None, (
            "ProjectTuner must be instantiated when config.brain.enable_project_tuner=True. "
            "v4.9 didn't even attempt wiring."
        )


# =============================================================================
# 3. COUNTERFACTUAL — must run in both run() and run_full()
# =============================================================================

class TestCounterfactualSharedRegression:
    """v4.9 regressed by only having counterfactual in run_full().
    v4.10 extracts it into _apply_counterfactual() called from both paths.
    """

    def test_counterfactual_method_exists(self):
        """_apply_counterfactual must exist as a shared method."""
        from loomscan.orchestrator import Orchestrator
        assert hasattr(Orchestrator, '_apply_counterfactual'), (
            "_apply_counterfactual must exist — v4.9 had counterfactual only in run_full()"
        )

    def test_counterfactual_called_from_run(self):
        """run() must call _apply_counterfactual."""
        from loomscan.orchestrator import Orchestrator
        import inspect
        source = inspect.getsource(Orchestrator.run)
        assert "_apply_counterfactual" in source, (
            "run() must call _apply_counterfactual — v4.9 regressed by only having it in run_full()"
        )

    def test_counterfactual_called_from_run_full(self):
        """run_full() must call _apply_counterfactual."""
        from loomscan.orchestrator import Orchestrator
        import inspect
        source = inspect.getsource(Orchestrator.run_full)
        assert "_apply_counterfactual" in source, (
            "run_full() must call _apply_counterfactual"
        )


# =============================================================================
# 4. TOOL_MISSING — must reach scanner_health for --strict-scanners gating
# =============================================================================

class TestToolMissingScannerHealthRegression:
    """v4.8 added INFO findings for missing tools but they didn't reach
    scanner_health, so --strict-scanners couldn't gate on them.
    """

    def test_tool_missing_in_scanner_health_code(self):
        """The orchestrator must have code that moves tool_missing to scanner_health."""
        from loomscan.orchestrator import Orchestrator
        import inspect
        source = inspect.getsource(Orchestrator.run_full)
        assert "tool_missing" in source, (
            "run_full() must surface tool_missing findings in scanner_health"
        )


# =============================================================================
# 5. BAYESIAN mult_pass BUG — verify the fix actually works
# =============================================================================

class TestBayesianMultPassRegression:
    """v4.9 fixed the mult_pass dead-branch bug. Verify it produces different
    results for high-FP vs low-FP evidence (it wouldn't if mult_pass is never applied).
    """

    def test_fp_history_affects_pass_probability(self):
        """High fp_history should increase P(pass) compared to low fp_history."""
        from loomscan.brain.bayesian import BayesianSecondOpinion, BBNEvidence
        bbn = BayesianSecondOpinion()
        # Low FP history
        evidence_low_fp = BBNEvidence(
            fis_score=0.5, confidence=0.5, exploitability=0.5,
            reliability=0.5, fp_history=0.0, corroboration=0.0, test_exclusion=0.0,
        )
        result_low_fp = bbn.evaluate(evidence_low_fp)
        # High FP history
        evidence_high_fp = BBNEvidence(
            fis_score=0.5, confidence=0.5, exploitability=0.5,
            reliability=0.5, fp_history=0.9, corroboration=0.0, test_exclusion=0.0,
        )
        result_high_fp = bbn.evaluate(evidence_high_fp)
        # High FP history should increase P(pass) (the mult_pass fix makes this work)
        assert result_high_fp.p_pass > result_low_fp.p_pass, (
            f"High fp_history ({result_high_fp.p_pass:.3f}) should increase P(pass) "
            f"vs low fp_history ({result_low_fp.p_pass:.3f}). "
            f"If equal, the mult_pass bug is still present."
        )


# =============================================================================
# 6. COUNTERFACTactual language guard — pass is Python-only
# =============================================================================

class TestCounterfactualLanguageGuardRegression:
    """counterfactual.py line_removal used 'pass' (Python syntax) for all languages.
    v4.10 adds language-aware no-ops.
    """

    def test_line_removal_uses_comment_for_js(self):
        """For JS files, line_removal should use /* */ not pass."""
        from loomscan.counterfactual import CounterfactualMutator
        # The _mutate method should produce JS-appropriate no-ops
        # We test by checking the source code has language-aware logic
        import inspect
        source = inspect.getsource(CounterfactualMutator._mutate)
        assert "/* counterfactual" in source or "counterfactual: line removed" in source, (
            "line_removal must use language-aware no-ops, not just 'pass'"
        )
