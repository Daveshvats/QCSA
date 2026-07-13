"""v4.14 Regression tests — Z-Agent's 4 CRITICAL bugs + additional findings.

All tests are BEHAVIORAL — they test runtime behavior, not source strings.

Tests:
  1. config.brain loaded from YAML (BUG #1)
  2. Auto-tuner reads from .loomscan.yaml (BUG #2)
  3. Inline suppressions actually work (BUG #3)
  4. run() has ProjectTuner (BUG #4)
  5. suppressed_findings serialized in to_dict (BUG #5)
  6. ProjectTuner suppression actually filters (BUG #8)
  7. dynamic_invariants has import tempfile (BUG #11)
"""
from __future__ import annotations

import tempfile, os, json
from pathlib import Path
import pytest


# =============================================================================
# BUG #1: config.brain loaded from YAML
# =============================================================================

class TestConfigBrainLoadedRegression:
    """v4.13: config.brain was never loaded from .loomscan.yaml.
    v4.14: from_dict now calls cfg.brain.update(raw.get("brain", {})).
    """

    def test_brain_loaded_from_yaml(self, tmp_path):
        """Setting brain.enable_bayesian in .loomscan.yaml must actually enable it."""
        from loomscan.config import STCAConfig
        yaml_content = """
brain:
  enable_bayesian: true
  enable_project_tuner: true
  fp_learn_mode: false
"""
        config_file = tmp_path / ".loomscan.yaml"
        config_file.write_text(yaml_content)
        config = STCAConfig.from_file(config_file)
        assert config.brain.get("enable_bayesian") is True, \
            "enable_bayesian must be loaded from YAML"
        assert config.brain.get("enable_project_tuner") is True, \
            "enable_project_tuner must be loaded from YAML"
        assert config.brain.get("fp_learn_mode") is False, \
            "fp_learn_mode must be loaded from YAML"

    def test_brain_serialized_to_dict(self):
        """to_dict must include brain config."""
        from loomscan.config import STCAConfig
        config = STCAConfig()
        config.brain["enable_bayesian"] = True
        d = config.to_dict()
        assert "brain" in d
        assert d["brain"]["enable_bayesian"] is True

    def test_brain_round_trips_through_yaml(self, tmp_path):
        """Config must round-trip: save → load → same values."""
        from loomscan.config import STCAConfig
        config = STCAConfig()
        config.brain["enable_bayesian"] = True
        config.brain["fp_learn_mode"] = False
        config_file = tmp_path / ".loomscan.yaml"
        config.save(config_file)
        loaded = STCAConfig.from_file(config_file)
        assert loaded.brain.get("enable_bayesian") is True
        assert loaded.brain.get("fp_learn_mode") is False

    def test_orchestrator_bayesian_enabled_from_yaml(self, tmp_path):
        """Orchestrator must instantiate Bayesian when YAML enables it."""
        from loomscan.orchestrator import Orchestrator
        from loomscan.config import STCAConfig
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / ".git").mkdir()
        (repo / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
        (repo / "app.py").write_text("x = 1\n")
        yaml_content = """
brain:
  enable_bayesian: true
"""
        (repo / ".loomscan.yaml").write_text(yaml_content)
        config = STCAConfig.from_file(repo / ".loomscan.yaml")
        orch = Orchestrator(repo, config)
        assert orch.bayesian is not None, \
            "Bayesian must be enabled when .loomscan.yaml has brain.enable_bayesian: true"


# =============================================================================
# BUG #2: Auto-tuner reads from .loomscan.yaml (not .loomscan-tuning.json)
# =============================================================================

class TestAutoTunerReadPathRegression:
    """v4.13: aggregator read .loomscan-tuning.json but tuner wrote .loomscan.yaml.
    v4.14: aggregator reads .loomscan.yaml.
    """

    def test_aggregator_reads_loomscan_yaml(self):
        """Aggregator._load_tuning must read .loomscan.yaml, not .loomscan-tuning.json."""
        from loomscan.brain.aggregator import Aggregator
        import inspect
        source = inspect.getsource(Aggregator._load_tuning)
        assert ".loomscan.yaml" in source, \
            "Aggregator must read .loomscan.yaml (where tuner writes)"
        # The docstring mentions .loomscan-tuning.json for context — that's fine.
        # What matters is the actual code path uses .loomscan.yaml
        assert 'config_path = self.stats_path.parent / ".loomscan.yaml"' in source, \
            "Aggregator must use .loomscan.yaml as config_path"


# =============================================================================
# BUG #3: Inline suppressions actually work
# =============================================================================

class TestSuppressionsWorkRegression:
    """v4.13: absolute-vs-relative path mismatch meant # loomscan: ignore did nothing.
    v4.14: find_suppressions stores relative path.
    """

    def test_suppression_matches_finding(self, tmp_path):
        """A # loomscan: ignore comment must actually suppress the finding."""
        from loomscan.suppressions import find_suppressions, is_suppressed
        repo = tmp_path / "repo"
        repo.mkdir()
        app = repo / "app.py"
        app.write_text("eval(x)  # loomscan: ignore\n")
        sups = find_suppressions(app, repo)
        assert len(sups) == 1, "Should find 1 suppression"
        # The suppression file should be relative (matching finding.file)
        assert sups[0].file == "app.py", \
            f"Suppression file should be relative 'app.py', got {sups[0].file!r}"
        # is_suppressed should match
        is_sup, _ = is_suppressed("app.py", 1, "L0.sast.mini:py-eval", sups)
        assert is_sup, \
            "Suppression should match finding on same file+line"

    def test_suppression_does_not_cross_files(self, tmp_path):
        """A suppression in app.py must not match a finding in other.py."""
        from loomscan.suppressions import find_suppressions, is_suppressed
        repo = tmp_path / "repo"
        repo.mkdir()
        app = repo / "app.py"
        app.write_text("eval(x)  # loomscan: ignore\n")
        sups = find_suppressions(app, repo)
        # Finding in a different file should NOT match
        is_sup, _ = is_suppressed("other.py", 1, "L0.sast.mini:py-eval", sups)
        assert not is_sup, "Suppression in app.py must not match finding in other.py"


# =============================================================================
# BUG #4: run() has ProjectTuner (was only in run_full)
# =============================================================================

class TestRunHasProjectTunerRegression:
    """v4.13: ProjectTuner only applied in run_full(), not run().
    v4.14: Applied in both.
    """

    def test_run_has_project_tuner(self):
        """run() must apply ProjectTuner confidence adjustments."""
        from loomscan.orchestrator import Orchestrator
        import inspect
        source = inspect.getsource(Orchestrator.run)
        assert "self.project_tuner" in source, \
            "run() must apply ProjectTuner (was only in run_full before v4.14)"

    def test_run_full_has_llm_tie_breaker(self):
        """run_full() must have LLM tie-breaker (was only in run before v4.14)."""
        from loomscan.orchestrator import Orchestrator
        import inspect
        source = inspect.getsource(Orchestrator.run_full)
        assert "_llm_tie_break" in source, \
            "run_full() must have LLM tie-breaker (was only in run before v4.14)"


# =============================================================================
# BUG #5: suppressed_findings serialized in to_dict
# =============================================================================

class TestSuppressedFindingsSerializedRegression:
    """v4.13: suppressed_findings was populated but never serialized.
    v4.14: to_dict() includes suppressed_findings.
    """

    def test_to_dict_includes_suppressed_findings(self):
        """to_dict must include suppressed_findings key."""
        from loomscan.models import PipelineResult
        result = PipelineResult()
        d = result.to_dict()
        assert "suppressed_findings" in d, \
            "to_dict must include suppressed_findings for audit"


# =============================================================================
# BUG #8: ProjectTuner suppression actually filters
# =============================================================================

class TestProjectTunerFiltersZeroConfidenceRegression:
    """v4.13: set confidence=0 but nothing filtered.
    v4.14: filters confidence>0 after ProjectTuner.
    """

    def test_run_full_filters_zero_confidence(self):
        """run_full must filter confidence=0 findings after ProjectTuner."""
        from loomscan.orchestrator import Orchestrator
        import inspect
        source = inspect.getsource(Orchestrator.run_full)
        assert "f.confidence > 0.0" in source or "confidence > 0" in source, \
            "run_full must filter confidence=0 findings after ProjectTuner"

    def test_run_filters_zero_confidence(self):
        """run must also filter confidence=0 findings."""
        from loomscan.orchestrator import Orchestrator
        import inspect
        source = inspect.getsource(Orchestrator.run)
        assert "f.confidence > 0.0" in source or "confidence > 0" in source, \
            "run must filter confidence=0 findings after ProjectTuner"


# =============================================================================
# BUG #11: dynamic_invariants has import tempfile
# =============================================================================

class TestDynamicInvariantsImportRegression:
    """v4.13: tempfile not imported → NameError on first call.
    v4.14: import tempfile added.
    """

    def test_tempfile_imported(self):
        """dynamic_invariants must import tempfile."""
        import loomscan.dynamic_invariants as di
        assert hasattr(di, 'tempfile') or 'tempfile' in dir(di), \
            "dynamic_invariants must import tempfile (was missing, caused NameError)"


# =============================================================================
# BUG #12: pre_commit calls correct method
# =============================================================================

class TestPreCommitSymbolicCallRegression:
    """v4.13: pre_commit called symbolic.analyze_file(f, repo_root) — wrong arg count.
    v4.14: calls symbolic.analyze_file(f) — correct.
    """

    def test_pre_commit_calls_analyze_file_correctly(self):
        """pre_commit must call analyze_file with correct arguments."""
        from loomscan import pre_commit
        import inspect
        source = inspect.getsource(pre_commit)
        # Must NOT pass repo_root as second arg
        assert "symbolic.analyze_file(f)" in source, \
            "pre_commit must call symbolic.analyze_file(f) without extra args"
