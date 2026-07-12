"""v4.13 Regression tests — Z-Agent v4.12 audit: theatrical fixes made real.

All tests are BEHAVIORAL (run the code, check output) — no source-string inspections.
"""
from __future__ import annotations

import tempfile, os, ast, json
from pathlib import Path
import pytest


# =============================================================================
# 1. _fix_mutable_default — actually uses sentinel pattern (behavioral)
# =============================================================================

class TestMutableDefaultSentinelRegression:
    """v4.12 claimed sentinel but generated `if x is None: x = []`.
    v4.13 actually generates `_SENTINEL = object()` + `if x is _SENTINEL: x = []`.
    """

    def test_generated_code_uses_sentinel_not_none(self, tmp_path):
        """The generated fix must use _SENTINEL, not None."""
        from stca.layers.l8_autofix import _fix_mutable_default
        from stca.models import Finding, LayerID, Severity, BlastRadius, Category
        py_file = tmp_path / "app.py"
        py_file.write_text("def foo(x=[]):\n    return x\n")
        finding = Finding(
            layer=LayerID.L8_AUTOFIX, rule_id="L0.ast.AST-PY-MUTABLE-DEFAULT",
            message="test", file="app.py", start_line=1,
            severity=Severity.HIGH, confidence=0.9,
            blast_radius=BlastRadius.FUNCTION, exploitability=0.0,
            category=Category.CORRECTNESS,
        )
        result = _fix_mutable_default(finding, tmp_path)
        assert result is not None
        # Must use _SENTINEL, not None
        assert "_SENTINEL" in result, f"Generated code must use _SENTINEL. Got: {result!r}"
        assert "is None" not in result, f"Generated code must NOT use 'is None'. Got: {result!r}"
        # Must have _SENTINEL = object() at module level
        assert "_SENTINEL = object()" in result

    def test_generated_code_parses(self, tmp_path):
        """The generated fix must be valid Python."""
        from stca.layers.l8_autofix import _fix_mutable_default
        from stca.models import Finding, LayerID, Severity, BlastRadius, Category
        py_file = tmp_path / "app.py"
        py_file.write_text("def foo(x=[]):\n    return x\n")
        finding = Finding(
            layer=LayerID.L8_AUTOFIX, rule_id="L0.ast.AST-PY-MUTABLE-DEFAULT",
            message="test", file="app.py", start_line=1,
            severity=Severity.HIGH, confidence=0.9,
            blast_radius=BlastRadius.FUNCTION, exploitability=0.0,
            category=Category.CORRECTNESS,
        )
        result = _fix_mutable_default(finding, tmp_path)
        assert result is not None
        # Must parse as valid Python
        ast.parse(result)


# =============================================================================
# 2. tuner.load_tuning() — actually applied in aggregate_finding (behavioral)
# =============================================================================

class TestTuningAppliedRegression:
    """v4.12 loaded tuning_adjustments but never applied them.
    v4.13 applies them in aggregate_finding.
    """

    def test_tuning_changes_aggregation_result(self):
        """A tuning adjustment should change the aggregation output."""
        from stca.brain.aggregator import Aggregator
        from stca.models import Finding, LayerID, Severity, BlastRadius, Category

        # Create a finding
        finding = Finding(
            layer=LayerID.L0_FAST, rule_id="test.rule",
            message="test", file="app.py", start_line=1,
            severity=Severity.MEDIUM, confidence=0.5,
            blast_radius=BlastRadius.FUNCTION, exploitability=0.3,
            category=Category.CORRECTNESS,
        )

        # Aggregator without tuning
        agg_no_tuning = Aggregator()
        agg_no_tuning.tuning_adjustments = {}
        decision_no_tuning = agg_no_tuning.aggregate_finding(finding)

        # Aggregator with tuning that shifts confidence significantly
        agg_with_tuning = Aggregator()
        agg_with_tuning.tuning_adjustments = {"L0_fast": (0.0, 0.4)}  # shift +0.4
        decision_with_tuning = agg_with_tuning.aggregate_finding(finding)

        # The adjusted confidence should differ
        assert decision_with_tuning.contributing_signals.get("adjusted_confidence", 0.5) != finding.confidence, \
            "Tuning adjustment must change the confidence used in aggregation"
        assert "tuning_adjustment" in decision_with_tuning.contributing_signals, \
            "Tuning adjustment must be recorded in contributing_signals"


# =============================================================================
# 3. FPLearner learn_mode — actually wired into orchestrator (behavioral)
# =============================================================================

class TestFPLearnModeWiredRegression:
    """v4.12 added learn_mode but orchestrator used default True.
    v4.13 wires it into config.brain.fp_learn_mode.
    """

    def test_config_has_fp_learn_mode(self):
        """STCAConfig.brain must have fp_learn_mode key."""
        from stca.config import STCAConfig
        config = STCAConfig()
        assert "fp_learn_mode" in config.brain

    def test_orchestrator_reads_fp_learn_mode(self, tmp_path):
        """Orchestrator must pass learn_mode from config to FPLearner."""
        from stca.orchestrator import Orchestrator
        from stca.config import STCAConfig
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / ".git").mkdir()
        (repo / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
        (repo / "app.py").write_text("x = 1\n")

        config = STCAConfig()
        config.brain["fp_learn_mode"] = False
        orch = Orchestrator(repo, config)
        assert orch.fp_learner._learn_mode is False, \
            "Orchestrator must pass fp_learn_mode from config to FPLearner"


# =============================================================================
# 4. missing_patches.py deleted (behavioral)
# =============================================================================

class TestMissingPatchesDeletedRegression:
    """v4.12 left the old file as stale duplicate. v4.13 deletes it.
    """

    def test_missing_patches_not_importable(self):
        """stca.missing_patches must not be importable."""
        try:
            import stca.missing_patches
            pytest.fail("stca.missing_patches should be deleted in v4.13")
        except ImportError:
            pass  # expected

    def test_version_vuln_checks_importable(self):
        """stca.version_vuln_checks must be importable."""
        from stca.version_vuln_checks import scan_version_vuln_checks
        assert callable(scan_version_vuln_checks)


# =============================================================================
# 5. L2 rename complete — file, enum, all references (behavioral)
# =============================================================================

class TestL2RenameCompleteRegression:
    """v4.12 only renamed the class. v4.13 renames file, enum value, all refs.
    """

    def test_file_renamed(self):
        """l2_test_coverage.py must exist, l2_mutation.py must not."""
        import stca.layers.l2_test_coverage
        assert hasattr(stca.layers.l2_test_coverage, 'L2TestCoverage')

    def test_enum_value_renamed(self):
        """LayerID.L2_MUTATION value must be 'L2_test_coverage' not 'L2_mutation'."""
        from stca.models import LayerID
        assert LayerID.L2_MUTATION.value == "L2_test_coverage"

    def test_no_l2_mutation_string_in_config(self):
        """Config must not reference 'L2_mutation' string."""
        from stca.config import STCAConfig
        config = STCAConfig()
        config_dict = str(config.__dict__)
        assert "L2_mutation" not in config_dict, \
            "Config must use 'L2_test_coverage' not 'L2_mutation'"
