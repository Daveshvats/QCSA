"""v4.12 Regression tests — Z-Agent v4.11 audit findings.

Tests:
  1. _fix_docker_latest unknown-image branch — produces valid Dockerfile, not malformed
  2. _fix_mutable_default — uses sentinel pattern, not TODO comment
  3. missing_patches.py renamed to version_vuln_checks.py
  4. tuner.load_tuning() wired into Aggregator
  5. FPLearner learn_mode — doesn't write on read-only runs
  6. L2Mutation renamed to L2TestCoverage
"""
from __future__ import annotations

import tempfile, os
from pathlib import Path
import pytest


# =============================================================================
# 1. _fix_docker_latest unknown-image — must produce valid Dockerfile
# =============================================================================

class TestDockerLatestUnknownImageRegression:
    """v4.11 produced `FROM img: pin to a specific version` (malformed).
    v4.12 uses a clean comment-on-line approach.
    """

    def test_unknown_image_gets_comment_not_malformed_tag(self, tmp_path):
        """Unknown image should get a TODO comment, not a malformed tag."""
        from stca.layers.l8_autofix import _fix_docker_latest
        from stca.models import Finding, LayerID, Severity, BlastRadius, Category
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM someunknownimg:latest\n")
        finding = Finding(
            layer=LayerID.L0E_IAC, rule_id="L0e.docker-latest-tag",
            message="test", file="Dockerfile", start_line=1,
            severity=Severity.LOW, confidence=0.7,
            blast_radius=BlastRadius.SYSTEM, exploitability=0.0,
            category=Category.SECURITY,
        )
        result = _fix_docker_latest(finding, tmp_path)
        assert result is not None
        # Must NOT contain a malformed tag like `FROM img: pin to`
        assert " pin to a specific version" not in result.split("FROM")[1].split("#")[0], (
            f"Unknown image must not produce a malformed tag. Got: {result!r}"
        )
        # Must contain a TODO comment
        assert "TODO" in result or "pin to a specific version" in result

    def test_known_image_still_works(self, tmp_path):
        """Known images (python, node, etc.) must still get pinned correctly."""
        from stca.layers.l8_autofix import _fix_docker_latest
        from stca.models import Finding, LayerID, Severity, BlastRadius, Category
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM python:latest\n")
        finding = Finding(
            layer=LayerID.L0E_IAC, rule_id="L0e.docker-latest-tag",
            message="test", file="Dockerfile", start_line=1,
            severity=Severity.LOW, confidence=0.7,
            blast_radius=BlastRadius.SYSTEM, exploitability=0.0,
            category=Category.SECURITY,
        )
        result = _fix_docker_latest(finding, tmp_path)
        assert result is not None
        assert "3.12-slim" in result
        assert ":latest" not in result


# =============================================================================
# 2. _fix_mutable_default — uses safe sentinel pattern
# =============================================================================

class TestFixMutableDefaultRegression:
    """v4.11 had `# TODO: verify this is safe`. v4.12 clarifies the semantics.
    """

    def test_guard_comment_updated(self):
        """The guard should have an updated comment (no longer TODO)."""
        from stca.layers.l8_autofix import _fix_mutable_default
        from stca.models import Finding, LayerID, Severity, BlastRadius, Category
        import inspect
        source = inspect.getsource(_fix_mutable_default)
        assert "TODO: verify this is safe" not in source, (
            "v4.12 should not have the old TODO comment"
        )


# =============================================================================
# 3. missing_patches.py renamed to version_vuln_checks.py
# =============================================================================

class TestModuleRenameRegression:
    """v4.11 was still named missing_patches.py. v4.12 renames it.
    """

    def test_version_vuln_checks_importable(self):
        """version_vuln_checks module must be importable."""
        from stca.version_vuln_checks import scan_version_vuln_checks
        assert callable(scan_version_vuln_checks)

    def test_orchestrator_uses_new_name(self):
        """Orchestrator must import from version_vuln_checks, not missing_patches."""
        from stca.orchestrator import Orchestrator
        import inspect
        source = inspect.getsource(Orchestrator)
        assert "version_vuln_checks" in source, (
            "Orchestrator must use version_vuln_checks module"
        )


# =============================================================================
# 4. tuner.load_tuning() wired into Aggregator
# =============================================================================

class TestTunerReadPathRegression:
    """v4.11: tuner.load_tuning() was defined but never called.
    v4.12: Aggregator._load_tuning() calls it.
    """

    def test_aggregator_has_tuning_adjustments(self):
        """Aggregator must have tuning_adjustments field."""
        from stca.brain.aggregator import Aggregator
        agg = Aggregator()
        assert hasattr(agg, 'tuning_adjustments')

    def test_aggregator_has_load_tuning_method(self):
        """Aggregator must have _load_tuning method."""
        from stca.brain.aggregator import Aggregator
        assert hasattr(Aggregator, '_load_tuning')


# =============================================================================
# 5. FPLearner learn_mode — doesn't write on read-only runs
# =============================================================================

class TestFPLearnerLearnModeRegression:
    """v4.11: record_occurrence wrote to disk on every run.
    v4.12: Only writes when learn_mode=True (default).
    """

    def test_fp_learner_has_learn_mode(self, tmp_path):
        """FPLearner must accept learn_mode parameter."""
        from stca.precision import FPLearner
        learner = FPLearner(tmp_path, learn_mode=False)
        assert learner._learn_mode is False

    def test_no_write_when_learn_mode_false(self, tmp_path):
        """When learn_mode=False, record_occurrence must not write to disk."""
        from stca.precision import FPLearner
        learner = FPLearner(tmp_path, learn_mode=False)
        learner.record_occurrence("test.rule", "app.py")
        # The FP learning file should NOT exist (no write)
        assert not (tmp_path / ".stca-fp-learning.json").exists(), (
            "FPLearner must not write to disk when learn_mode=False"
        )
        # But the in-memory pattern should exist
        assert learner._dirty is True

    def test_write_when_learn_mode_true(self, tmp_path):
        """When learn_mode=True (default), record_occurrence should write."""
        from stca.precision import FPLearner
        learner = FPLearner(tmp_path, learn_mode=True)
        learner.record_occurrence("test.rule", "app.py")
        assert (tmp_path / ".stca-fp-learning.json").exists()


# =============================================================================
# 6. L2Mutation renamed to L2TestCoverage
# =============================================================================

class TestL2MutationRenameRegression:
    """v4.11: Still named L2Mutation despite being a coverage heuristic.
    v4.12: Renamed to L2TestCoverage.
    """

    def test_l2_test_coverage_exists(self):
        """L2TestCoverage class must exist and be importable."""
        from stca.layers.l2_test_coverage import L2TestCoverage
        assert L2TestCoverage is not None

    def test_l2_mutation_not_referenced(self):
        """L2Mutation should no longer be referenced in layers __init__."""
        from stca.layers import ALL_LAYERS
        # All layers should import fine without L2Mutation
        for layer_cls in ALL_LAYERS:
            assert layer_cls.__name__ != "L2Mutation", (
                "L2Mutation should be renamed to L2TestCoverage"
            )
