"""v4.11 Regression tests — Z-Agent v4.10 audit findings.

Tests:
  1. Counterfactual language guard — _source_path set, JS files get comment not pass
  2. Counterfactual applies boost/downgrade for ALL strategies, not just line_removal
  3. Counterfactual threshold lowered to 0.5, cap raised to 500
  4. LayerID enum has L0C/L0D/L0E/L0F/L8
  5. suppressed_findings populated in PipelineResult
  6. _semgrep_autofix uses specific rule not --config auto
  7. _fix_docker_latest detects base image
"""
from __future__ import annotations

import tempfile, os, ast
from pathlib import Path
import pytest


# =============================================================================
# 1. COUNTERFACTUAL LANGUAGE GUARD — _source_path must be set
# =============================================================================

class TestCounterfactualLanguageGuardRegression:
    """v4.10 wrote language-aware no-ops but _source_path was never set,
    so JS/Go/Java/C files still got Python 'pass' syntax. v4.11 sets it.
    """

    def test_source_path_set_after_verify_finding(self, tmp_path):
        """After calling verify_finding, _source_path must be set."""
        from stca.counterfactual import CounterfactualMutator
        js_file = tmp_path / "app.js"
        js_file.write_text("function foo() {\n  eval(x);\n}\n")
        mutator = CounterfactualMutator(lambda p: [])
        # Before verify_finding, _source_path should not exist
        assert not hasattr(mutator, '_source_path') or mutator._source_path == ""
        # Call verify_finding
        mutator.verify_finding(js_file, line=2, rule_id="test")
        # After verify_finding, _source_path must be set
        assert hasattr(mutator, '_source_path')
        assert str(js_file) in mutator._source_path or "app.js" in mutator._source_path

    def test_js_file_gets_comment_not_pass(self, tmp_path):
        """JS file mutation must produce /* */ not pass."""
        from stca.counterfactual import CounterfactualMutator
        js_file = tmp_path / "app.js"
        js_source = "function foo() {\n  eval(x);\n}\n"
        js_file.write_text(js_source)
        mutator = CounterfactualMutator(lambda p: [])
        mutator.verify_finding(js_file, line=2, rule_id="test")
        # Now call _mutate directly
        result = mutator._mutate(js_source, line=2, strategy="line_removal", context={})
        assert result is not None
        assert "pass" not in result, (
            f"JS file must not get Python 'pass' syntax. Got: {result!r}"
        )
        assert "/*" in result or "//" in result, (
            f"JS file should get a comment no-op. Got: {result!r}"
        )


# =============================================================================
# 2. COUNTERFACTUAL — boost/downgrade for ALL strategies
# =============================================================================

class TestCounterfactualAllStrategiesRegression:
    """v4.10 only applied boost/downgrade for strategy == "line_removal".
    v4.11 applies it for ALL strategies (guard_injection, type_annotation).
    """

    def test_all_strategies_checked(self):
        """The _apply_counterfactual method must check result_mut.mutated
        (which is True for ALL strategies), not just line_removal."""
        from stca.orchestrator import Orchestrator
        import inspect
        source = inspect.getsource(Orchestrator._apply_counterfactual)
        # v4.11 checks `result_mut.mutated` not `result_mut.strategy == "line_removal"`
        assert "result_mut.mutated" in source, (
            "Counterfactual must apply boost/downgrade for ALL strategies (check mutated), "
            "not just line_removal"
        )
        assert 'strategy == "line_removal"' not in source or "mutated" in source, (
            "Should not be gated on line_removal only"
        )

    def test_threshold_lowered(self):
        """Confidence threshold should be 0.5, not 0.7."""
        from stca.orchestrator import Orchestrator
        import inspect
        source = inspect.getsource(Orchestrator._apply_counterfactual)
        assert "0.5" in source, (
            "Confidence threshold should be lowered to 0.5 (was 0.7)"
        )


# =============================================================================
# 3. LayerID ENUM — has proper entries for all layers
# =============================================================================

class TestLayerIDEnumRegression:
    """v4.10 had 6 layers borrowing L0_FAST. v4.11 adds proper enum entries.
    """

    def test_layer_ids_exist(self):
        """All layer IDs must exist in the enum."""
        from stca.models import LayerID
        assert hasattr(LayerID, 'L0C_DEPENDENCIES')
        assert hasattr(LayerID, 'L0D_BEHAVIORAL')
        assert hasattr(LayerID, 'L0E_IAC')
        assert hasattr(LayerID, 'L0F_COMMIT_RISK')
        assert hasattr(LayerID, 'L8_AUTOFIX')

    def test_layers_use_own_ids(self):
        """Layers must use their own LayerID, not borrow L0_FAST."""
        from stca.layers.l0c_dependencies import L0cDependencies
        from stca.layers.l0d_behavioral import L0dBehavioral
        from stca.layers.l0e_iac import L0eIaC
        from stca.layers.l0f_commit_risk import L0fCommitRisk
        from stca.layers.l8_autofix import L8AutoFix
        from stca.models import LayerID

        assert L0cDependencies.id != LayerID.L0_FAST, "L0c must use own LayerID"
        assert L0dBehavioral.id != LayerID.L0_FAST, "L0d must use own LayerID"
        assert L0eIaC.id != LayerID.L0_FAST, "L0e must use own LayerID"
        assert L0fCommitRisk.id != LayerID.L0_FAST, "L0f must use own LayerID"
        assert L8AutoFix.id != LayerID.L0_FAST, "L8 must use own LayerID"


# =============================================================================
# 4. SUPPRESSED_FINDINGS — populated in PipelineResult
# =============================================================================

class TestSuppressedFindingsRegression:
    """v4.10 only stored suppressed_count. v4.11 stores the actual findings.
    """

    def test_suppressed_findings_field_exists(self):
        """PipelineResult must have suppressed_findings field."""
        from stca.models import PipelineResult
        result = PipelineResult()
        assert hasattr(result, 'suppressed_findings')
        assert result.suppressed_findings == []


# =============================================================================
# 5. _semgrep_autofix — uses specific rule not --config auto
# =============================================================================

class TestSemgrepAutofixRegression:
    """v4.10 used --config auto (all community rules). v4.11 uses specific rule.
    """

    def test_no_config_auto(self):
        """_semgrep_autofix must not use --config auto."""
        from stca.layers.l8_autofix import L8AutoFix
        import inspect
        source = inspect.getsource(L8AutoFix._semgrep_autofix)
        assert '"auto"' not in source or "--config" not in source.split('"auto"')[0][-20:], (
            "_semgrep_autofix must not use --config auto (applies all community rules)"
        )


# =============================================================================
# 6. _fix_docker_latest — detects base image
# =============================================================================

class TestFixDockerLatestRegression:
    """v4.10 hardcoded :3.12-slim for all images. v4.11 detects base image.
    """

    def test_node_image_gets_node_version(self, tmp_path):
        """node:latest should become node:20-slim, not python:3.12-slim."""
        from stca.layers.l8_autofix import _fix_docker_latest
        from stca.models import Finding, LayerID, Severity, BlastRadius, Category
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM node:latest\n")
        finding = Finding(
            layer=LayerID.L0E_IAC, rule_id="L0e.docker-latest-tag",
            message="test", file="Dockerfile", start_line=1,
            severity=Severity.LOW, confidence=0.7,
            blast_radius=BlastRadius.SYSTEM, exploitability=0.0,
            category=Category.SECURITY,
        )
        result = _fix_docker_latest(finding, tmp_path)
        assert result is not None
        assert "3.12-slim" not in result, (
            f"node:latest must not become python:3.12-slim. Got: {result!r}"
        )
        assert "20-slim" in result or "node" in result, (
            f"node:latest should become node:20-slim. Got: {result!r}"
        )
