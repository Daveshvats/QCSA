"""v5.3 smoke tests — Multi-language metamorphic, LLM-verify, SARIF Pro tier.

Tests:
1. Multi-language metamorphic testing (JS/Java/Go function discovery)
2. Multi-language LLM-verify (language parameter)
3. SARIF Pro tier (threadFlow for taint paths, taxonomies, version)
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parent.parent


# =============================================================================
# 1. Multi-language metamorphic testing
# =============================================================================

class TestMultiLangMetamorphic:
    """v5.3: Metamorphic testing extended to JS/Java/Go (was Python-only)."""

    def test_discovers_js_functions(self, tmp_path):
        """discover_testable_functions should find JS functions."""
        from loomscan.metamorphic import discover_testable_functions
        f = tmp_path / "app.js"
        f.write_text(
            "function add(a, b) { return a + b; }\n"
            "const square = (x) => x * x;\n"
        )
        funcs = discover_testable_functions(f)
        assert len(funcs) >= 1, f"Should find JS functions. Got: {funcs}"
        names = [f[0] for f in funcs]
        assert "add" in names or "square" in names

    def test_discovers_java_functions(self, tmp_path):
        """discover_testable_functions should find Java methods."""
        from loomscan.metamorphic import discover_testable_functions
        f = tmp_path / "Calculator.java"
        f.write_text(
            "public class Calculator {\n"
            "    public int add(int a, int b) {\n"
            "        return a + b;\n"
            "    }\n"
            "}\n"
        )
        funcs = discover_testable_functions(f)
        assert len(funcs) >= 1, f"Should find Java methods. Got: {funcs}"
        names = [f[0] for f in funcs]
        assert "add" in names

    def test_discovers_go_functions(self, tmp_path):
        """discover_testable_functions should find Go functions."""
        from loomscan.metamorphic import discover_testable_functions
        f = tmp_path / "math.go"
        f.write_text(
            "package main\n\n"
            "func Add(a int, b int) int {\n"
            "    return a + b\n"
            "}\n"
        )
        funcs = discover_testable_functions(f)
        assert len(funcs) >= 1, f"Should find Go functions. Got: {funcs}"
        names = [f[0] for f in funcs]
        assert "Add" in names

    def test_js_metamorphic_runs_without_crash(self, tmp_path):
        """run_metamorphic_tests on a JS file should not crash."""
        from loomscan.metamorphic import run_metamorphic_tests
        f = tmp_path / "app.js"
        f.write_text(
            "function add(a, b) { return a + b; }\n"
        )
        violations = run_metamorphic_tests(f, tmp_path)
        assert isinstance(violations, list)

    def test_static_mr_analysis_detects_nondeterminism_js(self, tmp_path):
        """Static MR analysis should flag Math.random() in JS."""
        from loomscan.metamorphic import run_metamorphic_tests
        f = tmp_path / "app.js"
        f.write_text(
            "function getRandomNumber(max) {\n"
            "    return Math.floor(Math.random() * max);\n"
            "}\n"
        )
        violations = run_metamorphic_tests(f, tmp_path)
        # Should detect non-determinism (Math.random)
        assert len(violations) > 0, "Should flag Math.random() as non-deterministic"


# =============================================================================
# 2. Multi-language LLM-verify
# =============================================================================

class TestMultiLangLLMVerify:
    """v5.3: LLM-verify extended to JS/Java/Go (was Python-only)."""

    def test_generate_hypotheses_has_language_param(self):
        """generate_hypotheses should accept a language parameter."""
        import inspect
        from loomscan.llm_verify import generate_hypotheses
        sig = inspect.signature(generate_hypotheses)
        assert "language" in sig.parameters, (
            "generate_hypotheses should have a 'language' parameter"
        )

    def test_verify_hypothesis_has_language_param(self):
        """verify_hypothesis should accept a language parameter."""
        import inspect
        from loomscan.llm_verify import verify_hypothesis
        sig = inspect.signature(verify_hypothesis)
        assert "language" in sig.parameters

    def test_llm_verify_function_has_language_param(self):
        """llm_verify_function should accept a language parameter."""
        import inspect
        from loomscan.llm_verify import llm_verify_function
        sig = inspect.signature(llm_verify_function)
        assert "language" in sig.parameters

    def test_generate_hypotheses_js_prompt(self):
        """The LLM prompt for JS should mention JavaScript."""
        import inspect
        from loomscan.llm_verify import generate_hypotheses
        src = inspect.getsource(generate_hypotheses)
        assert "javascript" in src.lower() or "JavaScript" in src, (
            "generate_hypotheses should have JS language support"
        )


# =============================================================================
# 3. SARIF Pro tier
# =============================================================================

class TestSarifProTier:
    """v5.3: SARIF Pro tier with threadFlow for taint paths."""

    def test_sarif_has_taxonomies(self):
        """SARIF output should include taxonomies."""
        from loomscan.report.sarif import _TAXONOMIES
        assert len(_TAXONOMIES) >= 2, "Should have at least 2 taxonomies"

    def test_sarif_has_thread_flow_builder(self):
        """The SARIF module should have _build_thread_flow function."""
        from loomscan.report.sarif import _build_thread_flow
        assert callable(_build_thread_flow)

    def test_sarif_has_code_flows_builder(self):
        """The SARIF module should have _build_code_flows function."""
        from loomscan.report.sarif import _build_code_flows
        assert callable(_build_code_flows)

    def test_thread_flow_built_for_taint_finding(self):
        """A finding with source/sink data should produce a threadFlow."""
        from loomscan.report.sarif import _build_thread_flow
        from loomscan.models import Finding, Severity, LayerID, BlastRadius

        finding = Finding(
            layer=LayerID.L0_FAST,
            rule_id="L0.cpg_taint.eval",
            message="Taint flow: request → eval",
            file="app.py", start_line=10,
            severity=Severity.CRITICAL, confidence=0.85,
            blast_radius=BlastRadius.SYSTEM, exploitability=0.9,
            cwe="CWE-95",
            raw={"source": "request.args", "sink": "eval",
                 "intermediate_functions": ["parse_input", "sanitize"],
                 "cross_file": True},
        )
        flow = _build_thread_flow(finding)
        assert flow is not None, "Should produce threadFlow for taint finding"
        assert len(flow) >= 3, (
            f"ThreadFlow should have source + intermediates + sink. Got {len(flow)} locations"
        )
        # First location = source
        assert flow[0]["kinds"] == ["source"]
        # Last location = sink
        assert flow[-1]["kinds"] == ["sink"]

    def test_thread_flow_none_for_non_taint_finding(self):
        """A finding without taint data should not produce a threadFlow."""
        from loomscan.report.sarif import _build_thread_flow
        from loomscan.models import Finding, Severity, LayerID, BlastRadius

        finding = Finding(
            layer=LayerID.L0_FAST,
            rule_id="L0.secrets.regex",
            message="Hardcoded password",
            file="app.py", start_line=5,
            severity=Severity.HIGH, confidence=0.9,
            blast_radius=BlastRadius.FUNCTION, exploitability=0.5,
            cwe="CWE-798",
            raw={},
        )
        flow = _build_thread_flow(finding)
        assert flow is None, "Should not produce threadFlow for non-taint finding"

    def test_sarif_includes_code_flows_for_taint(self):
        """Full SARIF output should include codeFlows for taint findings."""
        from loomscan.report.sarif import to_sarif
        from loomscan.models import (PipelineResult, Finding, Severity, LayerID,
                                  BlastRadius, Decision, AggregatedDecision, Category)

        finding = Finding(
            layer=LayerID.L0_FAST,
            rule_id="L0.cpg_taint.test",
            message="Taint: source → sink",
            file="app.py", start_line=10,
            severity=Severity.CRITICAL, confidence=0.85,
            blast_radius=BlastRadius.SYSTEM, exploitability=0.9,
            cwe="CWE-89",
            raw={"source": "request.args", "sink": "execute",
                 "intermediate_functions": ["transform"],
                 "cross_file": False},
        )
        result = PipelineResult(
            findings=[finding],
            decisions=[AggregatedDecision(
                decision=Decision.BLOCK,
                confidence_interval=(0.8, 1.0),
                reasoning="Critical taint flow",
            )],
            final_decision=Decision.BLOCK,
        )
        sarif = to_sarif(result, Path("/repo"))
        results = sarif["runs"][0]["results"]
        assert len(results) == 1
        assert "codeFlows" in results[0], "Taint finding should have codeFlows"
        assert len(results[0]["codeFlows"]) >= 1
        assert "threadFlows" in results[0]["codeFlows"][0]

    def test_sarif_has_version_from_package(self):
        """SARIF tool version should come from __version__, not hardcoded."""
        from loomscan.report.sarif import to_sarif
        from loomscan.models import PipelineResult, Decision
        from loomscan import __version__

        result = PipelineResult(findings=[], decisions=[], final_decision=Decision.PASS)
        sarif = to_sarif(result, Path("/repo"))
        driver = sarif["runs"][0]["tool"]["driver"]
        assert driver["version"] == __version__, (
            f"SARIF version should be {__version__}, got {driver['version']}"
        )

    def test_sarif_has_severity_in_properties(self):
        """SARIF properties should include 'severity' for the workflow check."""
        from loomscan.report.sarif import to_sarif
        from loomscan.models import (PipelineResult, Finding, Severity, LayerID,
                                  BlastRadius, Decision)

        finding = Finding(
            layer=LayerID.L0_FAST, rule_id="test",
            message="test", file="app.py", start_line=1,
            severity=Severity.CRITICAL, confidence=0.9,
            blast_radius=BlastRadius.FUNCTION, exploitability=0.5,
        )
        result = PipelineResult(
            findings=[finding],
            decisions=[],
            final_decision=Decision.BLOCK,
        )
        sarif = to_sarif(result, Path("/repo"))
        props = sarif["runs"][0]["results"][0]["properties"]
        assert "severity" in props, "SARIF should include severity in properties"
        assert props["severity"] == "critical"


# =============================================================================
# 4. Version
# =============================================================================

class TestVersionV53:
    def test_version_is_5_3(self):
        from loomscan import __version__
        major, minor = int(__version__.split(".")[0]), int(__version__.split(".")[1])
        assert major >= 5 and minor >= 3, f"Expected >= 5.3.0, got {__version__}"

    def test_pyproject_matches(self):
        from loomscan import __version__
        import re as _re
        content = (PROJECT_ROOT / "pyproject.toml").read_text()
        m = _re.search(r'^version\s*=\s*["\']([^"\']+)["\']', content, _re.MULTILINE)
        assert m
        assert m.group(1) == __version__
