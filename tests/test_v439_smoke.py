"""v4.39 smoke tests — E2E execution tests for features that had only presence tests in v4.38.

v4.38 shipped spec_mining with a critical bug: the orchestrator referenced
4 non-existent attributes on SpecViolation (v.rule_id, v.suggestion,
v.pattern_name, v.expected). The try/except swallowed the AttributeError,
so stca check silently returned 0 spec_mining findings. The v4.38 smoke
tests verified presence (method exists, import works) not execution.

v4.39 fixes the bug and adds E2E tests that actually RUN the features:

1. spec_mining E2E: mine_and_check on real code → assert findings produced
2. spec_mining orchestrator E2E: _run_spec_mining on real code → assert findings
3. spec_mining CLI E2E: `stca spec` via subprocess → assert no crash
4. LSP hover E2E: populate cache → call _get_hover_info → assert markdown content
5. LSP code actions E2E: populate cache → call _get_code_actions → assert quickfix
6. pyproject.toml version matches __version__
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parent.parent


# =============================================================================
# 1. spec_mining E2E — mine_and_check on real code produces findings
# =============================================================================

class TestSpecMiningE2E:
    """v4.39: spec_mining actually works now (was silently broken in v4.38).

    These tests RUN the engine on real code and assert findings are produced.
    The v4.38 tests only checked that the method existed — not that it worked.
    """

    def test_mine_and_check_produces_findings(self):
        """End-to-end: mine_and_check on the STCA codebase should produce
        patterns AND violations (not silently return empty due to AttributeError)."""
        from stca.spec_mining import mine_and_check
        patterns, violations = mine_and_check(PROJECT_ROOT)
        # STCA has 140+ Python files — should mine at least 10 patterns
        total_patterns = sum(len(v) for v in patterns.values())
        assert total_patterns > 0, (
            "spec_mining should mine patterns from the STCA codebase. "
            f"Got 0 patterns across {len(patterns)} APIs."
        )
        # The codebase has known violations (e.g., methods called in unusual sequences)
        # With the v4.38 bug, violations was always empty due to AttributeError.
        # With the v4.39 fix, violations should be non-empty.
        assert len(violations) > 0, (
            "spec_mining should find violations in the STCA codebase. "
            "If this is 0, the v4.38 AttributeError bug may still be present."
        )

    def test_spec_violation_has_correct_fields(self):
        """Verify SpecViolation has the fields the orchestrator references."""
        from stca.spec_mining import SpecViolation
        import dataclasses
        fields = {f.name for f in dataclasses.fields(SpecViolation)}
        # These are the fields the orchestrator's _run_spec_mining references:
        assert "object_type" in fields, "SpecViolation must have object_type"
        assert "expected_pattern" in fields, "SpecViolation must have expected_pattern"
        assert "actual_sequence" in fields, "SpecViolation must have actual_sequence"
        assert "description" in fields, "SpecViolation must have description"
        assert "file" in fields, "SpecViolation must have file"
        assert "line" in fields, "SpecViolation must have line"
        # These are the fields v4.38 WRONGLY referenced (should NOT exist):
        assert "rule_id" not in fields, "SpecViolation should NOT have rule_id (v4.38 bug)"
        assert "suggestion" not in fields, "SpecViolation should NOT have suggestion (v4.38 bug)"
        assert "pattern_name" not in fields, "SpecViolation should NOT have pattern_name (v4.38 bug)"
        assert "expected" not in fields, "SpecViolation should NOT have expected (v4.38 bug)"

    def test_orchestrator_spec_mining_produces_findings(self, tmp_path):
        """End-to-end: Orchestrator._run_spec_mining on real code should produce
        Finding objects (not silently swallow AttributeError)."""
        from stca.orchestrator import Orchestrator
        from stca.config import STCAConfig
        from stca.models import DiffHunk, Finding

        # Use the STCA codebase itself (it has known spec violations)
        cfg = STCAConfig.default()
        orch = Orchestrator(PROJECT_ROOT, cfg)
        hunks = [DiffHunk(file="stca/spec_mining.py", start_line=1, end_line=10,
                          added_lines=["x = 1"], removed_lines=[])]
        findings = orch._run_spec_mining(hunks)

        # With the v4.38 bug, this was always [] (AttributeError swallowed).
        # With the v4.39 fix, this should produce findings.
        assert len(findings) > 0, (
            "Orchestrator._run_spec_mining should produce findings. "
            "If 0, the AttributeError bug from v4.38 may still be present."
        )
        # Verify each finding has valid fields
        for f in findings:
            assert isinstance(f, Finding)
            assert f.rule_id.startswith("L0.spec."), (
                f"rule_id should start with 'L0.spec.', got: {f.rule_id}"
            )
            assert f.file  # non-empty file path
            assert f.start_line > 0
            assert "expected" in f.raw
            assert "actual" in f.raw
            assert "pattern" in f.raw

    def test_spec_cmd_runs_without_crash(self, tmp_path):
        """End-to-end: `stca spec` CLI command should run without crashing.

        v4.38's stca spec crashed with AttributeError on any codebase with violations.
        """
        # Create a minimal repo with some Python code
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.py").write_text(
            "def f():\n"
            "    f = open('x.txt')\n"
            "    data = f.read()\n"
            "    f.close()\n"
            "    return data\n"
        )
        # Need at least 2 files with different patterns to mine
        (repo / "bad.py").write_text(
            "def g():\n"
            "    f = open('y.txt')\n"
            "    data = f.read()\n"
            "    # missing close() — spec violation\n"
            "    return data\n"
        )

        env = os.environ.copy()
        env["PYTHONPATH"] = str(PROJECT_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
        proc = subprocess.run(
            [sys.executable, "-c", "from stca.cli import main; main()",
             "spec", "--repo", str(repo), "--max-files", "10"],
            capture_output=True, text=True, env=env, timeout=30,
        )
        # Should NOT crash with AttributeError
        assert "AttributeError" not in proc.stderr, (
            f"stca spec crashed with AttributeError (v4.38 bug not fixed). stderr: {proc.stderr[:500]}"
        )
        assert "Traceback" not in proc.stderr, (
            f"stca spec crashed. stderr: {proc.stderr[:500]}"
        )

    def test_spec_cmd_mine_only_flag(self, tmp_path):
        """v4.39: --mine-only should only mine, not check violations."""
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.py").write_text("x = 1\n")

        env = os.environ.copy()
        env["PYTHONPATH"] = str(PROJECT_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
        proc = subprocess.run(
            [sys.executable, "-c", "from stca.cli import main; main()",
             "spec", "--repo", str(repo), "--mine-only"],
            capture_output=True, text=True, env=env, timeout=30,
        )
        # --mine-only should show "Mined" but NOT "Checking for spec violations"
        assert "Mining" in proc.stdout or "Mined" in proc.stdout
        assert "Checking for spec violations" not in proc.stdout

    def test_spec_cmd_check_only_flag(self, tmp_path):
        """v4.39: --check-only should check violations, not display mining."""
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.py").write_text("x = 1\n")

        env = os.environ.copy()
        env["PYTHONPATH"] = str(PROJECT_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
        proc = subprocess.run(
            [sys.executable, "-c", "from stca.cli import main; main()",
             "spec", "--repo", str(repo), "--check-only"],
            capture_output=True, text=True, env=env, timeout=30,
        )
        # --check-only should still mine (needed for check) but should show "Checking"
        assert "Checking" in proc.stdout or "violation" in proc.stdout.lower() or "No patterns" in proc.stdout


# =============================================================================
# 2. LSP hover/code actions E2E — execution tests (not just presence)
# =============================================================================

class TestLSPHoverCodeActionsE2E:
    """v4.39: LSP hover and code actions actually return content (not stubs).

    v4.38 tests verified the methods exist. These tests call the methods
    with real data and verify the return values.
    """

    def test_hover_returns_markdown_with_rule_details(self):
        """E2E: hover on a line with a finding should return markdown with
        the rule_id, severity, message, and fix suggestion."""
        from stca.lsp.server import LSPServer
        s = LSPServer()
        s._findings_cache.clear()
        s._findings_cache["file:///test.py"] = [
            {"rule_id": "L0.sast.mini:py-eval", "line": 5,
             "severity": "high", "message": "eval() — code injection risk",
             "fix": "Use ast.literal_eval() for literal expressions"}
        ]
        try:
            result = s._get_hover_info({
                "textDocument": {"uri": "file:///test.py"},
                "position": {"line": 4, "character": 0},  # LSP 0-indexed = file line 5
            })
            assert result is not None, "Hover should return content for a line with findings"
            assert result["contents"]["kind"] == "markdown"
            value = result["contents"]["value"]
            # Should contain the rule_id
            assert "py-eval" in value, f"Hover should contain rule_id, got: {value[:200]}"
            # Should contain the message
            assert "code injection" in value, f"Hover should contain message, got: {value[:200]}"
            # Should contain the fix
            assert "literal_eval" in value, f"Hover should contain fix, got: {value[:200]}"
            # Should contain the severity
            assert "HIGH" in value, f"Hover should contain severity, got: {value[:200]}"
        finally:
            s._findings_cache.clear()

    def test_hover_returns_none_for_line_without_findings(self):
        """E2E: hover on a line with NO findings should return None."""
        from stca.lsp.server import LSPServer
        s = LSPServer()
        s._findings_cache.clear()
        s._findings_cache["file:///test.py"] = [
            {"rule_id": "L0.test", "line": 5, "severity": "medium",
             "message": "test", "fix": ""}
        ]
        try:
            # Hover on line 1 (no finding there)
            result = s._get_hover_info({
                "textDocument": {"uri": "file:///test.py"},
                "position": {"line": 0, "character": 0},
            })
            assert result is None, "Hover should return None for a line without findings"
        finally:
            s._findings_cache.clear()

    def test_code_actions_returns_quickfix_with_apply_fix(self):
        """E2E: code actions on a line with an autofixable finding should
        return a quickfix action with 'Apply STCA fix'."""
        from stca.lsp.server import LSPServer
        s = LSPServer()
        s._findings_cache.clear()
        s._findings_cache["file:///test.py"] = [
            {"rule_id": "L0.sast.mini:py-eval", "line": 5,
             "severity": "high", "message": "eval is bad", "fix": ""}
        ]
        try:
            result = s._get_code_actions({
                "textDocument": {"uri": "file:///test.py"},
                "range": {"start": {"line": 4, "character": 0},
                          "end": {"line": 4, "character": 80}},
            })
            assert len(result) >= 1, "Should have at least 1 code action"
            # Find the quickfix action
            quickfixes = [a for a in result if a.get("kind") == "quickfix"]
            assert len(quickfixes) >= 1, (
                "Should have at least 1 quickfix for an autofixable rule"
            )
            qf = quickfixes[0]
            assert "Apply" in qf["title"], f"Quickfix title should contain 'Apply', got: {qf['title']}"
            assert qf["command"]["command"] == "stca.applyFix"
            assert len(qf["command"]["arguments"]) >= 2
        finally:
            s._findings_cache.clear()

    def test_code_actions_returns_show_details_for_non_autofixable(self):
        """E2E: code actions for a non-autofixable finding should still
        return a 'Show details' action."""
        from stca.lsp.server import LSPServer
        s = LSPServer()
        s._findings_cache.clear()
        s._findings_cache["file:///test.py"] = [
            {"rule_id": "UNKNOWN.NON.AUTOFIXABLE", "line": 5,
             "severity": "medium", "message": "test", "fix": ""}
        ]
        try:
            result = s._get_code_actions({
                "textDocument": {"uri": "file:///test.py"},
                "range": {"start": {"line": 4}, "end": {"line": 4}},
            })
            # Should still have the "Show details" action
            assert len(result) >= 1, "Should have 'Show details' action even without autofix"
            show_details = [a for a in result if "Show" in a.get("title", "")]
            assert len(show_details) >= 1, "Should have 'Show details' action"
        finally:
            s._findings_cache.clear()

    def test_findings_cache_populated_after_analysis(self):
        """E2E: after _analyze_and_publish runs, _findings_cache should be
        populated for that URI."""
        from stca.lsp.server import LSPServer
        s = LSPServer()
        s._findings_cache.clear()
        # Simulate a file open
        uri = "file:///test_cache.py"
        s.workspace_files[uri] = "x = 1\n"
        # Call _analyze_and_publish (it will analyze and cache)
        s._analyze_and_publish(uri)
        # Cache should now have an entry (even if empty list)
        assert uri in s._findings_cache, (
            "_findings_cache should be populated after _analyze_and_publish"
        )
        s._findings_cache.clear()


# =============================================================================
# 3. Version consistency
# =============================================================================

class TestVersionConsistency:
    """v4.39: pyproject.toml version should match __version__."""

    def test_pyproject_version_matches_init(self):
        """pyproject.toml version was stuck at 4.32.0 since v4.32. v4.39 fixes this."""
        from stca import __version__
        # Read pyproject.toml
        import re
        content = (PROJECT_ROOT / "pyproject.toml").read_text()
        m = re.search(r'^version\s*=\s*["\']([^"\']+)["\']', content, re.MULTILINE)
        assert m, "pyproject.toml should have a version field"
        pyproject_version = m.group(1)
        assert pyproject_version == __version__, (
            f"pyproject.toml version ({pyproject_version}) != __version__ ({__version__})"
        )

    def test_version_is_4_39(self):
        """v4.39+: version should be at least 4.39.0."""
        from stca import __version__
        major, minor = int(__version__.split(".")[0]), int(__version__.split(".")[1])
        assert major >= 4 and minor >= 39, f"Expected >= 4.39.0, got {__version__}"
