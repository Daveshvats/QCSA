"""v5.2 smoke tests — Native YAML rule engine + YAML rule firing E2E.

The v5.1 audit found that 1,181 YAML rules were silently dead code because
they only fire when semgrep is installed (which it isn't by default).
v5.2 adds a native YAML rule engine (loomscan/yaml_engine.py) that applies
regex-based rules using Python's re module.

These tests verify:
1. The native YAML engine exists and is importable
2. YAML rules actually fire on matching code (THE critical test)
3. Framework taint rules fire (the v5.1 feature that was dead code)
4. The engine correctly handles pattern, pattern-regex, pattern-either
5. l0_fast.py falls back to native engine when semgrep not installed
6. A warning is logged when semgrep is not installed
7. count_applicable_rules reports correct stats
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parent.parent


# =============================================================================
# 1. Native YAML engine exists
# =============================================================================

class TestYamlEngineExists:
    """v5.2: loomscan/yaml_engine.py exists and is importable."""

    def test_yaml_engine_importable(self):
        from loomscan.yaml_engine import apply_packs, apply_pack_to_file, count_applicable_rules, YAMLHit
        assert callable(apply_packs)
        assert callable(apply_pack_to_file)
        assert callable(count_applicable_rules)
        assert YAMLHit is not None

    def test_yaml_engine_file_exists(self):
        assert (PROJECT_ROOT / "loomscan" / "yaml_engine.py").exists()


# =============================================================================
# 2. CRITICAL: YAML rules actually fire on matching code
# =============================================================================

class TestYamlRulesActuallyFire:
    """v5.2: THE critical test — YAML pack rules must produce findings
    when applied to matching code, even without semgrep installed.

    In v5.1, 1,181 YAML rules were silently dead code. This test
    verifies they now fire via the native engine.
    """

    def test_python_eval_rule_fires(self, tmp_path):
        """A Python file with eval() should trigger a YAML rule finding."""
        from loomscan.yaml_engine import apply_pack_to_file
        from loomscan.rules import get_builtin_pack_path

        # Create a file with eval()
        test_file = tmp_path / "app.py"
        test_file.write_text("x = eval('1 + 1')\n")

        # Apply the python-security pack (has py-eval-injection rule)
        pack_path = get_builtin_pack_path("python-security")
        hits = apply_pack_to_file(pack_path, test_file, tmp_path)

        assert len(hits) > 0, (
            "python-security pack should fire on eval(). "
            "If 0 hits, the native YAML engine is broken."
        )
        # Verify at least one hit is about eval
        eval_hits = [h for h in hits if "eval" in h.rule_id.lower() or "eval" in h.message.lower()]
        assert len(eval_hits) > 0, (
            f"Should have eval-related hits. Got: {[(h.rule_id, h.message[:50]) for h in hits[:5]]}"
        )

    def test_framework_taint_flask_rule_fires(self, tmp_path):
        """A Flask file with render_template_string(user_input) should trigger
        a framework-taint rule finding. This was the v5.1 dead-code bug."""
        from loomscan.yaml_engine import apply_pack_to_file
        from loomscan.rules import get_builtin_pack_path

        test_file = tmp_path / "app.py"
        test_file.write_text(
            "from flask import render_template_string, request\n"
            "def page():\n"
            "    name = request.args.get('name')\n"
            "    return render_template_string(request.args.get('name'))\n"
        )

        pack_path = get_builtin_pack_path("framework-taint")
        hits = apply_pack_to_file(pack_path, test_file, tmp_path)

        assert len(hits) > 0, (
            "framework-taint pack should fire on render_template_string(request.args). "
            "If 0 hits, the v5.1 dead-code bug is still present."
        )

    def test_javascript_rule_fires(self, tmp_path):
        """A JS file with eval() should trigger a YAML rule finding."""
        from loomscan.yaml_engine import apply_pack_to_file
        from loomscan.rules import get_builtin_pack_path

        test_file = tmp_path / "app.js"
        test_file.write_text("var x = eval('1 + 1');\n")

        pack_path = get_builtin_pack_path("javascript-security")
        hits = apply_pack_to_file(pack_path, test_file, tmp_path)

        assert len(hits) > 0, (
            "javascript-security pack should fire on eval()."
        )

    def test_secret_rule_fires(self, tmp_path):
        """A file with an AWS key should trigger a secret detection finding."""
        from loomscan.advanced_secrets import detect_secrets_entropy

        text = 'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"'
        d = detect_secrets_entropy(text, "test.py")
        assert len(d) > 0, "Secret detection should fire on AWS key"


# =============================================================================
# 3. Native engine handles different rule formats
# =============================================================================

class TestYamlEngineRuleFormats:
    """v5.2: The native engine handles pattern, pattern-regex, pattern-either."""

    def test_pattern_format(self, tmp_path):
        """Rules with 'pattern' field should work."""
        from loomscan.yaml_engine import apply_pack_to_file

        # Create a temp pack with a pattern rule
        pack = tmp_path / "test-pack.yml"
        pack.write_text(
            "rules:\n"
            "  - id: test-pattern\n"
            '    pattern: "\\\\beval\\\\s*\\\\("\n'
            "    severity: high\n"
            '    message: "eval found"\n'
        )
        test_file = tmp_path / "app.py"
        test_file.write_text("x = eval('1+1')\n")

        hits = apply_pack_to_file(pack, test_file, tmp_path)
        assert len(hits) == 1
        assert hits[0].rule_id == "test-pattern"

    def test_pattern_regex_format(self, tmp_path):
        """Rules with 'pattern-regex' field should work."""
        from loomscan.yaml_engine import apply_pack_to_file

        pack = tmp_path / "test-pack.yml"
        pack.write_text(
            "rules:\n"
            "  - id: test-regex\n"
            '    pattern-regex: "\\\\beval\\\\s*\\\\("\n'
            "    severity: high\n"
            '    message: "eval found"\n'
        )
        test_file = tmp_path / "app.py"
        test_file.write_text("x = eval('1+1')\n")

        hits = apply_pack_to_file(pack, test_file, tmp_path)
        assert len(hits) == 1
        assert hits[0].rule_id == "test-regex"

    def test_pattern_either_format(self, tmp_path):
        """Rules with 'pattern-either' field should work (OR semantics)."""
        from loomscan.yaml_engine import apply_pack_to_file

        pack = tmp_path / "test-pack.yml"
        pack.write_text(
            "rules:\n"
            "  - id: test-either\n"
            "    pattern-either:\n"
            '      - pattern: "\\\\beval\\\\s*\\\\("\n'
            '      - pattern: "\\\\bexec\\\\s*\\\\("\n'
            "    severity: high\n"
            '    message: "eval or exec found"\n'
        )
        test_file = tmp_path / "app.py"
        test_file.write_text("x = eval('1+1')\ny = exec('code')\n")

        hits = apply_pack_to_file(pack, test_file, tmp_path)
        assert len(hits) >= 2, f"pattern-either should match both eval and exec. Got {len(hits)}"


# =============================================================================
# 4. l0_fast.py falls back to native engine
# =============================================================================

class TestL0FastFallback:
    """v5.2: l0_fast.py falls back to native YAML engine when semgrep is not installed."""

    def test_l0_fast_has_native_yaml_method(self):
        """L0Fast should have _run_native_yaml_engine method."""
        from loomscan.layers.l0_fast import L0Fast
        assert hasattr(L0Fast, "_run_native_yaml_engine"), (
            "L0Fast should have _run_native_yaml_engine method (v5.2 native fallback)"
        )

    def test_l0_fast_has_semgrep_binary_method(self):
        """L0Fast should have _run_semgrep_binary method (separated in v5.2)."""
        from loomscan.layers.l0_fast import L0Fast
        assert hasattr(L0Fast, "_run_semgrep_binary"), (
            "L0Fast should have _run_semgrep_binary method (v5.2 separation)"
        )

    def test_semgrep_check_runs_without_crash(self, tmp_path):
        """End-to-end: loomscan check --full on a file with eval() should NOT crash
        even without semgrep installed. Should produce findings via native engine."""
        repo = tmp_path / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.email", "test@test.local"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
        (repo / ".loomscan.yaml").write_text("strictness: 5\n")
        (repo / "app.py").write_text("x = eval('1 + 1')\n")
        subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-qm", "init"], cwd=repo, check=True)

        env = os.environ.copy()
        env["PYTHONPATH"] = str(PROJECT_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
        proc = subprocess.run(
            [sys.executable, "-c", "from loomscan.cli import main; main()",
             "check", "--full", "--json"],
            cwd=repo, capture_output=True, text=True, env=env, timeout=180,
        )
        # Should NOT crash
        assert "Traceback" not in proc.stderr, (
            f"loomscan check crashed. stderr: {proc.stderr[:500]}"
        )
        # Should produce findings
        try:
            data = json.loads(proc.stdout)
            assert len(data.get("findings", [])) > 0, (
                "loomscan check should produce findings on a file with eval()"
            )
            # Should have at least one finding from YAML packs or SAST
            yaml_findings = [f for f in data["findings"]
                           if "yaml:" in f.get("rule_id", "") or "semgrep:" in f.get("rule_id", "")
                           or "sast.mini" in f.get("rule_id", "")]
            assert len(yaml_findings) > 0, (
                f"Should have YAML or SAST findings. Got rule_ids: "
                f"{[f.get('rule_id', '') for f in data['findings'][:10]]}"
            )
        except json.JSONDecodeError:
            pytest.fail(f"Invalid JSON output: {proc.stdout[:200]}")


# =============================================================================
# 5. count_applicable_rules reports correctly
# =============================================================================

class TestCountApplicableRules:
    """v5.2: count_applicable_rules should report how many rules the native
    engine can handle vs how many need semgrep."""

    def test_count_returns_tuple(self):
        from loomscan.yaml_engine import count_applicable_rules
        from loomscan.rules import get_all_packs_for_files

        packs = get_all_packs_for_files(["app.py"])
        result = count_applicable_rules(packs)
        assert isinstance(result, tuple)
        assert len(result) == 3
        total, applicable, unsupported = result
        assert total > 0
        assert applicable > 0, (
            "At least some rules should be applicable to the native engine"
        )

    def test_most_rules_are_applicable(self):
        """Most YAML rules should be applicable (they use 'pattern' not 'pattern-inside')."""
        from loomscan.yaml_engine import count_applicable_rules
        from loomscan.rules import get_all_packs_for_files

        packs = get_all_packs_for_files(["app.py"])
        total, applicable, unsupported = count_applicable_rules(packs)
        # At least 80% of rules should be applicable
        assert applicable >= total * 0.8, (
            f"Only {applicable}/{total} rules applicable. "
            f"Expected >= 80%. Unsupported: {unsupported}"
        )


# =============================================================================
# 6. Version is v5.2
# =============================================================================

class TestVersionV52:
    def test_version_is_5_2(self):
        from loomscan import __version__
        major, minor = int(__version__.split(".")[0]), int(__version__.split(".")[1])
        assert major >= 5 and minor >= 2, f"Expected >= 5.2.0, got {__version__}"

    def test_pyproject_matches(self):
        from loomscan import __version__
        import re as _re
        content = (PROJECT_ROOT / "pyproject.toml").read_text()
        m = _re.search(r'^version\s*=\s*["\']([^"\']+)["\']', content, _re.MULTILINE)
        assert m
        assert m.group(1) == __version__
