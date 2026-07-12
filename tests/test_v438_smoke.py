"""v4.38 smoke tests — coverage for the "depth + breadth" release.

Tests:
1. Workflow install URLs fixed (no more Daveshvats/QCSA)
2. JetBrains plugin build CI workflow exists
3. 5 new language packs (Objective-C, Groovy, Julia, Perl, COBOL)
4. Spec mining wired into orchestrator + CLI command
5. LSP server depth (hover, code actions, findings cache)
6. Total counts (YAML 1300+, packs 35+, languages 25+)
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml


PROJECT_ROOT = Path(__file__).resolve().parent.parent
PACKS_DIR = PROJECT_ROOT / "stca" / "rules" / "packs"


# =============================================================================
# 1. Workflow install URLs fixed
# =============================================================================

class TestWorkflowUrlsFixed:
    """v4.38: All 3 install URLs now use `pip install .` instead of the
    non-existent github.com/Daveshvats/QCSA.git."""

    def test_no_broken_urls_in_stca_yml(self):
        content = (PROJECT_ROOT / ".github" / "workflows" / "stca.yml").read_text()
        assert "Daveshvats/QCSA" not in content, "Broken URL still in stca.yml"
        assert "pip install --user ." in content

    def test_no_broken_urls_in_stca_bot_yml(self):
        content = (PROJECT_ROOT / ".github" / "workflows" / "stca-bot.yml").read_text()
        assert "Daveshvats/QCSA" not in content, "Broken URL still in stca-bot.yml"
        assert "pip install --user ." in content

    def test_no_broken_urls_in_action_yml(self):
        content = (PROJECT_ROOT / ".github" / "actions" / "stca-action" / "action.yml").read_text()
        assert "Daveshvats/QCSA" not in content, "Broken URL still in action.yml"
        assert "pip install --user ." in content


# =============================================================================
# 2. JetBrains plugin build CI workflow
# =============================================================================

class TestJetBrainsBuildCI:
    """v4.38: CI workflow that builds the JetBrains plugin automatically."""

    def test_build_workflow_exists(self):
        assert (PROJECT_ROOT / ".github" / "workflows" / "build-jetbrains.yml").exists()

    def test_build_workflow_uses_gradle(self):
        content = (PROJECT_ROOT / ".github" / "workflows" / "build-jetbrains.yml").read_text()
        assert "buildPlugin" in content
        assert "gradle" in content.lower()

    def test_build_workflow_uploads_artifact(self):
        content = (PROJECT_ROOT / ".github" / "workflows" / "build-jetbrains.yml").read_text()
        assert "upload-artifact" in content
        assert "stca-intellij-plugin" in content

    def test_build_md_exists(self):
        assert (PROJECT_ROOT / "editor" / "intellij-stca" / "BUILD.md").exists()


# =============================================================================
# 3. 5 new language packs
# =============================================================================

class TestNewV438Packs:
    """v4.38: 5 new packs — Objective-C (30), Groovy (30), Julia (30), Perl (30), COBOL (25)."""

    @pytest.mark.parametrize("pack_name,min_count", [
        ("objectivec-security.yml", 25),
        ("groovy-security.yml", 25),
        ("julia-security.yml", 25),
        ("perl-security.yml", 25),
        ("cobol-security.yml", 20),
    ])
    def test_pack_exists_with_min_rules(self, pack_name: str, min_count: int):
        path = PACKS_DIR / pack_name
        assert path.exists(), f"Pack not found: {path}"
        with open(path) as f:
            data = yaml.safe_load(f)
        rules = data.get("rules", [])
        assert len(rules) >= min_count, (
            f"{pack_name}: expected {min_count}+ rules, got {len(rules)}"
        )

    @pytest.mark.parametrize("pack_name,lang", [
        ("objectivec-security", "objectivec"),
        ("groovy-security", "groovy"),
        ("julia-security", "julia"),
        ("perl-security", "perl"),
        ("cobol-security", "cobol"),
    ])
    def test_pack_registered(self, pack_name: str, lang: str):
        from stca.rules import BUILTIN_PACKS
        assert pack_name in BUILTIN_PACKS
        assert BUILTIN_PACKS[pack_name]["language"] == lang

    def test_objectivec_auto_selection(self):
        from stca.rules import get_all_packs_for_files
        packs = get_all_packs_for_files(["AppDelegate.m"])
        assert any("objectivec-security" in str(p) for p in packs)

    def test_groovy_auto_selection(self):
        from stca.rules import get_all_packs_for_files
        packs = get_all_packs_for_files(["build.gradle"])
        assert any("groovy-security" in str(p) for p in packs)

    def test_julia_auto_selection(self):
        from stca.rules import get_all_packs_for_files
        packs = get_all_packs_for_files(["analysis.jl"])
        assert any("julia-security" in str(p) for p in packs)

    def test_perl_auto_selection(self):
        from stca.rules import get_all_packs_for_files
        packs = get_all_packs_for_files(["script.pl"])
        assert any("perl-security" in str(p) for p in packs)

    def test_cobol_auto_selection(self):
        from stca.rules import get_all_packs_for_files
        packs = get_all_packs_for_files(["PAYROLL.CBL"])
        assert any("cobol-security" in str(p) for p in packs)

    def test_objectivec_has_keychain_rules(self):
        with open(PACKS_DIR / "objectivec-security.yml") as f:
            data = yaml.safe_load(f)
        rule_ids = {r["id"] for r in data["rules"]}
        assert "objc-keychain-hardcoded" in rule_ids
        assert "objc-cc-md5" in rule_ids

    def test_groovy_has_eval_rules(self):
        with open(PACKS_DIR / "groovy-security.yml") as f:
            data = yaml.safe_load(f)
        rule_ids = {r["id"] for r in data["rules"]}
        assert "groovy-eval" in rule_ids
        assert "groovy-gstring-sql" in rule_ids

    def test_perl_has_taint_rules(self):
        with open(PACKS_DIR / "perl-security.yml") as f:
            data = yaml.safe_load(f)
        rule_ids = {r["id"] for r in data["rules"]}
        assert "perl-eval-string" in rule_ids
        assert "perl-2-arg-open" in rule_ids

    def test_cobol_has_hardcoded_rules(self):
        with open(PACKS_DIR / "cobol-security.yml") as f:
            data = yaml.safe_load(f)
        rule_ids = {r["id"] for r in data["rules"]}
        assert "cobol-hardcoded-password" in rule_ids
        assert "cobol-call-system" in rule_ids


# =============================================================================
# 4. Spec mining wired
# =============================================================================

class TestSpecMining:
    """v4.38: spec_mining.py wired into orchestrator + CLI command."""

    def test_spec_command_exists(self):
        from click.testing import CliRunner
        from stca.cli import main
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert "spec" in result.output, "stca spec must appear in main --help"

    def test_spec_has_flags(self):
        from click.testing import CliRunner
        from stca.cli import main
        runner = CliRunner()
        result = runner.invoke(main, ["spec", "--help"])
        assert "--max-files" in result.output
        assert "--check-only" in result.output
        assert "--mine-only" in result.output

    def test_orchestrator_has_spec_mining_method(self):
        from stca.orchestrator import Orchestrator
        assert hasattr(Orchestrator, "_run_spec_mining"), (
            "Orchestrator must have _run_spec_mining method"
        )

    def test_spec_cmd_callback_uses_spec_mining(self):
        import inspect
        import stca.spec_mining_cmd as smc
        src = inspect.getsource(smc.spec_cmd.callback)
        assert "mine_api_patterns" in src
        assert "check_spec_violations" in src


# =============================================================================
# 5. LSP server depth
# =============================================================================

class TestLSPServerDepth:
    """v4.38: LSP server now has real hover + code actions (not stubs)."""

    def test_lsp_has_hover_method(self):
        from stca.lsp.server import LSPServer
        assert hasattr(LSPServer, "_get_hover_info")

    def test_lsp_has_code_actions_method(self):
        from stca.lsp.server import LSPServer
        assert hasattr(LSPServer, "_get_code_actions")

    def test_lsp_has_has_autofix_method(self):
        from stca.lsp.server import LSPServer
        assert hasattr(LSPServer, "_has_autofix")

    def test_lsp_findings_cache_exists(self):
        from stca.lsp.server import LSPServer
        # _findings_cache is a class attribute
        assert hasattr(LSPServer, "_findings_cache")

    def test_hover_returns_none_for_empty_cache(self):
        from stca.lsp.server import LSPServer
        s = LSPServer()
        # Empty cache → no hover
        result = s._get_hover_info({
            "textDocument": {"uri": "file:///test.py"},
            "position": {"line": 0, "character": 0},
        })
        assert result is None

    def test_hover_returns_markdown_for_cached_finding(self):
        from stca.lsp.server import LSPServer
        s = LSPServer()
        # Manually populate cache
        s._findings_cache.clear()
        s._findings_cache["file:///hover_test.py"] = [
            {"rule_id": "L0.sast.mini:py-eval", "line": 1,
             "severity": "high", "message": "eval is bad", "fix": "use ast.literal_eval"}
        ]
        try:
            result = s._get_hover_info({
                "textDocument": {"uri": "file:///hover_test.py"},
                "position": {"line": 0, "character": 0},  # LSP line 0 = file line 1
            })
            assert result is not None
            assert result["contents"]["kind"] == "markdown"
            assert "py-eval" in result["contents"]["value"]
            assert "eval is bad" in result["contents"]["value"]
        finally:
            s._findings_cache.clear()

    def test_code_actions_empty_for_no_findings(self):
        from stca.lsp.server import LSPServer
        s = LSPServer()
        # Use a URI that has no cached findings
        s._findings_cache.clear()
        result = s._get_code_actions({
            "textDocument": {"uri": "file:///empty.py"},
            "range": {"start": {"line": 0}, "end": {"line": 0}},
        })
        assert result == []

    def test_code_actions_returns_quickfix_for_findings(self):
        from stca.lsp.server import LSPServer
        s = LSPServer()
        s._findings_cache.clear()
        s._findings_cache["file:///action_test.py"] = [
            {"rule_id": "L0.sast.mini:py-eval", "line": 1,
             "severity": "high", "message": "eval is bad", "fix": ""}
        ]
        try:
            result = s._get_code_actions({
                "textDocument": {"uri": "file:///action_test.py"},
                "range": {"start": {"line": 0}, "end": {"line": 0}},
            })
            assert len(result) >= 1
            titles = [a["title"] for a in result]
            assert any("STCA" in t for t in titles)
        finally:
            s._findings_cache.clear()

    def test_has_autofix_returns_true_for_known_rule(self):
        from stca.lsp.server import LSPServer
        s = LSPServer()
        # L0.sast.mini:py-eval has an autofix pattern
        assert s._has_autofix("L0.sast.mini:py-eval") is True

    def test_has_autofix_returns_false_for_unknown_rule(self):
        from stca.lsp.server import LSPServer
        s = LSPServer()
        assert s._has_autofix("UNKNOWN.RULE.12345") is False


# =============================================================================
# 6. Total counts
# =============================================================================

class TestTotalCountsV438:
    """v4.38: verify breadth growth continues."""

    def test_yaml_pack_total_1300_plus(self):
        total = 0
        for path in sorted(PACKS_DIR.glob("*.yml")):
            with open(path) as f:
                data = yaml.safe_load(f)
            total += len(data.get("rules", []))
        assert total >= 1300, f"YAML packs total: {total} (expected 1300+)"

    def test_packs_count_35_plus(self):
        packs = list(PACKS_DIR.glob("*.yml"))
        assert len(packs) >= 35, f"Got {len(packs)} packs (expected 35+)"

    def test_languages_supported_25_plus(self):
        """Should support 25+ languages (was 21 in v4.37)."""
        from stca.rules import BUILTIN_PACKS
        langs = set()
        for info in BUILTIN_PACKS.values():
            lang = info.get("language", "")
            for l in lang.split(","):
                l = l.strip()
                if l and l != "rego" and l != "multi":
                    langs.add(l)
        assert len(langs) >= 25, (
            f"Got {len(langs)} languages: {sorted(langs)} (expected 25+)"
        )
