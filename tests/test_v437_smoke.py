"""v4.37 smoke tests — coverage for the "finish and ship (part 2)" release.

Tests:
1. JetBrains extension structure (plugin.xml, Kotlin sources, settings, actions)
2. 3 new YAML packs (owasp-top-10, sql-stored-procedures, bash-deep)
3. Monorepo support (config workspaces, resolve_workspaces, stca monorepo command)
4. PR comment bot (stca bot command, GitHub Actions workflow)
5. Online rule playground (stca playground command, match-finding logic, HTTP server)
6. Total counts (YAML 1150+, packs 30+)
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
import yaml


PROJECT_ROOT = Path(__file__).resolve().parent.parent
PACKS_DIR = PROJECT_ROOT / "stca" / "rules" / "packs"
INTELLIJ_DIR = PROJECT_ROOT / "editor" / "intellij-stca"
WORKFLOWS_DIR = PROJECT_ROOT / ".github" / "workflows"


# =============================================================================
# 1. JetBrains extension structure
# =============================================================================

class TestJetBrainsExtension:
    """v4.37: IntelliJ/JetBrains extension at editor/intellij-stca/."""

    def test_plugin_xml_exists(self):
        assert (INTELLIJ_DIR / "src" / "main" / "resources" / "META-INF" / "plugin.xml").exists()

    def test_plugin_xml_has_id(self):
        content = (INTELLIJ_DIR / "src" / "main" / "resources" / "META-INF" / "plugin.xml").read_text()
        assert "com.stca.pipeline.intellij" in content
        assert "STCA Pipeline" in content

    def test_plugin_xml_has_lsp_support(self):
        content = (INTELLIJ_DIR / "src" / "main" / "resources" / "META-INF" / "plugin.xml").read_text()
        assert "platform.lsp.serverSupport" in content
        assert "StcaLspServerSupport" in content

    def test_plugin_xml_has_actions(self):
        content = (INTELLIJ_DIR / "src" / "main" / "resources" / "META-INF" / "plugin.xml").read_text()
        for action_id in ["Stca.CheckRepo", "Stca.Gate", "Stca.Mine", "Stca.Restart"]:
            assert action_id in content, f"Action {action_id} missing in plugin.xml"

    def test_plugin_xml_has_tool_window(self):
        content = (INTELLIJ_DIR / "src" / "main" / "resources" / "META-INF" / "plugin.xml").read_text()
        assert "StcaToolWindowFactory" in content
        assert "toolWindow" in content

    def test_plugin_xml_has_settings(self):
        content = (INTELLIJ_DIR / "src" / "main" / "resources" / "META-INF" / "plugin.xml").read_text()
        assert "StcaSettingsConfigurable" in content
        assert "applicationConfigurable" in content

    def test_kotlin_sources_exist(self):
        kotlin_dir = INTELLIJ_DIR / "src" / "main" / "kotlin" / "com" / "stca" / "pipeline"
        assert (kotlin_dir / "lsp" / "StcaLspServerSupport.kt").exists()
        assert (kotlin_dir / "action" / "StcaActions.kt").exists()
        assert (kotlin_dir / "settings" / "StcaSettingsService.kt").exists()
        assert (kotlin_dir / "settings" / "StcaSettingsConfigurable.kt").exists()

    def test_kotlin_lsp_support_class(self):
        content = (INTELLIJ_DIR / "src" / "main" / "kotlin" / "com" / "stca" / "pipeline" / "lsp" / "StcaLspServerSupport.kt").read_text()
        assert "class StcaLspServerSupport" in content
        assert "LspServerSupportProvider" in content
        assert "stca.cli import main" in content or "from stca.cli import main" in content

    def test_kotlin_actions_class(self):
        content = (INTELLIJ_DIR / "src" / "main" / "kotlin" / "com" / "stca" / "pipeline" / "action" / "StcaActions.kt").read_text()
        assert "class CheckRepoAction" in content
        assert "class GateAction" in content
        assert "class MineAction" in content
        assert "class RestartAction" in content

    def test_kotlin_settings_supports_all_options(self):
        content = (INTELLIJ_DIR / "src" / "main" / "kotlin" / "com" / "stca" / "pipeline" / "settings" / "StcaSettingsService.kt").read_text()
        for setting in ["stcaEnabled", "pythonPath", "strictness", "gatePreset", "useLsp"]:
            assert setting in content, f"Setting {setting} missing in StcaSettingsService"

    def test_gradle_build_file(self):
        assert (INTELLIJ_DIR / "build.gradle.kts").exists()
        content = (INTELLIJ_DIR / "build.gradle.kts").read_text()
        assert "org.jetbrains.intellij" in content
        assert "org.jetbrains.kotlin.jvm" in content

    def test_readme_exists(self):
        assert (INTELLIJ_DIR / "README.md").exists()

    def test_supports_all_stca_languages(self):
        """The LSP support should list all 20+ STCA-supported languages."""
        content = (INTELLIJ_DIR / "src" / "main" / "kotlin" / "com" / "stca" / "pipeline" / "lsp" / "StcaLspServerSupport.kt").read_text()
        # Check a representative sample
        for ext in ["py", "js", "ts", "go", "java", "rs", "php", "rb", "cs",
                     "swift", "scala", "kt", "sql", "sh", "dart", "lua", "r", "hs", "ex"]:
            assert f'"{ext}"' in content, f"Extension {ext} not supported in LSP"


# =============================================================================
# 2. 3 new YAML packs
# =============================================================================

class TestNewV437Packs:
    """v4.37: 3 new packs — OWASP Top 10 (124), SQL Stored Procs (40), Bash Deep (41)."""

    @pytest.mark.parametrize("pack_name,min_count", [
        ("owasp-top-10.yml", 100),
        ("sql-stored-procedures.yml", 30),
        ("bash-deep.yml", 30),
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

    def test_owasp_pack_registered(self):
        from stca.rules import BUILTIN_PACKS
        assert "owasp-top-10" in BUILTIN_PACKS
        assert BUILTIN_PACKS["owasp-top-10"]["language"] == "multi"

    def test_sql_sp_pack_registered(self):
        from stca.rules import BUILTIN_PACKS
        assert "sql-stored-procedures" in BUILTIN_PACKS

    def test_bash_deep_pack_registered(self):
        from stca.rules import BUILTIN_PACKS
        assert "bash-deep" in BUILTIN_PACKS

    def test_owasp_auto_selected_always(self):
        """OWASP Top 10 is multi-language — should be selected for any file."""
        from stca.rules import get_all_packs_for_files
        for ext in [".py", ".js", ".go", ".java", ".rs", ".php", ".rb", ".cs"]:
            packs = get_all_packs_for_files([f"file{ext}"])
            assert any("owasp-top-10" in str(p) for p in packs), (
                f"OWASP pack not selected for {ext}"
            )

    def test_sql_sp_auto_selected_for_sql(self):
        from stca.rules import get_all_packs_for_files
        packs = get_all_packs_for_files(["procedure.sql"])
        assert any("sql-stored-procedures" in str(p) for p in packs)

    def test_bash_deep_auto_selected_for_sh(self):
        from stca.rules import get_all_packs_for_files
        packs = get_all_packs_for_files(["deploy.sh"])
        assert any("bash-deep" in str(p) for p in packs)

    def test_owasp_pack_has_a01_rules(self):
        with open(PACKS_DIR / "owasp-top-10.yml") as f:
            data = yaml.safe_load(f)
        rule_ids = {r["id"] for r in data["rules"]}
        assert any("owasp-a01" in r for r in rule_ids)
        assert any("owasp-a02" in r for r in rule_ids)
        assert any("owasp-a03" in r for r in rule_ids)

    def test_owasp_pack_has_cwe_rules(self):
        with open(PACKS_DIR / "owasp-top-10.yml") as f:
            data = yaml.safe_load(f)
        rule_ids = {r["id"] for r in data["rules"]}
        assert "cwe-89-sql-injection" in rule_ids
        assert "cwe-502-deserialization" in rule_ids
        assert "cwe-918-ssrf" in rule_ids

    def test_sql_sp_pack_has_dynamic_sql(self):
        with open(PACKS_DIR / "sql-stored-procedures.yml") as f:
            data = yaml.safe_load(f)
        rule_ids = {r["id"] for r in data["rules"]}
        assert "sqlsp-exec-dynamic-sql" in rule_ids
        assert "sqlsp-sp-executesql-no-params" in rule_ids

    def test_sql_sp_pack_has_sp_configure(self):
        with open(PACKS_DIR / "sql-stored-procedures.yml") as f:
            data = yaml.safe_load(f)
        rule_ids = {r["id"] for r in data["rules"]}
        assert "sqlsp-sp-allow-xp-cmdshell" in rule_ids
        assert "sqlsp-sp-allow-clr" in rule_ids

    def test_bash_deep_has_ifs_injection(self):
        with open(PACKS_DIR / "bash-deep.yml") as f:
            data = yaml.safe_load(f)
        rule_ids = {r["id"] for r in data["rules"]}
        assert "bash-ifs-injection" in rule_ids
        assert "bash-printf-format-string" in rule_ids
        assert "bash-ssh-known-hosts-disable" in rule_ids


# =============================================================================
# 3. Monorepo support
# =============================================================================

class TestMonorepoSupport:
    """v4.37: Monorepo support — config.workspaces, resolve_workspaces, stca monorepo command."""

    def test_config_has_workspaces_field(self):
        from stca.config import STCAConfig
        cfg = STCAConfig.default()
        assert hasattr(cfg, "workspaces")
        assert cfg.workspaces == []  # default empty

    def test_config_has_workspace_exclude(self):
        from stca.config import STCAConfig
        cfg = STCAConfig.default()
        assert hasattr(cfg, "workspace_exclude")
        assert "**/node_modules/**" in cfg.workspace_exclude

    def test_resolve_workspaces_default(self, tmp_path):
        """With no workspaces configured, returns [repo_root]."""
        from stca.config import STCAConfig
        cfg = STCAConfig.default()
        resolved = cfg.resolve_workspaces(tmp_path)
        assert resolved == [tmp_path]

    def test_resolve_workspaces_with_patterns(self, tmp_path):
        """Resolve glob patterns to actual directories."""
        from stca.config import STCAConfig
        (tmp_path / "apps" / "api").mkdir(parents=True)
        (tmp_path / "apps" / "web").mkdir(parents=True)
        (tmp_path / "packages" / "core").mkdir(parents=True)
        (tmp_path / "node_modules").mkdir()

        cfg = STCAConfig.default()
        cfg.workspaces = ["apps/*", "packages/*"]
        resolved = cfg.resolve_workspaces(tmp_path)
        rel_paths = sorted([p.relative_to(tmp_path).as_posix() for p in resolved])
        assert rel_paths == ["apps/api", "apps/web", "packages/core"]

    def test_resolve_workspaces_excludes_node_modules(self, tmp_path):
        from stca.config import STCAConfig
        (tmp_path / "apps" / "api").mkdir(parents=True)
        (tmp_path / "apps" / "node_modules").mkdir(parents=True)

        cfg = STCAConfig.default()
        cfg.workspaces = ["apps/*"]
        resolved = cfg.resolve_workspaces(tmp_path)
        rel_paths = [p.relative_to(tmp_path).as_posix() for p in resolved]
        assert "apps/api" in rel_paths
        assert "apps/node_modules" not in rel_paths

    def test_workspaces_round_trip_through_yaml(self, tmp_path):
        from stca.config import STCAConfig
        cfg = STCAConfig.default()
        cfg.workspaces = ["apps/*", "packages/*"]
        cfg.workspace_exclude = ["**/build/**"]
        cfg_path = tmp_path / ".stca.yaml"
        cfg.save(cfg_path)

        loaded = STCAConfig.from_file(cfg_path)
        assert loaded.workspaces == ["apps/*", "packages/*"]
        assert "**/build/**" in loaded.workspace_exclude

    def test_stca_monorepo_command_exists(self):
        from click.testing import CliRunner
        from stca.cli import main
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert "monorepo" in result.output

    def test_stca_monorepo_list_no_workspaces(self, tmp_path):
        """`stca monorepo --list` with no workspaces should report single-repo mode."""
        import subprocess
        repo = tmp_path / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.email", "test@test.local"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
        (repo / ".stca.yaml").write_text("strictness: 5\n")
        (repo / "app.py").write_text('x = 1\n')
        subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-qm", "init"], cwd=repo, check=True)

        env = os.environ.copy()
        env["PYTHONPATH"] = str(PROJECT_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
        proc = subprocess.run(
            [sys.executable, "-c", "from stca.cli import main; main()",
             "monorepo", "--list"],
            cwd=repo, capture_output=True, text=True, env=env, timeout=30,
        )
        assert "No workspaces configured" in proc.stdout or "single-repo mode" in proc.stdout


# =============================================================================
# 4. PR comment bot
# =============================================================================

class TestPrBot:
    """v4.37: stca bot command + GitHub Actions workflow."""

    def test_bot_command_exists(self):
        from click.testing import CliRunner
        from stca.cli import main
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert "bot" in result.output

    def test_bot_has_pr_flag(self):
        from click.testing import CliRunner
        from stca.cli import main
        runner = CliRunner()
        result = runner.invoke(main, ["bot", "--help"])
        assert "--pr" in result.output
        assert "--token" in result.output
        assert "--dry-run" in result.output

    def test_bot_dry_run_works(self, tmp_path):
        """`stca bot --dry-run` should print findings without posting."""
        import subprocess
        repo = tmp_path / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.email", "test@test.local"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
        (repo / ".stca.yaml").write_text("strictness: 5\n")
        (repo / "app.py").write_text('import os\npassword = "hardcoded-secret-12345"\n')
        subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-qm", "init"], cwd=repo, check=True)

        env = os.environ.copy()
        env["PYTHONPATH"] = str(PROJECT_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
        proc = subprocess.run(
            [sys.executable, "-c", "from stca.cli import main; main()",
             "bot", "--repo", str(repo), "--pr", "1", "--dry-run"],
            cwd=repo, capture_output=True, text=True, env=env, timeout=120,
        )
        # Should print findings without crashing
        assert "Dry run" in proc.stdout or "would post" in proc.stdout.lower() or "STCA bot" in proc.stdout

    def test_github_workflow_exists(self):
        assert (WORKFLOWS_DIR / "stca-bot.yml").exists()

    def test_github_workflow_runs_on_pr(self):
        content = (WORKFLOWS_DIR / "stca-bot.yml").read_text()
        assert "pull_request" in content
        assert "stca bot" in content
        assert "GITHUB_TOKEN" in content

    def test_bot_module_imports(self):
        from stca.bot import run_stca_check, post_pr_review, parse_pr_event, Finding
        assert Finding is not None


# =============================================================================
# 5. Online rule playground
# =============================================================================

class TestPlayground:
    """v4.37: stca playground command — web UI for testing rules."""

    def test_playground_command_exists(self):
        from click.testing import CliRunner
        from stca.cli import main
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert "playground" in result.output

    def test_playground_has_port_flag(self):
        from click.testing import CliRunner
        from stca.cli import main
        runner = CliRunner()
        result = runner.invoke(main, ["playground", "--help"])
        assert "--port" in result.output
        assert "--host" in result.output
        assert "--no-browser" in result.output

    def test_find_matches_basic(self):
        from stca.playground import find_matches
        matches = find_matches(r"\beval\s*\(", "x = eval('1+1')\ny = 1\nz = eval(input())")
        assert len(matches) == 2
        assert matches[0][0] == 1  # line 1
        assert matches[1][0] == 3  # line 3

    def test_find_matches_invalid_regex(self):
        from stca.playground import find_matches
        with pytest.raises(ValueError, match="Invalid regex"):
            find_matches(r"[unclosed", "test")

    def test_find_matches_no_matches(self):
        from stca.playground import find_matches
        matches = find_matches(r"\beval\s*\(", "x = 1\ny = 2")
        assert matches == []

    def test_playground_http_server(self):
        """End-to-end: start the playground server, GET /, POST /test."""
        from stca.playground import HTTPServer, PlaygroundHandler
        import urllib.request
        import urllib.parse

        server = HTTPServer(("localhost", 8770), PlaygroundHandler)
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        time.sleep(0.2)

        try:
            # GET /
            resp = urllib.request.urlopen("http://localhost:8770/")
            html_content = resp.read().decode()
            assert "STCA Rule Playground" in html_content

            # POST /test with a pattern that matches
            data = urllib.parse.urlencode({
                "pattern": r"\beval\s*\(",
                "code": "x = eval(input())",
                "severity": "critical",
                "rule_id": "test-eval",
                "message": "eval is bad",
                "cwe": "CWE-95",
            }).encode()
            resp = urllib.request.urlopen("http://localhost:8770/test", data=data)
            html_content = resp.read().decode()
            assert "1 match(es) found" in html_content
            assert "test-eval" in html_content
            assert "CWE-95" in html_content
        finally:
            server.shutdown()

    def test_playground_invalid_pattern_shows_error(self):
        """POST with an invalid regex should show an error message, not crash."""
        from stca.playground import HTTPServer, PlaygroundHandler
        import urllib.request
        import urllib.parse

        server = HTTPServer(("localhost", 8771), PlaygroundHandler)
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        time.sleep(0.2)

        try:
            data = urllib.parse.urlencode({
                "pattern": r"[unclosed",
                "code": "test",
                "severity": "medium",
                "rule_id": "test",
                "message": "",
                "cwe": "",
            }).encode()
            resp = urllib.request.urlopen("http://localhost:8771/test", data=data)
            html_content = resp.read().decode()
            assert "Invalid regex" in html_content or "error" in html_content.lower()
        finally:
            server.shutdown()


# =============================================================================
# 6. Total counts
# =============================================================================

class TestTotalCountsV437:
    """v4.37: verify breadth growth continues."""

    def test_yaml_pack_total_1150_plus(self):
        """Sum of YAML pack rules should be 1150+."""
        total = 0
        for path in sorted(PACKS_DIR.glob("*.yml")):
            with open(path) as f:
                data = yaml.safe_load(f)
            total += len(data.get("rules", []))
        assert total >= 1150, f"YAML packs total: {total} (expected 1150+)"

    def test_packs_count_30_plus(self):
        """Should have 30+ YAML packs."""
        packs = list(PACKS_DIR.glob("*.yml"))
        assert len(packs) >= 30, f"Got {len(packs)} packs (expected 30+)"

    def test_owasp_pack_has_100_plus(self):
        """OWASP Top 10 pack should have 100+ rules (it has 124)."""
        with open(PACKS_DIR / "owasp-top-10.yml") as f:
            data = yaml.safe_load(f)
        assert len(data["rules"]) >= 100
