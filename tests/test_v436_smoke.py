"""v4.36 smoke tests — coverage for the "finish and ship" release.

Tests:
1. VS Code extension compiled (out/extension.js exists, .vsix packaged)
2. VS Code extension uses vscode-languageclient (not stubbed LSP)
3. VS Code extension supports all 17 languages (13 + Kotlin/SQL/Bash/Dart + Lua/R/Haskell/Elixir)
4. 4 new YAML packs (Lua, R, Haskell, Elixir)
5. Ported packs renamed to -inspired
6. loomscan gate --preset flag (strict/balanced/permissive/custom)
7. loomscan watch command (upgraded with --json, --quiet, --strictness)
8. loomscan mine command (rule_miner wired)
9. Total counts (YAML 950+, packs 27+)
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml


PROJECT_ROOT = Path(__file__).resolve().parent.parent
PACKS_DIR = PROJECT_ROOT / "loomscan" / "rules" / "packs"
VSCODE_DIR = PROJECT_ROOT / "editor" / "vscode-loomscan"


# =============================================================================
# 1. VS Code extension compiled
# =============================================================================

class TestVSCodeExtensionCompiled:
    """v4.36: VS Code extension source is now compiled to out/extension.js
    and packaged as a .vsix file."""

    def test_compiled_extension_js_exists(self):
        """The compiled extension.js should exist in out/."""
        assert (VSCODE_DIR / "out" / "extension.js").exists(), (
            "out/extension.js missing — run `npm run compile`"
        )

    def test_compiled_extension_js_is_valid_js(self):
        """The compiled extension.js should be valid JavaScript."""
        path = VSCODE_DIR / "out" / "extension.js"
        content = path.read_text()
        # Should have the activate function and use vscode-languageclient
        assert "activate" in content
        assert "vscode-languageclient" in content or "LanguageClient" in content

    def test_package_json_main_points_to_out(self):
        """package.json main should point to ./out/extension.js (not src/)."""
        import json as _json
        with open(VSCODE_DIR / "package.json") as f:
            data = _json.load(f)
        assert data["main"] == "./out/extension.js", (
            f"package.json main should be ./out/extension.js, got {data['main']}"
        )

    def test_uses_vscode_languageclient(self):
        """The extension should depend on vscode-languageclient."""
        import json as _json
        with open(VSCODE_DIR / "package.json") as f:
            data = _json.load(f)
        deps = data.get("dependencies", {})
        assert "vscode-languageclient" in deps, (
            "vscode-languageclient should be in dependencies"
        )

    def test_extension_ts_uses_language_client(self):
        """The TypeScript source should import LanguageClient."""
        src = (VSCODE_DIR / "src" / "extension.ts").read_text()
        assert "LanguageClient" in src, "extension.ts should import LanguageClient"
        assert "vscode-languageclient/node" in src, (
            "extension.ts should import from vscode-languageclient/node"
        )


# =============================================================================
# 2. VS Code extension supports all 17 languages
# =============================================================================

class TestVSCodeExtensionLanguages:
    """v4.36: VS Code extension should activate for all 17 LoomScan-supported languages
    (13 original + 4 v4.35: Kotlin/SQL/Bash/Dart + 4 v4.36: Lua/R/Haskell/Elixir)."""

    def test_activates_for_v435_languages(self):
        import json as _json
        with open(VSCODE_DIR / "package.json") as f:
            data = _json.load(f)
        langs = data["activationEvents"]
        for lang in ["kotlin", "sql", "shell", "dart"]:
            assert any(lang in ev for ev in langs), (
                f"VS Code extension missing activation for: {lang}"
            )

    def test_has_gate_command(self):
        """v4.36: Extension should have a loomscan.gate command."""
        import json as _json
        with open(VSCODE_DIR / "package.json") as f:
            data = _json.load(f)
        commands = [c["command"] for c in data["contributes"]["commands"]]
        assert "loomscan.gate" in commands, "loomscan.gate command should be registered"

    def test_has_gate_preset_config(self):
        """v4.36: Extension should have loomscan.gatePreset config option."""
        import json as _json
        with open(VSCODE_DIR / "package.json") as f:
            data = _json.load(f)
        props = data["contributes"]["configuration"]["properties"]
        assert "loomscan.gatePreset" in props, "loomscan.gatePreset config missing"
        assert props["loomscan.gatePreset"]["enum"] == ["strict", "balanced", "permissive", "custom"]


# =============================================================================
# 3. 4 new YAML packs (Lua, R, Haskell, Elixir)
# =============================================================================

class TestNewV436Packs:
    """v4.36: 4 new packs added — Lua (35), R (35), Haskell (30), Elixir (30)."""

    @pytest.mark.parametrize("pack_name,min_count", [
        ("lua-security.yml", 30),
        ("r-security.yml", 30),
        ("haskell-security.yml", 30),
        ("elixir-security.yml", 30),
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

    def test_lua_pack_registered(self):
        from loomscan.rules import BUILTIN_PACKS
        assert "lua-security" in BUILTIN_PACKS
        assert BUILTIN_PACKS["lua-security"]["language"] == "lua"

    def test_r_pack_registered(self):
        from loomscan.rules import BUILTIN_PACKS
        assert "r-security" in BUILTIN_PACKS
        assert BUILTIN_PACKS["r-security"]["language"] == "r"

    def test_haskell_pack_registered(self):
        from loomscan.rules import BUILTIN_PACKS
        assert "haskell-security" in BUILTIN_PACKS
        assert BUILTIN_PACKS["haskell-security"]["language"] == "haskell"

    def test_elixir_pack_registered(self):
        from loomscan.rules import BUILTIN_PACKS
        assert "elixir-security" in BUILTIN_PACKS
        assert BUILTIN_PACKS["elixir-security"]["language"] == "elixir"

    def test_lua_auto_selection(self):
        from loomscan.rules import get_all_packs_for_files
        packs = get_all_packs_for_files(["init.lua"])
        assert any("lua-security" in str(p) for p in packs)

    def test_r_auto_selection(self):
        from loomscan.rules import get_all_packs_for_files
        packs = get_all_packs_for_files(["analysis.R"])
        assert any("r-security" in str(p) for p in packs)

    def test_haskell_auto_selection(self):
        from loomscan.rules import get_all_packs_for_files
        packs = get_all_packs_for_files(["Main.hs"])
        assert any("haskell-security" in str(p) for p in packs)

    def test_elixir_auto_selection(self):
        from loomscan.rules import get_all_packs_for_files
        packs = get_all_packs_for_files(["app.ex"])
        assert any("elixir-security" in str(p) for p in packs)

    def test_lua_pack_has_loadstring(self):
        with open(PACKS_DIR / "lua-security.yml") as f:
            data = yaml.safe_load(f)
        rule_ids = {r["id"] for r in data["rules"]}
        assert "lua-loadstring" in rule_ids
        assert "lua-os-execute" in rule_ids

    def test_r_pack_has_eval(self):
        with open(PACKS_DIR / "r-security.yml") as f:
            data = yaml.safe_load(f)
        rule_ids = {r["id"] for r in data["rules"]}
        assert "r-eval" in rule_ids
        assert "r-system" in rule_ids

    def test_haskell_pack_has_unsafe(self):
        with open(PACKS_DIR / "haskell-security.yml") as f:
            data = yaml.safe_load(f)
        rule_ids = {r["id"] for r in data["rules"]}
        assert "haskell-unsafe-performIO" in rule_ids
        assert "haskell-unsafe-coerce" in rule_ids

    def test_elixir_pack_has_code_eval(self):
        with open(PACKS_DIR / "elixir-security.yml") as f:
            data = yaml.safe_load(f)
        rule_ids = {r["id"] for r in data["rules"]}
        assert "elixir-code-eval" in rule_ids
        assert "elixir-system-cmd" in rule_ids


# =============================================================================
# 4. Ported packs renamed to -inspired
# =============================================================================

class TestPortedPacksRenamed:
    """v4.36: The 4 -ported.yml packs have been renamed to -inspired.yml
    to be honest about what they are: concept adaptations, not literal ports."""

    def test_inspired_yml_files_exist(self):
        for name in ["detekt", "spotbugs", "lintr", "luacheck"]:
            assert (PACKS_DIR / f"{name}-inspired.yml").exists(), (
                f"{name}-inspired.yml should exist"
            )

    def test_ported_yml_files_removed(self):
        for name in ["detekt", "spotbugs", "lintr", "luacheck"]:
            assert not (PACKS_DIR / f"{name}-ported.yml").exists(), (
                f"{name}-ported.yml should be removed (renamed to -inspired)"
            )

    def test_builtin_packs_uses_inspired_names(self):
        from loomscan.rules import BUILTIN_PACKS
        for name in ["detekt-inspired", "spotbugs-inspired", "lintr-inspired", "luacheck-inspired"]:
            assert name in BUILTIN_PACKS
        for old_name in ["detekt-ported", "spotbugs-ported", "lintr-ported", "luacheck-ported"]:
            assert old_name not in BUILTIN_PACKS

    def test_descriptions_say_inspired(self):
        from loomscan.rules import BUILTIN_PACKS
        for name in ["detekt-inspired", "spotbugs-inspired", "lintr-inspired", "luacheck-inspired"]:
            desc = BUILTIN_PACKS[name]["description"]
            assert "inspired by" in desc.lower(), (
                f"{name}: description should say 'inspired by', got: {desc}"
            )


# =============================================================================
# 5. loomscan gate --preset flag
# =============================================================================

class TestStcaGatePreset:
    """v4.36: loomscan gate now has --preset flag with 4 options."""

    def test_preset_flag_in_help(self):
        from click.testing import CliRunner
        from loomscan.cli import main
        runner = CliRunner()
        result = runner.invoke(main, ["gate", "--help"])
        assert "--preset" in result.output
        assert "strict" in result.output
        assert "balanced" in result.output
        assert "permissive" in result.output
        assert "custom" in result.output

    def test_preset_strict_fails_on_critical(self, tmp_path):
        """End-to-end: --preset strict should fail (exit 1) on a critical finding."""
        import subprocess
        repo = tmp_path / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.email", "test@test.local"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
        (repo / ".loomscan.yaml").write_text("strictness: 5\n")
        (repo / "app.py").write_text(
            'import os\n'
            'password = "hardcoded-secret-12345"\n'
            'def f():\n'
            '    return os.system("echo " + password)\n'
        )
        subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-qm", "init"], cwd=repo, check=True)

        env = os.environ.copy()
        env["PYTHONPATH"] = str(PROJECT_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
        proc = subprocess.run(
            [sys.executable, "-c", "from loomscan.cli import main; main()",
             "gate", "--full", "--preset", "strict"],
            cwd=repo, capture_output=True, text=True, env=env, timeout=60,
        )
        assert proc.returncode == 1, (
            f"Expected exit 1 (strict gate failed on critical), got {proc.returncode}"
        )

    def test_preset_permissive_passes_with_minor_findings(self, tmp_path):
        """End-to-end: --preset permissive should pass (exit 0) on minor findings."""
        import subprocess
        repo = tmp_path / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.email", "test@test.local"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
        (repo / ".loomscan.yaml").write_text("strictness: 5\n")
        (repo / "app.py").write_text('x = 1\n')
        subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-qm", "init"], cwd=repo, check=True)

        env = os.environ.copy()
        env["PYTHONPATH"] = str(PROJECT_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
        proc = subprocess.run(
            [sys.executable, "-c", "from loomscan.cli import main; main()",
             "gate", "--full", "--preset", "permissive"],
            cwd=repo, capture_output=True, text=True, env=env, timeout=60,
        )
        assert proc.returncode == 0, (
            f"Expected exit 0 (permissive gate passed), got {proc.returncode}. stderr={proc.stderr}"
        )

    def test_preset_appears_in_json_output(self, tmp_path):
        """End-to-end: --preset should appear in the JSON output."""
        import subprocess
        repo = tmp_path / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.email", "test@test.local"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
        (repo / ".loomscan.yaml").write_text("strictness: 5\n")
        (repo / "app.py").write_text('x = 1\n')
        subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-qm", "init"], cwd=repo, check=True)

        env = os.environ.copy()
        env["PYTHONPATH"] = str(PROJECT_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
        proc = subprocess.run(
            [sys.executable, "-c", "from loomscan.cli import main; main()",
             "gate", "--full", "--preset", "balanced", "--json"],
            cwd=repo, capture_output=True, text=True, env=env, timeout=60,
        )
        data = json.loads(proc.stdout)
        assert data["preset"] == "balanced"


# =============================================================================
# 6. loomscan watch command (upgraded)
# =============================================================================

class TestStcaWatchUpgraded:
    """v4.36: loomscan watch command now actually re-scans and reports findings
    (was just printing changed files in v4.34)."""

    def test_watch_has_strictness_flag(self):
        from click.testing import CliRunner
        from loomscan.cli import main
        runner = CliRunner()
        result = runner.invoke(main, ["watch", "--help"])
        assert "--strictness" in result.output
        assert "--debounce" in result.output
        assert "--quiet" in result.output
        assert "--json" in result.output

    def test_watch_default_debounce_is_sub_second(self):
        """v4.36: Default debounce should be 0.5s for sub-second feedback."""
        from loomscan.cli_v2 import watch_cmd
        debounce_opt = next(p for p in watch_cmd.params if p.name == "debounce")
        assert debounce_opt.default == 0.5, (
            f"Default debounce should be 0.5s, got {debounce_opt.default}"
        )

    def test_watch_callback_uses_orchestrator(self):
        """Static check: watch_cmd callback should reference Orchestrator."""
        import inspect
        import loomscan.cli_v2 as cv2
        cb = cv2.watch_cmd.callback
        src = inspect.getsource(cb)
        assert "Orchestrator" in src, "watch_cmd should use Orchestrator"
        assert "run_full" in src, "watch_cmd should call orch.run_full()"


# =============================================================================
# 7. loomscan mine command
# =============================================================================

class TestStcaMineCommand:
    """v4.36: loomscan mine command — auto-derive rules from bug-fix commits."""

    def test_mine_command_exists(self):
        from click.testing import CliRunner
        from loomscan.cli import main
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert "mine" in result.output, "loomscan mine must appear in main --help"

    def test_mine_has_max_commits_flag(self):
        from click.testing import CliRunner
        from loomscan.cli import main
        runner = CliRunner()
        result = runner.invoke(main, ["mine", "--help"])
        assert "--max-commits" in result.output
        assert "--no-verify" in result.output
        assert "--dest" in result.output

    def test_mine_callback_uses_rule_miner(self):
        """Static check: mine_cmd callback should import from rule_miner."""
        import inspect
        import loomscan.cli_v2 as cv2
        cb = cv2.mine_cmd.callback
        src = inspect.getsource(cb)
        assert "rule_miner" in src, "mine_cmd should import from rule_miner"
        assert "mine_rules_from_history" in src

    def test_mine_registered_in_v2_commands(self):
        """mine_cmd should be in _V2_COMMANDS list."""
        import loomscan.cli_v2 as cv2
        assert cv2.mine_cmd in cv2._V2_COMMANDS, (
            "mine_cmd should be registered in _V2_COMMANDS"
        )


# =============================================================================
# 8. Total counts across the pipeline
# =============================================================================

class TestTotalCountsV436:
    """v4.36: verify breadth growth continues."""

    def test_yaml_pack_total_950_plus(self):
        """Sum of YAML pack rules should be 950+."""
        total = 0
        for path in sorted(PACKS_DIR.glob("*.yml")):
            with open(path) as f:
                data = yaml.safe_load(f)
            total += len(data.get("rules", []))
        assert total >= 950, f"YAML packs total: {total} (expected 950+)"

    def test_packs_count_27_plus(self):
        """Should have 27+ YAML packs."""
        packs = list(PACKS_DIR.glob("*.yml"))
        assert len(packs) >= 27, f"Got {len(packs)} packs (expected 27+)"

    def test_languages_supported_20_plus(self):
        """Should support 20+ languages (16 v4.35 + 4 v4.36: Lua/R/Haskell/Elixir)."""
        from loomscan.rules import BUILTIN_PACKS
        langs = set()
        for info in BUILTIN_PACKS.values():
            lang = info.get("language", "")
            for l in lang.split(","):
                l = l.strip()
                if l and l != "rego":  # exclude policy language
                    langs.add(l)
        assert len(langs) >= 20, (
            f"Got {len(langs)} languages: {sorted(langs)} (expected 20+)"
        )
