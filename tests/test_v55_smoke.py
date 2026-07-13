"""v5.5 smoke tests — Critical YAML wiring fix + cleanup + Rust core.

Tests:
1. CRITICAL: YAML rules fire in default scan path (the _scan_sast wiring fix)
2. Flask XSS rule fires in full scan
3. README says v5.4+ (not v5.0)
4. .gitignore has correct paths (no .editor/)
5. Stale .stca files removed
6. Rust core source exists
7. Version is v5.5
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _run_cli(repo_root: Path, *args: str, timeout: int = 180):
    env = os.environ.copy()
    env["PYTHONPATH"] = str(PROJECT_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run(
        [sys.executable, "-c", "from loomscan.cli import main; main()", *args],
        cwd=repo_root, capture_output=True, text=True, env=env, timeout=timeout,
    )
    return proc.stdout, proc.stderr, proc.returncode


# =============================================================================
# 1. CRITICAL: YAML rules fire in default scan
# =============================================================================

class TestYamlRulesFireInDefaultScan:
    """v5.5: THE critical fix — _scan_sast now always calls _semgrep,
    which handles the native YAML fallback. YAML rules fire in default scan."""

    def test_yaml_findings_in_default_scan(self, tmp_path):
        """stca check --full --json should produce L0.yaml: findings."""
        repo = tmp_path / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.email", "t@test"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.name", "T"], cwd=repo, check=True)
        (repo / ".loomscan.yaml").write_text("strictness: 5\n")
        (repo / "app.py").write_text(
            "from flask import render_template_string, request\n"
            "def page():\n"
            "    return render_template_string(request.args.get('name'))\n"
        )
        subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-qm", "init"], cwd=repo, check=True)

        stdout, stderr, rc = _run_cli(repo, "check", "--full", "--json")
        assert "Traceback" not in stderr, f"Scan crashed. stderr: {stderr[:500]}"

        data = json.loads(stdout)
        yaml_findings = [f for f in data.get("findings", [])
                        if "yaml:" in f.get("rule_id", "")]
        assert len(yaml_findings) > 0, (
            "YAML findings should fire in default scan. "
            "If 0, the _scan_sast → _semgrep wiring is broken."
        )

    def test_flask_xss_rule_fires_in_scan(self, tmp_path):
        """The Flask XSS rule (flask-xss-render-template-string-user) should fire."""
        repo = tmp_path / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.email", "t@test"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.name", "T"], cwd=repo, check=True)
        (repo / ".loomscan.yaml").write_text("strictness: 5\n")
        (repo / "app.py").write_text(
            "from flask import render_template_string, request\n"
            "def page():\n"
            "    return render_template_string(request.args.get('name'))\n"
        )
        subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-qm", "init"], cwd=repo, check=True)

        stdout, stderr, rc = _run_cli(repo, "check", "--full", "--json")
        data = json.loads(stdout)
        flask_findings = [f for f in data.get("findings", [])
                         if "flask" in f.get("rule_id", "").lower()
                         or "render_template" in f.get("message", "").lower()]
        assert len(flask_findings) > 0, (
            "Flask XSS rule should fire on render_template_string(request.args). "
            f"Findings: {[f['rule_id'] for f in data.get('findings', [])[:10]]}"
        )

    def test_scan_sast_always_calls_semgrep(self):
        """Static check: _scan_sast should call _semgrep unconditionally."""
        import inspect
        from loomscan.layers.l0_fast import L0Fast
        src = inspect.getsource(L0Fast._scan_sast)
        assert "_semgrep" in src, "_scan_sast should call _semgrep"
        # Should NOT have the old conditional check
        assert "if self.is_tool_available" not in src or "is_tool_available" not in src.split("return")[0], (
            "_scan_sast should NOT conditionally check semgrep (always call _semgrep)"
        )


# =============================================================================
# 2. README and .gitignore fixes
# =============================================================================

class TestDocAndGitignoreFixes:
    """v5.5: README says v5.4+, .gitignore has correct paths."""

    def test_readme_says_v5_4_or_later(self):
        content = (PROJECT_ROOT / "README.md").read_text()
        assert "v5.4" in content or "v5.5" in content, (
            "README should mention v5.4 or v5.5 (was v5.0)"
        )

    def test_readme_says_loomscan(self):
        content = (PROJECT_ROOT / "README.md").read_text()
        assert "LoomScan" in content

    def test_gitignore_no_dot_editor(self):
        content = (PROJECT_ROOT / ".gitignore").read_text()
        assert ".editor/" not in content, (
            ".gitignore should not have .editor/ paths (should be editor/)"
        )

    def test_gitignore_has_stca_stale_files(self):
        content = (PROJECT_ROOT / ".gitignore").read_text()
        assert ".stca-audit.log" in content
        assert ".stca-issues.db" in content


# =============================================================================
# 3. Rust core exists
# =============================================================================

class TestRustCore:
    """v5.5: Rust core regex engine source exists."""

    def test_cargo_toml_exists(self):
        assert (PROJECT_ROOT / "rust-core" / "Cargo.toml").exists()

    def test_lib_rs_exists(self):
        assert (PROJECT_ROOT / "rust-core" / "src" / "lib.rs").exists()

    def test_lib_rs_has_regex_engine(self):
        content = (PROJECT_ROOT / "rust-core" / "src" / "lib.rs").read_text()
        assert "struct RegexEngine" in content
        assert "fn scan" in content
        assert "rayon" in content  # parallel scanning

    def test_readme_exists(self):
        assert (PROJECT_ROOT / "rust-core" / "README.md").exists()


# =============================================================================
# 4. Version
# =============================================================================

class TestVersionV55:
    def test_version_is_5_5(self):
        from loomscan import __version__
        major, minor = int(__version__.split(".")[0]), int(__version__.split(".")[1])
        assert major >= 5 and minor >= 5, f"Expected >= 5.5.0, got {__version__}"

    def test_pyproject_matches(self):
        from loomscan import __version__
        import re as _re
        content = (PROJECT_ROOT / "pyproject.toml").read_text()
        m = _re.search(r'^version\s*=\s*["\']([^"\']+)["\']', content, _re.MULTILINE)
        assert m
        assert m.group(1) == __version__
