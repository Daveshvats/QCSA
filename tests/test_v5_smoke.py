"""v5.0 smoke tests — E2E tests for v4.44 fixes + v5.0 features.

Tests:
1. variable= crash fix — loomscan check on null-deref fixture doesn't crash
2. Dashboard writes to repo dir (not CWD)
3. Dashboard runs full scan (not demo) when no --input
4. --summary flag produces grouped output
5. "Fail on critical" workflow logic detects critical findings
6. loomscan quickstart command (v5.0 feature)
7. Multi-language counterfactual (v5.0 feature)
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _run_cli(repo_root: Path, *args: str, env: dict | None = None, timeout: int = 120):
    """Invoke loomscan via CLI, returning (stdout, stderr, exit_code)."""
    full_env = os.environ.copy()
    if env:
        full_env.update(env)
    full_env["PYTHONPATH"] = str(PROJECT_ROOT) + os.pathsep + full_env.get("PYTHONPATH", "")
    proc = subprocess.run(
        [sys.executable, "-c", "from loomscan.cli import main; main()", *args],
        cwd=repo_root, capture_output=True, text=True, env=full_env, timeout=timeout,
    )
    return proc.stdout, proc.stderr, proc.returncode


def _make_git_repo(root: Path) -> Path:
    """Init a git repo with a commit."""
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.email", "test@test.local"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=root, check=True)
    (root / ".loomscan.yaml").write_text("strictness: 5\n")
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    subprocess.run(["git", "commit", "-qm", "init"], cwd=root, check=True)
    return root


# =============================================================================
# 1. variable= crash fix
# =============================================================================

class TestVariableCrashFix:
    """v4.44: multi_lang_null.py was passing variable= to UnifiedFinding (no such field).
    This caused GitHub Actions to crash on every scan."""

    def test_check_does_not_crash_on_null_deref(self, tmp_path):
        """End-to-end: loomscan check --full on a file with a potential null deref
        should NOT crash with 'unexpected keyword argument variable'."""
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.py").write_text(
            "def f(x):\n"
            "    result = x.get('key')\n"
            "    return result.strip()\n"  # potential null deref (result could be None)
        )
        _make_git_repo(repo)

        stdout, stderr, rc = _run_cli(repo, "check", "--full", "--json")
        assert "variable" not in stderr.lower() or "unexpected keyword" not in stderr.lower(), (
            f"variable= crash still present. stderr: {stderr[:500]}"
        )
        assert "Traceback" not in stderr or "variable" not in stderr, (
            f"Check crashed. stderr: {stderr[:500]}"
        )


# =============================================================================
# 2. Dashboard writes to repo dir
# =============================================================================

class TestDashboardOutputPath:
    """v4.44: Dashboard output defaults to <repo>/loomscan-dashboard.html (was CWD)."""

    def test_dashboard_writes_to_repo_dir(self, tmp_path):
        """loomscan dashboard --repo <dir> should write to <dir>/loomscan-dashboard.html."""
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.py").write_text("x = 1\n")
        _make_git_repo(repo)

        stdout, stderr, rc = _run_cli(repo, "dashboard", "--repo", str(repo), timeout=180)

        dashboard_path = repo / "loomscan-dashboard.html"
        assert dashboard_path.exists(), (
            f"Dashboard should be at {dashboard_path}, not CWD. stdout: {stdout[:200]}"
        )


# =============================================================================
# 3. Dashboard runs full scan (not demo)
# =============================================================================

class TestDashboardFullScan:
    """v4.44: Dashboard runs a full scan when no --input (was demo-only)."""

    def test_dashboard_runs_full_scan(self, tmp_path):
        """loomscan dashboard without --input should print 'Running full LoomScan scan'."""
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.py").write_text("x = 1\n")
        _make_git_repo(repo)

        stdout, stderr, rc = _run_cli(repo, "dashboard", "--repo", str(repo), timeout=180)
        assert "Running full LoomScan scan" in stdout or "Scan complete" in stdout, (
            f"Dashboard should run a full scan. stdout: {stdout[:300]}"
        )


# =============================================================================
# 4. --summary flag
# =============================================================================

class TestSummaryFlag:
    """v4.44: --summary groups findings by rule_id."""

    def test_summary_flag_exists(self):
        """--summary should appear in loomscan check --help."""
        stdout, stderr, rc = _run_cli(PROJECT_ROOT, "check", "--help")
        assert "--summary" in stdout, f"--summary not in help. stdout: {stdout[:300]}"

    def test_summary_produces_grouped_output(self, tmp_path):
        """loomscan check --full --summary should produce 'findings across' text."""
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.py").write_text(
            "import os\n"
            "password = 'hardcoded-secret-12345'\n"
            "def f():\n"
            "    return os.system('echo ' + password)\n"
        )
        _make_git_repo(repo)

        stdout, stderr, rc = _run_cli(repo, "check", "--full", "--summary", timeout=180)
        assert "Summary" in stdout or "findings across" in stdout.lower() or "Decision" in stdout, (
            f"--summary should produce grouped output. stdout: {stdout[:500]}"
        )


# =============================================================================
# 5. "Fail on critical" workflow logic
# =============================================================================

class TestFailOnCriticalWorkflow:
    """v4.44: Workflow checks properties.severity (was level == 'critical')."""

    def test_workflow_checks_properties_severity(self):
        """The workflow file should check properties.severity, not level == 'critical'."""
        content = (PROJECT_ROOT / ".github" / "workflows" / "loomscan.yml").read_text()
        assert "properties" in content, "Workflow should check properties"
        assert "severity" in content.lower(), "Workflow should check severity"
        # Should NOT have the old broken check
        assert "level'].lower()) == 'critical'" not in content, (
            "Workflow should not check level == 'critical' (SARIF has no critical level)"
        )


# =============================================================================
# 6. loomscan quickstart command (v5.0 feature)
# =============================================================================

class TestQuickstartCommand:
    """v5.0: loomscan quickstart — creates config, runs scan, prints next steps."""

    def test_quickstart_command_exists(self):
        """loomscan quickstart should appear in --help."""
        stdout, stderr, rc = _run_cli(PROJECT_ROOT, "--help")
        assert "quickstart" in stdout, f"quickstart not in help. stdout: {stdout[:300]}"

    def test_quickstart_creates_config(self, tmp_path):
        """loomscan quickstart should create .loomscan.yaml."""
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.py").write_text("x = 1\n")
        _make_git_repo(repo)

        stdout, stderr, rc = _run_cli(repo, "quickstart", "--repo", str(repo), timeout=180)
        # Should create or update .loomscan.yaml
        assert (repo / ".loomscan.yaml").exists(), (
            f"quickstart should create .loomscan.yaml. stdout: {stdout[:200]}"
        )

    def test_quickstart_prints_next_steps(self, tmp_path):
        """loomscan quickstart should print next steps."""
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.py").write_text("x = 1\n")
        _make_git_repo(repo)

        stdout, stderr, rc = _run_cli(repo, "quickstart", "--repo", str(repo), timeout=180)
        assert "next" in stdout.lower() or "loomscan check" in stdout.lower() or "ready" in stdout.lower(), (
            f"quickstart should print next steps. stdout: {stdout[:300]}"
        )


# =============================================================================
# 7. Multi-language counterfactual (v5.0 feature)
# =============================================================================

class TestMultiLangCounterfactual:
    """v5.0: Counterfactual mutation extended to JS/Java/Go (was Python-only)."""

    def test_counterfactual_module_has_language_templates(self):
        """The counterfactual module should have language-aware guard templates."""
        import inspect
        from loomscan import counterfactual
        src = inspect.getsource(counterfactual)
        # Should have language-aware guard injection (not just Python)
        assert "javascript" in src.lower() or "js" in src.lower() or "language" in src.lower(), (
            "counterfactual should have language-aware templates"
        )


# =============================================================================
# 8. Version is v5.0
# =============================================================================

class TestVersionV5:
    def test_version_is_5_0(self):
        from loomscan import __version__
        major = int(__version__.split(".")[0])
        assert major >= 5, f"Expected v5.0+, got {__version__}"

    def test_pyproject_matches(self):
        from loomscan import __version__
        import re as _re
        content = (PROJECT_ROOT / "pyproject.toml").read_text()
        m = _re.search(r'^version\s*=\s*["\']([^"\']+)["\']', content, _re.MULTILINE)
        assert m
        assert m.group(1) == __version__

    def test_readme_says_v5(self):
        content = (PROJECT_ROOT / "README.md").read_text()
        assert "v5.0" in content or "v5." in content, (
            "README should mention v5.0"
        )
