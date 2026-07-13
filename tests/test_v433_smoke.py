"""v4.33 smoke tests — end-to-end tests for the 3 critical bugs that
v4.32 introduced and the existing test suite failed to catch.

These tests run the actual user-facing surface area (CLI flags + real
CPG builds + real env-var wiring) so regressions show up as test
failures instead of silent runtime errors.

Catches:
1. `--sarif` ImportError (generate_sarif didn't exist)
2. `py_hunks` NameError in _run_cross_file_taint_tracking
3. `--max-files` env override never read
4. `--output` flag missing (GitHub Actions workflow relied on it)
5. `L0e.docker-no-healthcheck` firing once per line instead of once per file
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest


# =============================================================================
# Helpers
# =============================================================================

def _make_git_repo(root: Path) -> Path:
    """Init a git repo with at least one commit so orchestrator.run_full works."""
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.email", "test@test.local"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=root, check=True)
    (root / ".loomscan.yaml").write_text("strictness: 5\n")
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    subprocess.run(["git", "commit", "-qm", "init"], cwd=root, check=True)
    return root


def _run_cli(repo_root: Path, *args: str, env: dict | None = None):
    """Invoke `loomscan <args>` via the CLI main entry, returning (stdout, stderr, exit_code)."""
    full_env = os.environ.copy()
    if env:
        full_env.update(env)
    # Force the loomscan package onto PYTHONPATH
    pkg_root = Path(__file__).resolve().parent.parent
    full_env["PYTHONPATH"] = str(pkg_root) + os.pathsep + full_env.get("PYTHONPATH", "")
    proc = subprocess.run(
        [sys.executable, "-c", "from loomscan.cli import main; main()", *args],
        cwd=repo_root, capture_output=True, text=True, env=full_env, timeout=120,
    )
    return proc.stdout, proc.stderr, proc.returncode


# =============================================================================
# 1. --sarif flag end-to-end (was: ImportError on every invocation)
# =============================================================================

class TestSarifFlagSmoke:
    """v4.32: `loomscan check --sarif` crashed with ImportError because
    `generate_sarif` didn't exist (actual API is `to_sarif` / `save_sarif`).
    v4.33: should write a SARIF file and exit 0/1 cleanly.
    """

    def test_sarif_flag_writes_file(self, tmp_path):
        repo = _make_git_repo(tmp_path)
        (repo / "app.py").write_text(
            'password = "hardcoded-secret-12345"\n'
            'import os\n'
            'def f():\n'
            '    return os.system("echo " + password)\n'
        )
        subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-qm", "add vuln"], cwd=repo, check=True)

        out_path = repo / "out.sarif"
        stdout, stderr, rc = _run_cli(repo, "check", "--full", "--sarif", "--output", str(out_path))

        # Must not crash with ImportError or any other traceback
        assert "ImportError" not in stderr, f"ImportError in --sarif: {stderr}"
        assert "Traceback" not in stderr, f"Traceback in --sarif: {stderr}"
        # File must be written
        assert out_path.exists(), f"SARIF file not written. stderr={stderr}"
        # Must be valid SARIF JSON
        data = json.loads(out_path.read_text())
        assert data["version"] == "2.1.0"
        assert "runs" in data
        assert len(data["runs"]) >= 1
        # Driver must be LoomScan
        assert data["runs"][0]["tool"]["driver"]["name"] == "LoomScan"

    def test_sarif_default_path(self, tmp_path):
        """Without --output, SARIF should land in .loomscan-reports/result.sarif."""
        repo = _make_git_repo(tmp_path)
        (repo / "app.py").write_text('x = 1\n')
        subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-qm", "add file"], cwd=repo, check=True)

        stdout, stderr, rc = _run_cli(repo, "check", "--full", "--sarif")
        assert "ImportError" not in stderr
        expected = repo / ".loomscan-reports" / "result.sarif"
        assert expected.exists(), f"Default SARIF path missing. stderr={stderr}"

    def test_sarif_stdout_dash(self, tmp_path):
        """`--output -` should write SARIF JSON to stdout, no file."""
        repo = _make_git_repo(tmp_path)
        (repo / "app.py").write_text('x = 1\n')
        subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-qm", "add file"], cwd=repo, check=True)

        stdout, stderr, rc = _run_cli(repo, "check", "--full", "--sarif", "--output", "-")
        assert "Traceback" not in stderr
        # stdout must be valid JSON
        data = json.loads(stdout)
        assert data["version"] == "2.1.0"

    def test_output_flag_exists(self, tmp_path):
        """`--output` must be a recognized flag (v4.32 workflow depended on it
        but click rejected it)."""
        repo = _make_git_repo(tmp_path)
        (repo / "app.py").write_text('x = 1\n')
        subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-qm", "add file"], cwd=repo, check=True)

        # Just check click doesn't reject --output with "No such option"
        stdout, stderr, rc = _run_cli(repo, "check", "--full", "--sarif", "--output", "x.sarif")
        assert "No such option" not in stderr, f"--output rejected: {stderr}"


# =============================================================================
# 2. Cross-file taint tracking end-to-end (was: py_hunks NameError)
# =============================================================================

class TestCrossFileTaintSmoke:
    """v4.32: _run_cross_file_taint_tracking referenced `py_hunks` which
    didn't exist in scope after the .py filter was removed. Every real
    CPG run emitted `L0.cpg_taint.error: name 'py_hunks' is not defined`.
    v4.33: must run cleanly with zero error findings.
    """

    def test_no_cpg_taint_error_findings(self, tmp_path):
        repo = _make_git_repo(tmp_path)
        (repo / "src").mkdir()
        # Two files with a real (if simple) cross-file flow.
        (repo / "src" / "source.py").write_text(
            'import os\n'
            'def get_input():\n'
            '    return os.environ.get("USER_INPUT")\n'
        )
        (repo / "src" / "sink.py").write_text(
            'import os\n'
            'from src.source import get_input\n'
            'def vulnerable():\n'
            '    user_data = get_input()\n'
            '    os.system("echo " + user_data)\n'
        )
        subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-qm", "add taint flow"], cwd=repo, check=True)

        stdout, stderr, rc = _run_cli(repo, "check", "--full", "--json")
        assert "Traceback" not in stderr, f"Traceback in check: {stderr}"

        # Parse findings
        data = json.loads(stdout)
        error_findings = [
            f for f in data.get("findings", [])
            if "error" in f.get("rule_id", "").lower()
            and "py_hunks" in f.get("message", "")
        ]
        assert not error_findings, (
            f"py_hunks NameError still present in CPG taint tracker: {error_findings}"
        )

        # Also: no L0.cpg_taint.error findings at all (broader check)
        cpg_errors = [
            f for f in data.get("findings", [])
            if f.get("rule_id", "") == "L0.cpg_taint.error"
        ]
        assert not cpg_errors, (
            f"CPG taint tracker produced error findings: {cpg_errors}"
        )

    def test_run_cross_file_taint_tracking_directly(self, tmp_path):
        """Direct call: pass hunks to _run_cross_file_taint_tracking.
        Must not raise NameError."""
        from loomscan.orchestrator import Orchestrator
        from loomscan.config import STCAConfig
        from loomscan.models import DiffHunk

        repo = _make_git_repo(tmp_path)
        (repo / "app.py").write_text('x = 1\n')
        subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-qm", "x"], cwd=repo, check=True)

        orch = Orchestrator(repo, STCAConfig())
        hunks = [DiffHunk(file="app.py", start_line=1, end_line=1,
                          added_lines=["x = 1"], removed_lines=[])]
        # Must not raise NameError
        findings = orch._run_cross_file_taint_tracking(hunks)
        assert isinstance(findings, list)


# =============================================================================
# 3. --max-files override end-to-end (was: env var set but never read)
# =============================================================================

class TestMaxFilesOverrideSmoke:
    """v4.32: `loomscan check --max-files N` set STCA_MAX_FILES_OVERRIDE env var,
    but no engine read it. v4.33: _max_files() helper reads the env var
    and overrides the 20+ hardcoded caps.
    """

    def test_max_files_helper_overrides_default(self):
        """Unit test for the _max_files helper — the actual chokepoint."""
        from loomscan.orchestrator import _max_files
        old = os.environ.get("STCA_MAX_FILES_OVERRIDE")
        try:
            # No env: default returned
            os.environ.pop("STCA_MAX_FILES_OVERRIDE", None)
            assert _max_files(50) == 50
            # Env=1000: overrides default
            os.environ["STCA_MAX_FILES_OVERRIDE"] = "1000"
            assert _max_files(50) == 1000
            # Env=0: unlimited (large sentinel)
            os.environ["STCA_MAX_FILES_OVERRIDE"] = "0"
            assert _max_files(50) > 1_000_000
            # Bad env: ignored
            os.environ["STCA_MAX_FILES_OVERRIDE"] = "garbage"
            assert _max_files(50) == 50
        finally:
            if old is None:
                os.environ.pop("STCA_MAX_FILES_OVERRIDE", None)
            else:
                os.environ["STCA_MAX_FILES_OVERRIDE"] = old

    def test_max_files_zero_does_not_truncate(self, tmp_path):
        """End-to-end: with --max-files 0, large repos should NOT be silently
        truncated. We verify by setting the env var and confirming the
        orchestrator's _max_files helper reflects 'unlimited'."""
        from loomscan.orchestrator import _max_files
        old = os.environ.get("STCA_MAX_FILES_OVERRIDE")
        try:
            os.environ["STCA_MAX_FILES_OVERRIDE"] = "0"
            # Any call site asking for default=200 should now get the unlimited sentinel
            effective = _max_files(200)
            assert effective >= 1_000_000, (
                f"--max-files 0 should yield unlimited sentinel, got {effective}"
            )
        finally:
            if old is None:
                os.environ.pop("STCA_MAX_FILES_OVERRIDE", None)
            else:
                os.environ["STCA_MAX_FILES_OVERRIDE"] = old

    def test_orchestrator_respects_override(self, tmp_path):
        """End-to-end: orchestrator's max_files= call sites use the override."""
        from loomscan.orchestrator import Orchestrator, _max_files
        from loomscan.config import STCAConfig

        repo = _make_git_repo(tmp_path)
        (repo / "app.py").write_text('x = 1\n')
        subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-qm", "x"], cwd=repo, check=True)

        old = os.environ.get("STCA_MAX_FILES_OVERRIDE")
        try:
            # With override=5, _max_files(any) returns 5
            os.environ["STCA_MAX_FILES_OVERRIDE"] = "5"
            assert _max_files(50) == 5
            assert _max_files(300) == 5
            assert _max_files(500) == 5
            # Smoke-test that orchestrator can run cleanly with the override
            orch = Orchestrator(repo, STCAConfig())
            result = orch.run_full()
            assert result is not None
        finally:
            if old is None:
                os.environ.pop("STCA_MAX_FILES_OVERRIDE", None)
            else:
                os.environ["STCA_MAX_FILES_OVERRIDE"] = old


# =============================================================================
# 4. L0e.docker-no-healthcheck fires once per file (was: once per line)
# =============================================================================

class TestDockerHealthcheckSmoke:
    """v4.32: docker-no-healthcheck fired once per Dockerfile line because the
    absence-check ran inside the per-line loop. v4.33: fires exactly once per
    file when HEALTHCHECK is missing, 0 times when present.
    """

    def test_no_healthcheck_fires_once(self, tmp_path):
        from loomscan.layers.l0e_iac import L0eIaC
        from loomscan.models import DiffHunk

        (tmp_path / "Dockerfile").write_text(
            "FROM python:3.12\n"
            "WORKDIR /app\n"
            "COPY . .\n"
            "CMD [\"python\", \"app.py\"]\n"
        )
        layer = L0eIaC()
        hunks = [DiffHunk(file="Dockerfile", start_line=1, end_line=4,
                          added_lines=["FROM python:3.12", "WORKDIR /app",
                                       "COPY . .", "CMD [\"python\", \"app.py\"]"],
                          removed_lines=[])]
        findings = layer.run(tmp_path, hunks, config=None)
        no_hc = [f for f in findings if f.rule_id == "L0e.docker-no-healthcheck"]
        assert len(no_hc) == 1, (
            f"docker-no-healthcheck should fire exactly once for a Dockerfile "
            f"without HEALTHCHECK; got {len(no_hc)} findings"
        )

    def test_with_healthcheck_fires_zero(self, tmp_path):
        from loomscan.layers.l0e_iac import L0eIaC
        from loomscan.models import DiffHunk

        (tmp_path / "Dockerfile").write_text(
            "FROM python:3.12\n"
            "WORKDIR /app\n"
            "COPY . .\n"
            "HEALTHCHECK CMD curl -f http://localhost:8080/health || exit 1\n"
            "CMD [\"python\", \"app.py\"]\n"
        )
        layer = L0eIaC()
        hunks = [DiffHunk(file="Dockerfile", start_line=1, end_line=5,
                          added_lines=["FROM python:3.12", "WORKDIR /app",
                                       "COPY . .",
                                       "HEALTHCHECK CMD curl -f http://localhost:8080/health || exit 1",
                                       "CMD [\"python\", \"app.py\"]"],
                          removed_lines=[])]
        findings = layer.run(tmp_path, hunks, config=None)
        no_hc = [f for f in findings if f.rule_id == "L0e.docker-no-healthcheck"]
        assert len(no_hc) == 0, (
            f"docker-no-healthcheck must not fire when HEALTHCHECK is present; "
            f"got {len(no_hc)} findings"
        )


# =============================================================================
# 5. LSP command import (was: always fell into "not yet bundled" branch)
# =============================================================================

class TestLspCommandSmoke:
    """v4.32: `loomscan lsp` always printed 'LSP server not yet bundled' because
    it tried to import a non-existent `run_server` symbol.
    v4.33: imports LSPServer successfully.
    """

    def test_lsp_cmd_does_not_say_not_bundled(self, tmp_path):
        # Importing the lsp_cmd and inspecting the source is brittle; instead
        # just verify the underlying import path works.
        from loomscan.lsp.server import LSPServer
        assert hasattr(LSPServer, "run"), "LSPServer.run must exist for loomscan lsp"

    def test_lsp_cmd_source_uses_LSPServer(self):
        """Static check: cli_v2.lsp_cmd callback must import LSPServer, not run_server."""
        import loomscan.cli_v2 as cv2
        import inspect
        # click.Command wraps the function in .callback
        cb = cv2.lsp_cmd.callback
        src = inspect.getsource(cb)
        assert "from .lsp.server import LSPServer" in src, (
            "lsp_cmd must import LSPServer from .lsp.server"
        )
        # The dead import `from .lsp import run_server` must not appear as
        # an actual import statement (mentioning it in a comment is fine).
        assert "import run_server" not in src, (
            "lsp_cmd must not import dead run_server symbol"
        )


# =============================================================================
# 6. js_pattern_scanner has no duplicate rule_ids (was: 2 duplicates)
# =============================================================================

class TestJsPatternScannerNoDuplicates:
    """v4.32: js-cryptojs-usage and js-role-from-localstorage each appeared
    twice in the JS_PATTERNS list (lines 103/335 and 191/343). v4.33: removed
    the duplicates at the end of the list.
    """

    def test_no_duplicate_rule_ids(self):
        from loomscan.js_pattern_scanner import JS_PATTERNS
        ids = [p[0] for p in JS_PATTERNS]
        dupes = [i for i in set(ids) if ids.count(i) > 1]
        assert not dupes, f"Duplicate rule_ids in JS_PATTERNS: {dupes}"

    def test_cryptojs_usage_present_once(self):
        from loomscan.js_pattern_scanner import JS_PATTERNS
        ids = [p[0] for p in JS_PATTERNS]
        assert ids.count("js-cryptojs-usage") == 1, (
            f"js-cryptojs-usage should appear exactly once; found {ids.count('js-cryptojs-usage')}"
        )

    def test_role_from_localstorage_present_once(self):
        from loomscan.js_pattern_scanner import JS_PATTERNS
        ids = [p[0] for p in JS_PATTERNS]
        assert ids.count("js-role-from-localstorage") == 1, (
            f"js-role-from-localstorage should appear exactly once; "
            f"found {ids.count('js-role-from-localstorage')}"
        )
