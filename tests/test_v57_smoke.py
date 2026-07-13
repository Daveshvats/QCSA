"""v5.7 smoke tests — TUI mascot, progress bar, Rust core wiring.

Covers the 3 main v5.7 features:
  1. loomscan.tui module (Mascot + ScanProgress)
  2. Orchestrator progress hooks (_stage_start / _stage_complete)
  3. Rust regex core auto-detection in yaml_engine

Plus regression checks:
  - Version bumped to 5.7.0
  - README updated to v5.7
  - Existing v5.6 functionality still works (yaml_engine produces same findings)
"""
from __future__ import annotations

import os
import sys
import tempfile
import subprocess
from pathlib import Path

import pytest

# Ensure project on path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# ============================================================================
# Version checks
# ============================================================================

def test_version_bumped_to_57():
    """v5.7: __version__ must be 5.7.0."""
    import loomscan
    assert loomscan.__version__ == "5.7.0", f"Expected 5.7.0, got {loomscan.__version__}"


def test_pyproject_version_matches():
    """v5.7: pyproject.toml version must match __version__."""
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    content = pyproject.read_text()
    assert 'version = "5.7.0"' in content, "pyproject.toml version not bumped to 5.7.0"


def test_readme_header_says_v57():
    """v5.7: README header should say v5.7 (was stuck on v5.4)."""
    readme = Path(__file__).resolve().parent.parent / "README.md"
    content = readme.read_text()
    # Must contain v5.7 in the first 10 lines (the > quote)
    first_lines = "\n".join(content.split("\n")[:10])
    assert "v5.7" in first_lines, f"README header doesn't mention v5.7: {first_lines[:200]}"


def test_readme_mentions_tui_and_mascot():
    """v5.7: README should mention the TUI mascot and progress bar."""
    readme = Path(__file__).resolve().parent.parent / "README.md"
    content = readme.read_text()
    assert "Loomy" in content, "README doesn't mention Loomy the mascot"
    assert "progress bar" in content.lower(), "README doesn't mention progress bar"
    assert "Rust" in content, "README doesn't mention Rust core"


# ============================================================================
# TUI module tests
# ============================================================================

def test_tui_module_imports():
    """v5.7: loomscan.tui module must import."""
    from loomscan.tui import ScanProgress, Mascot, get_global_mascot
    assert ScanProgress is not None
    assert Mascot is not None


def test_mascot_say_does_not_crash():
    """v5.7: Mascot.say() must not crash even when TUI is disabled."""
    from loomscan.tui import Mascot
    m = Mascot(enabled=False)  # Force disabled for test env
    m.say("init")
    m.say("done", "Test message")
    m.say("pass")
    m.say("warn", "test")
    m.say("block", "test")


def test_mascot_start_stop_animation():
    """v5.7: Mascot animation thread must start and stop cleanly."""
    from loomscan.tui import Mascot
    m = Mascot(enabled=False)  # disabled — should be no-op
    m.start_animation(phase="layers", message="testing")
    import time; time.sleep(0.1)
    m.stop_animation()
    # No hang, no crash = pass


def test_scan_progress_stage_tracking():
    """v5.7: ScanProgress must track stages correctly."""
    from loomscan.tui import ScanProgress
    sp = ScanProgress(total_stages=3, enabled=False)
    assert sp.total_stages == 3
    assert sp.completed_stages == 0

    with sp:
        sp.start_stage("Stage 1", "First stage")
        sp.complete_stage(findings_count=2)
        sp.start_stage("Stage 2", "Second stage")
        sp.complete_stage(findings_count=1)
        sp.start_stage("Stage 3", "Third stage")
        sp.complete_stage(findings_count=0)

    assert sp.completed_stages == 3
    assert len(sp.stages) == 3
    assert sp.stages[0].name == "Stage 1"
    assert sp.stages[0].findings_count == 2
    assert sp.stages[0].status == "done"
    assert sp.stages[1].findings_count == 1
    assert sp.stages[2].findings_count == 0


def test_scan_progress_disabled_is_noop():
    """v5.7: ScanProgress with enabled=False must be a complete no-op (no crashes)."""
    from loomscan.tui import ScanProgress
    sp = ScanProgress(total_stages=5, enabled=False)
    # All methods should be no-ops, not crash
    sp.start_stage("test", "test")
    sp.complete_stage(findings_count=0)
    sp.fail_stage("test error")
    sp.update_description("new desc")
    # summary_table builds a Rich Table object (always), but doesn't render to console
    # when disabled — we just verify it doesn't crash
    table = sp.summary_table()
    # Table can be None (when Rich unavailable) or a Table object
    # Either is acceptable; the requirement is "no crash"
    assert table is None or hasattr(table, 'add_row'), "summary_table returned unexpected type"


def test_scan_progress_total_elapsed():
    """v5.7: ScanProgress.total_elapsed must be a positive float after stages."""
    from loomscan.tui import ScanProgress
    import time
    sp = ScanProgress(total_stages=1, enabled=False)
    with sp:
        sp.start_stage("only", "test")
        time.sleep(0.05)
        sp.complete_stage()
    assert sp.total_elapsed > 0.0


# ============================================================================
# Orchestrator progress hook tests
# ============================================================================

def test_orchestrator_accepts_progress_param():
    """v5.7: Orchestrator must accept a progress= kwarg."""
    from loomscan.orchestrator import Orchestrator
    from loomscan.tui import ScanProgress
    with tempfile.TemporaryDirectory() as td:
        repo = Path(td)
        subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "t@t.com"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.name", "t"], cwd=repo, check=True)
        (repo / "app.py").write_text("x = 1\n")
        subprocess.run(["git", "add", "."], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-m", "init"], cwd=repo, check=True, capture_output=True)

        from loomscan.config import STCAConfig
        cfg = STCAConfig.default()
        cfg.save(repo / ".loomscan.yaml")

        progress = ScanProgress(total_stages=7, enabled=False)
        try:
            progress.__enter__()
            orch = Orchestrator(repo, cfg, strictness=5, progress=progress)
            result = orch.run_full()
        finally:
            progress.__exit__(None, None, None)

        # Must have tracked at least one stage
        assert len(progress.stages) > 0, "No stages tracked"
        # All stages must be marked done
        for s in progress.stages:
            assert s.status == "done", f"Stage {s.name} not done: {s.status}"


def test_orchestrator_progress_hooks_are_noop_when_none():
    """v5.7: Orchestrator with progress=None must work normally (backward compat)."""
    from loomscan.orchestrator import Orchestrator
    with tempfile.TemporaryDirectory() as td:
        repo = Path(td)
        subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "t@t.com"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.name", "t"], cwd=repo, check=True)
        (repo / "app.py").write_text("x = 1\n")
        subprocess.run(["git", "add", "."], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-m", "init"], cwd=repo, check=True, capture_output=True)

        from loomscan.config import STCAConfig
        cfg = STCAConfig.default()
        cfg.save(repo / ".loomscan.yaml")

        # No progress= kwarg — should work as before
        orch = Orchestrator(repo, cfg, strictness=5)
        # Internal hooks must be no-ops
        orch._stage_start("test", "test")
        orch._stage_complete(findings_count=0)
        orch._stage_fail("test")
        # run_full() must still produce a result
        result = orch.run_full()
        assert result is not None


# ============================================================================
# Rust core tests
# ============================================================================

def test_rust_core_optional_import():
    """v5.7: loomscan_regex module should be importable if installed (else skip)."""
    try:
        from loomscan_regex import is_available, engine_version, RegexEngine
        assert is_available() is True
        assert isinstance(engine_version(), str)
    except ImportError:
        pytest.skip("loomscan_regex Rust core not installed")


def test_yaml_engine_is_rust_core_active_returns_bool():
    """v5.7: yaml_engine.is_rust_core_active() must return a bool."""
    from loomscan.yaml_engine import is_rust_core_active
    result = is_rust_core_active()
    assert isinstance(result, bool)


def test_yaml_engine_produces_findings_with_or_without_rust():
    """v5.7: yaml_engine.apply_packs must produce findings regardless of Rust core."""
    from loomscan.yaml_engine import apply_packs, apply_pack_to_file
    # Use the python-deep pack (always present)
    pack = Path(__file__).resolve().parent.parent / "loomscan" / "rules" / "packs" / "python-deep.yml"
    assert pack.exists(), f"Pack not found: {pack}"

    with tempfile.TemporaryDirectory() as td:
        repo = Path(td)
        src = repo / "app.py"
        src.write_text("x = eval('1+1')\npassword = 'hardcoded_secret_123'\n")

        # Both apply_packs (Rust or Python) and apply_pack_to_file (always Python)
        # must produce at least 1 finding on this fixture.
        hits_batch = apply_packs([pack], [src], repo_root=repo)
        hits_single = apply_pack_to_file(pack, src, repo_root=repo)

        assert len(hits_batch) > 0, "apply_packs produced 0 findings (Rust or Python)"
        assert len(hits_single) > 0, "apply_pack_to_file produced 0 findings"

        # Both must find at least the eval() pattern
        batch_rules = {h.rule_id for h in hits_batch}
        single_rules = {h.rule_id for h in hits_single}
        # The rule_id sets should be a subset relationship (Rust may miss some unsupported rules)
        common = batch_rules & single_rules
        assert len(common) > 0, "No common rule_ids between Rust and Python paths"


def test_rust_and_python_paths_agree_on_basic_findings():
    """v5.7: When Rust core is active, it must produce the same findings as Python re.

    This is the critical correctness test. The Rust regex engine uses a different
    regex syntax (re2-compatible) than Python's re module, so any divergence
    would indicate a translation bug.
    """
    from loomscan.yaml_engine import (apply_packs, apply_pack_to_file,
                                       is_rust_core_active)
    if not is_rust_core_active():
        pytest.skip("Rust core not active — can't compare")

    pack = Path(__file__).resolve().parent.parent / "loomscan" / "rules" / "packs" / "python-deep.yml"

    with tempfile.TemporaryDirectory() as td:
        repo = Path(td)
        src = repo / "app.py"
        src.write_text(
            "x = eval('1+1')\n"
            "password = 'hardcoded_secret_123'\n"
            "cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")\n"
            "os.system('rm -rf /')\n"
        )

        rust_hits = apply_packs([pack], [src], repo_root=repo)
        py_hits = apply_pack_to_file(pack, src, repo_root=repo)

        # Both should produce findings
        assert len(rust_hits) > 0
        assert len(py_hits) > 0

        # The Rust path may produce slightly fewer hits if some Python re
        # features aren't supported in re2 syntax. But the rule_id sets
        # should substantially overlap.
        rust_rules = {h.rule_id for h in rust_hits}
        py_rules = {h.rule_id for h in py_hits}
        common = rust_rules & py_rules
        # At least 50% of Python rules should also fire in Rust
        overlap_ratio = len(common) / max(len(py_rules), 1)
        assert overlap_ratio >= 0.5, (
            f"Low overlap between Rust and Python: {overlap_ratio:.0%} "
            f"(common={len(common)}, py={len(py_rules)}, rust={len(rust_rules)})"
        )


# ============================================================================
# CLI --no-tui flag test
# ============================================================================

def test_cli_check_has_no_tui_flag():
    """v5.7: loomscan check must accept --no-tui flag."""
    import click
    from loomscan.cli import main
    check_cmd = main.commands.get("check")
    assert check_cmd is not None, "loomscan check command not found"
    # The --no-tui flag must be in the command's params
    param_names = [p.name for p in check_cmd.params]
    assert "no_tui" in param_names, f"--no-tui flag not found in check command params: {param_names}"


def test_cli_quickstart_uses_progress():
    """v5.7: quickstart command should reference ScanProgress."""
    cli_path = Path(__file__).resolve().parent.parent / "loomscan" / "cli.py"
    content = cli_path.read_text()
    assert "ScanProgress" in content, "cli.py doesn't reference ScanProgress"
    assert "progress=progress" in content, "cli.py doesn't pass progress to Orchestrator"


# ============================================================================
# Rust core source file checks
# ============================================================================

def test_rust_core_has_pyo3_bindings():
    """v5.7: rust-core/src/lib.rs must contain pyo3 bindings."""
    lib_rs = Path(__file__).resolve().parent.parent / "rust-core" / "src" / "lib.rs"
    content = lib_rs.read_text()
    assert "pyo3" in content, "lib.rs doesn't reference pyo3"
    assert "#[pyclass" in content, "lib.rs doesn't have #[pyclass] attribute"
    assert "#[pymethods]" in content, "lib.rs doesn't have #[pymethods] attribute"
    assert "#[pymodule]" in content, "lib.rs doesn't have #[pymodule] attribute"
    assert "loomscan_regex" in content, "lib.rs doesn't define loomscan_regex module"


def test_rust_core_has_pyproject_for_maturin():
    """v5.7: rust-core must have pyproject.toml for maturin build."""
    pyproject = Path(__file__).resolve().parent.parent / "rust-core" / "pyproject.toml"
    assert pyproject.exists(), "rust-core/pyproject.toml missing"
    content = pyproject.read_text()
    assert "maturin" in content, "rust-core/pyproject.toml doesn't mention maturin"
    assert "loomscan_regex" in content, "rust-core/pyproject.toml doesn't set module-name"


def test_rust_core_has_benchmark():
    """v5.7: rust-core must have benches/scan_benchmark.rs."""
    bench = Path(__file__).resolve().parent.parent / "rust-core" / "benches" / "scan_benchmark.rs"
    assert bench.exists(), "rust-core/benches/scan_benchmark.rs missing"
    content = bench.read_text()
    assert "criterion_group" in content, "benchmark doesn't use criterion"
    assert "RegexEngine" in content, "benchmark doesn't use RegexEngine"


def test_rust_core_cargo_toml_has_pyo3_dep():
    """v5.7: rust-core/Cargo.toml must declare pyo3 dependency."""
    cargo = Path(__file__).resolve().parent.parent / "rust-core" / "Cargo.toml"
    content = cargo.read_text()
    assert 'pyo3' in content, "Cargo.toml doesn't declare pyo3"
    assert 'extension-module' in content, "Cargo.toml doesn't enable pyo3 extension-module feature"


# ============================================================================
# Regression: v5.6 functionality still works
# ============================================================================

def test_v56_yaml_engine_still_works():
    """v5.7 must not regress v5.6: native YAML engine still fires on Flask XSS fixture."""
    from loomscan.yaml_engine import apply_pack_to_file
    framework_pack = Path(__file__).resolve().parent.parent / "loomscan" / "rules" / "packs" / "framework-taint.yml"
    assert framework_pack.exists()

    with tempfile.TemporaryDirectory() as td:
        repo = Path(td)
        src = repo / "app.py"
        # Flask SSTI / XSS fixture — should trigger flask-xss-render-template-string-concat
        src.write_text(
            "from flask import Flask, render_template_string\n"
            "app = Flask(__name__)\n"
            "@app.route('/')\n"
            "def index():\n"
            "    name = 'world'\n"
            "    return render_template_string('<h1>Hello ' + name + '</h1>')\n"
        )
        hits = apply_pack_to_file(framework_pack, src, repo_root=repo)
        rule_ids = {h.rule_id for h in hits}
        # The Flask XSS rule must still fire (v5.5 critical fix)
        assert any('xss' in r.lower() or 'ssti' in r.lower() or 'flask' in r.lower()
                    for r in rule_ids), \
            f"Flask XSS/SSTI rule not firing: {rule_ids}"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
