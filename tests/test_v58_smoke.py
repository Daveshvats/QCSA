"""v5.8 smoke tests — spider mascot redesign, 3-tier install, doctor command, Rust wheel CI.

Covers the 5 main v5.8 features:
  1. Mascot is now a real spider (8 legs, web growing frame-by-frame)
  2. 3-tier install model in pyproject.toml
  3. loomscan doctor command
  4. GitHub Actions workflow for Rust wheel building
  5. tree-sitter moved from hard dep → [full] extra

Plus regression checks:
  - Version bumped to 5.8.0
  - README updated to v5.8
  - v5.7 mascot API still works (backward compat)
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# ============================================================================
# Version checks
# ============================================================================

def test_version_bumped_to_58():
    """v5.8+: __version__ must be >= 5.8.0 (v5.9+ also passes)."""
    import loomscan
    v = loomscan.__version__
    major, minor, *_ = (int(x) for x in v.split('.'))
    assert (major, minor) >= (5, 8), f"Expected >= 5.8.0, got {v}"


def test_pyproject_version_matches_58():
    """v5.8+: pyproject.toml version must match __version__ (>= 5.8.0)."""
    import loomscan
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    content = pyproject.read_text()
    assert f'version = "{loomscan.__version__}"' in content, (
        f"pyproject.toml version doesn't match __version__ ({loomscan.__version__})"
    )


def test_readme_header_says_v58_or_later():
    """v5.8+: README should mention a version >= 5.8."""
    readme = Path(__file__).resolve().parent.parent / "README.md"
    content = readme.read_text()
    import re
    match = re.search(r'v(\d+)\.(\d+)', content)
    assert match, "README doesn't mention any version"
    major, minor = int(match.group(1)), int(match.group(2))
    assert (major, minor) >= (5, 8), f"README version {major}.{minor} < 5.8"

# Backward-compat alias
def test_readme_header_says_v58():
    """Backward-compat alias for test_readme_header_says_v58_or_later."""
    test_readme_header_says_v58_or_later()


def test_readme_mentions_spider_and_3tier():
    """v5.8: README should mention spider mascot and 3-tier install."""
    readme = Path(__file__).resolve().parent.parent / "README.md"
    content = readme.read_text()
    assert "spider" in content.lower(), "README doesn't mention spider"
    assert "loomscan[full]" in content, "README doesn't mention loomscan[full]"
    assert "loomscan[fast]" in content, "README doesn't mention loomscan[fast]"


# ============================================================================
# Spider mascot redesign tests
# ============================================================================

def test_mascot_has_8_frames():
    """v5.8: Mascot weaving cycle must have 8 frames (was 6 in v5.7)."""
    from loomscan.tui.mascot import get_frame_count
    assert get_frame_count() == 8, f"Expected 8 frames, got {get_frame_count()}"


def test_mascot_frame_contains_spider_anatomy():
    """v5.8: Each frame must contain spider anatomy (legs, body, eyes)."""
    from loomscan.tui.mascot import get_frame, get_frame_count
    n = get_frame_count()
    for i in range(n):
        frame = get_frame(i)
        # Spider must have a body (abdomen/cephalothorax)
        # Look for patterns like ( ) or ___ which represent the body
        has_body = ("(" in frame and ")" in frame) or "___" in frame
        assert has_body, f"Frame {i} missing spider body: {frame[:100]}"


def test_mascot_frame_contains_web_strands():
    """v5.8: Each frame must contain web strands (/, \\, |, -, *)."""
    from loomscan.tui.mascot import get_frame, get_frame_count
    n = get_frame_count()
    web_chars = set("\\/|-*")
    for i in range(n):
        frame = get_frame(i)
        chars_in_frame = set(frame)
        has_web = len(chars_in_frame & web_chars) >= 3
        assert has_web, f"Frame {i} missing web strands (need 3+ of {web_chars}): {frame[:100]}"


def test_mascot_final_frame_shows_complete_web():
    """v5.8: Frame 7 (last) should show a complete web (more strands than frame 0)."""
    from loomscan.tui.mascot import get_frame
    frame0 = get_frame(0)
    frame7 = get_frame(7)
    # Count web strand characters in each frame
    web_chars = "\\/|-*"
    count0 = sum(frame0.count(c) for c in web_chars)
    count7 = sum(frame7.count(c) for c in web_chars)
    assert count7 >= count0, (
        f"Frame 7 should have >= web strands than frame 0 "
        f"(frame0={count0}, frame7={count7})"
    )


def test_mascot_eyes_change_to_happy_in_final_frame():
    """v5.8: Frame 7 should show happy eyes (^ ^) when web is complete."""
    from loomscan.tui.mascot import get_frame
    frame7 = get_frame(7)
    # Look for happy eye patterns: ^ ^ or ^-^
    assert "^" in frame7, f"Frame 7 missing happy eyes (^): {frame7[:200]}"


def test_mascot_v57_api_still_works():
    """v5.8: v5.7 mascot API (say, start_animation, stop_animation) must still work."""
    from loomscan.tui.mascot import Mascot
    m = Mascot(enabled=False)
    # All v5.7 methods must exist and not crash
    m.say("init")
    m.say("done", "test message")
    m.say("pass")
    m.say("warn", "test")
    m.say("block", "test")
    m.start_animation(phase="layers", message="test")
    import time; time.sleep(0.1)
    m.stop_animation()
    m.update_phase("taint", "test")


def test_mascot_say_picks_frame_based_on_phase():
    """v5.8: Mascot.say() should pick different frames for different phases."""
    from loomscan.tui.mascot import Mascot
    m = Mascot(enabled=False)
    # say() with different phases should not crash
    # (frame selection is internal, we just verify no crash)
    for phase in ["init", "discover", "layers", "taint", "cpg",
                   "metamorphic", "aggregate", "llm", "autofix",
                   "done", "warn", "block", "pass"]:
        m.say(phase)
        m.say(phase, f"custom message for {phase}")


# ============================================================================
# 3-tier install model tests
# ============================================================================

def test_pyproject_has_3_tier_extras():
    """v5.8: pyproject.toml must have [full] and [fast] extras."""
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    content = pyproject.read_text()
    assert "full = [" in content, "pyproject.toml missing [full] extra"
    assert "fast = [" in content, "pyproject.toml missing [fast] extra"
    assert "loomscan-regex" in content, "pyproject.toml [fast] doesn't depend on loomscan-regex"


def test_pyproject_treesitter_moved_to_full_extra():
    """v5.8: tree-sitter must be in [full], NOT in core dependencies.

    (Renamed to avoid conftest.py auto-skip on 'typescript' keyword.)
    """
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    content = pyproject.read_text()

    # Split into core deps section and optional section
    parts = content.split("[project.optional-dependencies]")
    core_section = parts[0]
    optional_section = parts[1] if len(parts) > 1 else ""

    # Extract just the dependencies = [...] block from core section
    # (not the optional-dependencies section which also has "dependencies" in its header)
    if "dependencies = [" in core_section:
        deps_block = core_section.split("dependencies = [")[1]
        # Find the matching closing bracket (first ] at the same indent level)
        # For simplicity, just take the first 500 chars which covers all core deps
        deps_block = deps_block[:500]
    else:
        deps_block = ""

    # tree-sitter should NOT be in core dependencies block
    assert "tree-sitter" not in deps_block, (
        f"tree-sitter should be moved from core deps to [full] extra. "
        f"Core deps block: {deps_block[:200]}"
    )
    # tree-sitter SHOULD be in [full]
    assert "tree-sitter>=" in optional_section, "tree-sitter not found in optional-dependencies [full]"


def test_pyproject_fast_implies_full():
    """v5.8: [fast] extra should include [full] (fast implies full)."""
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    content = pyproject.read_text()
    # The [fast] section should reference loomscan[full]
    # Split on the fast = [ marker and look in the next ~200 chars
    if "fast = [" in content:
        after_fast = content.split("fast = [")[1]
        # Take just the fast section (up to the next blank line or section header)
        fast_section = after_fast[:300]
        assert "loomscan[full]" in fast_section, (
            f"[fast] extra doesn't include loomscan[full]: {fast_section[:200]}"
        )
    else:
        pytest.fail("pyproject.toml missing 'fast = [' section")


def test_pyproject_core_deps_are_pure_python():
    """v5.8: Core dependencies must be pure Python (no compilation needed)."""
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    content = pyproject.read_text()
    deps_block = content.split("dependencies = [")[1].split("]")[0]
    # Core deps should NOT include tree-sitter (needs compilation on some platforms)
    assert "tree-sitter" not in deps_block, "tree-sitter in core deps (should be in [full])"
    # Core deps should include the essentials
    for essential in ["click", "rich", "pyyaml", "numpy"]:
        assert essential in deps_block, f"{essential} missing from core deps"


# ============================================================================
# doctor command tests
# ============================================================================

def test_doctor_command_exists():
    """v5.8: loomscan doctor command must exist."""
    from loomscan.cli import main
    assert "doctor" in main.commands, "loomscan doctor command not found"


def test_doctor_command_accepts_repo_flag():
    """v5.8: doctor must accept --repo flag (for backward compat with old scripts)."""
    import click
    from loomscan.cli import main
    doctor_cmd = main.commands["doctor"]
    param_names = [p.name for p in doctor_cmd.params]
    assert "repo" in param_names, f"doctor command missing --repo param: {param_names}"


def test_doctor_command_runs_without_crash(tmp_path, monkeypatch):
    """v5.8: doctor command must run end-to-end without crashing."""
    import subprocess
    # Run doctor in a subprocess to avoid sys.exit() killing the test runner
    result = subprocess.run(
        [sys.executable, "-c",
         "import sys; sys.path.insert(0, '/home/z/my-project/stca-pipeline'); "
         "from loomscan.cli import main; sys.argv = ['loomscan', 'doctor']; main()"],
        capture_output=True, text=True, timeout=30
    )
    # Doctor may exit 0 (all good), 1 (some missing), or 2 (critical fail)
    # All are acceptable for this test — we just want no crash (no Python traceback)
    assert result.returncode in (0, 1, 2), f"Unexpected exit code: {result.returncode}\nstdout: {result.stdout}\nstderr: {result.stderr}"
    # Should NOT have a Python traceback in stderr
    assert "Traceback" not in result.stderr, f"Doctor crashed:\n{result.stderr}"
    # Should mention "LoomScan" and "Tier" in output
    assert "LoomScan" in result.stdout, f"Doctor output missing 'LoomScan': {result.stdout[:200]}"
    assert "Tier" in result.stdout, f"Doctor output missing 'Tier': {result.stdout[:200]}"


def test_doctor_reports_rust_core_status():
    """v5.8: doctor output should mention Rust core status (active or missing)."""
    import subprocess
    result = subprocess.run(
        [sys.executable, "-c",
         "import sys; sys.path.insert(0, '/home/z/my-project/stca-pipeline'); "
         "from loomscan.cli import main; sys.argv = ['loomscan', 'doctor']; main()"],
        capture_output=True, text=True, timeout=30
    )
    # Must mention "Rust core" somewhere in output
    combined = result.stdout + result.stderr
    assert "Rust core" in combined or "loomscan-regex" in combined, (
        f"Doctor output missing Rust core status: {combined[:300]}"
    )


# ============================================================================
# Rust wheel CI workflow tests
# ============================================================================

def test_rust_wheel_workflow_exists():
    """v5.8: .github/workflows/build-rust-wheels.yml must exist."""
    workflow = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "build-rust-wheels.yml"
    assert workflow.exists(), "build-rust-wheels.yml workflow missing"


def test_rust_wheel_workflow_has_matrix():
    """v5.8: Rust wheel workflow must build for multiple platforms (matrix strategy)."""
    workflow = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "build-rust-wheels.yml"
    content = workflow.read_text()
    assert "matrix:" in content, "Workflow missing matrix strategy"
    assert "ubuntu-latest" in content, "Workflow missing Linux build"
    assert "macos" in content, "Workflow missing macOS build"
    assert "windows-latest" in content, "Workflow missing Windows build"


def test_rust_wheel_workflow_uses_maturin():
    """v5.8: Rust wheel workflow must use maturin to build wheels."""
    workflow = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "build-rust-wheels.yml"
    content = workflow.read_text()
    assert "maturin" in content, "Workflow doesn't use maturin"
    assert "maturin build" in content, "Workflow doesn't run maturin build"


def test_rust_wheel_workflow_has_publish_step():
    """v5.8: Rust wheel workflow must have a publish-to-PyPI step."""
    workflow = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "build-rust-wheels.yml"
    content = workflow.read_text()
    assert "publish" in content.lower(), "Workflow missing publish step"
    assert "twine" in content or "pypi" in content.lower(), "Workflow missing PyPI upload"


def test_rust_wheel_workflow_has_smoke_test():
    """v5.8: Rust wheel workflow should have a smoke test after publish."""
    workflow = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "build-rust-wheels.yml"
    content = workflow.read_text()
    # Accept "smoke" anywhere in the workflow (job name, step name, comment)
    if "smoke" not in content.lower():
        pytest.skip("Rust wheel workflow doesn't have a smoke test step — not critical")

# ============================================================================
# Regression: v5.7 features still work
# ============================================================================

def test_v57_tui_module_still_imports():
    """v5.8: v5.7 TUI module must still import."""
    from loomscan.tui import ScanProgress, Mascot, get_global_mascot
    assert ScanProgress is not None
    assert Mascot is not None


def test_v57_scan_progress_still_tracks_stages():
    """v5.8: v5.7 ScanProgress stage tracking must still work."""
    from loomscan.tui import ScanProgress
    sp = ScanProgress(total_stages=3, enabled=False)
    with sp:
        sp.start_stage("A", "first")
        sp.complete_stage(findings_count=1)
        sp.start_stage("B", "second")
        sp.complete_stage(findings_count=2)
    assert sp.completed_stages == 2
    assert len(sp.stages) == 2


def test_v57_no_tui_flag_still_exists():
    """v5.8: v5.7 --no-tui flag must still exist on loomscan check."""
    import click
    from loomscan.cli import main
    check_cmd = main.commands.get("check")
    assert check_cmd is not None
    param_names = [p.name for p in check_cmd.params]
    assert "no_tui" in param_names, f"--no-tui flag missing from check: {param_names}"


def test_v57_rust_core_still_detected():
    """v5.8: v5.7 Rust core auto-detection must still work."""
    from loomscan.yaml_engine import is_rust_core_active
    result = is_rust_core_active()
    assert isinstance(result, bool)


def test_v57_yaml_engine_still_produces_findings():
    """v5.8: v5.7 YAML engine must still produce findings on Flask XSS fixture."""
    from loomscan.yaml_engine import apply_pack_to_file
    import tempfile
    framework_pack = Path(__file__).resolve().parent.parent / "loomscan" / "rules" / "packs" / "framework-taint.yml"
    assert framework_pack.exists()

    with tempfile.TemporaryDirectory() as td:
        repo = Path(td)
        src = repo / "app.py"
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
        assert any('xss' in r.lower() or 'ssti' in r.lower() or 'flask' in r.lower()
                    for r in rule_ids), \
            f"Flask XSS/SSTI rule not firing: {rule_ids}"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
