"""v5.4 smoke tests — Multi-lang CPG def-use chains + Incremental caching + Rename.

Tests:
1. Package renamed from stca to loomscan
2. Multi-language CPG def-use chains (JS/Java/Go)
3. Incremental CPG caching
"""
from __future__ import annotations

from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parent.parent


# =============================================================================
# 1. Package renamed from stca to loomscan
# =============================================================================

class TestLoomScanRename:
    """v5.4: Package renamed from stca to loomscan."""

    def test_loomscan_imports(self):
        from loomscan import __version__
        assert __version__ >= "5.4.0"

    def test_loomscan_cli_imports(self):
        from loomscan.cli import main
        assert callable(main)

    def test_loomscan_dir_exists(self):
        assert (PROJECT_ROOT / "loomscan").exists()
        assert not (PROJECT_ROOT / "stca").exists()

    def test_loomscan_in_pyproject(self):
        content = (PROJECT_ROOT / "pyproject.toml").read_text()
        assert 'name = "loomscan"' in content

    def test_vscode_extension_renamed(self):
        assert (PROJECT_ROOT / "editor" / "vscode-loomscan").exists()

    def test_intellij_extension_renamed(self):
        assert (PROJECT_ROOT / "editor" / "intellij-loomscan").exists()

    def test_workflows_renamed(self):
        assert (PROJECT_ROOT / ".github" / "workflows" / "loomscan.yml").exists()
        assert (PROJECT_ROOT / ".github" / "workflows" / "loomscan-bot.yml").exists()


# =============================================================================
# 2. Multi-language CPG def-use chains
# =============================================================================

class TestMultiLangCPGDefUse:
    """v5.4: CPG def-use chains for JS/Java/Go via NormalizedNode."""

    def test_def_use_chain_function_exists(self):
        """The _add_multi_lang_def_use_chains function should exist."""
        from loomscan.cpg import _add_multi_lang_def_use_chains
        assert callable(_add_multi_lang_def_use_chains)

    def test_cpg_builds_without_crash_on_js(self, tmp_path):
        """Building CPG for a JS file should not crash (may have 0 nodes if tree-sitter JS not installed)."""
        from loomscan.cpg import build_cpg_for_file_multi
        f = tmp_path / "app.js"
        f.write_text(
            "function processInput(data) {\n"
            "    var result = transform(data);\n"
            "    return eval(result);\n"
            "}\n"
        )
        cpg = build_cpg_for_file_multi(f, tmp_path)
        # May have 0 nodes if tree-sitter JS not installed, but shouldn't crash
        assert isinstance(cpg.nodes, dict)

    def test_cpg_builds_without_crash_on_go(self, tmp_path):
        """Building CPG for a Go file should not crash."""
        from loomscan.cpg import build_cpg_for_file_multi
        f = tmp_path / "main.go"
        f.write_text(
            "package main\n\n"
            "func process(data string) string {\n"
            "    result := transform(data)\n"
            "    return result\n"
            "}\n"
        )
        cpg = build_cpg_for_file_multi(f, tmp_path)
        # May have 0 nodes if tree-sitter Go not installed, but shouldn't crash
        assert isinstance(cpg.nodes, dict)

    def test_def_use_chains_produce_data_dep_edges_on_py(self, tmp_path):
        """Python CPG should have data_dep edges (existing behavior, not regressed)."""
        from loomscan.cpg import build_cpg_for_file
        f = tmp_path / "app.py"
        f.write_text(
            "def f(x):\n"
            "    y = x + 1\n"
            "    return y * 2\n"
        )
        cpg = build_cpg_for_file(f, tmp_path)
        data_dep_edges = [e for e in cpg.edges if e.kind == "data_dep"]
        assert len(data_dep_edges) > 0, "Python CPG should have data_dep edges"


# =============================================================================
# 3. Incremental CPG caching
# =============================================================================

class TestIncrementalCPGCaching:
    """v5.4: CPG is cached per-file. Second build should use cache."""

    def test_cache_dir_created(self, tmp_path):
        """Building CPG for a repo should create a cache directory."""
        from loomscan.cpg import build_cpg_for_repo_multi
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.py").write_text("x = 1\n")

        build_cpg_for_repo_multi(repo, max_files=10)
        cache_dir = repo / ".loomscan-cache" / "cpg"
        assert cache_dir.exists(), "CPG cache directory should be created"

    def test_cache_manifest_created(self, tmp_path):
        """Cache manifest.json should be created after first build."""
        from loomscan.cpg import build_cpg_for_repo_multi
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.py").write_text("x = 1\n")

        build_cpg_for_repo_multi(repo, max_files=10)
        manifest = repo / ".loomscan-cache" / "cpg" / "manifest.json"
        assert manifest.exists(), "Cache manifest should be created"

    def test_second_build_uses_cache(self, tmp_path):
        """Second build should produce same CPG (cache hit)."""
        import json
        from loomscan.cpg import build_cpg_for_repo_multi
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.py").write_text("x = 1\n")

        # First build — cache miss
        cpg1 = build_cpg_for_repo_multi(repo, max_files=10)
        nodes1 = len(cpg1.nodes)

        # Second build — should use cache
        cpg2 = build_cpg_for_repo_multi(repo, max_files=10)
        nodes2 = len(cpg2.nodes)

        assert nodes1 == nodes2, (
            f"Second build should produce same node count. "
            f"First: {nodes1}, Second: {nodes2}"
        )

    def test_changed_file_rebuilds(self, tmp_path):
        """Changing a file should invalidate its cache entry."""
        import time
        from loomscan.cpg import build_cpg_for_repo_multi
        repo = tmp_path / "repo"
        repo.mkdir()
        f = repo / "app.py"
        f.write_text("x = 1\n")

        cpg1 = build_cpg_for_repo_multi(repo, max_files=10)
        nodes1 = len(cpg1.nodes)

        # Change the file significantly (more nodes)
        time.sleep(0.1)  # ensure mtime changes
        f.write_text(
            "def f(x):\n"
            "    y = x + 1\n"
            "    z = y * 2\n"
            "    return z\n"
        )

        cpg2 = build_cpg_for_repo_multi(repo, max_files=10)
        nodes2 = len(cpg2.nodes)

        # Node count should be different (more complex code = more nodes)
        assert nodes2 > nodes1, (
            f"Changed file with more code should have more CPG nodes. "
            f"First: {nodes1}, Second: {nodes2}"
        )


# =============================================================================
# 4. Version
# =============================================================================

class TestVersionV54:
    def test_version_is_5_4(self):
        from loomscan import __version__
        major, minor = int(__version__.split(".")[0]), int(__version__.split(".")[1])
        assert major >= 5 and minor >= 4, f"Expected >= 5.4.0, got {__version__}"

    def test_pyproject_matches(self):
        from loomscan import __version__
        import re as _re
        content = (PROJECT_ROOT / "pyproject.toml").read_text()
        m = _re.search(r'^version\s*=\s*["\']([^"\']+)["\']', content, _re.MULTILINE)
        assert m
        assert m.group(1) == __version__
