"""v4.43 smoke tests — E2E tests for CLI crash fixes, dedup, and docs.

Tests:
1. stca metamorphic --file with relative path (was crashing)
2. stca strictness --level N with __strictness__ in YAML (was crashing)
3. No duplicate rule_ids across YAML packs (was 38 duplicates)
4. Stale TODO in brain/project_tuner.py removed
5. README.md and GUIDE.md are up to date
"""
from __future__ import annotations

import os
import subprocess
import sys
import yaml
from pathlib import Path
from collections import defaultdict

import pytest


PROJECT_ROOT = Path(__file__).resolve().parent.parent
PACKS_DIR = PROJECT_ROOT / "stca" / "rules" / "packs"


# =============================================================================
# 1. stca metamorphic --file relative path fix
# =============================================================================

class TestMetamorphicRelativePath:
    """v4.43: stca metamorphic --file <relative_path> was crashing.
    The path wasn't resolved against repo_root."""

    def test_metamorphic_relative_path_no_crash(self, tmp_path):
        """End-to-end: stca metamorphic --file with a relative path should
        resolve against --repo and not crash."""
        import subprocess
        repo = tmp_path / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.email", "test@test.local"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
        (repo / "app.py").write_text(
            "def add(a, b):\n"
            "    return a + b\n"
        )
        subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-qm", "init"], cwd=repo, check=True)

        env = os.environ.copy()
        env["PYTHONPATH"] = str(PROJECT_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
        # Use a relative path — this was crashing in v4.42
        proc = subprocess.run(
            [sys.executable, "-c", "from stca.cli import main; main()",
             "metamorphic", "--repo", str(repo), "--file", "app.py"],
            cwd=repo, capture_output=True, text=True, env=env, timeout=60,
        )
        # Should NOT crash with "relative_to" error
        assert "relative_to" not in proc.stderr, (
            f"metamorphic --file relative path still crashes. stderr: {proc.stderr[:500]}"
        )
        assert "Traceback" not in proc.stderr or "ValueError" not in proc.stderr, (
            f"metamorphic --file crashed. stderr: {proc.stderr[:500]}"
        )


# =============================================================================
# 2. stca strictness --level N with __strictness__ fix
# =============================================================================

class TestStrictnessLevelFix:
    """v4.43: stca strictness --level N crashed when .stca.yaml contained
    __strictness__ key in layers. Fixed by storing strictness as a
    top-level config field."""

    def test_strictness_level_no_crash_with_old_config(self, tmp_path):
        """End-to-end: setting strictness level should not crash even with
        a stale __strictness__ key in the config."""
        import subprocess
        repo = tmp_path / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        # Create a config with the old __strictness__ format (v4.42 and earlier)
        (repo / ".stca.yaml").write_text(
            "strictness: 5\n"
            "layers:\n"
            "  __strictness__:\n"
            "    level: 3\n"
        )
        subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-qm", "init"], cwd=repo, check=True)

        env = os.environ.copy()
        env["PYTHONPATH"] = str(PROJECT_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
        proc = subprocess.run(
            [sys.executable, "-c", "from stca.cli import main; main()",
             "strictness", "--repo", str(repo), "--level", "5"],
            cwd=repo, capture_output=True, text=True, env=env, timeout=30,
        )
        # Should NOT crash with AttributeError
        assert "AttributeError" not in proc.stderr, (
            f"strictness --level crashed with AttributeError. stderr: {proc.stderr[:500]}"
        )
        assert "Traceback" not in proc.stderr, (
            f"strictness --level crashed. stderr: {proc.stderr[:500]}"
        )

    def test_strictness_level_stored_as_top_level(self, tmp_path):
        """The strictness level should be stored as strictness_level, not in layers."""
        from stca.config import STCAConfig
        cfg = STCAConfig.default()
        assert hasattr(cfg, "strictness_level")
        assert cfg.strictness_level == 5  # default

    def test_config_cleans_stale_strictness(self, tmp_path):
        """from_dict should remove stale __strictness__ from layers."""
        from stca.config import STCAConfig
        cfg = STCAConfig.from_dict({
            "layers": {"__strictness__": {"level": 3}},
            "strictness_level": 7,
        })
        assert "__strictness__" not in cfg.layers
        assert cfg.strictness_level == 7


# =============================================================================
# 3. No duplicate rule_ids across YAML packs
# =============================================================================

class TestNoDuplicateRuleIds:
    """v4.43: 38 duplicate rule_ids were causing double-firing on Java findings.
    All duplicates have been renamed."""

    def test_zero_duplicate_rule_ids(self):
        """Verify NO duplicate rule_ids exist across ALL YAML packs."""
        all_ids = defaultdict(list)
        for p in sorted(PACKS_DIR.glob("*.yml")):
            with open(p) as f:
                data = yaml.safe_load(f)
            for rule in data.get("rules", []):
                rid = rule.get("id", "")
                all_ids[rid].append(p.stem)
        dupes = {k: v for k, v in all_ids.items() if len(v) > 1}
        assert len(dupes) == 0, (
            f"Found {len(dupes)} duplicate rule_ids: "
            + ", ".join(f"{k} in {v}" for k, v in sorted(dupes.items())[:5])
        )


# =============================================================================
# 4. Stale TODO removed
# =============================================================================

class TestStaleTodoRemoved:
    """v4.43: brain/project_tuner.py had a stale 'v4.9: TODO — Wire into feedback loop'
    comment, but it's been wired since v4.10."""

    def test_no_stale_todo_in_project_tuner(self):
        content = (PROJECT_ROOT / "stca" / "brain" / "project_tuner.py").read_text()
        assert "v4.9: TODO" not in content, (
            "Stale TODO 'v4.9: TODO — Wire into feedback loop' should be removed"
        )


# =============================================================================
# 5. README.md and GUIDE.md are up to date
# =============================================================================

class TestDocsUpToDate:
    """v4.43: README.md and GUIDE.md should reflect current stats."""

    def test_readme_mentions_24_languages(self):
        content = (PROJECT_ROOT / "README.md").read_text()
        assert "24" in content, "README should mention 24 languages"

    def test_readme_mentions_1995_rules(self):
        content = (PROJECT_ROOT / "README.md").read_text()
        assert "1,995" in content, "README should mention 1,995 rules"

    def test_readme_mentions_quality_gates(self):
        content = (PROJECT_ROOT / "README.md").read_text()
        assert "gate" in content.lower()
        assert "preset" in content.lower()

    def test_readme_mentions_pr_bot(self):
        content = (PROJECT_ROOT / "README.md").read_text()
        assert "bot" in content.lower()

    def test_readme_mentions_monorepo(self):
        content = (PROJECT_ROOT / "README.md").read_text()
        assert "monorepo" in content.lower()

    def test_readme_mentions_spec_mining(self):
        content = (PROJECT_ROOT / "README.md").read_text()
        assert "spec" in content.lower() and "mining" in content.lower()

    def test_readme_mentions_rule_mining(self):
        content = (PROJECT_ROOT / "README.md").read_text()
        assert "mine" in content.lower()

    def test_guide_mentions_24_languages(self):
        content = (PROJECT_ROOT / "GUIDE.md").read_text()
        assert "24" in content, "GUIDE should mention 24 languages"

    def test_guide_mentions_quality_gates(self):
        content = (PROJECT_ROOT / "GUIDE.md").read_text()
        assert "gate" in content.lower() or "Quality Gate" in content

    def test_guide_has_updated_toc(self):
        content = (PROJECT_ROOT / "GUIDE.md").read_text()
        assert "Quality Gates" in content or "quality-gates" in content.lower()


# =============================================================================
# 6. Version consistency
# =============================================================================

class TestVersionV443:
    def test_version_is_4_43(self):
        from stca import __version__
        major, minor = int(__version__.split(".")[0]), int(__version__.split(".")[1])
        assert major >= 4 and minor >= 43, f"Expected >= 4.43.0, got {__version__}"

    def test_pyproject_matches(self):
        from stca import __version__
        import re as _re
        content = (PROJECT_ROOT / "pyproject.toml").read_text()
        m = _re.search(r'^version\s*=\s*["\']([^"\']+)["\']', content, _re.MULTILINE)
        assert m
        assert m.group(1) == __version__
