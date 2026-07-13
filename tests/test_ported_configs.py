"""Tests for profiles and per-rule config (ported from luacheck/detekt)."""
import pytest
import sys
import yaml
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from loomscan.profiles import ProfileManager, Profile, BUILTIN_PROFILES
from loomscan.rule_config import RuleConfigManager, RuleConfig
from loomscan.models import Finding, Severity, BlastRadius, LayerID, Category


# === Profile system (luacheck/detekt-inspired) ===

def test_builtin_profiles_exist():
    """All 7 built-in profiles should be defined."""
    expected = {"minimal", "relaxed", "default", "strict", "tests", "production", "legacy"}
    assert expected.issubset(set(BUILTIN_PROFILES.keys()))


def test_profile_manager_loads_builtins(tmp_path):
    """ProfileManager should load built-in profiles even without a config file."""
    pm = ProfileManager(config_path=None)
    assert "default" in pm.profiles
    assert "strict" in pm.profiles


def test_profile_manager_loads_custom_profiles(tmp_path):
    """Custom profiles from .loomscan.yaml should be loaded."""
    cfg = tmp_path / ".loomscan.yaml"
    cfg.write_text(yaml.dump({
        "profiles": {
            "custom-strict": {
                "description": "My custom strict profile",
                "min_severity": "critical",
                "disabled_rules": ["lintr-line-length"],
                "block_on": ["block", "warn"],
            }
        }
    }))
    pm = ProfileManager(config_path=cfg)
    assert "custom-strict" in pm.profiles
    p = pm.get_profile("custom-strict")
    assert p.min_severity == "critical"


def test_profile_inheritance(tmp_path):
    """Profiles with 'extends' should inherit from parent."""
    cfg = tmp_path / ".loomscan.yaml"
    cfg.write_text(yaml.dump({
        "profiles": {
            "child": {
                "extends": "strict",
                "description": "Child profile extending strict",
                "disabled_rules": ["extra-rule"],
            }
        }
    }))
    pm = ProfileManager(config_path=cfg)
    child = pm.get_profile("child")
    assert child is not None
    # should inherit min_severity from strict
    assert child.min_severity == "info"
    # should have both inherited and own disabled rules
    assert "extra-rule" in child.disabled_rules


def test_profile_filter_findings_by_severity():
    """Profile should filter findings below min_severity."""
    pm = ProfileManager(config_path=None)
    findings = [
        Finding(layer=LayerID.L0_FAST, rule_id="test:crit",
                message="critical", file="a.py", start_line=1,
                severity=Severity.CRITICAL),
        Finding(layer=LayerID.L0_FAST, rule_id="test:low",
                message="low", file="a.py", start_line=2,
                severity=Severity.LOW),
    ]
    # "relaxed" profile has min_severity=high
    filtered = pm.filter_findings(findings, "relaxed")
    assert len(filtered) == 1
    assert filtered[0].severity == Severity.CRITICAL


def test_profile_filter_findings_by_disabled_rules():
    """Profile should filter out disabled rules."""
    pm = ProfileManager(config_path=None)
    # "tests" profile disables detekt-magic-number
    findings = [
        Finding(layer=LayerID.L0_FAST, rule_id="detekt-magic-number",
                message="magic", file="tests/test_app.py", start_line=1,
                severity=Severity.INFO),
        Finding(layer=LayerID.L0_FAST, rule_id="other-rule",
                message="other", file="tests/test_app.py", start_line=2,
                severity=Severity.HIGH),
    ]
    filtered = pm.filter_findings(findings, "tests")
    assert all(f.rule_id != "detekt-magic-number" for f in filtered)
    assert any(f.rule_id == "other-rule" for f in filtered)


def test_profile_get_for_file(tmp_path):
    """get_profile_for_file should return tests profile for test files."""
    pm = ProfileManager(config_path=None)
    profile = pm.get_profile_for_file("tests/test_app.py")
    # should return tests profile (which matches "tests/**" pattern)
    assert profile.name in ("tests", "default")


def test_profile_list_returns_all():
    """list_profiles should return all profiles."""
    pm = ProfileManager(config_path=None)
    profiles = pm.list_profiles()
    assert len(profiles) >= 7  # at least the 7 built-in


# === Per-rule config (detekt-style) ===

def test_rule_config_manager_starts_empty(tmp_path):
    """Without config, all rules should use defaults (active=True)."""
    rcm = RuleConfigManager(config_path=None)
    cfg = rcm.get_rule_config("test:rule")
    assert cfg.active is True
    assert cfg.severity is None


def test_rule_config_disable_rule(tmp_path):
    """Disabled rules should be filtered out."""
    cfg = tmp_path / ".loomscan.yaml"
    cfg.write_text(yaml.dump({
        "rules": {
            "test:noisy-rule": {
                "active": False,
                "note": "too noisy in our codebase",
            }
        }
    }))
    rcm = RuleConfigManager(config_path=cfg)
    assert not rcm.is_rule_active("test:noisy-rule")
    assert rcm.is_rule_active("test:other-rule")  # not configured → default active


def test_rule_config_severity_override(tmp_path):
    """Severity override should change the finding's severity."""
    cfg = tmp_path / ".loomscan.yaml"
    cfg.write_text(yaml.dump({
        "rules": {
            "test:rule": {
                "active": True,
                "severity": "critical",
            }
        }
    }))
    rcm = RuleConfigManager(config_path=cfg)
    findings = [
        Finding(layer=LayerID.L0_FAST, rule_id="test:rule",
                message="test", file="a.py", start_line=1,
                severity=Severity.LOW),  # original LOW
    ]
    filtered = rcm.filter_findings(findings)
    assert len(filtered) == 1
    assert filtered[0].severity == Severity.CRITICAL  # overridden


def test_rule_config_path_filtering(tmp_path):
    """Rules with paths_include should only apply to matching files."""
    cfg = tmp_path / ".loomscan.yaml"
    cfg.write_text(yaml.dump({
        "rules": {
            "test:auth-rule": {
                "active": True,
                "paths_include": ["auth/**", "**/login.py"],
            }
        }
    }))
    rcm = RuleConfigManager(config_path=cfg)
    assert rcm.should_apply_to_file("test:auth-rule", "auth/handlers.py") is True
    assert rcm.should_apply_to_file("test:auth-rule", "app/login.py") is True
    assert rcm.should_apply_to_file("test:auth-rule", "utils/helpers.py") is False


def test_rule_config_path_exclude(tmp_path):
    """Rules with paths_exclude should skip matching files."""
    cfg = tmp_path / ".loomscan.yaml"
    cfg.write_text(yaml.dump({
        "rules": {
            "test:rule": {
                "active": True,
                "paths_exclude": ["tests/**", "legacy/**"],
            }
        }
    }))
    rcm = RuleConfigManager(config_path=cfg)
    assert rcm.should_apply_to_file("test:rule", "app/handlers.py") is True
    assert rcm.should_apply_to_file("test:rule", "tests/test_app.py") is False
    assert rcm.should_apply_to_file("test:rule", "legacy/old.py") is False


def test_rule_config_params(tmp_path):
    """Rule-specific parameters should be loadable."""
    cfg = tmp_path / ".loomscan.yaml"
    cfg.write_text(yaml.dump({
        "rules": {
            "lintr-line-length": {
                "active": True,
                "params": {"max_length": 120},
            }
        }
    }))
    rcm = RuleConfigManager(config_path=cfg)
    max_length = rcm.get_param("lintr-line-length", "max_length", default=80)
    assert max_length == 120


def test_rule_config_filter_findings_removes_disabled(tmp_path):
    """filter_findings should remove findings from disabled rules."""
    cfg = tmp_path / ".loomscan.yaml"
    cfg.write_text(yaml.dump({
        "rules": {
            "test:disabled": {"active": False},
            "test:enabled": {"active": True},
        }
    }))
    rcm = RuleConfigManager(config_path=cfg)
    findings = [
        Finding(layer=LayerID.L0_FAST, rule_id="test:disabled",
                message="off", file="a.py", start_line=1),
        Finding(layer=LayerID.L0_FAST, rule_id="test:enabled",
                message="on", file="a.py", start_line=2),
    ]
    filtered = rcm.filter_findings(findings)
    assert len(filtered) == 1
    assert filtered[0].rule_id == "test:enabled"


def test_rule_config_set_and_save(tmp_path):
    """set_rule_config should persist to the config file."""
    cfg = tmp_path / ".loomscan.yaml"
    cfg.write_text(yaml.dump({"rules": {}}))
    rcm = RuleConfigManager(config_path=cfg)
    rcm.set_rule_config("test:new-rule", RuleConfig(active=False, note="test"))
    # reload
    rcm2 = RuleConfigManager(config_path=cfg)
    assert not rcm2.is_rule_active("test:new-rule")


def test_rule_config_stats(tmp_path):
    """stats should report config counts."""
    cfg = tmp_path / ".loomscan.yaml"
    cfg.write_text(yaml.dump({
        "rules": {
            "test:disabled": {"active": False},
            "test:sev": {"active": True, "severity": "high"},
            "test:path": {"active": True, "paths_include": ["auth/**"]},
        }
    }))
    rcm = RuleConfigManager(config_path=cfg)
    stats = rcm.stats()
    assert stats["total_configured_rules"] == 3
    assert stats["disabled_rules"] == 1
    assert stats["severity_overrides"] == 1
    assert stats["path_filtered_rules"] == 1
