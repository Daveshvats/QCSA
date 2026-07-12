"""Configuration profile system — luacheck + detekt inspired.

Profiles let you define named rule sets for different contexts:
  - "strict"     — all rules enabled, warnings are errors
  - "relaxed"    — only critical/high severity rules
  - "tests"      — relaxed rules for test files (allow some leniency)
  - "production" — strict for auth/payment/crypto paths
  - "legacy"     — minimal rules for legacy code you can't refactor

Profiles are defined in .stca.yaml under the "profiles" key:
    profiles:
      strict:
        extends: default
        rules:
          detekt-empty-catch: error
          detekt-broad-exception: error
      tests:
        extends: relaxed
        paths:
          - "tests/**"
          - "test_*.py"
        rules:
          lintr-line-length: off
          detekt-magic-number: off

Or use built-in profiles via CLI:
    stca check --profile strict
    stca check --profile tests
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Set, Optional
import yaml


# Built-in profiles (always available, even without config)
BUILTIN_PROFILES = {
    "minimal": {
        "description": "Only CRITICAL findings (level 1 equivalent)",
        "min_severity": "critical",
        "disabled_rule_categories": ["style", "performance", "maintainability"],
        "block_on": ["block"],
    },
    "relaxed": {
        "description": "Critical + High severity only",
        "min_severity": "high",
        "disabled_rule_categories": ["style"],
        "block_on": ["block"],
    },
    "default": {
        "description": "Balanced — all severities, all categories",
        "min_severity": "low",
        "disabled_rule_categories": [],
        "block_on": ["block"],
    },
    "strict": {
        "description": "All rules, warnings treated as errors",
        "min_severity": "info",
        "disabled_rule_categories": [],
        "block_on": ["block", "warn"],
    },
    "tests": {
        "description": "For test files — relaxed style rules",
        "min_severity": "medium",
        "disabled_rule_categories": ["style", "maintainability"],
        "disabled_rules": [
            "lintr-line-length", "detekt-magic-number", "detekt-long-parameter-list",
            "detekt-too-long-method", "spotbugs-unused-param",
        ],
        "paths": ["tests/**", "test_*.py", "*_test.py"],
        "block_on": ["block"],
    },
    "production": {
        "description": "Strict for production code (auth/crypto/payment)",
        "min_severity": "low",
        "disabled_rule_categories": [],
        "block_on": ["block", "warn"],
        "paths": ["auth/**", "crypto/**", "payment/**", "pii/**"],
    },
    "legacy": {
        "description": "Minimal rules for legacy code you can't refactor",
        "min_severity": "critical",
        "disabled_rule_categories": ["style", "maintainability", "performance"],
        "block_on": [],  # never block on legacy code
    },
}


@dataclass
class Profile:
    """A configuration profile."""
    name: str
    description: str = ""
    min_severity: str = "low"  # critical, high, medium, low, info
    disabled_rule_categories: List[str] = field(default_factory=list)
    disabled_rules: List[str] = field(default_factory=list)
    enabled_rules: List[str] = field(default_factory=list)  # overrides disabled
    paths: List[str] = field(default_factory=list)  # glob patterns this profile applies to
    block_on: List[str] = field(default_factory=lambda: ["block"])
    extends: Optional[str] = None  # parent profile name

    @classmethod
    def from_dict(cls, name: str, data: dict) -> "Profile":
        return cls(
            name=name,
            description=data.get("description", ""),
            min_severity=data.get("min_severity", "low"),
            disabled_rule_categories=data.get("disabled_rule_categories", []),
            disabled_rules=data.get("disabled_rules", []),
            enabled_rules=data.get("enabled_rules", []),
            paths=data.get("paths", []),
            block_on=data.get("block_on", ["block"]),
            extends=data.get("extends"),
        )

    def to_dict(self) -> dict:
        return {
            "description": self.description,
            "min_severity": self.min_severity,
            "disabled_rule_categories": self.disabled_rule_categories,
            "disabled_rules": self.disabled_rules,
            "enabled_rules": self.enabled_rules,
            "paths": self.paths,
            "block_on": self.block_on,
            "extends": self.extends,
        }


SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class ProfileManager:
    """Manages configuration profiles."""

    def __init__(self, config_path: Optional[Path] = None):
        self.config_path = config_path
        self.profiles: Dict[str, Profile] = {}
        self._load_builtin_profiles()
        if config_path and config_path.exists():
            self._load_custom_profiles()

    def _load_builtin_profiles(self) -> None:
        for name, data in BUILTIN_PROFILES.items():
            self.profiles[name] = Profile.from_dict(name, data)

    def _load_custom_profiles(self) -> None:
        try:
            raw = yaml.safe_load(self.config_path.read_text(encoding="utf-8")) or {}
            for name, data in (raw.get("profiles") or {}).items():
                self.profiles[name] = Profile.from_dict(name, data)
        except Exception:
            pass

    def get_profile(self, name: str) -> Optional[Profile]:
        """Get a profile by name, resolving 'extends' inheritance."""
        if name not in self.profiles:
            return None
        profile = self.profiles[name]
        if profile.extends and profile.extends in self.profiles:
            parent = self.get_profile(profile.extends)
            if parent:
                # merge: child overrides parent
                merged = Profile(
                    name=profile.name,
                    description=profile.description or parent.description,
                    min_severity=profile.min_severity if profile.min_severity != "low" else parent.min_severity,
                    disabled_rule_categories=list(set(profile.disabled_rule_categories + parent.disabled_rule_categories)),
                    disabled_rules=list(set(profile.disabled_rules + parent.disabled_rules)),
                    enabled_rules=list(set(profile.enabled_rules + parent.enabled_rules)),
                    paths=profile.paths or parent.paths,
                    block_on=profile.block_on or parent.block_on,
                )
                return merged
        return profile

    def get_profile_for_file(self, file_path: str) -> Profile:
        """Get the most specific profile for a given file path.

        If a profile has 'paths' that match, use it. Otherwise use 'default'.
        """
        from fnmatch import fnmatch
        for name in ("production", "tests", "legacy"):
            profile = self.get_profile(name)
            if profile and profile.paths:
                if any(fnmatch(file_path, pat) for pat in profile.paths):
                    return profile
        return self.get_profile("default")

    def filter_findings(self, findings: List, profile_name: str = "default") -> List:
        """Filter findings based on a profile's rules."""
        profile = self.get_profile(profile_name)
        if not profile:
            return findings

        min_sev = SEVERITY_ORDER.get(profile.min_severity, 1)
        filtered = []
        for f in findings:
            # check severity threshold
            f_sev = SEVERITY_ORDER.get(f.severity.value, 1)
            if f_sev < min_sev:
                continue
            # check disabled rules
            if f.rule_id in profile.disabled_rules and f.rule_id not in profile.enabled_rules:
                continue
            filtered.append(f)
        return filtered

    def list_profiles(self) -> List[dict]:
        """List all available profiles."""
        return [
            {
                "name": name,
                "description": p.description,
                "min_severity": p.min_severity,
                "disabled_categories": len(p.disabled_rule_categories),
                "disabled_rules": len(p.disabled_rules),
                "paths": len(p.paths),
                "extends": p.extends,
            }
            for name, p in self.profiles.items()
        ]

    def save_profile(self, name: str, profile: Profile) -> None:
        """Save a custom profile to the config file."""
        if not self.config_path:
            return
        try:
            raw = yaml.safe_load(self.config_path.read_text(encoding="utf-8")) or {}
        except Exception:
            raw = {}
        raw.setdefault("profiles", {})[name] = profile.to_dict()
        self.config_path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
        self.profiles[name] = profile
