"""detekt-style per-rule configuration.

detekt allows per-rule configuration in YAML:
    complexity:
      LongMethod:
        active: true
        threshold: 60
      LongParameterList:
        active: true
        functionThreshold: 6
        constructorThreshold: 7

This module lets STCA do the same — each rule can be individually:
  - enabled/disabled
  - have its severity overridden
  - have rule-specific parameters (thresholds, patterns, etc.)

Config goes in .stca.yaml under "rules":
    rules:
      detekt-empty-catch:
        active: false
        severity: error
      lintr-line-length:
        active: true
        severity: info
        params:
          max_length: 120
      spotbugs-null-deref:
        active: true
        severity: warning
        params:
          confidence_threshold: 0.7
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Any
import yaml


@dataclass
class RuleConfig:
    """Per-rule configuration."""
    active: bool = True
    severity: Optional[str] = None  # override severity (None = use rule default)
    params: Dict[str, Any] = field(default_factory=dict)  # rule-specific parameters
    paths_include: List[str] = field(default_factory=list)  # only apply to these paths
    paths_exclude: List[str] = field(default_factory=list)  # skip these paths
    note: str = ""  # user note for why this rule is configured this way


class RuleConfigManager:
    """Manages per-rule configuration (detekt-style)."""

    def __init__(self, config_path: Optional[Path] = None):
        self.config_path = config_path
        self.rule_configs: Dict[str, RuleConfig] = {}
        if config_path and config_path.exists():
            self._load()

    def _load(self) -> None:
        try:
            raw = yaml.safe_load(self.config_path.read_text(encoding="utf-8")) or {}
            for rule_id, rule_data in (raw.get("rules") or {}).items():
                self.rule_configs[rule_id] = RuleConfig(
                    active=rule_data.get("active", True),
                    severity=rule_data.get("severity"),
                    params=rule_data.get("params", {}),
                    paths_include=rule_data.get("paths_include", []),
                    paths_exclude=rule_data.get("paths_exclude", []),
                    note=rule_data.get("note", ""),
                )
        except Exception:
            pass

    def get_rule_config(self, rule_id: str) -> RuleConfig:
        """Get config for a rule. Returns default if not configured."""
        return self.rule_configs.get(rule_id, RuleConfig())

    def is_rule_active(self, rule_id: str) -> bool:
        """Check if a rule is active (not disabled)."""
        return self.get_rule_config(rule_id).active

    def get_severity_override(self, rule_id: str) -> Optional[str]:
        """Get severity override for a rule, if any."""
        return self.get_rule_config(rule_id).severity

    def should_apply_to_file(self, rule_id: str, file_path: str) -> bool:
        """Check if a rule should apply to a given file (based on include/exclude patterns)."""
        cfg = self.get_rule_config(rule_id)
        from fnmatch import fnmatch
        if cfg.paths_include:
            if not any(fnmatch(file_path, pat) for pat in cfg.paths_include):
                return False
        if cfg.paths_exclude:
            if any(fnmatch(file_path, pat) for pat in cfg.paths_exclude):
                return False
        return True

    def get_param(self, rule_id: str, param_name: str, default: Any = None) -> Any:
        """Get a rule-specific parameter."""
        cfg = self.get_rule_config(rule_id)
        return cfg.params.get(param_name, default)

    def filter_findings(self, findings: List) -> List:
        """Filter findings based on per-rule config."""
        filtered = []
        for f in findings:
            cfg = self.get_rule_config(f.rule_id)
            if not cfg.active:
                continue
            if not self.should_apply_to_file(f.rule_id, f.file):
                continue
            # apply severity override
            if cfg.severity:
                from .models import Severity
                sev_map = {
                    "error": Severity.CRITICAL, "critical": Severity.CRITICAL,
                    "warning": Severity.HIGH, "high": Severity.HIGH,
                    "info": Severity.LOW, "low": Severity.LOW,
                }
                f.severity = sev_map.get(cfg.severity.lower(), f.severity)
            filtered.append(f)
        return filtered

    def set_rule_config(self, rule_id: str, config: RuleConfig) -> None:
        """Set config for a rule and save to file."""
        self.rule_configs[rule_id] = config
        self._save()

    def _save(self) -> None:
        if not self.config_path:
            return
        try:
            raw = yaml.safe_load(self.config_path.read_text(encoding="utf-8")) or {}
        except Exception:
            raw = {}
        raw.setdefault("rules", {})
        for rule_id, cfg in self.rule_configs.items():
            raw["rules"][rule_id] = {
                "active": cfg.active,
                "severity": cfg.severity,
                "params": cfg.params,
                "paths_include": cfg.paths_include,
                "paths_exclude": cfg.paths_exclude,
                "note": cfg.note,
            }
        self.config_path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")

    def stats(self) -> dict:
        """Return config statistics."""
        return {
            "total_configured_rules": len(self.rule_configs),
            "disabled_rules": sum(1 for c in self.rule_configs.values() if not c.active),
            "severity_overrides": sum(1 for c in self.rule_configs.values() if c.severity),
            "path_filtered_rules": sum(1 for c in self.rule_configs.values()
                                        if c.paths_include or c.paths_exclude),
        }
