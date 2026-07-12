"""Configuration loader for `.stca.yaml`.

A per-repo config file controls:
  - which layers are enabled
  - per-layer tuning (timeouts, extra args)
  - file tagging (which paths are 'critical' → trigger L6/L7)
  - the LLM tie-breaker (off by default)
  - blocking policy (which decisions block the commit)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set
import os
import yaml


DEFAULT_CONFIG_NAME = ".stca.yaml"


@dataclass
class LayerConfig:
    enabled: bool = True
    timeout_seconds: int = 60
    extra_args: Dict[str, str] = field(default_factory=dict)


@dataclass
class STCAConfig:
    # layer enable flags
    layers: Dict[str, LayerConfig] = field(default_factory=dict)

    # paths tagged as critical → trigger L6/L7 symbolic verification
    critical_paths: List[str] = field(default_factory=lambda: [
        "**/auth/**", "**/crypto/**", "**/payment/**", "**/pii/**",
    ])

    # paths tagged as concurrency-critical → trigger L7 simulation
    concurrency_paths: List[str] = field(default_factory=lambda: [
        "**/concurrency/**", "**/async/**", "**/worker/**",
    ])

    # blocking policy
    block_on: List[str] = field(default_factory=lambda: ["block"])
    warn_on: List[str] = field(default_factory=lambda: ["warn"])

    # v4.37: Monorepo support — multiple workspace roots
    # When set, STCA scans each workspace as a separate logical project,
    # merging findings with workspace-prefixed paths (e.g. "apps/api/...").
    # Supports glob patterns (e.g. "packages/*") and explicit paths.
    workspaces: List[str] = field(default_factory=list)

    # v4.37: Exclude paths from monorepo scanning
    workspace_exclude: List[str] = field(default_factory=lambda: [
        "**/node_modules/**", "**/.git/**", "**/build/**", "**/dist/**",
        "**/__pycache__/**", "**/.venv/**", "**/venv/**",
    ])

    # LLM tie-breaker
    llm: Dict[str, object] = field(default_factory=lambda: {
        "enabled": False,                # off by default — pipeline is deterministic-first
        "provider": "ollama",
        "model": "qwen3-coder-1.5b",     # smallest viable coder model
        "endpoint": "http://localhost:11434",
        "prm_threshold": 0.6,            # drop LLM findings with PRM step-score < this
        "only_on_uncertain": True,       # only invoke when IT2-FIS returns UNCERTAIN
    })

    # v4.10: Brain configuration — Bayesian second opinion and per-rule tuning
    brain: Dict[str, object] = field(default_factory=lambda: {
        "enable_bayesian": False,        # off by default — opt-in second opinion
        "enable_project_tuner": False,   # off by default — opt-in per-rule tuning
        "fp_learn_mode": False,          # v4.25: Default False — don't write on every run
    })

    # external tool paths (auto-detected if not set)
    tools: Dict[str, str] = field(default_factory=dict)

    # feedback stats file
    stats_file: str = ".stca-stats.json"

    # report directory
    report_dir: str = ".stca-reports"

    @classmethod
    def default(cls) -> "STCAConfig":
        cfg = cls()
        # All layers enabled by default with sane timeouts
        for layer_id in ["L0_fast", "L1_property", "L2_test_coverage", "L3_invariants",
                         "L4_fuzz", "L5_policy", "L6_symbolic", "L7_simulation"]:
            cfg.layers[layer_id] = LayerConfig(
                enabled=(layer_id in {"L0_fast", "L1_property", "L2_test_coverage",
                                       "L3_invariants", "L5_policy"}),
                timeout_seconds={
                    "L0_fast": 10, "L1_property": 30, "L2_test_coverage": 60,
                    "L3_invariants": 5, "L4_fuzz": 60, "L5_policy": 15,
                    "L6_symbolic": 120, "L7_simulation": 300,
                }.get(layer_id, 60),
            )
        return cfg

    @classmethod
    def from_file(cls, path: Path) -> "STCAConfig":
        if not path.exists():
            return cls.default()
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return cls.from_dict(raw)

    @classmethod
    def from_dict(cls, raw: Dict) -> "STCAConfig":
        cfg = cls.default()
        if "layers" in raw:
            for layer_id, layer_raw in raw["layers"].items():
                cfg.layers[layer_id] = LayerConfig(
                    enabled=layer_raw.get("enabled", True),
                    timeout_seconds=layer_raw.get("timeout_seconds", 60),
                    extra_args=layer_raw.get("extra_args", {}),
                )
        cfg.critical_paths = raw.get("critical_paths", cfg.critical_paths)
        cfg.concurrency_paths = raw.get("concurrency_paths", cfg.concurrency_paths)
        cfg.block_on = raw.get("block_on", cfg.block_on)
        cfg.warn_on = raw.get("warn_on", cfg.warn_on)
        # v4.37: Monorepo support
        cfg.workspaces = raw.get("workspaces", cfg.workspaces)
        cfg.workspace_exclude = raw.get("workspace_exclude", cfg.workspace_exclude)
        cfg.llm.update(raw.get("llm", {}))
        cfg.tools.update(raw.get("tools", {}))
        cfg.stats_file = raw.get("stats_file", cfg.stats_file)
        cfg.report_dir = raw.get("report_dir", cfg.report_dir)
        # v4.14 BUG #1 FIX: Load brain config from YAML. Without this line,
        # enable_bayesian, enable_project_tuner, and fp_learn_mode set by
        # users in .stca.yaml are silently ignored. The entire v4.10-v4.13
        # brain wiring works in tests but is dead in production.
        cfg.brain.update(raw.get("brain", {}))
        return cfg

    def to_dict(self) -> Dict:
        return {
            "layers": {
                k: {"enabled": v.enabled, "timeout_seconds": v.timeout_seconds,
                    "extra_args": v.extra_args}
                for k, v in self.layers.items()
            },
            "critical_paths": self.critical_paths,
            "concurrency_paths": self.concurrency_paths,
            "block_on": self.block_on,
            "warn_on": self.warn_on,
            # v4.37: Monorepo support
            "workspaces": self.workspaces,
            "workspace_exclude": self.workspace_exclude,
            "llm": self.llm,
            "tools": self.tools,
            "stats_file": self.stats_file,
            "report_dir": self.report_dir,
            # v4.14: Serialize brain config so it round-trips through YAML
            "brain": self.brain,
        }

    def resolve_workspaces(self, repo_root: Path) -> List[Path]:
        """v4.37: Resolve workspace globs to actual paths.

        Supports:
          - Explicit paths: "apps/api"
          - Glob patterns: "packages/*"
          - Recursive: "services/*/*"

        Excludes paths matching workspace_exclude (supports ** for any depth).
        """
        if not self.workspaces:
            return [repo_root]  # single-workspace mode (default)
        import fnmatch
        resolved: List[Path] = []
        for pattern in self.workspaces:
            # Use glob for directory patterns
            for p in repo_root.glob(pattern):
                if not p.is_dir():
                    continue
                # Check excludes — convert ** patterns to fnmatch-compatible
                rel = str(p.relative_to(repo_root))
                excluded = False
                for exc in self.workspace_exclude:
                    # Convert glob ** to fnmatch *
                    exc_fnm = exc.replace("**/", "").replace("/**", "")
                    if fnmatch.fnmatch(rel, exc_fnm) or exc_fnm in rel:
                        excluded = True
                        break
                if excluded:
                    continue
                resolved.append(p)
        return resolved or [repo_root]

    def save(self, path: Path) -> None:
        path.write_text(yaml.safe_dump(self.to_dict(), sort_keys=False), encoding="utf-8")

    def is_critical_path(self, file_path: str) -> bool:
        from fnmatch import fnmatch
        return any(fnmatch(file_path, pat) for pat in self.critical_paths)

    def is_concurrency_path(self, file_path: str) -> bool:
        from fnmatch import fnmatch
        return any(fnmatch(file_path, pat) for pat in self.concurrency_paths)


def find_config(repo_root: Optional[Path] = None) -> Path:
    """Walk up from repo_root (or cwd) to find .stca.yaml."""
    start = repo_root or Path.cwd()
    for p in [start] + list(start.parents):
        candidate = p / DEFAULT_CONFIG_NAME
        if candidate.exists():
            return candidate
    return start / DEFAULT_CONFIG_NAME  # default path even if missing
