"""Strictness levels — progressive onboarding (PHPStan-inspired).

PHPStan has 9 levels (0-9). Users start at level 0 (basic checks) and
gradually increase as they fix issues. This is the #1 reason PHPStan has
high adoption — you don't have to fix everything at once.

LoomScan's strictness levels:

  Level 1 — Critical only (CRITICAL severity, BLOCK decision only)
    - Only genuinely dangerous findings block
    - Good for: first-time users, legacy codebases

  Level 2 — Critical + High
    - Adds HIGH severity findings
    - Good for: teams that want to catch serious bugs

  Level 3 — + Supply chain
    - Adds L0b (dependency CVEs), L0c (dependency health)
    - Good for: teams that care about supply chain

  Level 4 — + Code quality
    - Adds L0d (behavioral/hotspots), L0f (commit risk)
    - Good for: teams that want to reduce technical debt

  Level 5 — + IaC + secrets
    - Adds L0e (IaC scanning), advanced secret detection
    - Good for: teams with infrastructure code

  Level 6 — + Taint analysis
    - Adds CPG cross-file taint tracking, Pysa
    - Good for: web apps with injection risks

  Level 7 — + Typestate + metamorphic
    - Adds typestate analysis, metamorphic testing, differential testing
    - Good for: teams that want deep semantic analysis

  Level 8 — + Symbolic + mutation
    - Adds L6 (Kani symbolic verification), L2 (mutation testing)
    - Good for: critical code (auth, crypto, payment)

  Level 9 — Everything, strict
    - All layers, all rules, no suppressions (except inline)
    - Treats WARN as BLOCK
    - Good for: regulated industries, final gate before release

The level is set in .loomscan.yaml:
    strictness: 5

Or via CLI:
    loomscan check --strictness 7
"""
from __future__ import annotations

from typing import Dict, List, Set
from dataclasses import dataclass


@dataclass
class StrictnessLevel:
    """Definition of a strictness level."""
    level: int
    name: str
    description: str
    enabled_layers: Set[str]
    enabled_severities: Set[str]  # which severities to report
    block_on: Set[str]  # which decisions block
    enable_advanced_detection: bool = False  # taint, typestate, etc.


LEVELS: Dict[int, StrictnessLevel] = {
    1: StrictnessLevel(
        level=1, name="Critical Only",
        description="Only CRITICAL findings block. Good for first-time users.",
        enabled_layers={"L0_fast", "L0b_supply", "L5_policy"},
        enabled_severities={"critical"},
        block_on={"block"},
    ),
    2: StrictnessLevel(
        level=2, name="Critical + High",
        description="Adds HIGH severity findings.",
        enabled_layers={"L0_fast", "L0b_supply", "L5_policy", "L3_invariants"},
        enabled_severities={"critical", "high"},
        block_on={"block"},
    ),
    3: StrictnessLevel(
        level=3, name="+ Supply Chain",
        description="Adds dependency CVEs and dependency health.",
        enabled_layers={"L0_fast", "L0b_supply", "L0c_deps", "L5_policy", "L3_invariants"},
        enabled_severities={"critical", "high"},
        block_on={"block"},
    ),
    4: StrictnessLevel(
        level=4, name="+ Code Quality",
        description="Adds behavioral analysis and commit risk.",
        enabled_layers={"L0_fast", "L0b_supply", "L0c_deps", "L0d_behavioral",
                        "L0f_commit", "L5_policy", "L3_invariants"},
        enabled_severities={"critical", "high", "medium"},
        block_on={"block"},
    ),
    5: StrictnessLevel(
        level=5, name="+ IaC + Secrets",
        description="Adds IaC scanning and advanced secret detection.",
        enabled_layers={"L0_fast", "L0b_supply", "L0c_deps", "L0d_behavioral",
                        "L0e_iac", "L0f_commit", "L5_policy", "L3_invariants",
                        "L1_property"},
        enabled_severities={"critical", "high", "medium", "low"},
        block_on={"block"},
    ),
    6: StrictnessLevel(
        level=6, name="+ Taint Analysis",
        description="Adds CPG cross-file taint tracking and Pysa.",
        enabled_layers={"L0_fast", "L0b_supply", "L0c_deps", "L0d_behavioral",
                        "L0e_iac", "L0f_commit", "L5_policy", "L3_invariants",
                        "L1_property"},
        enabled_severities={"critical", "high", "medium"},
        block_on={"block"},
        enable_advanced_detection=True,
    ),
    7: StrictnessLevel(
        level=7, name="+ Typestate + Metamorphic",
        description="Adds typestate, metamorphic, and differential testing.",
        enabled_layers={"L0_fast", "L0b_supply", "L0c_deps", "L0d_behavioral",
                        "L0e_iac", "L0f_commit", "L5_policy", "L3_invariants",
                        "L1_property", "L2_test_coverage"},
        enabled_severities={"critical", "high", "medium", "low"},
        block_on={"block"},
        enable_advanced_detection=True,
    ),
    8: StrictnessLevel(
        level=8, name="+ Symbolic + Mutation",
        description="Adds symbolic verification and mutation testing.",
        enabled_layers={"L0_fast", "L0b_supply", "L0c_deps", "L0d_behavioral",
                        "L0e_iac", "L0f_commit", "L5_policy", "L3_invariants",
                        "L1_property", "L2_test_coverage", "L6_symbolic", "L4_fuzz"},
        enabled_severities={"critical", "high", "medium", "low"},
        block_on={"block"},
        enable_advanced_detection=True,
    ),
    9: StrictnessLevel(
        level=9, name="Everything, Strict",
        description="All layers, all rules, WARN treated as BLOCK.",
        enabled_layers={"L0_fast", "L0b_supply", "L0c_deps", "L0d_behavioral",
                        "L0e_iac", "L0f_commit", "L5_policy", "L3_invariants",
                        "L1_property", "L2_test_coverage", "L6_symbolic", "L4_fuzz",
                        "L7_simulation"},
        enabled_severities={"critical", "high", "medium", "low", "info"},
        block_on={"block", "warn"},  # warn also blocks at level 9
        enable_advanced_detection=True,
    ),
}


def get_level(level: int) -> StrictnessLevel:
    """Get the strictness level definition. Clamps to 1-9."""
    level = max(1, min(9, level))
    return LEVELS[level]


def filter_findings_by_strictness(findings: List, level: int) -> List:
    """Filter findings based on strictness level.

    At lower levels, only high-severity findings are reported.
    """
    sl = get_level(level)
    return [f for f in findings if f.severity.value in sl.enabled_severities]


def should_block(decision: str, level: int) -> bool:
    """Check if a decision should block at a given strictness level."""
    sl = get_level(level)
    return decision in sl.block_on


def list_levels() -> List[dict]:
    """List all strictness levels for display."""
    return [
        {
            "level": sl.level,
            "name": sl.name,
            "description": sl.description,
            "layers": len(sl.enabled_layers),
            "severities": ", ".join(sorted(sl.enabled_severities)),
            "blocks_on": ", ".join(sorted(sl.block_on)),
        }
        for sl in LEVELS.values()
    ]
