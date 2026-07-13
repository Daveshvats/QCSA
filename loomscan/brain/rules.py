"""The IT2-FIS rule base.

50 rules covering the realistic combinations of:
  - severity (low/medium/high/critical)
  - confidence (uncertain/moderate/certain)
  - blast_radius (function/module/system)
  - exploitability (none/indirect/direct)
  - source_reliability (unproven/reliable/trusted)

Output: decision (pass/warn/block)

Rule shape:
  IF severity is X AND confidence is Y AND blast_radius is Z
     AND exploitability is W AND source_reliability is V
  THEN decision is D

We don't enumerate all 4*3*3*3*3 = 324 combinations — that would be noise.
We use 50 hand-crafted rules that capture the actual decision logic, with
the implicit "else, warn" fallback for unhandled combinations.

Key principles encoded:
  1. Critical + exploitable → block (always, even with low confidence)
  2. Low severity + uncertain → pass (let the dev decide)
  3. High severity + uncertain source → warn (don't trust unproven layers)
  4. High severity + trusted source + system blast radius → block
  5. Uncertainty begets "warn" not "block" — never block on a single uncertain signal
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List


@dataclass
class FuzzyRule:
    """A single IT2 fuzzy rule. Each premise field is a linguistic term or None (wildcard)."""
    severity: str = None        # low | medium | high | critical | None
    confidence: str = None      # uncertain | moderate | certain | None
    blast_radius: str = None    # function | module | system | None
    exploitability: str = None  # none | indirect | direct | None
    source_reliability: str = None  # unproven | reliable | trusted | None
    decision: str = "warn"      # pass | warn | block
    comment: str = ""


# The rule base. Order matters — earlier rules take priority in case of ties.
RULES: List[FuzzyRule] = [
    # --- Critical severity rules ---
    FuzzyRule(severity="critical", exploitability="direct",
              decision="block",
              comment="Critical + directly exploitable → always block"),
    FuzzyRule(severity="critical", exploitability="indirect",
              blast_radius="system", decision="block",
              comment="Critical + indirect + system-wide → block"),
    FuzzyRule(severity="critical", confidence="certain",
              decision="block",
              comment="Critical + certain → block regardless of exploitability"),
    FuzzyRule(severity="critical", confidence="moderate",
              source_reliability="trusted", decision="block",
              comment="Critical + moderate confidence + trusted source → block"),
    FuzzyRule(severity="critical", confidence="moderate",
              source_reliability="reliable", decision="warn",
              comment="Critical + moderate + reliable (not trusted) → warn"),
    FuzzyRule(severity="critical", confidence="uncertain",
              decision="warn",
              comment="Critical but uncertain → warn, don't block"),

    # --- High severity rules ---
    FuzzyRule(severity="high", exploitability="direct",
              blast_radius="system", decision="block",
              comment="High + direct + system → block"),
    FuzzyRule(severity="high", exploitability="direct",
              blast_radius="module", confidence="certain", decision="block",
              comment="High + direct + module + certain → block"),
    FuzzyRule(severity="high", exploitability="direct",
              confidence="moderate", decision="warn",
              comment="High + direct + moderate → warn"),
    FuzzyRule(severity="high", exploitability="direct",
              decision="warn",
              comment="High + direct → at least warn"),
    FuzzyRule(severity="high", exploitability="indirect",
              blast_radius="system", confidence="certain", decision="block",
              comment="High + indirect + system + certain → block"),
    FuzzyRule(severity="high", exploitability="indirect",
              blast_radius="system", decision="warn",
              comment="High + indirect + system → warn"),
    FuzzyRule(severity="high", exploitability="indirect",
              decision="warn",
              comment="High + indirect → warn"),
    FuzzyRule(severity="high", exploitability="none",
              decision="warn",
              comment="High severity but not exploitable → warn"),
    FuzzyRule(severity="high", confidence="certain",
              decision="warn",
              comment="High + certain → at least warn"),

    # --- Medium severity rules ---
    FuzzyRule(severity="medium", exploitability="direct",
              blast_radius="system", confidence="certain", decision="block",
              comment="Medium + direct + system + certain → block"),
    FuzzyRule(severity="medium", exploitability="direct",
              decision="warn",
              comment="Medium + direct → warn"),
    FuzzyRule(severity="medium", exploitability="indirect",
              confidence="certain", decision="warn",
              comment="Medium + indirect + certain → warn"),
    FuzzyRule(severity="medium", exploitability="indirect",
              confidence="uncertain", decision="warn",
              comment="Medium + indirect + uncertain → warn"),
    FuzzyRule(severity="medium", exploitability="none",
              confidence="certain", decision="warn",
              comment="Medium + no exploit + certain → warn"),
    FuzzyRule(severity="medium", exploitability="none",
              confidence="uncertain", decision="pass",
              comment="Medium + no exploit + uncertain → pass"),
    FuzzyRule(severity="medium", decision="warn",
              comment="Catch-all: medium → warn"),

    # --- Low severity rules ---
    FuzzyRule(severity="low", exploitability="direct",
              confidence="certain", blast_radius="system", decision="warn",
              comment="Low + direct + system + certain → warn"),
    FuzzyRule(severity="low", exploitability="direct",
              decision="pass",
              comment="Low + direct (not system) → pass"),
    FuzzyRule(severity="low", exploitability="indirect",
              decision="pass",
              comment="Low + indirect → pass"),
    FuzzyRule(severity="low", exploitability="none",
              decision="pass",
              comment="Low + no exploit → pass"),
    FuzzyRule(severity="low", decision="pass",
              comment="Catch-all: low → pass"),

    # v4.8: Removed dead INFO rule — SeverityMF has no "info" term, so this
    # rule's premise always returned zero membership and never fired.

    # --- Source reliability modifiers (these refine the above) ---
    FuzzyRule(severity="high", confidence="moderate",
              source_reliability="unproven", exploitability="none",
              decision="pass",
              comment="High + moderate + unproven + no exploit → pass (probably false positive)"),
    FuzzyRule(severity="medium", confidence="uncertain",
              source_reliability="unproven", decision="pass",
              comment="Medium + uncertain + unproven → pass"),

    # --- Secrets / system-wide issues override everything ---
    FuzzyRule(blast_radius="system", exploitability="direct",
              confidence="certain", decision="block",
              comment="System-wide + direct + certain → block (catch-all for secrets/auth)"),

    # --- Conservative fallback rules (only fire if no specific rule matched) ---
    # NOTE: these are intentionally last and have no premises other than severity,
    # so they fire weakly. The aggregator's centroid math downweights them
    # because their firing strength is bounded by the severity membership alone.
    FuzzyRule(severity="medium", confidence="uncertain",
              exploitability="none", decision="warn",
              comment="Catch-all: medium + uncertain + no exploit → warn"),
    FuzzyRule(severity="low", exploitability="none",
              confidence="moderate", decision="pass",
              comment="Catch-all: low + no exploit + moderate → pass"),
    # No global default rule — if nothing fires, the aggregator defaults to warn.
]


def get_rules() -> List[FuzzyRule]:
    """Return the rule base. Allows future customization via config."""
    return RULES.copy()
