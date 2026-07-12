"""v4.22: Facade module — re-exports from v4_restored for logical separation.

v4_restored.py is a 1564-line monolith created during a loss-recovery event.
This facade provides the API surface for multi_language_typestate without breaking existing
imports from v4_restored. Future development should move implementation
here; for now, this documents the intended module boundaries.

Ponytail: "Already in this codebase? Reuse it, don't rewrite."
"""
from .v4_restored import (
    detect_typestate_multi, detect_state_machine_multi,
    detect_spec_mining_multi,
)

__all__ = ["detect_typestate_multi", "detect_state_machine_multi", "detect_spec_mining_multi"]
