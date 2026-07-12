"""v4.22: Facade module — re-exports from v4_restored for logical separation.

v4_restored.py is a 1564-line monolith created during a loss-recovery event.
This facade provides the API surface for multi_language_null without breaking existing
imports from v4_restored. Future development should move implementation
here; for now, this documents the intended module boundaries.

Ponytail: "Already in this codebase? Reuse it, don't rewrite."
"""
from .v4_restored import (
    detect_null_dereference_multi, detect_null_repo,
    _detect_null_normalized, _detect_null_py,
)

__all__ = ["detect_null_dereference_multi", "detect_null_repo"]
