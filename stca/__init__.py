"""STCA — Static + Test + Constraint Analysis pipeline.

A multi-layer bug detection pipeline that runs deterministic checks on a git diff,
aggregates findings through an interval type-2 fuzzy inference system, and
optionally invokes an LLM tie-breaker (gated by a process reward model).
"""

__version__ = "4.42.0"
