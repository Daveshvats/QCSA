"""LLM package — optional tie-breaker only.

The LLM is NEVER in the default pipeline path. It is only invoked when:
  1. The IT2-FIS returns UNCERTAIN for a finding
  2. The user has explicitly enabled it in .loomscan.yaml
  3. The PRM (Process Reward Model) score of the LLM's reasoning exceeds threshold

This is the "LLM as compiler, not runtime" pattern — used sparingly for
high-value tie-breaking, with hallucination filtering.
"""
from .client import LLMClient
from .prm import PRMScorer

__all__ = ["LLMClient", "PRMScorer"]
