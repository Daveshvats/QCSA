"""Bootstrap utilities — one-time setup that creates deterministic artifacts.

These run ONCE per function (or on demand). They use the LLM as a *compiler*:
the LLM generates artifacts (invariants, fuzz harnesses, property tests) that
are then committed to the repo and run deterministically forever after.
"""
from .invariant_inference import InvariantInferrer
from .harness_gen import HarnessGenerator
from .property_gen import PropertyTestGenerator

__all__ = ["InvariantInferrer", "HarnessGenerator", "PropertyTestGenerator"]
