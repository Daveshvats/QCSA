"""v4.22: Facade module — re-exports from v4_restored for logical separation.

v4_restored.py is a 1564-line monolith created during a loss-recovery event.
This facade provides the API surface for multi_language_testing without breaking existing
imports from v4_restored. Future development should move implementation
here; for now, this documents the intended module boundaries.

Ponytail: "Already in this codebase? Reuse it, don't rewrite."
"""
from .v4_restored import (
    generate_js_pbt_test, generate_go_pbt_test, generate_java_pbt_test,
    generate_rust_proptest, generate_cpp_fuzz_harness,
    get_dynamic_capabilities, detect_metamorphic_multi,
)

__all__ = ["generate_js_pbt_test", "generate_go_pbt_test", "generate_java_pbt_test",
           "generate_rust_proptest", "generate_cpp_fuzz_harness",
           "get_dynamic_capabilities", "detect_metamorphic_multi"]
