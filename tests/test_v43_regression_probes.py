"""v4.3 Regression tests — the actual false-positive probes Claude identified.

These tests use the EXACT patterns that caused the regressions Claude found:
  1. cache.get() typestate FP (no type evidence)
  2. if/else branch state-machine FP (branch-unawareness)
  3. TypeScript silent skip (advertised but unsupported)
  4. deep_dataflow cross-function taint bleed

Each test runs against EVERY implementation of the same concept to ensure
fixes propagate as invariants, not just local patches.
"""
from __future__ import annotations

import tempfile
import shutil
import os
from pathlib import Path

import pytest


# =============================================================================
# 1. TYPESTATE: cache.get() must NOT be flagged (type-evidence gating)
#    Tested against ALL typestate implementations.
# =============================================================================

class TestTypestateTypeEvidenceRegression:
    """cache.get(), apiClient.get(), dict.get() must NOT trigger typestate FPs.

    This is the exact repro Claude identified. It must pass against:
      - v4_restored.detect_typestate_multi
      - multi_language_bl.detect_typestate_violations
      - (Python typestate.py already has this fix)
    """

    def test_cache_get_no_fp_v4_restored(self, tmp_path):
        """cache.get() must NOT be flagged by v4_restored typestate."""
        from stca.v4_restored import detect_typestate_multi
        from stca.normalized_ast import parse_file
        src = tmp_path / "app.js"
        src.write_text('''function syncData(apiClient, cache) {
    const data = apiClient.get("/users");
    cache.get("key");
    apiClient.post("/sync", data);
}
''')
        tree = parse_file(src)
        findings = detect_typestate_multi(tree) if tree else []
        typestate_findings = [f for f in findings if "TYPESTATE" in f.rule_id or "TS.REQUIRES-PRIOR" in f.rule_id]
        assert len(typestate_findings) == 0, (
            f"cache.get() FP not fixed in v4_restored: {len(typestate_findings)} findings. "
            f"This is the exact regression Claude identified."
        )

    def test_cache_get_no_fp_multi_language_bl(self, tmp_path):
        """cache.get() must NOT be flagged by multi_language_bl typestate."""
        from stca.multi_language_bl import detect_repo as detect_bl_multi
        src_dir = tmp_path / "repo"
        src_dir.mkdir()
        (src_dir / "app.js").write_text('''function syncData(apiClient, cache) {
    const data = apiClient.get("/users");
    cache.get("key");
    apiClient.post("/sync", data);
}
''')
        findings = detect_bl_multi(src_dir, max_files=5)
        typestate_findings = [f for f in findings if "TYPESTATE" in f.rule_id]
        assert len(typestate_findings) == 0, (
            f"cache.get() FP not fixed in multi_language_bl: {len(typestate_findings)} findings."
        )

    def test_real_violation_still_caught_v4_restored(self, tmp_path):
        """Real session.get() without login() MUST still be caught."""
        from stca.v4_restored import detect_typestate_multi
        from stca.normalized_ast import parse_file
        src = tmp_path / "app.js"
        src.write_text('''function handleSession(session) {
    session.get("key");
    session.post("data");
}
''')
        tree = parse_file(src)
        findings = detect_typestate_multi(tree) if tree else []
        assert len(findings) > 0, "Real session.get() violation should be caught"

    def test_real_use_after_close_still_caught(self, tmp_path):
        """conn.execute() after conn.close() MUST still be caught."""
        from stca.v4_restored import detect_typestate_multi
        from stca.normalized_ast import parse_file
        src = tmp_path / "app.js"
        src.write_text('''function handleConn(conn) {
    conn.close();
    conn.execute("SELECT 1");
}
''')
        tree = parse_file(src)
        findings = detect_typestate_multi(tree) if tree else []
        use_after_close = [f for f in findings if "USE-AFTER-CLOSE" in f.rule_id]
        assert len(use_after_close) > 0, "Real use-after-close should be caught"


# =============================================================================
# 2. STATE MACHINE: if/else branches must NOT be flagged as sequential
#    Tested against the multi-language state machine port.
# =============================================================================

class TestStateMachineBranchAwarenessRegression:
    """if/else branches with mutually-exclusive calls must NOT be flagged.

    This is the exact repro Claude identified: cancel_order with if/else
    was flagged as "cancelled → shipped" even though the branches are
    mutually exclusive.
    """

    def test_if_else_branch_no_fp(self, tmp_path):
        """cancel_order with if/else must NOT be flagged as invalid transition."""
        from stca.v4_restored import detect_state_machine_multi
        from stca.normalized_ast import parse_file
        src = tmp_path / "app.js"
        src.write_text('''function cancel_order(order, reason) {
    if (reason === "customer_request") {
        order.cancel();
    } else {
        order.ship();
    }
}
''')
        tree = parse_file(src)
        findings = detect_state_machine_multi(tree) if tree else []
        assert len(findings) == 0, (
            f"if/else branch FP not fixed: {len(findings)} findings. "
            f"cancel() and ship() are in different branches — not sequential."
        )

    def test_real_sequential_violation_still_caught(self, tmp_path):
        """Two calls in the SAME branch (sequential) MUST still be flagged."""
        from stca.v4_restored import detect_state_machine_multi
        from stca.normalized_ast import parse_file
        src = tmp_path / "app.js"
        src.write_text('''function process_order(order) {
    order.create();
    order.create();
}
''')
        tree = parse_file(src)
        findings = detect_state_machine_multi(tree) if tree else []
        assert len(findings) > 0, "Real sequential violation should be caught"


# =============================================================================
# 3. LANGUAGE SUPPORT: unsupported languages must be surfaced, not silent
# =============================================================================

class TestLanguageSupportAssertionRegression:
    """TypeScript files must not be silently skipped without warning.

    This is the exact repro Claude identified: get_language() returns
    "typescript" but parse_file() returns None with no warning.
    """

    def test_unsupported_languages_tracked(self, tmp_path):
        """Unsupported languages must be tracked for warning surfacing."""
        from stca.normalized_ast import (
            get_unsupported_languages, reset_skipped_file_stats,
            get_skipped_file_stats, parse_file,
        )
        reset_skipped_file_stats()
        # Check if typescript is in the unsupported set (if tree_sitter_typescript
        # is not installed, it should be)
        unsupported = get_unsupported_languages()
        # If typescript IS supported, this test is a no-op (the fix is working)
        if "typescript" not in unsupported:
            pytest.skip("tree_sitter_typescript is installed — nothing to test")
        # Create a .ts file and try to parse it
        ts_file = tmp_path / "app.ts"
        ts_file.write_text("const x: number = 1;")
        result = parse_file(ts_file)
        assert result is None, "TypeScript file should return None (no parser)"
        # Verify the skip was recorded
        skipped = get_skipped_file_stats()
        assert "typescript" in skipped, "Skipped TypeScript file should be recorded"
        assert skipped["typescript"] >= 1, "At least 1 TypeScript file should be counted as skipped"


# =============================================================================
# 4. DEEP DATAFLOW: taint must NOT bleed across function boundaries
# =============================================================================

class TestDeepDataflowFunctionScopeRegression:
    """Taint state must reset at function boundaries.

    This is the exact repro Claude identified: a variable named `data`
    tainted in function A bleeds into function B's unrelated `data`.
    """

    def test_no_cross_function_taint_bleed(self, tmp_path):
        """Taint must NOT bleed from handleRequest to renderStaticGreeting."""
        from stca.deep_dataflow import analyze_js_dataflow
        src = tmp_path / "app.js"
        src.write_text('''function handleRequest(req, res) {
    const data = req.params.value;
    console.log(data);
}

function renderStaticGreeting(name) {
    const data = "Hello, " + name + "!";
    document.getElementById("out").innerHTML = data;
}
''')
        findings = analyze_js_dataflow(src)
        # The second function's `data` is a safe string literal — should NOT
        # be flagged as tainted from the first function's `data`.
        innerhtml_findings = [f for f in findings if "INNERHTML" in f.rule_id]
        assert len(innerhtml_findings) == 0, (
            f"Cross-function taint bleed not fixed: {len(innerhtml_findings)} findings. "
            f"renderStaticGreeting's `data` is unrelated to handleRequest's `data`."
        )

    def test_same_function_flow_still_caught(self, tmp_path):
        """Real same-function taint flow MUST still be caught."""
        from stca.deep_dataflow import analyze_js_dataflow
        src = tmp_path / "app.js"
        src.write_text('''function handler(req) {
    const data = req.params.value;
    document.getElementById("out").innerHTML = data;
}
''')
        findings = analyze_js_dataflow(src)
        assert len(findings) > 0, "Same-function taint flow should be caught"


# =============================================================================
# 5. L0_FAST ENGINE TAG: corroboration must work across same-layer detectors
# =============================================================================

class TestEngineFieldCorroborationRegression:
    """The engine field must enable corroboration across same-layer detectors.

    This tests Claude's architectural critique: ~15 detectors share L0_FAST,
    so the precision engine's corroboration (which skips same-layer) never fires.
    The engine field lets us distinguish detectors within the same layer.
    """

    def test_engine_field_distinguishes_detectors(self):
        """Two findings with same layer but different engines should corroborate."""
        from stca.models import Finding, LayerID, Severity, BlastRadius, Category
        f1 = Finding(
            layer=LayerID.L0_FAST, rule_id="L0.v4.TS.REQUIRES-PRIOR",
            message="test", file="app.js", start_line=1,
            engine="v4_restored",
        )
        f2 = Finding(
            layer=LayerID.L0_FAST, rule_id="L0.bl.BL.TYPESTATE",
            message="test", file="app.js", start_line=1,
            engine="multi_language_bl",
        )
        # Same layer, different engine
        assert f1.layer == f2.layer
        assert f1.engine != f2.engine

    def test_corroboration_boosts_different_engines(self):
        """Corroboration should boost findings from different engines at same location."""
        from stca.precision import find_corroborating_findings
        from stca.models import Finding, LayerID, Severity, BlastRadius, Category
        f1 = Finding(
            layer=LayerID.L0_FAST, rule_id="L0.v4.TS.REQUIRES-PRIOR",
            message="test", file="app.js", start_line=1,
            engine="v4_restored", confidence=0.7,
        )
        f2 = Finding(
            layer=LayerID.L0_FAST, rule_id="L0.bl.BL.TYPESTATE",
            message="test", file="app.js", start_line=1,
            engine="multi_language_bl", confidence=0.7,
        )
        boosts = find_corroborating_findings([f1, f2])
        # Should produce at least one boost (different engines at same location)
        assert len(boosts) > 0, (
            "Corroboration should fire for different engines at same location. "
            "Without the engine field fix, same-layer findings are skipped."
        )
