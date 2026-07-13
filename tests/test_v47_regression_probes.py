"""v4.7 Regression tests — Claude's nullness/contracts/concurrency findings.

Tests the 3 issues Claude identified in deep dive #11:
  1. nullness.py — biggest FP source in pipeline: any user function call
     treated as possibly-None (HIGH severity, 0.75 confidence, default-on)
  2. contracts.py — validation keyword matching is relevance-blind
     (FeatureFlags.check() suppresses finding for unrelated params)
  3. concurrency.py — method-name collision: collector.gather() flagged
     as asyncio.gather() without receiver-type check
"""
from __future__ import annotations

import tempfile
import os
from pathlib import Path

import pytest


# =============================================================================
# 1. NULLNESS: user function calls must NOT be treated as possibly-None
#    without interprocedural callee return-value check
# =============================================================================

class TestNullnessInterproceduralRegression:
    """Bare function calls to non-None-returning functions must NOT be flagged.

    Claude identified this as the single biggest false-positive source in
    the entire pipeline — any user-defined function call was treated as
    possibly-None, firing on the most common shape of ordinary Python code.
    """

    def test_non_none_returning_function_not_flagged(self, tmp_path):
        """get_default_config() returns a dict, never None — must NOT be flagged."""
        from loomscan.nullness import NullnessAnalyzer
        src = tmp_path / "app.py"
        src.write_text("""def get_default_config():
    \"\"\"Always returns a dict, never None - by design.\"\"\"
    return {"timeout": 30}

def process():
    config = get_default_config()
    return config["timeout"]
""")
        findings = NullnessAnalyzer().analyze_file(src)
        assert len(findings) == 0, (
            f"get_default_config() provably never returns None — should not be "
            f"flagged. Got {len(findings)} findings. This is the biggest FP "
            f"source Claude identified in the entire review."
        )

    def test_none_returning_function_still_caught(self, tmp_path):
        """maybe_get() can return None — MUST still be flagged."""
        from loomscan.nullness import NullnessAnalyzer
        src = tmp_path / "app.py"
        src.write_text("""def maybe_get():
    if condition:
        return None
    return {"data": 1}

def process():
    result = maybe_get()
    return result["data"]
""")
        findings = NullnessAnalyzer().analyze_file(src)
        assert len(findings) > 0, "maybe_get() can return None — should be flagged"

    def test_function_with_bare_return_flagged(self, tmp_path):
        """A function with bare `return` returns None — must be flagged."""
        from loomscan.nullness import NullnessAnalyzer
        src = tmp_path / "app.py"
        src.write_text("""def maybe_get(x):
    if x > 0:
        return
    return {"data": 1}

def process():
    result = maybe_get(5)
    return result["data"]
""")
        findings = NullnessAnalyzer().analyze_file(src)
        assert len(findings) > 0, "Function with bare return can return None — should be flagged"

    def test_builtin_not_flagged(self, tmp_path):
        """Builtin calls like len() must NOT be flagged (was already fixed)."""
        from loomscan.nullness import NullnessAnalyzer
        src = tmp_path / "app.py"
        src.write_text("""def process(items):
    count = len(items)
    return count.bit_length()
""")
        findings = NullnessAnalyzer().analyze_file(src)
        assert len(findings) == 0, "len() is a builtin — should not be flagged"


# =============================================================================
# 2. CONTRACTS: validation keyword must reference the function's own parameters
# =============================================================================

class TestContractsValidationRelevanceRegression:
    """Validation keywords (check, guard, validate) must reference the
    function's own parameters. Claude found that FeatureFlags.check()
    suppressed the finding for unrelated payment parameters.
    """

    def test_unrelated_check_does_not_suppress(self, tmp_path):
        """FeatureFlags.check() must NOT suppress missing-precondition finding."""
        from loomscan.v4_restored import detect_contracts_multi
        src = tmp_path / "app.py"
        src.write_text("""def process_payment(amount, currency):
    guard = FeatureFlags.check("new_payment_flow")
    if guard:
        return new_charge(amount, currency)
    return charge(amount, currency)
""")
        findings = detect_contracts_multi(src)
        contract_findings = [f for f in findings if "PRECONDITION" in f.rule_id]
        assert len(contract_findings) > 0, (
            "FeatureFlags.check() is unrelated to amount/currency validation. "
            "The missing-precondition finding should NOT be suppressed."
        )

    def test_real_param_validation_suppresses(self, tmp_path):
        """if amount <= 0: raise ValueError — real validation should suppress."""
        from loomscan.v4_restored import detect_contracts_multi
        src = tmp_path / "app.py"
        src.write_text("""def process_payment(amount, currency):
    if amount <= 0:
        raise ValueError("amount must be positive")
    if not currency:
        raise ValueError("currency required")
    return charge(amount, currency)
""")
        findings = detect_contracts_multi(src)
        contract_findings = [f for f in findings if "PRECONDITION" in f.rule_id]
        assert len(contract_findings) == 0, (
            "Real validation of amount and currency should suppress the finding."
        )

    def test_annotation_validation_suppresses(self, tmp_path):
        """Python type annotations with validation should suppress the finding.

        Note: Java parameter annotations (@NotNull, @Min) are on the signature
        line, not in the body — the detector currently only checks body lines.
        This test uses Python's inline validation with type hints instead.
        """
        from loomscan.v4_restored import detect_contracts_multi
        src = tmp_path / "app.py"
        src.write_text("""from typing import Optional

def process(data: str, amount: int) -> None:
    if data is None:
        raise ValueError("data required")
    if amount <= 0:
        raise ValueError("amount must be positive")
    return data
""")
        findings = detect_contracts_multi(src)
        contract_findings = [f for f in findings if "PRECONDITION" in f.rule_id]
        assert len(contract_findings) == 0, (
            "Real validation of data and amount should suppress the finding."
        )


# =============================================================================
# 3. CONCURRENCY: collector.gather() must NOT be flagged as asyncio.gather()
# =============================================================================

class TestConcurrencyReceiverCheckRegression:
    """gather/create_task must verify the receiver is the asyncio module.

    Claude found that collector.gather() was flagged as asyncio.gather()
    without try/except — a method-name collision with no receiver-type check.
    """

    def test_custom_gather_not_flagged(self, tmp_path):
        """collector.gather() must NOT be flagged as asyncio.gather()."""
        from loomscan.concurrency import PythonAsyncAnalyzer
        src = tmp_path / "app.py"
        src.write_text("""class MetricsCollector:
    async def gather(self, *sources):
        \"\"\"Custom async method — nothing to do with asyncio.gather().\"\"\"
        pass

async def collect_metrics(collector, sources):
    return await collector.gather(*sources)
""")
        findings = PythonAsyncAnalyzer().analyze_file(src)
        gather_findings = [f for f in findings if "GATHER" in f.rule_id]
        assert len(gather_findings) == 0, (
            f"collector.gather() is a user-defined method, not asyncio.gather(). "
            f"Got {len(gather_findings)} false positives."
        )

    def test_real_asyncio_gather_still_caught(self, tmp_path):
        """asyncio.gather() without try/except MUST still be caught."""
        from loomscan.concurrency import PythonAsyncAnalyzer
        src = tmp_path / "app.py"
        src.write_text("""import asyncio

async def handler():
    await asyncio.gather(task1(), task2())
""")
        findings = PythonAsyncAnalyzer().analyze_file(src)
        gather_findings = [f for f in findings if "GATHER" in f.rule_id]
        assert len(gather_findings) > 0, "Real asyncio.gather() should be caught"

    def test_custom_create_task_not_flagged(self, tmp_path):
        """obj.create_task() must NOT be flagged as asyncio.create_task()."""
        from loomscan.concurrency import PythonAsyncAnalyzer
        src = tmp_path / "app.py"
        src.write_text("""class TaskManager:
    def create_task(self, name):
        pass

def run(manager):
    manager.create_task("test")
""")
        findings = PythonAsyncAnalyzer().analyze_file(src)
        task_findings = [f for f in findings if "CREATE-TASK" in f.rule_id]
        assert len(task_findings) == 0, (
            f"manager.create_task() is a user-defined method, not asyncio.create_task(). "
            f"Got {len(task_findings)} false positives."
        )
