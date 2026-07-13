"""Tests for the cross-platform fuzzing backends.

Verifies that:
1. FuzzedDataProvider consumes bytes correctly (atheris-compatible API)
2. The coverage-guided fuzzer finds crashes in buggy functions
3. The coverage-guided fuzzer does NOT flag well-behaved functions
4. L4 detects the right backend (atheris → coverage-python → random-python)
5. L4 generates valid harness code for each backend
6. L4 actually finds crashes end-to-end on simulated Windows
"""
from __future__ import annotations

import ast
import textwrap
from pathlib import Path

import pytest

from loomscan.fuzz_fallback import FuzzedDataProvider, fuzz, _generate_random_input
from loomscan.fuzz_coverage import fuzz_coverage, CoverageGuidedFuzzer
from loomscan.layers.l4_fuzz import L4Fuzz
from loomscan.models import DiffHunk, Severity


# === FuzzedDataProvider tests ===

class TestFuzzedDataProvider:
    def test_consume_bytes(self):
        fdp = FuzzedDataProvider(b"hello world")
        assert fdp.ConsumeBytes(5) == b"hello"
        assert fdp.ConsumeBytes(6) == b" world"
        assert fdp.remaining_bytes() == 0

    def test_consume_bytes_past_end(self):
        fdp = FuzzedDataProvider(b"hi")
        assert fdp.ConsumeBytes(10) == b"hi"
        assert fdp.remaining_bytes() == 0

    def test_consume_unicode(self):
        fdp = FuzzedDataProvider(b"hello")
        result = fdp.ConsumeUnicodeNoSurrogates(5)
        assert isinstance(result, str)
        assert result == "hello"

    def test_consume_unicode_invalid_utf8(self):
        fdp = FuzzedDataProvider(b"\xff\xfe\xfd")
        result = fdp.ConsumeUnicodeNoSurrogates(3)
        assert isinstance(result, str)  # should not raise

    def test_consume_int(self):
        fdp = FuzzedDataProvider(b"\x01\x00\x00\x00")
        assert fdp.ConsumeInt(4) == 1

    def test_consume_int_in_range(self):
        fdp = FuzzedDataProvider(b"\x05\x00\x00\x00")
        result = fdp.ConsumeIntInRange(1, 10)
        assert 1 <= result <= 10

    def test_consume_float(self):
        fdp = FuzzedDataProvider(b"\x00" * 8)
        result = fdp.ConsumeFloat()
        assert isinstance(result, float)
        assert 0.0 <= result < 1.0

    def test_consume_boolean(self):
        fdp = FuzzedDataProvider(b"\x01")
        assert fdp.ConsumeBoolean() is True
        fdp = FuzzedDataProvider(b"\x00")
        assert fdp.ConsumeBoolean() is False

    def test_snake_case_aliases(self):
        fdp1 = FuzzedDataProvider(b"hello")
        fdp2 = FuzzedDataProvider(b"hello")
        assert fdp1.consume_bytes(5) == fdp2.ConsumeBytes(5) == b"hello"


# === fuzz() random fuzzer tests ===

class TestRandomFuzzer:
    def test_fuzz_finds_crash_in_buggy_function(self):
        def buggy_function(data: bytes):
            fdp = FuzzedDataProvider(data)
            s = fdp.consume_unicode_no_surrogates(fdp.remaining_bytes() or 1)
            if len(s) == 0:
                raise RuntimeError("crash on empty input!")

        crash = fuzz(buggy_function, duration_seconds=1, seed=42)
        assert crash != ""
        assert "RuntimeError" in crash

    def test_fuzz_no_crash_on_well_behaved_function(self):
        def safe_function(data: bytes):
            fdp = FuzzedDataProvider(data)
            s = fdp.consume_unicode_no_surrogates(fdp.remaining_bytes() or 1)
            if s:
                return s.upper()
            return ""

        crash = fuzz(safe_function, duration_seconds=1, seed=42)
        assert crash == ""

    def test_generate_random_input_strategies(self):
        import random
        rng = random.Random(42)
        inputs = [_generate_random_input(256, rng) for _ in range(20)]
        lengths = [len(i) for i in inputs]
        assert 0 in lengths or any(l <= 8 for l in lengths)  # empty or short
        assert any(l >= 64 for l in lengths)  # long


# === fuzz_coverage() coverage-guided fuzzer tests ===

class TestCoverageGuidedFuzzer:
    def test_fuzz_coverage_finds_surface_crash(self):
        """The coverage-guided fuzzer should find a crash on empty input."""
        def function_with_surface_crash(data: bytes):
            fdp = FuzzedDataProvider(data)
            s = fdp.consume_unicode_no_surrogates(fdp.remaining_bytes() or 1)
            return s[0].upper()  # crashes on empty input → IndexError

        crash = fuzz_coverage(function_with_surface_crash, duration_seconds=2, seed=42)
        assert crash != ""
        assert "IndexError" in crash

    def test_fuzz_coverage_no_crash_on_safe_function(self):
        """The coverage-guided fuzzer should NOT find crashes in safe functions."""
        def safe_function(data: bytes):
            fdp = FuzzedDataProvider(data)
            s = fdp.consume_unicode_no_surrogates(fdp.remaining_bytes() or 1)
            if s:
                return s.upper()
            return ""

        crash = fuzz_coverage(safe_function, duration_seconds=2, seed=42)
        assert crash == ""

    def test_fuzzer_stats(self):
        """CoverageGuidedFuzzer should track stats."""
        def func(data: bytes):
            fdp = FuzzedDataProvider(data)
            s = fdp.consume_unicode_no_surrogates(fdp.remaining_bytes() or 1)
            return s.upper() if s else ""

        fuzzer = CoverageGuidedFuzzer(seed=42)
        fuzzer.fuzz(func, duration_seconds=1)
        stats = fuzzer.stats
        assert stats["iterations"] > 0
        assert stats["corpus_size"] > 0
        assert stats["coverage_branches"] > 0
        assert stats["backend"] == "coverage-guided-python"


# === L4 fuzz layer tests ===

class TestL4FuzzLayer:
    def test_l4_detects_coverage_python_when_atheris_missing(self, tmp_path, monkeypatch):
        """L4 should detect coverage-python backend when atheris is missing."""
        import builtins
        original_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "atheris":
                raise ImportError("simulated: atheris not installed")
            return original_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", mock_import)

        (tmp_path / "app.py").write_text("def foo(x):\n    return x\n")
        hunk = DiffHunk(file="app.py", start_line=1, end_line=1, function_name="foo")
        layer = L4Fuzz()
        backend = layer._detect_backend()
        assert backend == "coverage-python"

    def test_l4_generates_coverage_harness(self, tmp_path):
        """L4 should generate valid Python for the coverage-python backend."""
        (tmp_path / "app.py").write_text("def foo(x):\n    return x\n")
        hunk = DiffHunk(file="app.py", start_line=1, end_line=1, function_name="foo")
        layer = L4Fuzz()
        harness_path = layer._generate_harness(tmp_path, hunk, backend="coverage-python")

        assert harness_path.exists()
        code = harness_path.read_text()
        assert "from loomscan.fuzz_coverage import" in code
        assert "def test_one_input" in code
        assert "fuzz_coverage" in code
        ast.parse(code)  # valid Python

    def test_l4_generates_atheris_harness(self, tmp_path):
        """L4 should generate valid Python for the atheris backend."""
        (tmp_path / "app.py").write_text("def foo(x):\n    return x\n")
        hunk = DiffHunk(file="app.py", start_line=1, end_line=1, function_name="foo")
        layer = L4Fuzz()
        harness_path = layer._generate_harness(tmp_path, hunk, backend="atheris")

        assert harness_path.exists()
        code = harness_path.read_text()
        assert "import atheris" in code
        ast.parse(code)

    def test_l4_skips_non_python_files(self, tmp_path):
        """L4 should skip hunks that aren't Python files."""
        hunk = DiffHunk(file="app.js", start_line=1, end_line=1, function_name="foo")
        layer = L4Fuzz()
        findings = layer.run(tmp_path, [hunk], config=None)
        assert findings == []

    def test_l4_finds_crash_on_simulated_windows(self, tmp_path, monkeypatch):
        """End-to-end: L4 should find a crash even when atheris is missing.

        This simulates Windows/macOS by hiding atheris. The coverage-python
        backend should still find the crash.
        """
        import builtins
        original_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "atheris":
                raise ImportError("simulated Windows — no atheris")
            return original_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", mock_import)

        # Function with a surface crash (empty input → IndexError)
        (tmp_path / "app.py").write_text(textwrap.dedent("""
            def process(data):
                return data[0].upper()
        """))

        hunk = DiffHunk(file="app.py", start_line=2, end_line=3, function_name="process")
        layer = L4Fuzz()
        layer.DEFAULT_DURATION_SECONDS = 3  # short for test speed
        findings = layer.run(tmp_path, [hunk], config=None)

        # Should have 2 findings: backend info + crash
        assert len(findings) == 2

        # Verify backend is coverage-python (not atheris)
        backend_findings = [f for f in findings if f.rule_id == "L4.fuzz.backend"]
        assert len(backend_findings) == 1
        assert backend_findings[0].raw["backend"] == "coverage-python"

        # Verify crash was found
        crash_findings = [f for f in findings if f.rule_id == "L4.fuzz.crash"]
        assert len(crash_findings) == 1
        assert crash_findings[0].severity == Severity.CRITICAL
        assert "IndexError" in crash_findings[0].message or "IndexError" in crash_findings[0].raw.get("crash", "")
