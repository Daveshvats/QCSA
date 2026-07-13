"""Tests for multi-language business logic detection.

Tests the normalized AST layer and multi-language BL detectors.
Works with or without tree-sitter (falls back to Python ast).
"""
import tempfile
from pathlib import Path

import pytest

from loomscan.normalized_ast import (
    NormalizedNode, parse_file, get_language, is_supported, get_language
)
from loomscan.multi_language_bl import (
    detect_all, detect_auth_violations, detect_reentrancy, detect_toctou,
    detect_missing_auth_in_chain, detect_typestate_violations,
    get_capabilities, get_supported_languages, BLFinding
)


class TestNormalizedAST:
    """Tests for the normalized AST layer."""

    def test_parses_python(self, tmp_path):
        """Should parse Python files via built-in ast."""
        src = tmp_path / "app.py"
        src.write_text("def foo(x):\n    return x\n")
        tree = parse_file(src)
        assert tree is not None
        assert tree.language == "python"
        funcs = tree.find_function_defs()
        assert len(funcs) == 1
        assert funcs[0].name == "foo"

    def test_detects_language_from_extension(self, tmp_path):
        """Should detect language from file extension."""
        assert get_language(Path("app.py")) == "python"
        assert get_language(Path("app.js")) == "javascript"
        assert get_language(Path("app.go")) == "go"
        assert get_language(Path("App.java")) == "java"
        assert get_language(Path("app.c")) == "c"
        assert get_language(Path("app.cpp")) == "cpp"
        assert get_language(Path("app.rs")) == "rust"
        assert get_language(Path("app.txt")) == "unknown"

    def test_is_supported(self, tmp_path):
        """Python should always be supported; others depend on tree-sitter."""
        assert is_supported(Path("app.py")) is True
        assert is_supported(Path("app.txt")) is False

    def test_normalizes_function_def(self, tmp_path):
        """Should normalize function definitions."""
        src = tmp_path / "app.py"
        src.write_text("def compute(x, y):\n    return x + y\n")
        tree = parse_file(src)
        func = tree.find_function_defs()[0]
        assert func.kind == "function_def"
        assert func.name == "compute"
        assert "x" in func.params
        assert "y" in func.params

    def test_normalizes_calls(self, tmp_path):
        """Should normalize function calls."""
        src = tmp_path / "app.py"
        src.write_text("def f():\n    do_something(1, 2)\n")
        tree = parse_file(src)
        calls = tree.find_calls()
        assert len(calls) >= 1
        assert calls[0].name == "do_something"

    def test_normalizes_class_def(self, tmp_path):
        """Should normalize class definitions."""
        src = tmp_path / "app.py"
        src.write_text("class Wallet:\n    pass\n")
        tree = parse_file(src)
        classes = tree.find_class_defs()
        assert len(classes) == 1
        assert classes[0].name == "Wallet"

    def test_normalizes_decorators(self, tmp_path):
        """Should normalize decorators."""
        src = tmp_path / "app.py"
        src.write_text("@login_required\ndef delete(uid):\n    pass\n")
        tree = parse_file(src)
        func = tree.find_function_defs()[0]
        decs = func.find_decorators()
        assert len(decs) >= 1
        assert decs[0].decorator_name == "login_required"


class TestAuthViolationDetection:
    """Tests for multi-language auth violation detection."""

    def test_detects_delete_without_auth(self, tmp_path):
        src = tmp_path / "app.py"
        src.write_text("def delete_account(uid):\n    db.delete(uid)\n")
        tree = parse_file(src)
        findings = detect_auth_violations(tree)
        assert len(findings) >= 1
        assert "AUTH" in findings[0].rule_id

    def test_detects_refund_without_auth(self, tmp_path):
        src = tmp_path / "app.py"
        src.write_text("def refund_payment(pid):\n    payment.refund(pid)\n")
        tree = parse_file(src)
        findings = detect_auth_violations(tree)
        assert len(findings) >= 1

    def test_no_fp_with_login_required(self, tmp_path):
        src = tmp_path / "app.py"
        src.write_text("@login_required\ndef delete_safe(uid):\n    db.delete(uid)\n")
        tree = parse_file(src)
        findings = detect_auth_violations(tree)
        assert len(findings) == 0

    def test_no_fp_with_inline_auth_check(self, tmp_path):
        src = tmp_path / "app.py"
        src.write_text("""
def delete_checked(uid):
    if not current_user.is_authenticated:
        raise PermissionError()
    db.delete(uid)
""")
        tree = parse_file(src)
        findings = detect_auth_violations(tree)
        assert len(findings) == 0

    def test_no_fp_on_normal_function(self, tmp_path):
        src = tmp_path / "app.py"
        src.write_text("def process(data):\n    return data.upper()\n")
        tree = parse_file(src)
        findings = detect_auth_violations(tree)
        assert len(findings) == 0


class TestReentrancyDetection:
    """Tests for multi-language reentrancy detection."""

    def test_detects_callback_before_state_update(self, tmp_path):
        src = tmp_path / "app.py"
        src.write_text("""
def withdraw(wallet, amount, callback):
    callback.notify()
    wallet.balance -= amount
""")
        tree = parse_file(src)
        findings = detect_reentrancy(tree)
        assert len(findings) >= 1
        assert findings[0].rule_id == "BL.REENTRANCY"

    def test_no_fp_when_state_update_first(self, tmp_path):
        src = tmp_path / "app.py"
        src.write_text("""
def safe_withdraw(wallet, amount, callback):
    wallet.balance -= amount
    callback.notify()
""")
        tree = parse_file(src)
        findings = detect_reentrancy(tree)
        assert len(findings) == 0


class TestTOCTOUDetection:
    """Tests for TOCTOU detection."""

    def test_detects_check_then_act(self, tmp_path):
        src = tmp_path / "app.py"
        src.write_text("""
def transfer(account, amount):
    if account.balance > amount:
        execute_transfer(account, amount)
""")
        tree = parse_file(src)
        findings = detect_toctou(tree)
        assert len(findings) >= 1
        assert findings[0].rule_id == "BL.TOCTOU"

    def test_no_fp_without_condition(self, tmp_path):
        src = tmp_path / "app.py"
        src.write_text("def f(x):\n    do_thing(x)\n")
        tree = parse_file(src)
        findings = detect_toctou(tree)
        assert len(findings) == 0


class TestMissingAuthInChain:
    """Tests for missing auth in call chain detection."""

    def test_detects_direct_call_to_sensitive(self, tmp_path):
        src = tmp_path / "app.py"
        src.write_text("""
def handle(uid):
    delete(uid)
def delete(uid):
    db.delete(uid)
""")
        tree = parse_file(src)
        findings = detect_missing_auth_in_chain(tree)
        assert len(findings) >= 1

    def test_no_fp_with_auth_in_chain(self, tmp_path):
        src = tmp_path / "app.py"
        src.write_text("""
@login_required
def handle(uid):
    delete(uid)
def delete(uid):
    db.delete(uid)
""")
        tree = parse_file(src)
        findings = detect_missing_auth_in_chain(tree)
        # handle() has auth, so the chain is safe
        handle_findings = [f for f in findings if f.function == "handle"]
        assert len(handle_findings) == 0


class TestTypestateDetection:
    """Tests for typestate violation detection."""

    def test_detects_use_after_close(self, tmp_path):
        src = tmp_path / "app.py"
        src.write_text("""
def process():
    f = open("file.txt")
    f.close()
    f.write("after close")
""")
        tree = parse_file(src)
        findings = detect_typestate_violations(tree)
        assert any(f.rule_id == "BL.TYPESTATE-USE-AFTER-CLOSE" for f in findings)

    def test_detects_missing_open(self, tmp_path):
        src = tmp_path / "app.py"
        src.write_text("""
def process(f):
    f.write("no open")
""")
        tree = parse_file(src)
        findings = detect_typestate_violations(tree)
        assert any(f.rule_id == "BL.TYPESTATE-REQUIRES-PRIOR" for f in findings)

    def test_no_fp_on_db_delete(self, tmp_path):
        """db.delete() should NOT be flagged as typestate violation."""
        src = tmp_path / "app.py"
        src.write_text("def delete_account(uid):\n    db.delete(uid)\n")
        tree = parse_file(src)
        findings = detect_typestate_violations(tree)
        assert len(findings) == 0

    def test_no_fp_on_normal_function(self, tmp_path):
        src = tmp_path / "app.py"
        src.write_text("def process(data):\n    return data.upper()\n")
        tree = parse_file(src)
        findings = detect_typestate_violations(tree)
        assert len(findings) == 0


class TestDetectAll:
    """Tests for the unified detect_all entry point."""

    def test_detects_multiple_bug_types(self, tmp_path):
        src = tmp_path / "app.py"
        src.write_text("""
def delete_account(uid):
    db.delete(uid)

def withdraw(wallet, amount, callback):
    callback.notify()
    wallet.balance -= amount

def process():
    f = open("file.txt")
    f.close()
    f.write("after close")
""")
        findings = detect_all(src)
        rule_ids = {f.rule_id for f in findings}
        assert "BL.AUTH-NO-CHECK-DELETE" in rule_ids
        assert "BL.REENTRANCY" in rule_ids
        assert "BL.TYPESTATE-USE-AFTER-CLOSE" in rule_ids

    def test_no_fp_on_clean_code(self, tmp_path):
        src = tmp_path / "app.py"
        src.write_text("""
def process(data):
    result = data.upper()
    return result

def safe_function(x):
    if x > 0:
        return x * 2
    return 0
""")
        findings = detect_all(src)
        assert len(findings) == 0

    def test_reports_language(self, tmp_path):
        src = tmp_path / "app.py"
        src.write_text("def delete_account(uid):\n    db.delete(uid)\n")
        findings = detect_all(src)
        assert all(f.language == "python" for f in findings)


class TestCapabilities:
    """Tests for capability reporting."""

    def test_reports_supported_languages(self):
        langs = get_supported_languages()
        assert "python" in langs

    def test_reports_capabilities(self):
        caps = get_capabilities()
        assert "detectors" in caps
        assert "auth_violations" in caps["detectors"]
        assert len(caps["detectors"]) >= 5
