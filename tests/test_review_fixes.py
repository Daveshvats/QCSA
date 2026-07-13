"""Regression tests for bugs found in the Claude code review.

Each test verifies a specific bug identified in the review is now fixed.
These tests use the exact reproduction cases from the review to ensure
the bugs don't regress.
"""
import ast
import re
import tempfile
from pathlib import Path

import pytest

from loomscan.business_logic import AuthViolationDetector, BusinessStateMachineAnalyzer
from loomscan.cpg import build_cpg_for_file
from loomscan.taint_cross_file import track_taint_cross_file
from loomscan.typestate import analyze_typestate
from loomscan.layers.l8_autofix import (
    _fix_eval_python, _fix_hardcoded_password, _verify_python_parses,
    _is_eval_arg_literal,
)
from loomscan.layers.l0_fast import MINI_SAST_RULES, SECRET_PATTERNS


# === Tier 1: Auto-fix safety guards ===

class TestAutoFixSafety:
    """Tests for the auto-fix parse-verification guard."""

    def test_eval_fix_only_for_literals(self, tmp_path):
        """eval() with a literal argument should be fixed to ast.literal_eval()."""
        src = tmp_path / "app.py"
        src.write_text("def f():\n    return eval('[1, 2, 3]')\n")
        from loomscan.models import Finding, LayerID
        finding = Finding(
            layer=LayerID.L0_FAST, rule_id="L0.sast.mini:py-eval",
            message="eval()", file="app.py", start_line=2,
        )
        patch = _fix_eval_python(finding, tmp_path)
        assert patch is not None
        assert "ast.literal_eval" in patch
        # CRITICAL: the patched code must parse
        ast.parse(patch)

    def test_eval_fix_rejects_dynamic_args(self, tmp_path):
        """eval() with a variable or f-string argument must NOT be fixed."""
        from loomscan.models import Finding, LayerID

        # Variable argument
        src = tmp_path / "app.py"
        src.write_text("def f(x):\n    return eval(x)\n")
        finding = Finding(
            layer=LayerID.L0_FAST, rule_id="L0.sast.mini:py-eval",
            message="eval()", file="app.py", start_line=2,
        )
        assert _fix_eval_python(finding, tmp_path) is None

        # F-string argument (the exact case from the review)
        src.write_text("def f(name):\n    return eval(f'f\"\"\"{template}\"\"\"')\n")
        finding = Finding(
            layer=LayerID.L0_FAST, rule_id="L0.sast.mini:py-eval",
            message="eval()", file="app.py", start_line=2,
        )
        assert _fix_eval_python(finding, tmp_path) is None

    def test_password_fix_produces_valid_syntax(self, tmp_path):
        """The password fixer must produce code that parses.

        Regression test for the bug where commenting out just the `if` line
        left the indented body, causing a SyntaxError.
        """
        src = tmp_path / "app.py"
        src.write_text(
            'def check(user_input):\n'
            '    password = user_input\n'
            '    if password == "admin123":\n'
            '        print("authenticated")\n'
            '        return True\n'
            '    return False\n'
        )
        from loomscan.models import Finding, LayerID
        finding = Finding(
            layer=LayerID.L0_FAST, rule_id="L0.sast.mini:py-hardcoded-password",
            message="hardcoded password", file="app.py", start_line=3,
        )
        patch = _fix_hardcoded_password(finding, tmp_path)
        assert patch is not None
        # CRITICAL: the patched code must parse without SyntaxError
        ast.parse(patch)
        # Both the if-line and body should be commented out
        assert '# if password == "admin123":' in patch
        assert '# print("authenticated")' in patch
        assert '# return True' in patch

    def test_verify_python_parses_catches_broken_code(self):
        """The parse verifier should reject broken Python."""
        assert _verify_python_parses("x = 1") is True
        assert _verify_python_parses("def f():\n    return 1") is True
        assert _verify_python_parses("if True:\nprint('broken')") is False
        assert _verify_python_parses("def f(") is False

    def test_is_eval_arg_literal_detection(self):
        """The literal argument detector should correctly identify literals."""
        assert _is_eval_arg_literal("'[1, 2, 3]'") is True
        assert _is_eval_arg_literal("123") is True
        assert _is_eval_arg_literal("['a', 'b']") is True
        assert _is_eval_arg_literal("None") is True
        assert _is_eval_arg_literal("True") is True

        # Non-literals should be rejected
        assert _is_eval_arg_literal("x") is False  # variable
        assert _is_eval_arg_literal("f'{x}'") is False  # f-string
        assert _is_eval_arg_literal("foo(x)") is False  # function call
        assert _is_eval_arg_literal("x + y") is False  # binary op


# === Tier 1d: AuthViolationDetector ===

class TestAuthViolationDetector:
    """Tests for the fixed AuthViolationDetector.

    The old version was 100% non-functional because it matched regexes
    requiring '(' against bare method names (which never contain '(').
    """

    def test_detects_delete_without_auth(self, tmp_path):
        """Should flag delete_account() with no auth check."""
        src = tmp_path / "app.py"
        src.write_text("""
def delete_account(user_id):
    db.delete(user_id)
""")
        detector = AuthViolationDetector()
        violations = detector.analyze_file(src)
        assert len(violations) >= 1
        assert any("delete" in v.description.lower() for v in violations)

    def test_detects_grant_without_auth(self, tmp_path):
        """Should flag grant_privilege() with no auth check."""
        src = tmp_path / "app.py"
        src.write_text("""
def grant_privilege(user_id, role):
    db.update_role(user_id, role)
""")
        detector = AuthViolationDetector()
        violations = detector.analyze_file(src)
        assert len(violations) >= 1

    def test_detects_refund_without_auth(self, tmp_path):
        """Should flag refund_payment() with no auth check."""
        src = tmp_path / "app.py"
        src.write_text("""
def refund_payment(payment_id):
    payment.refund(payment_id)
""")
        detector = AuthViolationDetector()
        violations = detector.analyze_file(src)
        assert len(violations) >= 1

    def test_does_not_flag_with_auth_decorator(self, tmp_path):
        """Should NOT flag functions with @login_required decorator."""
        src = tmp_path / "app.py"
        src.write_text("""
@login_required
def delete_with_auth(user_id):
    db.delete(user_id)
""")
        detector = AuthViolationDetector()
        violations = detector.analyze_file(src)
        assert not any("delete_with_auth" in v.description for v in violations)

    def test_does_not_flag_with_auth_call(self, tmp_path):
        """Should NOT flag functions that call check_auth() etc."""
        src = tmp_path / "app.py"
        src.write_text("""
def delete_with_check(user_id):
    if not current_user.is_authenticated:
        raise PermissionError()
    db.delete(user_id)
""")
        detector = AuthViolationDetector()
        violations = detector.analyze_file(src)
        assert not any("delete_with_check" in v.description for v in violations)


# === Tier 2a: Typestate type-awareness ===

class TestTypestateTypeAware:
    """Tests for the type-aware typestate analyzer.

    The old version matched protocols purely on method name, causing false
    positives on dict.get(), cache.get(), etc.
    """

    def test_no_false_positive_on_dict_get(self, tmp_path):
        """dict.get() and cache.get() must NOT be flagged as session_like violations."""
        src = tmp_path / "app.py"
        src.write_text("""
def sync_data(api_client, cache):
    data = api_client.get("/users")
    cache.get("key")
    api_client.post("/sync", data=data)
    return data
""")
        violations = analyze_typestate(src)
        assert len(violations) == 0

    def test_no_false_positive_on_executor(self, tmp_path):
        """executor.execute()/commit() must NOT be flagged as connection_like."""
        src = tmp_path / "app.py"
        src.write_text("""
def run_task(executor):
    executor.execute()
    executor.commit()
""")
        violations = analyze_typestate(src)
        assert len(violations) == 0

    def test_detects_violation_with_annotation(self, tmp_path):
        """Should flag violation when type annotation is present."""
        src = tmp_path / "app.py"
        src.write_text("""
def process(conn: sqlite3.Connection):
    return conn.execute("SELECT 1")
""")
        violations = analyze_typestate(src)
        assert len(violations) >= 1

    def test_detects_use_after_close(self, tmp_path):
        """Should flag use-after-close when type evidence exists."""
        src = tmp_path / "app.py"
        src.write_text("""
def process():
    f = open("file.txt")
    f.close()
    f.write("after close")
""")
        violations = analyze_typestate(src)
        assert any(v.violation == "close_then_use" for v in violations)


# === Tier 2b: Metamorphic testing ===

class TestMetamorphicArityAware:
    """Tests for the arity-aware metamorphic testing.

    The old version generated tests with hardcoded 1-arg templates for every
    function, causing TypeErrors that were mislabeled as "determinism violations."
    """

    def test_no_false_positive_on_two_arg_string_function(self, tmp_path):
        """A correct 2-arg string function should NOT get a determinism violation.

        The old version called concat_names(x) with one integer argument,
        got a TypeError, and mislabeled it as a "Determinism violation."
        """
        from loomscan.metamorphic import _classify_function, _get_function_arity
        import ast as _ast

        src = """
def concat_names(first, last):
    return first + " " + last
"""
        tree = _ast.parse(src)
        func = next(n for n in _ast.walk(tree) if isinstance(n, _ast.FunctionDef))
        arity = _get_function_arity(func)
        cats = _classify_function("concat_names", src, arity, ["str", "str"])

        # concat_names is arity 2, so "identity" (determinism) should NOT be added
        assert "identity" not in cats, f"identity should not be added for arity-{arity} functions"
        # concat is NOT commutative, so "commutative" should NOT be added
        assert "commutative" not in cats, "concat should not be classified as commutative"

    def test_commutative_only_for_arithmetic(self, tmp_path):
        """Only add/sum/multiply with int params should be commutative."""
        from loomscan.metamorphic import _classify_function, _get_function_arity
        import ast as _ast

        # add_numbers with int params → commutative
        src = "def add_numbers(a: int, b: int):\n    return a + b"
        tree = _ast.parse(src)
        func = next(n for n in _ast.walk(tree) if isinstance(n, _ast.FunctionDef))
        arity = _get_function_arity(func)
        cats = _classify_function("add_numbers", src, arity, ["int", "int"])
        assert "commutative" in cats

        # concat_strings with str params → NOT commutative
        src = "def concat_strings(a: str, b: str):\n    return a + b"
        tree = _ast.parse(src)
        func = next(n for n in _ast.walk(tree) if isinstance(n, _ast.FunctionDef))
        arity = _get_function_arity(func)
        cats = _classify_function("concat_strings", src, arity, ["str", "str"])
        assert "commutative" not in cats


# === Tier 2c: BusinessStateMachineAnalyzer ===

class TestBusinessStateMachine:
    """Tests for the fixed BusinessStateMachineAnalyzer.

    The old version used substring matching (causing "order" to match
    "recorder") and ast.walk (treating if/else branches as sequential).
    """

    def test_no_false_positive_on_recorder(self, tmp_path):
        """'recorder' should NOT match the 'order' state machine."""
        src = tmp_path / "app.py"
        src.write_text("""
def log_recorder_event(recorder):
    recorder.cancel()
    recorder.ship()
""")
        analyzer = BusinessStateMachineAnalyzer()
        violations = analyzer.analyze_file(src)
        assert len(violations) == 0

    def test_no_false_positive_on_if_else(self, tmp_path):
        """Mutually exclusive if/else branches should NOT be chained."""
        src = tmp_path / "app.py"
        src.write_text("""
def cancel_order(order, reason):
    if reason == "customer_request":
        order.cancel()
    else:
        order.ship()
""")
        analyzer = BusinessStateMachineAnalyzer()
        violations = analyzer.analyze_file(src)
        assert len(violations) == 0

    def test_detects_real_invalid_transition(self, tmp_path):
        """Should flag real invalid transition in linear code."""
        src = tmp_path / "app.py"
        src.write_text("""
def process_order(order):
    order.create()
    order.ship()
""")
        analyzer = BusinessStateMachineAnalyzer()
        violations = analyzer.analyze_file(src)
        assert len(violations) >= 1


# === Tier 3: CPG taint tracking ===

class TestCPGTaintTracking:
    """Tests for the fixed CPG taint engine.

    The old version had no def-use chains, so it couldn't propagate taint
    across even two sequential statements.
    """

    def test_direct_param_to_sink(self, tmp_path):
        """Should detect: param used directly as sink argument.

        This is Test 3 from the review — the simplest possible taint flow.
        The old version returned 0 flows.
        """
        src = tmp_path / "app.py"
        src.write_text("""
def get_user(user_id):
    cursor.execute(user_id)
""")
        cpg = build_cpg_for_file(src, tmp_path)
        flows = track_taint_cross_file(cpg)
        assert len(flows) >= 1
        assert flows[0].sink == "execute"
        assert "user_id" in flows[0].source

    def test_param_through_variable_to_sink(self, tmp_path):
        """Should detect: param → variable assignment → sink.

        This is Test 2 from the review. The old version returned 0 flows
        because there was no def-use chain connecting the assignment to
        the later read.
        """
        src = tmp_path / "app.py"
        src.write_text("""
def get_user(user_id):
    query = user_id
    cursor.execute(query)
""")
        cpg = build_cpg_for_file(src, tmp_path)
        flows = track_taint_cross_file(cpg)
        assert len(flows) >= 1
        assert flows[0].sink == "execute"


# === Tier 4: Regex fixes ===

class TestRegexFixes:
    """Tests for the fixed SQL injection and hardcoded password regexes."""

    def test_hardcoded_password_comparison_form(self):
        """Should match `if password == "x":` (comparison, not just assignment)."""
        pattern = next(p[0] for p in SECRET_PATTERNS if "password" in p[1].lower())
        # Assignment form
        assert re.search(pattern, 'password = "admin123"') is not None
        # Comparison form (the bug from the review)
        assert re.search(pattern, 'if password == "admin123":') is not None

    def test_sql_injection_variable_built_query(self):
        """Should match `query = f"..."` (variable-built query)."""
        sql_var_rule = next(r for r in MINI_SAST_RULES if r["id"] == "py-sql-var-fstring")
        pattern = sql_var_rule["pattern"]
        # Variable-built query (the bug from the review)
        assert re.search(pattern, 'query = f"SELECT * FROM users WHERE id = {user_id}"') is not None
        assert re.search(pattern, 'sql = f"INSERT INTO payments VALUES ({amount})"') is not None

    def test_sql_injection_direct_fstring_still_works(self):
        """The original direct f-string detection should still work."""
        sql_rule = next(r for r in MINI_SAST_RULES if r["id"] == "py-sql-string-format")
        pattern = sql_rule["pattern"]
        assert re.search(pattern, 'cursor.execute(f"SELECT * FROM users")') is not None
