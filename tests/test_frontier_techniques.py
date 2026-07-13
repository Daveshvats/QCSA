"""Tests for v4 frontier techniques: stateful PBT, dynamic invariants,
spec mining, runtime verification, multi-call analysis, counterexamples,
and expanded metamorphic relations.
"""
import ast
import tempfile
import textwrap
from pathlib import Path

import pytest

from loomscan.stateful_pbt import discover_stateful_targets, generate_stateful_test_code
from loomscan.dynamic_invariants import infer_invariants_from_observations, InferredInvariant
from loomscan.spec_mining import mine_api_patterns, check_spec_violations, mine_and_check
from loomscan.runtime_verification import find_invariant_annotations, instrument_code_with_invariants
from loomscan.multi_call import analyze_reentrancy, analyze_missing_auth_in_chain, analyze_toctou, analyze_multi_call
from loomscan.counterexamples import generate_counterexample_for_invariant, Counterexample
from loomscan.metamorphic import _classify_function, _get_function_arity, METAMORPHIC_RELATIONS


# === 1. Stateful PBT ===

class TestStatefulPBT:
    def test_discovers_stateful_targets(self, tmp_path):
        """Should find classes with 2+ public methods and state vars."""
        src = tmp_path / "app.py"
        src.write_text("""
class ShoppingCart:
    def __init__(self):
        self.items = {}
        self.total = 0
    def add_item(self, item, qty):
        self.items[item] = self.items.get(item, 0) + qty
        self.total += qty
    def remove_item(self, item):
        if item in self.items:
            self.total -= self.items[item]
            del self.items[item]
    def checkout(self):
        result = self.total
        self.items.clear()
        self.total = 0
        return result
""")
        targets = discover_stateful_targets(src)
        assert len(targets) == 1
        class_name, _, methods, state_vars = targets[0]
        assert class_name == "ShoppingCart"
        assert "add_item" in methods
        assert "remove_item" in methods
        assert "checkout" in methods
        assert "items" in state_vars
        assert "total" in state_vars

    def test_ignores_non_stateful_classes(self, tmp_path):
        """Should NOT find classes with only 1 method or no state."""
        src = tmp_path / "app.py"
        src.write_text("""
class Helper:
    def one_method(self):
        pass
class NoState:
    def method_a(self):
        pass
    def method_b(self):
        pass
""")
        targets = discover_stateful_targets(src)
        # NoState has 2 methods but no self.X assignments
        assert len(targets) == 0

    def test_generates_valid_test_code(self, tmp_path):
        """Generated test code should be valid Python."""
        src = tmp_path / "app.py"
        src.write_text("""
class Counter:
    def __init__(self):
        self.count = 0
    def increment(self, item, qty):
        self.count += qty
    def reset(self, item, qty):
        self.count = 0
""")
        targets = discover_stateful_targets(src)
        assert len(targets) >= 1
        class_name, class_source, methods, state_vars = targets[0]
        test_code = generate_stateful_test_code(class_name, class_source, methods, state_vars, "app")
        # Should be valid Python
        ast.parse(test_code)
        assert "RuleBasedStateMachine" in test_code
        assert "increment" in test_code
        assert "reset" in test_code


# === 2. Dynamic Invariant Inference ===

class TestDynamicInvariants:
    def test_infers_positive_invariant(self):
        """Should infer 'amount > 0' when all observations are positive."""
        observations = [
            {"amount": 10, "return": 20},
            {"amount": 50, "return": 100},
            {"amount": 1, "return": 2},
        ]
        invariants = infer_invariants_from_observations(observations, "test_func")
        # Should infer amount > 0
        amount_invs = [i for i in invariants if i.variable == "amount"]
        assert len(amount_invs) >= 1
        assert any("> 0" in i.expression for i in amount_invs)

    def test_infers_constant_invariant(self):
        """Should infer 'x == c' when all values are the same."""
        observations = [
            {"mode": "production", "x": 1},
            {"mode": "production", "x": 2},
            {"mode": "production", "x": 3},
        ]
        invariants = infer_invariants_from_observations(observations, "test_func")
        mode_invs = [i for i in invariants if i.variable == "mode"]
        assert len(mode_invs) >= 1
        assert any("== 'production'" in i.expression for i in mode_invs)

    def test_infers_relationship_invariant(self):
        """Should infer 'return == input * 2' when return is always 2x input."""
        observations = [
            {"x": 5, "return": 10},
            {"x": 3, "return": 6},
            {"x": 7, "return": 14},
        ]
        invariants = infer_invariants_from_observations(observations, "test_func")
        rel_invs = [i for i in invariants if i.invariant_type == "relationship"]
        # Should find a relationship between x and return
        assert len(rel_invs) >= 1

    def test_no_invariants_with_insufficient_data(self):
        """Should return no invariants with < 2 observations."""
        observations = [{"x": 1}]
        invariants = infer_invariants_from_observations(observations, "test_func")
        assert len(invariants) == 0


# === 3. Statistical Specification Mining ===

class TestSpecMining:
    def test_mines_api_patterns(self, tmp_path):
        """Should mine common API call patterns."""
        # Create a repo with consistent patterns
        (tmp_path / "a.py").write_text("""
def process(cursor):
    cursor.connect()
    cursor.execute("SELECT 1")
    cursor.close()
""")
        (tmp_path / "b.py").write_text("""
def process2(cursor):
    cursor.connect()
    cursor.execute("SELECT 2")
    cursor.close()
""")
        patterns = mine_api_patterns(tmp_path)
        # Should find the connect → execute → close pattern
        assert "cursor" in patterns
        cursor_patterns = patterns["cursor"]
        assert any(p.sequence == ("connect", "execute", "close") for p in cursor_patterns)

    def test_detects_spec_violations(self, tmp_path):
        """Should flag call sequences that deviate from patterns."""
        # First, establish a pattern
        (tmp_path / "a.py").write_text("""
def process(cursor):
    cursor.connect()
    cursor.execute("SELECT 1")
    cursor.close()
""")
        (tmp_path / "b.py").write_text("""
def process2(cursor):
    cursor.connect()
    cursor.execute("SELECT 2")
    cursor.close()
""")
        patterns = mine_api_patterns(tmp_path)

        # Now add a violating file
        (tmp_path / "c.py").write_text("""
def bad_process(cursor):
    cursor.execute("SELECT 3")  # missing connect!
    cursor.close()
""")
        violations = check_spec_violations(tmp_path, patterns)
        assert len(violations) >= 1
        assert any("cursor" in v.object_type for v in violations)


# === 4. Runtime Verification ===

class TestRuntimeVerification:
    def test_finds_invariant_annotations(self, tmp_path):
        """Should find @invariant annotations."""
        src = tmp_path / "app.py"
        src.write_text("""
from loomscan.runtime_verification import invariant

@invariant("self.balance >= 0")
class Wallet:
    def __init__(self):
        self.balance = 0
    def deposit(self, amount):
        self.balance += amount
    def withdraw(self, amount):
        self.balance -= amount
""")
        annotations = find_invariant_annotations(src)
        assert len(annotations) >= 1
        assert annotations[0]["invariant_expr"] == "self.balance >= 0"
        assert annotations[0]["target_name"] == "Wallet"

    def test_instruments_code_with_invariant_checks(self, tmp_path):
        """Should add runtime invariant checks to methods."""
        src = tmp_path / "app.py"
        src.write_text("""
@invariant("self.balance >= 0")
class Wallet:
    def __init__(self):
        self.balance = 0
    def withdraw(self, amount):
        self.balance -= amount
""")
        instrumented = instrument_code_with_invariants(src)
        assert instrumented is not None
        # The instrumented code should have an assert checking the invariant
        assert "assert self.balance >= 0" in instrumented
        # Should be valid Python
        ast.parse(instrumented)


# === 5. Multi-Call Analysis ===

class TestMultiCallAnalysis:
    def test_detects_reentrancy(self, tmp_path):
        """Should detect reentrancy: external call before state update."""
        src = tmp_path / "app.py"
        src.write_text("""
def withdraw(wallet, amount, callback):
    callback.notify()  # external call BEFORE state update
    wallet.balance -= amount  # state update AFTER external call
""")
        violations = analyze_reentrancy(src)
        assert len(violations) >= 1
        assert violations[0].violation_type == "reentrancy"

    def test_no_reentrancy_for_safe_order(self, tmp_path):
        """Should NOT flag when state update comes before external call."""
        src = tmp_path / "app.py"
        src.write_text("""
def withdraw(wallet, amount, callback):
    wallet.balance -= amount  # state update FIRST
    callback.notify()  # external call AFTER
""")
        violations = analyze_reentrancy(src)
        assert len(violations) == 0

    def test_detects_missing_auth_in_chain(self, tmp_path):
        """Should detect sensitive action reachable without auth."""
        src = tmp_path / "app.py"
        src.write_text("""
def handle_request(user_id):
    process_user(user_id)

def process_user(user_id):
    delete_account(user_id)

def delete_account(user_id):
    db.delete(user_id)
""")
        violations = analyze_missing_auth_in_chain(src)
        # Should flag that handle_request → process_user → delete_account
        # has no auth check
        assert len(violations) >= 1
        assert violations[0].violation_type == "missing_auth_in_chain"

    def test_detects_toctou(self, tmp_path):
        """Should detect time-of-check-time-of-use patterns."""
        src = tmp_path / "app.py"
        src.write_text("""
def transfer(account, amount):
    if account.balance > amount:
        execute_transfer(account, amount)
""")
        violations = analyze_toctou(src)
        assert len(violations) >= 1
        assert violations[0].violation_type == "toctou"


# === 6. Counterexamples ===

class TestCounterexamples:
    def test_generates_counterexample(self):
        """Should find a concrete input that violates an invariant."""
        # Function: def withdraw(balance, amount): if amount > 0: return balance - amount
        # Invariant: return >= 0 (should always be non-negative)
        # Counterexample: balance=50, amount=100 → return=-50 (violates)
        func_source = """
def withdraw(balance, amount):
    if amount > 0:
        return balance - amount
    return balance
"""
        ce = generate_counterexample_for_invariant(
            func_source, "return >= 0", "withdraw", "app.py", 1
        )
        if ce is not None:  # Z3 might not be available
            assert ce.function == "withdraw"
            assert "balance" in ce.inputs
            assert "amount" in ce.inputs
            # The inputs should actually violate the invariant
            balance = ce.inputs["balance"]
            amount = ce.inputs["amount"]
            if amount > 0:
                assert balance - amount < 0, "Counterexample should violate return >= 0"

    def test_returns_none_when_no_violation_possible(self):
        """Should return None when the invariant always holds."""
        func_source = """
def safe_add(x, y):
    return x + y
"""
        # x + y >= 0 is not always true (e.g., x=-1, y=-1)
        # So this should find a counterexample, not return None
        # Let's use an invariant that CAN'T be violated
        ce = generate_counterexample_for_invariant(
            func_source, "True", "safe_add", "app.py", 1
        )
        assert ce is None  # "True" can never be violated


# === 7. Expanded Metamorphic Relations ===

class TestExpandedMetamorphic:
    def test_has_new_relations(self):
        """METAMORPHIC_RELATIONS should include the new v4 relations."""
        assert "associative" in METAMORPHIC_RELATIONS
        assert "round_trip" in METAMORPHIC_RELATIONS
        assert "inversion" in METAMORPHIC_RELATIONS
        assert "subset" in METAMORPHIC_RELATIONS
        assert "extremum" in METAMORPHIC_RELATIONS
        assert "double_inverse" in METAMORPHIC_RELATIONS
        assert "monotonic" in METAMORPHIC_RELATIONS

    def test_classifies_encode_as_round_trip(self):
        """encode functions should be classified for round-trip testing."""
        src = "def encode_data(x):\n    return x.encode('utf-8')"
        tree = ast.parse(src)
        func = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef))
        arity = _get_function_arity(func)
        cats = _classify_function("encode_data", src, arity, ["str"])
        assert "round_trip" in cats

    def test_classifies_reverse_as_double_inverse(self):
        """reverse functions should be classified for double-inverse testing."""
        src = "def reverse_list(x):\n    return x[::-1]"
        tree = ast.parse(src)
        func = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef))
        arity = _get_function_arity(func)
        cats = _classify_function("reverse_list", src, arity, ["list"])
        assert "double_inverse" in cats

    def test_classifies_max_as_extremum(self):
        """max functions should be classified for extremum testing."""
        src = "def max_value(x):\n    return max(x)"
        tree = ast.parse(src)
        func = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef))
        arity = _get_function_arity(func)
        cats = _classify_function("max_value", src, arity, ["list"])
        assert "extremum" in cats

    def test_classifies_filter_as_subset(self):
        """filter functions should be classified for subset testing."""
        src = "def filter_active(x):\n    return [i for i in x if i > 0]"
        tree = ast.parse(src)
        func = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef))
        arity = _get_function_arity(func)
        cats = _classify_function("filter_active", src, arity, ["list"])
        assert "subset" in cats

    def test_classifies_add_as_associative(self):
        """add functions with int params should be classified as associative."""
        src = "def add_numbers(a: int, b: int):\n    return a + b"
        tree = ast.parse(src)
        func = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef))
        arity = _get_function_arity(func)
        cats = _classify_function("add_numbers", src, arity, ["int", "int"])
        assert "associative" in cats
