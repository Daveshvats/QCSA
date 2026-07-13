"""Tests for the precision engine: rule mining, FP learning, calibration,
bug-seed cross-referencing, codebase mining."""
import pytest
import sys
import subprocess
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from loomscan.precision import (FPLearner, ConfidenceCalibrator, apply_corroboration,
                              find_corroborating_findings, apply_precision_pipeline)
from loomscan.bug_seeds import BUG_SEEDS, cross_reference_finding, boost_finding_confidence
from loomscan.codebase_miner import (mine_assertion_rules, mine_guard_rules,
                                   mine_docstring_rules, mine_all_rules)
from loomscan.rule_miner import (find_bug_fix_commits, extract_bug_fix_pairs,
                               detect_language, generate_semgrep_rule)
from loomscan.rule_compiler import mutate_function
from loomscan.models import Finding, Severity, BlastRadius, LayerID


# === Bug-seed cross-referencing ===

def test_bug_seeds_database_has_major_cwes():
    """The bug-seed database should include major CWEs."""
    assert "CWE-79" in BUG_SEEDS  # XSS
    assert "CWE-89" in BUG_SEEDS  # SQL injection
    assert "CWE-95" in BUG_SEEDS  # eval
    assert "CWE-78" in BUG_SEEDS  # OS command injection
    assert "CWE-22" in BUG_SEEDS  # path traversal
    assert "CWE-798" in BUG_SEEDS  # hardcoded creds


def test_cross_reference_finding_by_cwe():
    """Should match a finding to a bug seed by CWE."""
    f = Finding(layer=LayerID.L0_FAST, rule_id="test:sql",
                message="SQL injection", file="app.py", start_line=1,
                cwe="CWE-89")
    seed = cross_reference_finding(f)
    assert seed is not None
    assert seed.cwe == "CWE-89"


def test_cross_reference_finding_by_keyword():
    """Should match a finding to a bug seed by keyword in message."""
    f = Finding(layer=LayerID.L0_FAST, rule_id="test:eval",
                message="Use of eval() — code injection risk", file="app.py",
                start_line=1, cwe=None)
    seed = cross_reference_finding(f)
    assert seed is not None
    # pattern_keywords for CWE-95 include "eval("
    assert any("eval" in kw for kw in seed.pattern_keywords)


def test_boost_finding_confidence_increases_for_known_pattern():
    """Confidence should be boosted for a known bug pattern."""
    f = Finding(layer=LayerID.L0_FAST, rule_id="test:sql",
                message="SQL injection", file="app.py", start_line=1,
                cwe="CWE-89", confidence=0.5)
    new_conf, seed_name = boost_finding_confidence(f)
    assert new_conf > 0.5
    assert seed_name == "SQL Injection"


def test_boost_finding_confidence_unchanged_for_unknown_pattern():
    """Confidence should not change for an unknown pattern."""
    f = Finding(layer=LayerID.L0_FAST, rule_id="test:style",
                message="Bad variable name", file="app.py", start_line=1,
                cwe=None, confidence=0.5)
    new_conf, seed_name = boost_finding_confidence(f)
    assert new_conf == 0.5
    assert seed_name is None


# === FP learning ===

def test_fp_learner_starts_empty(tmp_path):
    fp = FPLearner(tmp_path)
    assert fp.stats()["total_patterns"] == 0


def test_fp_learner_records_occurrence(tmp_path):
    fp = FPLearner(tmp_path)
    fp.record_occurrence("test:rule", "app.py")
    assert fp.stats()["total_patterns"] == 1


def test_fp_learner_records_false_positive(tmp_path):
    fp = FPLearner(tmp_path)
    fp.record_false_positive("test:rule", "app.py")
    rate = fp.suppression_rate("test:rule", "app.py")
    assert rate == 1.0  # 1 occurrence, 1 FP


def test_fp_learner_auto_suppresses_after_threshold(tmp_path):
    """A rule with >50% FP rate after 5 occurrences should be auto-suppressed."""
    fp = FPLearner(tmp_path)
    # 5 occurrences, 3 FPs = 60% FP rate
    for _ in range(2):
        fp.record_occurrence("noisy:rule", "app.py")
    for _ in range(3):
        fp.record_false_positive("noisy:rule", "app.py")
    assert fp.is_suppressed("noisy:rule", "app.py")


def test_fp_learner_does_not_suppress_with_low_fp_rate(tmp_path):
    """A rule with <50% FP rate should not be suppressed."""
    fp = FPLearner(tmp_path)
    for _ in range(4):
        fp.record_occurrence("good:rule", "app.py")
    fp.record_false_positive("good:rule", "app.py")  # 20% FP rate
    assert not fp.is_suppressed("good:rule", "app.py")


def test_fp_learner_filter_suppressed(tmp_path):
    """filter_suppressed should remove auto-suppressed findings."""
    fp = FPLearner(tmp_path)
    # create a noisy rule that gets auto-suppressed
    for _ in range(2):
        fp.record_occurrence("noisy:rule", "app.py")
    for _ in range(3):
        fp.record_false_positive("noisy:rule", "app.py")

    findings = [
        Finding(layer=LayerID.L0_FAST, rule_id="noisy:rule",
                message="noise", file="app.py", start_line=1),
        Finding(layer=LayerID.L0_FAST, rule_id="good:rule",
                message="real bug", file="app.py", start_line=2),
    ]
    kept, suppressed = fp.filter_suppressed(findings)
    assert len(suppressed) == 1
    assert len(kept) == 1
    assert kept[0].rule_id == "good:rule"


# === Confidence calibration ===

def test_calibrator_starts_empty(tmp_path):
    cal = ConfidenceCalibrator(tmp_path)
    assert cal.stats()["total_data_points"] == 0


def test_calibrator_records_data(tmp_path):
    cal = ConfidenceCalibrator(tmp_path)
    cal.record(0.85, is_true_positive=True)
    cal.record(0.85, is_true_positive=False)
    assert cal.stats()["total_data_points"] == 2


def test_calibrator_returns_raw_with_insufficient_data(tmp_path):
    """With <5 data points, should return raw confidence."""
    cal = ConfidenceCalibrator(tmp_path)
    cal.record(0.85, is_true_positive=True)
    # only 1 data point — should return raw
    assert cal.calibrate(0.85) == 0.85


def test_calibrator_returns_actual_accuracy_with_sufficient_data(tmp_path):
    """With >=5 data points, should return actual accuracy."""
    cal = ConfidenceCalibrator(tmp_path)
    # 10 data points at 0.85 confidence, 5 are TPs → actual accuracy = 50%
    for _ in range(5):
        cal.record(0.85, is_true_positive=True)
    for _ in range(5):
        cal.record(0.85, is_true_positive=False)
    calibrated = cal.calibrate(0.85)
    assert abs(calibrated - 0.5) < 0.01


# === Cross-layer corroboration ===

def test_corroboration_finds_agreeing_layers():
    """Should boost confidence when multiple layers flag the same line."""
    findings = [
        Finding(layer=LayerID.L0_FAST, rule_id="L0:eval",
                message="eval", file="app.py", start_line=10, confidence=0.5),
        Finding(layer=LayerID.L5_POLICY, rule_id="L5:eval",
                message="eval policy", file="app.py", start_line=10, confidence=0.5),
    ]
    boosts = find_corroborating_findings(findings)
    assert len(boosts) >= 2  # both findings get a boost


def test_corroboration_no_boost_for_single_layer():
    """A single layer flagging a line should not get a boost."""
    findings = [
        Finding(layer=LayerID.L0_FAST, rule_id="L0:eval",
                message="eval", file="app.py", start_line=10, confidence=0.5),
    ]
    boosts = find_corroborating_findings(findings)
    assert len(boosts) == 0


def test_apply_corroboration_increases_confidence():
    """apply_corroboration should increase confidence of corroborated findings."""
    findings = [
        Finding(layer=LayerID.L0_FAST, rule_id="L0:eval",
                message="eval", file="app.py", start_line=10, confidence=0.5),
        Finding(layer=LayerID.L5_POLICY, rule_id="L5:eval",
                message="eval policy", file="app.py", start_line=10, confidence=0.5),
    ]
    original_conf = findings[0].confidence
    findings = apply_corroboration(findings)
    assert findings[0].confidence > original_conf


# === Codebase mining ===

def test_mine_assertion_rules_from_test_file(tmp_path):
    """Should mine rules from assert statements in test files."""
    test_file = tmp_path / "test_app.py"
    test_file.write_text("""
def test_add():
    assert add(1, 2) == 3
    assert add(0, 0) == 0
""")
    rules = mine_assertion_rules(test_file, tmp_path)
    assert len(rules) >= 1
    assert all(r.source == "assertion" for r in rules)


def test_mine_guard_rules(tmp_path):
    """Should mine rules from None-guard patterns."""
    src = tmp_path / "app.py"
    src.write_text("""
def process(data):
    if data is None:
        raise ValueError("data must not be None")
    return data.process()
""")
    rules = mine_guard_rules(src, tmp_path)
    assert len(rules) >= 1
    assert all(r.source == "guard" for r in rules)


def test_mine_docstring_rules(tmp_path):
    """Should mine rules from docstrings with 'must' contracts."""
    src = tmp_path / "app.py"
    src.write_text('''
def calculate(x):
    """Calculate something.

    x must be positive.
    """
    return x * 2
''')
    rules = mine_docstring_rules(src, tmp_path)
    assert len(rules) >= 1
    assert all(r.source == "docstring" for r in rules)


def test_mine_all_rules_combines_sources(tmp_path):
    """mine_all_rules should combine all mining sources."""
    test_file = tmp_path / "test_app.py"
    test_file.write_text("""
def test_add():
    assert add(1, 2) == 3
""")
    src = tmp_path / "app.py"
    src.write_text("""
def process(data):
    if data is None:
        raise ValueError("None not allowed")
    return data
""")
    rules = mine_all_rules(test_file, tmp_path)
    rules += mine_all_rules(src, tmp_path)
    sources = {r.source for r in rules}
    assert "assertion" in sources or "guard" in sources


# === Git history mining ===

def test_find_bug_fix_commits(tmp_path):
    """Should find commits with bug-fix messages."""
    subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True)
    subprocess.run(["git", "config", "user.email", "t@t.com"], cwd=tmp_path, capture_output=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=tmp_path, capture_output=True)
    (tmp_path / "f.txt").write_text("a")
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, capture_output=True)
    subprocess.run(["git", "commit", "-m", "initial"], cwd=tmp_path, capture_output=True)
    (tmp_path / "f.txt").write_text("b")
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, capture_output=True)
    subprocess.run(["git", "commit", "-m", "fix: handle None input"], cwd=tmp_path, capture_output=True)

    commits = find_bug_fix_commits(tmp_path)
    assert len(commits) >= 1
    assert any("fix" in msg.lower() for _, msg in commits)


def test_extract_bug_fix_pairs():
    """Should extract (file, removed, added) pairs from a diff."""
    diff = """diff --git a/app.py b/app.py
index abc..def 100644
--- a/app.py
+++ b/app.py
@@ -1,3 +1,3 @@
 def f(x):
-    return x + 1
+    return x + 2
"""
    pairs = extract_bug_fix_pairs(diff)
    assert len(pairs) >= 1
    file, removed, added = pairs[0]
    assert file == "app.py"
    assert "return x + 1" in removed
    assert "return x + 2" in added


def test_detect_language():
    assert detect_language("app.py") == "python"
    assert detect_language("app.js") == "javascript"
    assert detect_language("app.go") == "go"
    assert detect_language("app.java") == "java"
    assert detect_language("app.unknown") == ""


def test_generate_semgrep_rule_produces_valid_yaml():
    """Should generate valid Semgrep YAML from a bug-fix pair."""
    yaml = generate_semgrep_rule(
        rule_id="test-rule",
        bug_pattern='    return x == 1',
        fix_pattern='    return x == 2',
        language="python",
        commit_hash="abc12345",
        commit_message="fix: wrong comparison",
    )
    assert yaml is not None
    assert "test-rule" in yaml
    assert "rules:" in yaml
    assert "python" in yaml


# === Rule compiler (mutation) ===

def test_mutate_function_generates_mutants():
    """Should generate mutants for a simple function."""
    func = """
def add(a, b):
    if a == 0:
        return b
    return a + b
"""
    mutants = mutate_function(func, "python")
    assert len(mutants) > 0
    # at least one mutant should change == to !=
    assert any("!=" in m for m in mutants)


def test_mutate_function_returns_empty_for_non_python():
    """Non-Python functions should return empty (not crash)."""
    mutants = mutate_function("function f() { return 1; }", "javascript")
    assert mutants == []


# === End-to-end precision pipeline ===

def test_apply_precision_pipeline_reduces_findings(tmp_path):
    """The precision pipeline should reduce findings (FP suppression + corroboration)."""
    # set up a noisy rule that gets auto-suppressed
    fp = FPLearner(tmp_path)
    for _ in range(2):
        fp.record_occurrence("noisy:rule", "app.py")
    for _ in range(3):
        fp.record_false_positive("noisy:rule", "app.py")

    findings = [
        Finding(layer=LayerID.L0_FAST, rule_id="noisy:rule",
                message="noise", file="app.py", start_line=1, confidence=0.7),
        Finding(layer=LayerID.L0_FAST, rule_id="good:rule",
                message="real bug", file="app.py", start_line=2, confidence=0.8),
    ]
    filtered, stats = apply_precision_pipeline(findings, tmp_path, fp_learner=fp)
    assert stats["input_findings"] == 2
    assert stats["fp_suppressed"] >= 1
    assert len(filtered) < 2
