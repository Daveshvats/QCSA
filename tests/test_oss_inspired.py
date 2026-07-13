"""Tests for the OSS-inspired modules: baseline, strictness, nullness,
issue store, consistency."""
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from loomscan.baseline import Baseline, BaselineEntry
from loomscan.strictness import get_level, filter_findings_by_strictness, should_block, list_levels, LEVELS
from loomscan.nullness import NullnessAnalyzer, NullnessIssue
from loomscan.issue_store import IssueStore, Issue
from loomscan.consistency import (check_string_formatting_consistency, check_logging_consistency,
                               check_none_check_consistency, check_all_consistencies,
                               check_import_consistency, Inconsistency)
from loomscan.models import Finding, Severity, BlastRadius, LayerID, Category


# === Baseline (detekt-inspired) ===

def test_baseline_starts_empty(tmp_path):
    bl = Baseline(tmp_path)
    assert not bl.exists()
    assert bl.stats()["total_entries"] == 0


def test_baseline_create(tmp_path):
    """Creating a baseline should capture all current findings."""
    bl = Baseline(tmp_path)
    findings = [
        Finding(layer=LayerID.L0_FAST, rule_id="test:rule1",
                message="bug1", file="app.py", start_line=1),
        Finding(layer=LayerID.L0_FAST, rule_id="test:rule2",
                message="bug2", file="app.py", start_line=2),
    ]
    count = bl.create(findings)
    assert count == 2
    assert bl.exists()


def test_baseline_filter_new(tmp_path):
    """Baseline should filter out known (baselined) findings."""
    bl = Baseline(tmp_path)
    findings = [
        Finding(layer=LayerID.L0_FAST, rule_id="test:rule1",
                message="bug1", file="app.py", start_line=1),
    ]
    bl.create(findings)

    # now run again with same + new finding
    findings2 = [
        Finding(layer=LayerID.L0_FAST, rule_id="test:rule1",
                message="bug1", file="app.py", start_line=1),  # baselined
        Finding(layer=LayerID.L0_FAST, rule_id="test:new",
                message="new bug", file="app.py", start_line=3),  # new
    ]
    new, baselined = bl.filter_new(findings2)
    assert len(new) == 1
    assert len(baselined) == 1
    assert new[0].rule_id == "test:new"


def test_baseline_update(tmp_path):
    """Update should add new findings without removing existing."""
    bl = Baseline(tmp_path)
    bl.create([
        Finding(layer=LayerID.L0_FAST, rule_id="test:rule1",
                message="bug1", file="app.py", start_line=1),
    ])
    added, total = bl.update([
        Finding(layer=LayerID.L0_FAST, rule_id="test:rule1",
                message="bug1", file="app.py", start_line=1),  # existing
        Finding(layer=LayerID.L0_FAST, rule_id="test:new",
                message="new", file="app.py", start_line=2),  # new
    ])
    assert added == 1
    assert total == 2


def test_baseline_remove_resolved(tmp_path):
    """Resolved findings should be removed from baseline."""
    bl = Baseline(tmp_path)
    f1 = Finding(layer=LayerID.L0_FAST, rule_id="test:rule1",
                 message="bug1", file="app.py", start_line=1)
    f2 = Finding(layer=LayerID.L0_FAST, rule_id="test:rule2",
                 message="bug2", file="app.py", start_line=2)
    bl.create([f1, f2])
    # rule1 was fixed (no longer in current findings) — only rule2 remains
    removed = bl.remove_resolved({f2.fingerprint})
    assert removed == 1


# === Strictness levels (PHPStan-inspired) ===

def test_strictness_levels_exist():
    """All 9 levels should be defined."""
    for i in range(1, 10):
        sl = get_level(i)
        assert sl.level == i


def test_strictness_level_1_only_critical():
    """Level 1 should only include critical severity."""
    sl = get_level(1)
    assert "critical" in sl.enabled_severities
    assert "high" not in sl.enabled_severities


def test_strictness_level_9_includes_all():
    """Level 9 should include all severities."""
    sl = get_level(9)
    assert "critical" in sl.enabled_severities
    assert "info" in sl.enabled_severities


def test_strictness_level_9_blocks_on_warn():
    """Level 9 should block on warn (strict mode)."""
    sl = get_level(9)
    assert "warn" in sl.block_on


def test_filter_findings_by_strictness_level_1():
    """Level 1 should filter out non-critical findings."""
    findings = [
        Finding(layer=LayerID.L0_FAST, rule_id="test:crit",
                message="critical", file="a.py", start_line=1,
                severity=Severity.CRITICAL),
        Finding(layer=LayerID.L0_FAST, rule_id="test:high",
                message="high", file="a.py", start_line=2,
                severity=Severity.HIGH),
        Finding(layer=LayerID.L0_FAST, rule_id="test:low",
                message="low", file="a.py", start_line=3,
                severity=Severity.LOW),
    ]
    filtered = filter_findings_by_strictness(findings, 1)
    assert len(filtered) == 1
    assert filtered[0].severity == Severity.CRITICAL


def test_filter_findings_by_strictness_level_9():
    """Level 9 should include all findings."""
    findings = [
        Finding(layer=LayerID.L0_FAST, rule_id="test:crit",
                message="critical", file="a.py", start_line=1,
                severity=Severity.CRITICAL),
        Finding(layer=LayerID.L0_FAST, rule_id="test:info",
                message="info", file="a.py", start_line=2,
                severity=Severity.INFO),
    ]
    filtered = filter_findings_by_strictness(findings, 9)
    assert len(filtered) == 2


def test_should_block_at_level_1():
    """Level 1 should block on 'block' but not 'warn'."""
    assert should_block("block", 1) is True
    assert should_block("warn", 1) is False


def test_should_block_at_level_9():
    """Level 9 should block on both 'block' and 'warn'."""
    assert should_block("block", 9) is True
    assert should_block("warn", 9) is True


def test_list_levels_returns_all_9():
    levels = list_levels()
    assert len(levels) == 9


# === Nullness analyzer (NilAway-inspired) ===

def test_nullness_detects_none_dereference(tmp_path):
    """Should detect calling a method on a possibly-None variable."""
    src = tmp_path / "app.py"
    src.write_text("""
def process(data):
    result = get_value()
    return result.lower()
""")
    analyzer = NullnessAnalyzer()
    issues = analyzer.analyze_file(src, tmp_path)
    # 'result' is from a function call, possibly None, and .lower() is called
    assert len(issues) >= 1
    assert any(iss.variable == "result" for iss in issues)


def test_nullness_respects_none_guard(tmp_path):
    """Should NOT flag variables that have been guarded against None."""
    src = tmp_path / "app.py"
    src.write_text("""
def process(data):
    result = get_value()
    if result is None:
        return None
    return result.lower()
""")
    analyzer = NullnessAnalyzer()
    issues = analyzer.analyze_file(src, tmp_path)
    # after the guard, result is non-None — no issue
    result_issues = [iss for iss in issues if iss.variable == "result"]
    assert len(result_issues) == 0


def test_nullness_detects_subscript_on_none(tmp_path):
    """Should detect subscripting a possibly-None variable."""
    src = tmp_path / "app.py"
    src.write_text("""
def process(data):
    items = get_list()
    return items[0]
""")
    analyzer = NullnessAnalyzer()
    issues = analyzer.analyze_file(src, tmp_path)
    assert any(iss.variable == "items" for iss in issues)


def test_nullness_detects_none_param_with_default(tmp_path):
    """Should flag method calls on params with default None."""
    src = tmp_path / "app.py"
    src.write_text("""
def process(data=None):
    return data.method()
""")
    analyzer = NullnessAnalyzer()
    issues = analyzer.analyze_file(src, tmp_path)
    assert any(iss.variable == "data" for iss in issues)


def test_nullness_no_false_positive_on_safe_code(tmp_path):
    """Should NOT flag code where variables are definitely non-None."""
    src = tmp_path / "app.py"
    src.write_text("""
def process(data):
    x = "hello"
    return x.upper()
""")
    analyzer = NullnessAnalyzer()
    issues = analyzer.analyze_file(src, tmp_path)
    assert len(issues) == 0


# === Issue store (CodeChecker-inspired) ===

def test_issue_store_starts_empty(tmp_path):
    store = IssueStore(tmp_path)
    stats = store.stats()
    assert stats["total_issues"] == 0


def test_issue_store_upsert_new(tmp_path):
    """Upserting new findings should report them as new."""
    store = IssueStore(tmp_path)
    findings = [
        Finding(layer=LayerID.L0_FAST, rule_id="test:rule1",
                message="bug1", file="app.py", start_line=1,
                severity=Severity.HIGH),
    ]
    new, recurring = store.upsert_findings(findings)
    assert new == 1
    assert recurring == 0


def test_issue_store_upsert_recurring(tmp_path):
    """Upserting the same finding twice should report it as recurring."""
    store = IssueStore(tmp_path)
    f = Finding(layer=LayerID.L0_FAST, rule_id="test:rule1",
                message="bug1", file="app.py", start_line=1,
                severity=Severity.HIGH)
    store.upsert_findings([f])
    new, recurring = store.upsert_findings([f])
    assert new == 0
    assert recurring == 1


def test_issue_store_resolve(tmp_path):
    """Should be able to mark an issue as resolved."""
    store = IssueStore(tmp_path)
    f = Finding(layer=LayerID.L0_FAST, rule_id="test:rule1",
                message="bug1", file="app.py", start_line=1,
                severity=Severity.HIGH)
    store.upsert_findings([f])
    assert store.mark_resolved(f.fingerprint, "fixed", "tester", "fixed in PR #1")
    issues = store.list_issues(state="fixed")
    assert len(issues) == 1
    assert issues[0].state == "fixed"


def test_issue_store_record_run(tmp_path):
    """Should record runs for trend tracking."""
    store = IssueStore(tmp_path)
    store.record_run(total=10, new=3, resolved=1, decision="warn")
    trend = store.get_trend(weeks=4)
    assert len(trend) == 1
    assert trend[0]["total"] == 10
    assert trend[0]["new"] == 3


def test_issue_store_list_by_state(tmp_path):
    """Should list issues filtered by state."""
    store = IssueStore(tmp_path)
    f1 = Finding(layer=LayerID.L0_FAST, rule_id="test:rule1",
                 message="bug1", file="a.py", start_line=1, severity=Severity.HIGH)
    f2 = Finding(layer=LayerID.L0_FAST, rule_id="test:rule2",
                 message="bug2", file="b.py", start_line=1, severity=Severity.HIGH)
    store.upsert_findings([f1, f2])
    store.mark_resolved(f1.fingerprint, "fixed", "tester")
    open_issues = store.list_issues(state="open")
    fixed_issues = store.list_issues(state="fixed")
    assert len(open_issues) == 1
    assert len(fixed_issues) == 1


# === Consistency checker (credo-inspired) ===

def test_consistency_detects_mixed_string_formatting(tmp_path):
    """Should detect mixed f-string and .format() usage."""
    (tmp_path / "a.py").write_text('msg = f"hello {name}"\n')
    (tmp_path / "b.py").write_text('msg = "hello {}".format(name)\n')
    inconsistencies = check_string_formatting_consistency(tmp_path, max_files=10)
    assert len(inconsistencies) >= 1
    assert any(inc.category == "string_format" for inc in inconsistencies)


def test_consistency_detects_mixed_logging(tmp_path):
    """Should detect mixed print() and logging usage."""
    (tmp_path / "a.py").write_text('print("hello")\n')
    (tmp_path / "b.py").write_text('import logging\nlogging.info("hello")\n')
    inconsistencies = check_logging_consistency(tmp_path, max_files=10)
    assert len(inconsistencies) >= 1


def test_consistency_detects_mixed_none_checks(tmp_path):
    """Should detect mixed 'is None' and '== None' usage."""
    (tmp_path / "a.py").write_text('if x is None:\n    pass\n')
    (tmp_path / "b.py").write_text('if x == None:\n    pass\n')
    inconsistencies = check_none_check_consistency(tmp_path, max_files=10)
    assert len(inconsistencies) >= 1


def test_consistency_no_false_positive_when_consistent(tmp_path):
    """Should NOT report inconsistencies when code is consistent."""
    (tmp_path / "a.py").write_text('msg = f"hello {name}"\n')
    (tmp_path / "b.py").write_text('msg = f"world {x}"\n')
    inconsistencies = check_string_formatting_consistency(tmp_path, max_files=10)
    assert len(inconsistencies) == 0


def test_check_all_consistencies_combines(tmp_path):
    """check_all_consistencies should combine all checks."""
    (tmp_path / "a.py").write_text('msg = f"hello {name}"\nprint(msg)\n')
    (tmp_path / "b.py").write_text('msg = "hello {}".format(name)\nimport logging\nlogging.info(msg)\n')
    inconsistencies = check_all_consistencies(tmp_path, max_files=10)
    assert len(inconsistencies) >= 1


# === Category axis (lintr-inspired) ===

def test_finding_has_category():
    """Findings should have a category field."""
    f = Finding(layer=LayerID.L0_FAST, rule_id="test",
                message="test", file="a.py", start_line=1,
                category=Category.SECURITY)
    assert f.category == Category.SECURITY


def test_finding_category_defaults_to_correctness():
    """Default category should be CORRECTNESS."""
    f = Finding(layer=LayerID.L0_FAST, rule_id="test",
                message="test", file="a.py", start_line=1)
    assert f.category == Category.CORRECTNESS


def test_finding_to_dict_includes_category():
    """to_dict should include the category."""
    f = Finding(layer=LayerID.L0_FAST, rule_id="test",
                message="test", file="a.py", start_line=1,
                category=Category.PERFORMANCE)
    d = f.to_dict()
    assert "category" in d
    assert d["category"] == "performance"


def test_category_enum_has_expected_values():
    """Category should have all expected values."""
    assert Category.SECURITY.value == "security"
    assert Category.CORRECTNESS.value == "correctness"
    assert Category.PERFORMANCE.value == "performance"
    assert Category.STYLE.value == "style"
    assert Category.RELIABILITY.value == "reliability"
    assert Category.SUPPLY_CHAIN.value == "supply_chain"
    assert Category.INFRASTRUCTURE.value == "infrastructure"
    assert Category.BEHAVIORAL.value == "behavioral"
