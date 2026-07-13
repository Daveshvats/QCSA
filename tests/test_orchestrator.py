"""Tests for the aggregator."""
import pytest
from pathlib import Path
from loomscan.brain.aggregator import Aggregator
from loomscan.models import Finding, Severity, BlastRadius, LayerID, Decision


@pytest.fixture
def aggregator(tmp_path):
    return Aggregator(stats_path=tmp_path / "stats.json")


def test_no_findings_returns_pass(aggregator):
    decisions, final = aggregator.aggregate([])
    assert decisions == []
    assert final == Decision.PASS


def test_critical_finding_blocks(aggregator):
    finding = Finding(
        layer=LayerID.L0_FAST, rule_id="test:secret",
        message="Hardcoded secret",
        file="app.py", start_line=10,
        severity=Severity.CRITICAL, confidence=0.9,
        blast_radius=BlastRadius.SYSTEM, exploitability=0.95,
    )
    decisions, final = aggregator.aggregate([finding])
    assert final == Decision.BLOCK
    assert decisions[0].decision in (Decision.BLOCK, Decision.WARN)


def test_low_finding_passes(aggregator):
    finding = Finding(
        layer=LayerID.L0_FAST, rule_id="test:style",
        message="Style issue",
        file="app.py", start_line=10,
        severity=Severity.LOW, confidence=0.8,
        blast_radius=BlastRadius.FUNCTION, exploitability=0.0,
    )
    decisions, final = aggregator.aggregate([finding])
    assert final == Decision.PASS


def test_high_severity_warns(aggregator):
    finding = Finding(
        layer=LayerID.L5_POLICY, rule_id="test:policy",
        message="Policy violation",
        file="app.py", start_line=10,
        severity=Severity.HIGH, confidence=0.7,
        blast_radius=BlastRadius.MODULE, exploitability=0.5,
    )
    decisions, final = aggregator.aggregate([finding])
    assert final == Decision.WARN


def test_final_decision_is_max_of_individuals(aggregator):
    findings = [
        Finding(
            layer=LayerID.L0_FAST, rule_id="test:low",
            message="Low issue",
            file="a.py", start_line=1,
            severity=Severity.LOW, confidence=0.9,
            blast_radius=BlastRadius.FUNCTION, exploitability=0.0,
        ),
        Finding(
            layer=LayerID.L0_FAST, rule_id="test:high",
            message="High issue",
            file="b.py", start_line=1,
            severity=Severity.HIGH, confidence=0.9,
            blast_radius=BlastRadius.SYSTEM, exploitability=0.8,
        ),
    ]
    decisions, final = aggregator.aggregate(findings)
    # the high finding should drive the final decision
    assert final in (Decision.WARN, Decision.BLOCK)
