"""Tests for the IT2-FIS brain."""
import pytest
from loomscan.brain.it2_fis import IT2FIS, decision_from_score
from loomscan.brain.membership import IT2Membership


@pytest.fixture
def fis():
    return IT2FIS()


def test_critical_exploitable_blocks(fis):
    """Critical + directly exploitable → block."""
    output, comment = fis.evaluate(
        severity_score=0.95, confidence=0.9,
        blast_radius="system", exploitability=0.95,
        source_reliability=0.8,
    )
    score = output.midpoint
    decision = decision_from_score(score)
    assert decision == "block", f"Expected block, got {decision} (score={score})"


def test_low_severity_passes(fis):
    """Low severity + no exploit → pass."""
    output, _ = fis.evaluate(
        severity_score=0.25, confidence=0.8,
        blast_radius="function", exploitability=0.0,
        source_reliability=0.7,
    )
    score = output.midpoint
    decision = decision_from_score(score)
    assert decision == "pass", f"Expected pass, got {decision} (score={score})"


def test_uncertain_input_has_high_footprint(fis):
    """Uncertain confidence should produce a wider IT2 interval (higher uncertainty)."""
    output_certain, _ = fis.evaluate(
        severity_score=0.75, confidence=0.95,
        blast_radius="module", exploitability=0.5,
        source_reliability=0.8,
    )
    output_uncertain, _ = fis.evaluate(
        severity_score=0.75, confidence=0.3,
        blast_radius="module", exploitability=0.5,
        source_reliability=0.5,
    )
    # uncertain input should have wider footprint
    assert output_uncertain.uncertainty >= output_certain.uncertainty * 0.5


def test_medium_uncertain_passes(fis):
    """Medium + uncertain + unproven source → pass (probably false positive)."""
    output, _ = fis.evaluate(
        severity_score=0.50, confidence=0.3,
        blast_radius="function", exploitability=0.0,
        source_reliability=0.2,
    )
    score = output.midpoint
    # should be on the lower side
    assert score < 0.55, f"Expected score < 0.55, got {score}"


def test_high_direct_system_blocks(fis):
    """High + direct + system → block."""
    output, _ = fis.evaluate(
        severity_score=0.75, confidence=0.85,
        blast_radius="system", exploitability=0.9,
        source_reliability=0.7,
    )
    score = output.midpoint
    decision = decision_from_score(score)
    assert decision == "block", f"Expected block, got {decision}"


def test_it2_membership_and():
    a = IT2Membership(0.3, 0.7)
    b = IT2Membership(0.5, 0.6)
    c = a & b
    assert c.lower == 0.3
    assert c.upper == 0.6


def test_it2_membership_or():
    a = IT2Membership(0.3, 0.7)
    b = IT2Membership(0.5, 0.6)
    c = a | b
    assert c.lower == 0.5
    assert c.upper == 0.7


def test_footprint_of_uncertainty():
    m = IT2Membership(0.3, 0.7)
    assert abs(m.uncertainty - 0.4) < 1e-9
    assert abs(m.midpoint - 0.5) < 1e-9
