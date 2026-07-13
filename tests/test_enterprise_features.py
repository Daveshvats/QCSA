"""Tests for new modules: hotspots, pysa integration, advanced secrets,
coverage, audit log."""
import pytest
import json
import os
import sys
import subprocess
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from loomscan.hotspots import HotspotManager, HOTSPOT_PATTERNS
from loomscan.advanced_secrets import (detect_secrets_entropy, shannon_entropy,
                                    detect_secrets_advanced, scan_git_history,
                                    SECRET_PREFIXES)
from loomscan.coverage import (parse_coverage_py, parse_jacoco, parse_istanbul,
                            parse_go_coverage, find_coverage_report,
                            track_coverage_history, CoverageReport, FileCoverage)
from loomscan.audit import AuditLogger


# === Shannon entropy ===

def test_shannon_entropy_of_constant_string():
    """Constant string should have low entropy."""
    assert shannon_entropy("aaaa") < 1.0

def test_shannon_entropy_of_random_string():
    """Random string should have high entropy."""
    assert shannon_entropy("xK9$mP2qL7nR4vT8") > 3.0

def test_shannon_entropy_of_empty_string():
    assert shannon_entropy("") == 0.0


# === Secret detection ===

def test_detect_aws_key_prefix(tmp_path):
    """Should detect AWS access key by prefix."""
    src = tmp_path / "config.py"
    src.write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    detections = detect_secrets_entropy(src.read_text(), str(src))
    assert any(d.secret_type == "aws" for d in detections)


def test_detect_github_pat(tmp_path):
    """Should detect GitHub PAT by prefix."""
    src = tmp_path / "config.py"
    src.write_text('GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"\n')
    detections = detect_secrets_entropy(src.read_text(), str(src))
    assert any(d.secret_type == "github" for d in detections)


def test_detect_high_entropy_secret(tmp_path):
    """Should detect high-entropy string as potential secret."""
    src = tmp_path / "config.py"
    src.write_text('TOKEN = "xK9mP2qL7nR4vT8wY6bH3cF5dJ1gM0zU9"\n')
    detections = detect_secrets_entropy(src.read_text(), str(src))
    assert any(d.secret_type == "generic_entropy" for d in detections)


def test_no_false_positive_on_normal_code(tmp_path):
    """Normal code should not trigger secret detection."""
    src = tmp_path / "app.py"
    src.write_text("def add(a, b):\n    return a + b\n")
    detections = detect_secrets_entropy(src.read_text(), str(src))
    assert len(detections) == 0


def test_secret_prefix_list_includes_known_providers():
    assert "AKIA" in SECRET_PREFIXES  # AWS
    assert "ghp_" in SECRET_PREFIXES  # GitHub
    assert "sk-" in SECRET_PREFIXES   # Stripe


# === Hotspot review workflow ===

def test_hotspot_detection_finds_eval(tmp_path):
    """Should detect eval() as a security hotspot."""
    src = tmp_path / "app.py"
    src.write_text("def f(x):\n    return eval(x)\n")
    hm = HotspotManager(tmp_path)
    new = hm.detect_hotspots([src])
    assert any(h.category == "code_injection" for h in new)


def test_hotspot_detection_finds_md5(tmp_path):
    """Should detect MD5 as a crypto hotspot."""
    src = tmp_path / "app.py"
    src.write_text("import hashlib\ndef f(x):\n    return hashlib.md5(x).hexdigest()\n")
    hm = HotspotManager(tmp_path)
    new = hm.detect_hotspots([src])
    assert any(h.category == "crypto" for h in new)


def test_hotspot_review_safe(tmp_path):
    """Reviewing a hotspot as 'safe' should update its status."""
    src = tmp_path / "app.py"
    src.write_text("def f(x):\n    return eval(x)\n")
    hm = HotspotManager(tmp_path)
    new = hm.detect_hotspots([src])
    assert len(new) > 0
    hotspot_id = new[0].id
    assert hm.review(hotspot_id, "safe", "testuser", "input is trusted") is True
    assert hm.hotspots[hotspot_id].status == "safe"
    assert hm.hotspots[hotspot_id].reviewed_by == "testuser"


def test_hotspot_review_invalid_id(tmp_path):
    """Reviewing a non-existent hotspot should fail."""
    hm = HotspotManager(tmp_path)
    assert hm.review("nonexistent", "safe", "user") is False


def test_hotspot_review_invalid_decision(tmp_path):
    """Invalid decision should fail."""
    src = tmp_path / "app.py"
    src.write_text("def f(x):\n    return eval(x)\n")
    hm = HotspotManager(tmp_path)
    new = hm.detect_hotspots([src])
    assert hm.review(new[0].id, "invalid_decision", "user") is False


def test_hotspot_audit_chain_verifies(tmp_path):
    """The audit chain should verify as valid after reviews."""
    src = tmp_path / "app.py"
    src.write_text("def f(x):\n    return eval(x)\n")
    hm = HotspotManager(tmp_path)
    new = hm.detect_hotspots([src])
    hm.review(new[0].id, "safe", "testuser", "ok")
    valid, msg = hm.verify_audit_chain()
    assert valid, f"Audit chain should be valid: {msg}"


def test_hotspot_audit_chain_detects_tampering(tmp_path):
    """Tampering with the audit log should be detected."""
    src = tmp_path / "app.py"
    src.write_text("def f(x):\n    return eval(x)\n")
    hm = HotspotManager(tmp_path)
    new = hm.detect_hotspots([src])
    hm.review(new[0].id, "safe", "testuser", "ok")
    # tamper with the hotspot audit log (now .loomscan-hotspot-audit.log)
    audit_file = tmp_path / ".loomscan-hotspot-audit.log"
    lines = audit_file.read_text().strip().splitlines()
    # modify the second line
    if len(lines) >= 2:
        entry = json.loads(lines[1])
        entry["note"] = "tampered"
        lines[1] = json.dumps(entry)
        audit_file.write_text("\n".join(lines) + "\n")
    valid, msg = hm.verify_audit_chain()
    assert not valid, "Tampered audit chain should be invalid"


def test_hotspot_stats(tmp_path):
    """Stats should report hotspot counts by status."""
    src = tmp_path / "app.py"
    src.write_text("def f(x):\n    return eval(x)\n")
    hm = HotspotManager(tmp_path)
    hm.detect_hotspots([src])
    stats = hm.stats()
    assert stats["total"] >= 1
    assert stats["open"] >= 1


# === Audit log ===

def test_audit_log_writes_entries(tmp_path):
    """Audit log should write entries with tamper-evident hashes."""
    al = AuditLogger(tmp_path)
    al.log("test_action", {"key": "value"})
    entries = al.tail(1)
    assert len(entries) == 1
    assert entries[0]["action"] == "test_action"
    assert "this_hash" in entries[0]
    assert "prev_hash" in entries[0]


def test_audit_log_chain_verifies(tmp_path):
    """Chain should verify as valid after multiple entries."""
    al = AuditLogger(tmp_path)
    for i in range(5):
        al.log("test_action", {"iteration": i})
    valid, msg = al.verify_chain()
    assert valid, f"Chain should be valid: {msg}"
    assert "5 entries" in msg


def test_audit_log_detects_tampering(tmp_path):
    """Tampering with any entry should break the chain."""
    al = AuditLogger(tmp_path)
    for i in range(3):
        al.log("test_action", {"iteration": i})
    # tamper
    log_file = tmp_path / ".loomscan-audit.log"
    lines = log_file.read_text().strip().splitlines()
    entry = json.loads(lines[1])
    entry["details"] = '{"tampered": true}'
    lines[1] = json.dumps(entry)
    log_file.write_text("\n".join(lines) + "\n")
    valid, msg = al.verify_chain()
    assert not valid


def test_audit_stats(tmp_path):
    """Stats should report counts by action and user."""
    al = AuditLogger(tmp_path)
    al.log("action_a", {})
    al.log("action_a", {})
    al.log("action_b", {})
    stats = al.stats()
    assert stats["total_entries"] == 3
    assert stats["by_action"]["action_a"] == 2
    assert stats["by_action"]["action_b"] == 1


# === Coverage ===

def test_parse_coverage_py(tmp_path):
    """Should parse a coverage.py JSON report."""
    report_data = {
        "files": {
            "app.py": {
                "summary": {"percent_covered": 80.0, "covered_lines": 8, "num_statements": 10},
                "missing_lines": [[11, 12]],
            }
        },
        "totals": {"percent_covered": 80.0, "covered_lines": 8, "num_statements": 10},
    }
    report_path = tmp_path / "coverage.json"
    report_path.write_text(json.dumps(report_data))
    report = parse_coverage_py(report_path)
    assert report is not None
    assert report.overall_line_rate == 0.8
    assert "app.py" in report.files
    assert report.files["app.py"].line_rate == 0.8


def test_parse_jacoco(tmp_path):
    """Should parse a JaCoCo XML report."""
    xml = '''<report>
        <package name="com/example">
            <sourcefile name="App.java">
                <counter type="LINE" covered="8" missed="2"/>
                <counter type="BRANCH" covered="3" missed="1"/>
            </sourcefile>
        </package>
        <counter type="LINE" covered="8" missed="2"/>
    </report>'''
    report_path = tmp_path / "jacoco.xml"
    report_path.write_text(xml)
    report = parse_jacoco(report_path)
    assert report is not None
    assert report.overall_line_rate == 0.8
    assert "com/example/App.java" in report.files


def test_parse_istanbul(tmp_path):
    """Should parse an Istanbul JSON report."""
    data = {
        "app.js": {
            "s": {"0": 1, "1": 0, "2": 1},
            "b": {"0": [1, 0]},
            "statementMap": {"0": {"start": {"line": 1}}, "1": {"start": {"line": 2}}, "2": {"start": {"line": 3}}}
        }
    }
    report_path = tmp_path / "coverage-final.json"
    report_path.write_text(json.dumps(data))
    report = parse_istanbul(report_path)
    assert report is not None
    assert "app.js" in report.files
    # 2 of 3 statements covered
    assert abs(report.files["app.js"].line_rate - 2/3) < 0.01


def test_parse_go_coverage(tmp_path):
    """Should parse a Go coverage profile."""
    content = '''mode: set
app.go:1.1,5.1 4 1
app.go:6.1,8.1 2 0
'''
    report_path = tmp_path / "coverage.out"
    report_path.write_text(content)
    report = parse_go_coverage(report_path)
    assert report is not None
    assert "app.go" in report.files


def test_coverage_history_tracking(tmp_path):
    """Should track coverage over time and detect drops."""
    history_file = tmp_path / ".loomscan-coverage-history.json"
    # first run
    report1 = CoverageReport(tool="coverage.py")
    report1.files["app.py"] = FileCoverage(file="app.py", line_rate=0.9, branch_rate=0.5)
    report1.overall_line_rate = 0.9
    drops1 = track_coverage_history(tmp_path, report1)
    assert drops1 == {}  # no previous, no drops
    # second run with lower coverage
    report2 = CoverageReport(tool="coverage.py")
    report2.files["app.py"] = FileCoverage(file="app.py", line_rate=0.7, branch_rate=0.5)
    report2.overall_line_rate = 0.7
    drops2 = track_coverage_history(tmp_path, report2)
    assert "app.py" in drops2
    assert drops2["app.py"] > 0.15  # 20% drop


def test_find_coverage_report_auto_discovers(tmp_path):
    """Should auto-discover a coverage report in standard locations."""
    # create a coverage.py report
    (tmp_path / "coverage.json").write_text(json.dumps({
        "files": {}, "totals": {"percent_covered": 0}
    }))
    report = find_coverage_report(tmp_path)
    assert report is not None
    assert report.tool == "coverage.py"


# === Pysa integration (mock — no Pysa in CI) ===

def test_pysa_module_imports():
    from loomscan import pysa_integration
    assert hasattr(pysa_integration, "PysaIntegration")
    assert hasattr(pysa_integration, "get_pysa_findings_or_fallback")


def test_pysa_unavailable_returns_empty(tmp_path):
    """Without Pysa installed, run() should return empty list."""
    from loomscan.pysa_integration import PysaIntegration
    pysa = PysaIntegration(tmp_path)
    if not pysa.is_available():
        findings = pysa.run([tmp_path / "app.py"])
        assert findings == []


# === Historical scan ===

def test_historical_scan_finds_secret_in_old_commit(tmp_path):
    """Should find a secret committed in git history."""
    # init git repo
    subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True)
    subprocess.run(["git", "config", "user.email", "t@t.com"], cwd=tmp_path, capture_output=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=tmp_path, capture_output=True)
    # commit a file with a secret
    (tmp_path / "config.py").write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, capture_output=True)
    subprocess.run(["git", "commit", "-m", "add config"], cwd=tmp_path, capture_output=True)
    # remove the secret in a new commit
    (tmp_path / "config.py").write_text('# no secrets here\n')
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, capture_output=True)
    subprocess.run(["git", "commit", "-m", "remove secret"], cwd=tmp_path, capture_output=True)

    findings = scan_git_history(tmp_path, max_commits=10)
    # should find the AWS key in the old commit
    aws_findings = [f for f in findings if "aws" in f.rule_id]
    assert len(aws_findings) >= 1, "Should find AWS key in git history"
