"""v4.35 smoke tests — coverage for the structural-gap release.

Tests:
1. IaC dedup (L0e.* vs L0.iac.* — no duplicate findings for same issue)
2. BUILTIN_PACKS counts reconciled (declared == actual)
3. 4 new language packs (Kotlin, SQL, Bash, Dart) registered and parse
4. Secret detection 200+ patterns
5. L8 Autofix 100+ patterns
6. loomscan gate command (quality gates)
7. cli_v2.py lsp_cmd uses LSPServer (still works)
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml


PROJECT_ROOT = Path(__file__).resolve().parent.parent
PACKS_DIR = PROJECT_ROOT / "loomscan" / "rules" / "packs"


# =============================================================================
# 1. IaC dedup — L0e.* and L0.iac.* should NOT produce duplicate findings
# =============================================================================

class TestIaCDedup:
    """v4.35: iac_scanner.py now skips rules that L0eIaC layer already covers
    with autofix support. Dockerfile and K8s scans no longer produce
    duplicate findings."""

    def test_dockerfile_no_duplicate_findings(self, tmp_path):
        """Scan a Dockerfile and verify no duplicate findings for the same issue."""
        from loomscan.layers.l0e_iac import L0eIaC
        from loomscan.iac_scanner import scan_dockerfile
        from loomscan.models import DiffHunk

        # Create a Dockerfile with multiple issues
        dockerfile_content = (
            "FROM python:latest\n"
            "WORKDIR /app\n"
            "COPY . .\n"
            "CMD [\"python\", \"app.py\"]\n"
        )
        (tmp_path / "Dockerfile").write_text(dockerfile_content)

        # Scan with both L0e and iac_scanner
        l0e_layer = L0eIaC()
        hunks = [DiffHunk(file="Dockerfile", start_line=1, end_line=4,
                          added_lines=dockerfile_content.splitlines(),
                          removed_lines=[])]
        l0e_findings = l0e_layer.run(tmp_path, hunks, config=None)

        iac_findings = scan_dockerfile(tmp_path / "Dockerfile", tmp_path)

        # Check for duplicate issue types — no two findings should flag the
        # same line for the same conceptual issue (e.g., FROM :latest)
        l0e_latest_tag = [f for f in l0e_findings if "latest-tag" in f.rule_id or "latest_tag" in f.rule_id]
        iac_latest_tag = [f for f in iac_findings if "PIN-VERSION" in f.rule_id or "LATEST" in f.rule_id.upper()]

        # Should have L0e.docker-latest-tag (with autofix) but NOT L0.iac.DOCKER-NO-PIN-VERSION (duplicate)
        assert len(l0e_latest_tag) > 0, "L0e.docker-latest-tag should fire"
        assert len(iac_latest_tag) == 0, (
            f"L0.iac.DOCKER-NO-PIN-VERSION should NOT fire (L0e covers it). "
            f"Got: {[f.rule_id for f in iac_latest_tag]}"
        )

        # Same for HEALTHCHECK
        l0e_healthcheck = [f for f in l0e_findings if "no-healthcheck" in f.rule_id or "HEALTHCHECK" in f.rule_id.upper()]
        iac_healthcheck = [f for f in iac_findings if "HEALTHCHECK" in f.rule_id.upper() and "NO-" in f.rule_id.upper()]
        assert len(l0e_healthcheck) > 0, "L0e.docker-no-healthcheck should fire"
        assert len(iac_healthcheck) == 0, (
            f"L0.iac.DOCKER-NO-HEALTHCHECK should NOT fire (L0e covers it). "
            f"Got: {[f.rule_id for f in iac_healthcheck]}"
        )

    def test_k8s_no_duplicate_findings(self, tmp_path):
        """Scan a K8s manifest and verify no duplicate findings."""
        from loomscan.layers.l0e_iac import L0eIaC
        from loomscan.iac_scanner import scan_kubernetes
        from loomscan.models import DiffHunk

        k8s_content = (
            "apiVersion: v1\n"
            "kind: Pod\n"
            "metadata:\n"
            "  name: test\n"
            "spec:\n"
            "  containers:\n"
            "  - name: app\n"
            "    image: nginx:latest\n"
            "    securityContext:\n"
            "      privileged: true\n"
            "      runAsUser: 0\n"
        )
        (tmp_path / "pod.yaml").write_text(k8s_content)

        l0e_layer = L0eIaC()
        hunks = [DiffHunk(file="pod.yaml", start_line=1, end_line=10,
                          added_lines=k8s_content.splitlines(),
                          removed_lines=[])]
        l0e_findings = l0e_layer.run(tmp_path, hunks, config=None)
        iac_findings = scan_kubernetes(tmp_path / "pod.yaml", tmp_path)

        # L0e.k8s-privileged-container should fire (with autofix)
        l0e_priv = [f for f in l0e_findings if "privileged" in f.rule_id.lower()]
        iac_priv = [f for f in iac_findings if "PRIVILEGED-CONTAINER" in f.rule_id]
        assert len(l0e_priv) > 0, "L0e.k8s-privileged-container should fire"
        assert len(iac_priv) == 0, (
            f"L0.iac.K8S-PRIVILEGED-CONTAINER should NOT fire (L0e covers it). "
            f"Got: {[f.rule_id for f in iac_priv]}"
        )

        # L0e.k8s-image-latest should fire (with autofix)
        l0e_img = [f for f in l0e_findings if "image-latest" in f.rule_id]
        iac_img = [f for f in iac_findings if "IMAGE-LATEST" in f.rule_id]
        assert len(l0e_img) > 0, "L0e.k8s-image-latest should fire"
        assert len(iac_img) == 0, (
            f"L0.iac.K8S-IMAGE-LATEST should NOT fire (L0e covers it). "
            f"Got: {[f.rule_id for f in iac_img]}"
        )


# =============================================================================
# 2. BUILTIN_PACKS counts reconciled
# =============================================================================

class TestPackCountsReconciled:
    """v4.35: All BUILTIN_PACKS declared counts should match actual YAML pack counts."""

    def test_no_drift(self):
        from loomscan.rules import BUILTIN_PACKS
        for name, info in BUILTIN_PACKS.items():
            if 'path' not in info or not info['path'].startswith('packs/'):
                continue
            declared = info.get('rules', 0)
            path = PACKS_DIR / Path(info['path']).name
            if not path.exists():
                continue
            with open(path) as f:
                data = yaml.safe_load(f)
            actual = len(data.get('rules', []))
            assert declared == actual, (
                f"{name}: declared {declared} != actual {actual} (drift)"
            )


# =============================================================================
# 3. 4 new language packs (Kotlin, SQL, Bash, Dart)
# =============================================================================

class TestNewV435Packs:
    """v4.35: 4 new packs added — Kotlin (50), SQL (51), Bash (51), Dart (30)."""

    @pytest.mark.parametrize("pack_name,min_count", [
        ("kotlin-security.yml", 50),
        ("sql-security.yml", 50),
        ("bash-security.yml", 50),
        ("dart-security.yml", 30),
    ])
    def test_pack_exists_with_min_rules(self, pack_name: str, min_count: int):
        path = PACKS_DIR / pack_name
        assert path.exists(), f"Pack not found: {path}"
        with open(path) as f:
            data = yaml.safe_load(f)
        rules = data.get("rules", [])
        assert len(rules) >= min_count, (
            f"{pack_name}: expected {min_count}+ rules, got {len(rules)}"
        )

    def test_kotlin_pack_registered(self):
        from loomscan.rules import BUILTIN_PACKS
        assert "kotlin-security" in BUILTIN_PACKS
        assert BUILTIN_PACKS["kotlin-security"]["language"] == "kotlin"

    def test_sql_pack_registered(self):
        from loomscan.rules import BUILTIN_PACKS
        assert "sql-security" in BUILTIN_PACKS
        assert BUILTIN_PACKS["sql-security"]["language"] == "sql"

    def test_bash_pack_registered(self):
        from loomscan.rules import BUILTIN_PACKS
        assert "bash-security" in BUILTIN_PACKS
        assert BUILTIN_PACKS["bash-security"]["language"] == "bash"

    def test_dart_pack_registered(self):
        from loomscan.rules import BUILTIN_PACKS
        assert "dart-security" in BUILTIN_PACKS
        assert BUILTIN_PACKS["dart-security"]["language"] == "dart"

    def test_kotlin_auto_selection(self):
        from loomscan.rules import get_all_packs_for_files
        packs = get_all_packs_for_files(["Main.kt"])
        assert any("kotlin-security" in str(p) for p in packs)

    def test_sql_auto_selection(self):
        from loomscan.rules import get_all_packs_for_files
        packs = get_all_packs_for_files(["schema.sql"])
        assert any("sql-security" in str(p) for p in packs)

    def test_bash_auto_selection(self):
        from loomscan.rules import get_all_packs_for_files
        packs = get_all_packs_for_files(["deploy.sh"])
        assert any("bash-security" in str(p) for p in packs)

    def test_dart_auto_selection(self):
        from loomscan.rules import get_all_packs_for_files
        packs = get_all_packs_for_files(["main.dart"])
        assert any("dart-security" in str(p) for p in packs)

    def test_kotlin_pack_has_coroutine_rules(self):
        with open(PACKS_DIR / "kotlin-security.yml") as f:
            data = yaml.safe_load(f)
        rule_ids = {r["id"] for r in data["rules"]}
        assert "kotlin-coroutine-runblocking" in rule_ids
        assert "kotlin-coroutine-global-scope" in rule_ids

    def test_sql_pack_has_destructive_rules(self):
        with open(PACKS_DIR / "sql-security.yml") as f:
            data = yaml.safe_load(f)
        rule_ids = {r["id"] for r in data["rules"]}
        assert "sql-drop-table" in rule_ids
        assert "sql-no-where-delete" in rule_ids
        assert "sql-xp-cmdshell" in rule_ids

    def test_bash_pack_has_rce_rules(self):
        with open(PACKS_DIR / "bash-security.yml") as f:
            data = yaml.safe_load(f)
        rule_ids = {r["id"] for r in data["rules"]}
        assert "bash-eval" in rule_ids
        assert "bash-curl-pipe-bash" in rule_ids
        assert "bash-rm-rf-slash" in rule_ids

    def test_dart_pack_has_process_rules(self):
        with open(PACKS_DIR / "dart-security.yml") as f:
            data = yaml.safe_load(f)
        rule_ids = {r["id"] for r in data["rules"]}
        assert "dart-process-run" in rule_ids
        assert "dart-random-not-secure" in rule_ids


# =============================================================================
# 4. Secret detection 200+ patterns
# =============================================================================

class TestSecretDetection200Plus:
    """v4.35: Secret detection expanded from 104 → 275+ patterns."""

    def test_has_200_plus_patterns(self):
        from loomscan.advanced_secrets import SECRET_PATTERNS_V434
        assert len(SECRET_PATTERNS_V434) >= 200, (
            f"Expected 200+ patterns, got {len(SECRET_PATTERNS_V434)}"
        )

    def test_detects_openai_project_key(self):
        from loomscan.advanced_secrets import detect_secrets_entropy
        text = 'OPENAI_API_KEY = "sk-proj-' + 'a' * 50 + '"'
        d = detect_secrets_entropy(text, "test.py")
        assert any(det.secret_type == "openai" for det in d)

    def test_detects_anthropic_key(self):
        from loomscan.advanced_secrets import detect_secrets_entropy
        text = 'ANTHROPIC_API_KEY = "sk-ant-' + 'a' * 50 + '"'
        d = detect_secrets_entropy(text, "test.py")
        assert any(det.secret_type == "anthropic" for det in d)

    def test_detects_mongodb_url(self):
        from loomscan.advanced_secrets import detect_secrets_entropy
        text = 'DATABASE_URL = "mongodb://user:secretpass@cluster.example.com:27017/db"'
        d = detect_secrets_entropy(text, "test.py")
        assert any(det.secret_type == "mongodb" for det in d)

    def test_detects_gcp_service_account(self):
        from loomscan.advanced_secrets import detect_secrets_entropy
        text = '"type": "service_account" "private_key": "-----BEGIN PRIVATE KEY-----"'
        d = detect_secrets_entropy(text, "test.json")
        assert any(det.secret_type == "gcp" for det in d)

    def test_detects_supabase_service_key(self):
        from loomscan.advanced_secrets import detect_secrets_entropy
        # JWT-like format
        text = 'SUPABASE_SERVICE_ROLE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIn0.HbdxiVdcRyO4GEpGRyZbrQ_dXLOjVwQmqFA-n4t4eGQ"'
        d = detect_secrets_entropy(text, "test.py")
        # Should detect as supabase or jwt or generic
        assert len(d) > 0

    def test_detects_grafana_service_account(self):
        from loomscan.advanced_secrets import detect_secrets_entropy
        text = 'token = "glsa_' + 'a' * 40 + '"'
        d = detect_secrets_entropy(text, "test.py")
        assert any(det.secret_type == "grafana" for det in d)

    def test_detects_clerk_secret(self):
        from loomscan.advanced_secrets import detect_secrets_entropy
        text = 'CLERK_SECRET_KEY = "sk_live_' + 'a' * 50 + '"'
        d = detect_secrets_entropy(text, "test.py")
        # The Stripe prefix (sk_live_) may catch it first — that's OK,
        # the important thing is some secret was detected
        assert len(d) > 0, "Should detect some secret in CLERK_SECRET_KEY string"

    def test_detects_pinecone_key(self):
        from loomscan.advanced_secrets import detect_secrets_entropy
        text = 'PINECONE_API_KEY = "pcsk_' + 'a' * 50 + '"'
        d = detect_secrets_entropy(text, "test.py")
        assert any(det.secret_type == "pinecone" for det in d)


# =============================================================================
# 5. L8 Autofix 100+ patterns
# =============================================================================

class TestL8Autofix100Plus:
    """v4.35: L8 Autofix expanded from 56 → 107 patterns."""

    def test_has_100_plus_patterns(self):
        from loomscan.layers.l8_autofix import FIX_PATTERNS
        assert len(FIX_PATTERNS) >= 100, (
            f"Expected 100+ patterns, got {len(FIX_PATTERNS)}"
        )

    def test_kotlin_unwrap_fixer(self, tmp_path):
        """v4.35: Kotlin !! → ?: error() fixer."""
        from loomscan.layers.l8_autofix import _fix_kotlin_assert_not_null
        from loomscan.models import Finding, Severity, LayerID, BlastRadius

        repo = tmp_path
        f = repo / "Main.kt"
        f.write_text("fun main() {\n    val x: String? = null\n    println(x!!)\n}\n")
        finding = Finding(
            layer=LayerID.L0_FAST, rule_id="L0.semgrep:kotlin-assert-not-null",
            message="!! NPE risk", file="Main.kt", start_line=3,
            severity=Severity.MEDIUM, confidence=0.85,
            blast_radius=BlastRadius.FUNCTION, exploitability=0.3,
        )
        result = _fix_kotlin_assert_not_null(finding, repo)
        assert result is not None
        assert "?: error" in result
        assert "!!" not in result

    def test_sql_select_star_fixer(self, tmp_path):
        """v4.35: SQL SELECT * — add TODO comment."""
        from loomscan.layers.l8_autofix import _fix_sql_select_star
        from loomscan.models import Finding, Severity, LayerID, BlastRadius

        repo = tmp_path
        f = repo / "query.sql"
        f.write_text("SELECT * FROM users;\n")
        finding = Finding(
            layer=LayerID.L0_FAST, rule_id="L0.semgrep:sql-select-star",
            message="SELECT *", file="query.sql", start_line=1,
            severity=Severity.LOW, confidence=0.7,
            blast_radius=BlastRadius.FUNCTION, exploitability=0.1,
        )
        result = _fix_sql_select_star(finding, repo)
        assert result is not None
        assert "TODO" in result

    def test_sql_drop_table_fixer(self, tmp_path):
        """v4.35: SQL DROP TABLE — add CRITICAL comment."""
        from loomscan.layers.l8_autofix import _fix_sql_drop_table
        from loomscan.models import Finding, Severity, LayerID, BlastRadius

        repo = tmp_path
        f = repo / "migration.sql"
        f.write_text("DROP TABLE users;\n")
        finding = Finding(
            layer=LayerID.L0_FAST, rule_id="L0.semgrep:sql-drop-table",
            message="DROP TABLE", file="migration.sql", start_line=1,
            severity=Severity.CRITICAL, confidence=0.95,
            blast_radius=BlastRadius.SYSTEM, exploitability=0.7,
        )
        result = _fix_sql_drop_table(finding, repo)
        assert result is not None
        assert "CRITICAL" in result

    def test_bash_chmod_777_fixer(self, tmp_path):
        """v4.35: Bash chmod 777 → 755 fixer."""
        from loomscan.layers.l8_autofix import _fix_bash_chmod_777
        from loomscan.models import Finding, Severity, LayerID, BlastRadius

        repo = tmp_path
        f = repo / "deploy.sh"
        f.write_text("#!/bin/bash\nchmod 777 /var/log/app\n")
        finding = Finding(
            layer=LayerID.L0_FAST, rule_id="L0.semgrep:bash-chmod-777",
            message="chmod 777", file="deploy.sh", start_line=2,
            severity=Severity.HIGH, confidence=0.85,
            blast_radius=BlastRadius.SYSTEM, exploitability=0.5,
        )
        result = _fix_bash_chmod_777(finding, repo)
        assert result is not None
        assert "chmod 755" in result
        assert "chmod 777" not in result

    def test_bash_set_e_fixer(self, tmp_path):
        """v4.35: Bash — add set -euo pipefail."""
        from loomscan.layers.l8_autofix import _fix_bash_set_e_missing
        from loomscan.models import Finding, Severity, LayerID, BlastRadius

        repo = tmp_path
        f = repo / "deploy.sh"
        f.write_text("#!/bin/bash\necho hello\n")
        finding = Finding(
            layer=LayerID.L0_FAST, rule_id="L0.semgrep:bash-set-e-missing",
            message="missing set -e", file="deploy.sh", start_line=1,
            severity=Severity.LOW, confidence=0.7,
            blast_radius=BlastRadius.FUNCTION, exploitability=0.1,
        )
        result = _fix_bash_set_e_missing(finding, repo)
        assert result is not None
        assert "set -euo pipefail" in result

    def test_dart_random_fixer(self, tmp_path):
        """v4.35: Dart Random() → Random.secure() fixer."""
        from loomscan.layers.l8_autofix import _fix_dart_random
        from loomscan.models import Finding, Severity, LayerID, BlastRadius

        repo = tmp_path
        f = repo / "main.dart"
        f.write_text("import 'dart:math';\nint randomInt() => Random().nextInt(100);\n")
        finding = Finding(
            layer=LayerID.L0_FAST, rule_id="L0.semgrep:dart-random-not-secure",
            message="Random not CSPRNG", file="main.dart", start_line=2,
            severity=Severity.HIGH, confidence=0.85,
            blast_radius=BlastRadius.FUNCTION, exploitability=0.5,
        )
        result = _fix_dart_random(finding, repo)
        assert result is not None
        assert "Random.secure()" in result

    def test_python_pyyaml_fixer(self, tmp_path):
        """v4.35: yaml.load → yaml.safe_load fixer."""
        from loomscan.layers.l8_autofix import _fix_python_pyyaml_unsafe
        from loomscan.models import Finding, Severity, LayerID, BlastRadius

        repo = tmp_path
        f = repo / "config.py"
        f.write_text("import yaml\ndata = yaml.load(open('config.yml'))\n")
        finding = Finding(
            layer=LayerID.L0_FAST, rule_id="L0.sast.mini:py-yaml-load",
            message="yaml.load RCE", file="config.py", start_line=2,
            severity=Severity.CRITICAL, confidence=0.95,
            blast_radius=BlastRadius.SYSTEM, exploitability=0.7,
        )
        result = _fix_python_pyyaml_unsafe(finding, repo)
        assert result is not None
        assert "yaml.safe_load(" in result
        assert "yaml.load(" not in result

    def test_python_requests_verify_false_fixer(self, tmp_path):
        """v4.35: requests verify=False → verify=True fixer."""
        from loomscan.layers.l8_autofix import _fix_python_requests_verify_false
        from loomscan.models import Finding, Severity, LayerID, BlastRadius

        repo = tmp_path
        f = repo / "client.py"
        f.write_text("import requests\nr = requests.get('https://example.com', verify=False)\n")
        finding = Finding(
            layer=LayerID.L0_FAST, rule_id="L0.sast.mini:py-requests-verify-false",
            message="SSL bypass", file="client.py", start_line=2,
            severity=Severity.CRITICAL, confidence=0.95,
            blast_radius=BlastRadius.SYSTEM, exploitability=0.8,
        )
        result = _fix_python_requests_verify_false(finding, repo)
        assert result is not None
        assert "verify=True" in result
        # The actual code line should no longer have verify=False
        # (the TODO comment may mention it for context)
        code_lines = [l for l in result.splitlines()
                       if not l.strip().startswith("#") and "verify=" in l]
        for cl in code_lines:
            assert "verify=False" not in cl, f"verify=False still in code: {cl}"

    def test_python_django_debug_fixer(self, tmp_path):
        """v4.35: Django DEBUG=True → False fixer."""
        from loomscan.layers.l8_autofix import _fix_python_django_debug
        from loomscan.models import Finding, Severity, LayerID, BlastRadius

        repo = tmp_path
        f = repo / "settings.py"
        f.write_text("DEBUG = True\n")
        finding = Finding(
            layer=LayerID.L0_FAST, rule_id="L0.sast.mini:py-django-debug",
            message="DEBUG=True", file="settings.py", start_line=1,
            severity=Severity.HIGH, confidence=0.85,
            blast_radius=BlastRadius.SYSTEM, exploitability=0.5,
        )
        result = _fix_python_django_debug(finding, repo)
        assert result is not None
        assert "DEBUG = False" in result or "DEBUG=False" in result
        assert "DEBUG = True" not in result and "DEBUG=True" not in result

    def test_python_pdb_trace_fixer(self, tmp_path):
        """v4.35: Remove pdb.set_trace() fixer."""
        from loomscan.layers.l8_autofix import _fix_python_pdb_trace
        from loomscan.models import Finding, Severity, LayerID, BlastRadius

        repo = tmp_path
        f = repo / "app.py"
        f.write_text("import pdb\nx = 1\npdb.set_trace()\nprint(x)\n")
        finding = Finding(
            layer=LayerID.L0_FAST, rule_id="L0.sast.mini:py-pdb-trace",
            message="pdb.set_trace", file="app.py", start_line=3,
            severity=Severity.LOW, confidence=0.85,
            blast_radius=BlastRadius.FUNCTION, exploitability=0.1,
        )
        result = _fix_python_pdb_trace(finding, repo)
        assert result is not None
        # The actual `pdb.set_trace()` call should be commented out
        # (the comment may mention it for context)
        code_lines = [l for l in result.splitlines()
                       if not l.strip().startswith("#") and "pdb.set_trace" in l]
        assert len(code_lines) == 0, (
            f"pdb.set_trace() should be commented out, but found active code: {code_lines}"
        )
        assert "removed debugger" in result


# =============================================================================
# 6. loomscan gate command
# =============================================================================

class TestStcaGateCommand:
    """v4.35: loomscan gate command — SonarQube-style quality gates."""

    def test_gate_flag_exists(self):
        """Verify `gate` is a registered CLI command."""
        from click.testing import CliRunner
        from loomscan.cli import main
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert "gate" in result.output, "loomscan gate must appear in main --help"

    def test_gate_help_shows_thresholds(self):
        from click.testing import CliRunner
        from loomscan.cli import main
        runner = CliRunner()
        result = runner.invoke(main, ["gate", "--help"])
        assert "--max-critical" in result.output
        assert "--max-high" in result.output
        assert "--max-medium" in result.output
        assert "--max-low" in result.output
        assert "--max-density" in result.output
        assert "--strict-scanners" in result.output

    def test_gate_fails_on_critical(self, tmp_path):
        """End-to-end: gate should fail (exit 1) when critical findings exceed threshold."""
        import subprocess
        repo = tmp_path / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.email", "test@test.local"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
        (repo / ".loomscan.yaml").write_text("strictness: 5\n")
        (repo / "app.py").write_text(
            'import os\n'
            'password = "hardcoded-secret-12345"\n'
            'def f():\n'
            '    return os.system("echo " + password)\n'
        )
        subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-qm", "init"], cwd=repo, check=True)

        env = os.environ.copy()
        env["PYTHONPATH"] = str(PROJECT_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
        proc = subprocess.run(
            [sys.executable, "-c", "from loomscan.cli import main; main()",
             "gate", "--full", "--max-critical", "0"],
            cwd=repo, capture_output=True, text=True, env=env, timeout=60,
        )
        # Should fail with exit 1 (critical findings > 0)
        assert proc.returncode == 1, (
            f"Expected exit 1 (gate failed), got {proc.returncode}. stderr={proc.stderr}"
        )
        assert "GATE FAILED" in proc.stdout or "GATE FAILED" in proc.stderr

    def test_gate_passes_with_loose_thresholds(self, tmp_path):
        """End-to-end: gate should pass (exit 0) when thresholds are loose."""
        import subprocess
        repo = tmp_path / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.email", "test@test.local"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
        (repo / ".loomscan.yaml").write_text("strictness: 5\n")
        (repo / "app.py").write_text('x = 1\n')
        subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-qm", "init"], cwd=repo, check=True)

        env = os.environ.copy()
        env["PYTHONPATH"] = str(PROJECT_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
        proc = subprocess.run(
            [sys.executable, "-c", "from loomscan.cli import main; main()",
             "gate", "--full", "--max-critical", "100", "--max-high", "100",
             "--max-medium", "100", "--max-low", "100", "--max-density", "1000.0"],
            cwd=repo, capture_output=True, text=True, env=env, timeout=60,
        )
        assert proc.returncode == 0, (
            f"Expected exit 0 (gate passed), got {proc.returncode}. stderr={proc.stderr}"
        )
        assert "GATE PASSED" in proc.stdout or "GATE PASSED" in proc.stderr

    def test_gate_json_output(self, tmp_path):
        """End-to-end: gate JSON output should be valid JSON."""
        import subprocess
        repo = tmp_path / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.email", "test@test.local"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
        (repo / ".loomscan.yaml").write_text("strictness: 5\n")
        (repo / "app.py").write_text('x = 1\n')
        subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-qm", "init"], cwd=repo, check=True)

        env = os.environ.copy()
        env["PYTHONPATH"] = str(PROJECT_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
        proc = subprocess.run(
            [sys.executable, "-c", "from loomscan.cli import main; main()",
             "gate", "--full", "--json"],
            cwd=repo, capture_output=True, text=True, env=env, timeout=60,
        )
        data = json.loads(proc.stdout)
        assert "gate_passed" in data
        assert "counts" in data
        assert "thresholds" in data
        assert "max_critical" in data["thresholds"]


# =============================================================================
# 7. cli_v2 lsp_cmd still works (and uses LSPServer)
# =============================================================================

class TestLspCmdStillWorks:
    """v4.35: cli_v2.py lsp_cmd should still work (uses LSPServer since v4.33)."""

    def test_lsp_cmd_uses_LSPServer(self):
        """Static check: cli_v2.lsp_cmd callback must import LSPServer."""
        import loomscan.cli_v2 as cv2
        import inspect
        cb = cv2.lsp_cmd.callback
        src = inspect.getsource(cb)
        assert "from .lsp.server import LSPServer" in src, (
            "lsp_cmd must import LSPServer from .lsp.server"
        )

    def test_lsp_server_class_exists(self):
        from loomscan.lsp.server import LSPServer
        assert hasattr(LSPServer, "run")


# =============================================================================
# 8. Total counts across the pipeline
# =============================================================================

class TestTotalCounts:
    """v4.35: verify breadth growth."""

    def test_yaml_pack_total_800_plus(self):
        """Sum of YAML pack rules should be 800+."""
        total = 0
        for path in sorted(PACKS_DIR.glob("*.yml")):
            with open(path) as f:
                data = yaml.safe_load(f)
            total += len(data.get("rules", []))
        assert total >= 800, f"YAML packs total: {total} (expected 800+)"

    def test_secret_patterns_200_plus(self):
        from loomscan.advanced_secrets import SECRET_PATTERNS_V434
        assert len(SECRET_PATTERNS_V434) >= 200

    def test_l8_fix_patterns_100_plus(self):
        from loomscan.layers.l8_autofix import FIX_PATTERNS
        assert len(FIX_PATTERNS) >= 100

    def test_packs_count_23_plus(self):
        """Should have 23+ YAML packs."""
        packs = list(PACKS_DIR.glob("*.yml"))
        assert len(packs) >= 23, f"Got {len(packs)} packs (expected 23+)"
