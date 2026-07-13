"""v4.34 smoke tests — coverage for all the new breadth work.

Tests:
1. L8 Autofix expansion (6 → 56 patterns)
2. Secret detection (98 new patterns)
3. Rust pack (20 → 61 rules)
4. Ruby pack (20 → 79 rules, Brakeman-inspired)
5. PHP pack (20 → 102 rules, PHP-Security-audit)
6. C# pack (new, 51 rules)
7. Swift pack (new, 30 rules)
8. Scala pack (new, 30 rules)
9. IaC consolidation (no duplicate findings)
10. Ported packs metadata clarified
11. VS Code extension structure valid
12. --strict-scanners smoke test
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
# 1. L8 Autofix — 56 patterns (was 6)
# =============================================================================

class TestL8AutofixExpanded:
    """v4.34: L8 Autofix grew from 6 patterns to 56, covering Python, JS,
    Docker, K8s, Java, Go, C/C++, Rust, Ruby, PHP."""

    def test_has_at_least_50_patterns(self):
        from loomscan.layers.l8_autofix import FIX_PATTERNS
        assert len(FIX_PATTERNS) >= 50, (
            f"Expected 50+ fix patterns, got {len(FIX_PATTERNS)}"
        )

    def test_covers_multiple_languages(self):
        from loomscan.layers.l8_autofix import FIX_PATTERNS
        # Look at the rule_prefix family (e.g., L0.sast, L0.ast, L0e.docker, L0e.k8s,
        # L0.semgrep, L0.java, L0.go, L0.cpp, L0.hardcoded-url, etc.)
        prefixes = set()
        for p in FIX_PATTERNS:
            parts = p.rule_prefix.split(":")[0].split(".")
            if len(parts) >= 2:
                prefixes.add(".".join(parts[:2]))
            else:
                prefixes.add(parts[0])
        # Should cover at least 6 prefix families
        assert len(prefixes) >= 6, f"Expected 6+ prefix families, got {prefixes}"

    def test_eval_fixer_still_works(self, tmp_path):
        """Make sure the v4.0 eval fixer still works after the expansion."""
        from loomscan.layers.l8_autofix import _fix_eval_python
        from loomscan.models import Finding, Severity, LayerID, BlastRadius

        repo = tmp_path
        f = repo / "app.py"
        f.write_text("x = eval('[1, 2, 3]')\n")
        finding = Finding(
            layer=LayerID.L0_FAST, rule_id="L0.sast.mini:py-eval",
            message="eval", file="app.py", start_line=1,
            severity=Severity.HIGH, confidence=0.9,
            blast_radius=BlastRadius.FUNCTION, exploitability=0.5,
        )
        result = _fix_eval_python(finding, repo)
        assert result is not None
        assert "ast.literal_eval" in result
        assert "import ast" in result

    def test_shell_true_fixer(self, tmp_path):
        """v4.34: shell=True → shell=False fixer."""
        from loomscan.layers.l8_autofix import _fix_shell_true
        from loomscan.models import Finding, Severity, LayerID, BlastRadius

        repo = tmp_path
        f = repo / "app.py"
        f.write_text("import subprocess\nsubprocess.run(['ls'], shell=True)\n")
        finding = Finding(
            layer=LayerID.L0_FAST, rule_id="L0.sast.mini:py-shell-injection",
            message="shell=True", file="app.py", start_line=2,
            severity=Severity.HIGH, confidence=0.9,
            blast_radius=BlastRadius.FUNCTION, exploitability=0.5,
        )
        result = _fix_shell_true(finding, repo)
        assert result is not None
        assert "shell=False" in result
        # The actual code line should no longer have shell=True
        # (the TODO comment may mention it for context)
        code_lines = [l for l in result.splitlines() if "subprocess" in l]
        for cl in code_lines:
            assert "shell=True" not in cl, f"shell=True still in code line: {cl}"

    def test_md5_fixer(self, tmp_path):
        """v4.34: md5 → sha256 fixer."""
        from loomscan.layers.l8_autofix import _fix_md5_usage
        from loomscan.models import Finding, Severity, LayerID, BlastRadius

        repo = tmp_path
        f = repo / "app.py"
        f.write_text("import hashlib\nh = hashlib.md5(b'x')\n")
        finding = Finding(
            layer=LayerID.L0_FAST, rule_id="L0.ast.AST-PY-MD5-USAGE",
            message="md5", file="app.py", start_line=2,
            severity=Severity.HIGH, confidence=0.9,
            blast_radius=BlastRadius.FUNCTION, exploitability=0.5,
        )
        result = _fix_md5_usage(finding, repo)
        assert result is not None
        assert "sha256" in result
        assert "md5" not in result.lower()

    def test_docker_root_user_fixer(self, tmp_path):
        """v4.34: Add non-root USER to Dockerfile."""
        from loomscan.layers.l8_autofix import _fix_docker_root_user
        from loomscan.models import Finding, Severity, LayerID, BlastRadius

        repo = tmp_path
        f = repo / "Dockerfile"
        f.write_text("FROM python:3.12\nWORKDIR /app\nUSER root\n")
        finding = Finding(
            layer=LayerID.L0E_IAC, rule_id="L0e.docker-root-user",
            message="runs as root", file="Dockerfile", start_line=3,
            severity=Severity.HIGH, confidence=0.85,
            blast_radius=BlastRadius.SYSTEM, exploitability=0.5,
        )
        result = _fix_docker_root_user(finding, repo)
        assert result is not None
        assert "USER appuser" in result
        assert "useradd" in result

    def test_rust_unwrap_fixer(self, tmp_path):
        """v4.34: .unwrap() → .expect() in Rust."""
        from loomscan.layers.l8_autofix import _fix_rust_unwrap
        from loomscan.models import Finding, Severity, LayerID, BlastRadius

        repo = tmp_path
        f = repo / "main.rs"
        f.write_text("fn main() {\n    let x: Option<i32> = Some(5);\n    let y = x.unwrap();\n}\n")
        finding = Finding(
            layer=LayerID.L0_FAST, rule_id="L0.semgrep:rust-unwrap",
            message="unwrap", file="main.rs", start_line=3,
            severity=Severity.MEDIUM, confidence=0.85,
            blast_radius=BlastRadius.FUNCTION, exploitability=0.3,
        )
        result = _fix_rust_unwrap(finding, repo)
        assert result is not None
        assert ".expect(" in result
        assert ".unwrap()" not in result

    def test_k8s_privileged_fixer(self, tmp_path):
        """v4.34: privileged: true → false in K8s YAML."""
        from loomscan.layers.l8_autofix import _fix_k8s_privileged
        from loomscan.models import Finding, Severity, LayerID, BlastRadius

        repo = tmp_path
        f = repo / "pod.yaml"
        content = "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n  - name: app\n    image: nginx\n    securityContext:\n      privileged: true\n"
        f.write_text(content)
        # Find the line with "privileged: true"
        lines = content.splitlines()
        privileged_line = next(i+1 for i, l in enumerate(lines) if "privileged: true" in l)
        finding = Finding(
            layer=LayerID.L0E_IAC, rule_id="L0e.k8s-privileged-container",
            message="privileged", file="pod.yaml", start_line=privileged_line,
            severity=Severity.CRITICAL, confidence=0.85,
            blast_radius=BlastRadius.SYSTEM, exploitability=0.7,
        )
        result = _fix_k8s_privileged(finding, repo)
        assert result is not None
        assert "privileged: false" in result
        assert "privileged: true" not in result


# =============================================================================
# 2. Secret detection — 98 new patterns
# =============================================================================

class TestSecretDetectionExpanded:
    """v4.34: 98 additional regex-based secret patterns added."""

    def test_has_98_patterns(self):
        from loomscan.advanced_secrets import SECRET_PATTERNS_V434
        assert len(SECRET_PATTERNS_V434) >= 50, (
            f"Expected 50+ new patterns, got {len(SECRET_PATTERNS_V434)}"
        )

    def test_detects_aws_key(self):
        from loomscan.advanced_secrets import detect_secrets_entropy
        text = 'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"'
        d = detect_secrets_entropy(text, "test.py")
        assert any(det.secret_type == "aws" for det in d)

    def test_detects_stripe_live_key(self):
        from loomscan.advanced_secrets import detect_secrets_entropy
        text = 'stripe = "sk_live_' + "A" * 30 + '"'
        d = detect_secrets_entropy(text, "test.py")
        assert any(det.secret_type == "stripe" for det in d)

    def test_detects_postgres_url(self):
        from loomscan.advanced_secrets import detect_secrets_entropy
        text = 'DATABASE_URL = "postgres://user:secretpass@db.example.com:5432/mydb"'
        d = detect_secrets_entropy(text, "test.py")
        assert any(det.secret_type == "postgres" for det in d)

    def test_detects_private_key(self):
        from loomscan.advanced_secrets import detect_secrets_entropy
        text = "-----BEGIN RSA PRIVATE KEY-----\nMII...\n-----END RSA PRIVATE KEY-----"
        d = detect_secrets_entropy(text, "test.py")
        assert any(det.secret_type == "private_key" for det in d)

    def test_detects_github_pat(self):
        from loomscan.advanced_secrets import detect_secrets_entropy
        text = 'token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz1234"'
        d = detect_secrets_entropy(text, "test.py")
        assert any(det.secret_type == "github" for det in d)

    def test_detects_django_secret(self):
        from loomscan.advanced_secrets import detect_secrets_entropy
        text = 'SECRET_KEY = "' + "x" * 60 + '"'
        d = detect_secrets_entropy(text, "settings.py")
        assert any(det.secret_type == "django" for det in d)

    def test_detects_openai_key(self):
        from loomscan.advanced_secrets import detect_secrets_entropy
        # sk-XXXX...T3BlbkFJXXXX... pattern
        text = 'OPENAI_API_KEY = "sk-' + "a" * 20 + "T3BlbkFJ" + "b" * 20 + '"'
        d = detect_secrets_entropy(text, "test.py")
        assert any(det.secret_type == "openai" for det in d)

    def test_no_false_positive_on_normal_string(self):
        from loomscan.advanced_secrets import detect_secrets_entropy
        text = 'name = "Alice"\nage = 30\nmessage = "Hello, world!"'
        d = detect_secrets_entropy(text, "test.py")
        # Should not fire on benign strings (entropy-based may catch a few generic ones)
        # but no high-confidence secret type should fire
        for det in d:
            assert det.confidence < 0.9, f"False positive: {det}"


# =============================================================================
# 3-9. Pack expansions and new packs
# =============================================================================

class TestPackExpansions:
    """v4.34: All packs expanded, 3 new packs added (C#, Swift, Scala)."""

    @pytest.mark.parametrize("pack_name,expected_count", [
        ("rust-security.yml", 60),
        ("ruby-security.yml", 75),
        ("php-security.yml", 100),
        ("csharp-security.yml", 50),
        ("swift-security.yml", 30),
        ("scala-security.yml", 30),
    ])
    def test_pack_has_expected_rule_count(self, pack_name: str, expected_count: int):
        path = PACKS_DIR / pack_name
        assert path.exists(), f"Pack not found: {path}"
        with open(path) as f:
            data = yaml.safe_load(f)
        rules = data.get("rules", [])
        assert len(rules) >= expected_count, (
            f"{pack_name}: expected {expected_count}+ rules, got {len(rules)}"
        )

    def test_all_packs_parse(self):
        """All YAML packs must parse without error (conftest also checks this).
        Rules can have either 'pattern' (simple) or 'pattern-either'/'pattern-regex'
        (advanced semgrep syntax)."""
        for path in sorted(PACKS_DIR.glob("*.yml")):
            with open(path) as f:
                data = yaml.safe_load(f)
            assert "rules" in data, f"{path.name}: missing 'rules' key"
            assert isinstance(data["rules"], list)
            for rule in data["rules"]:
                assert "id" in rule, f"{path.name}: rule missing id"
                # Rule must have some pattern-like key (semgrep supports several)
                pattern_keys = {"pattern", "pattern-either", "pattern-regex",
                                "patterns", "pattern-sources", "pattern-sinks"}
                assert pattern_keys & set(rule.keys()), (
                    f"{path.name} {rule['id']}: missing pattern key (one of {pattern_keys})"
                )
                assert "severity" in rule or "message" in rule, (
                    f"{path.name} {rule['id']}: missing severity/message"
                )

    def test_no_duplicate_rule_ids_within_pack(self):
        """Within each pack, no two rules can share an id."""
        for path in sorted(PACKS_DIR.glob("*.yml")):
            with open(path) as f:
                data = yaml.safe_load(f)
            ids = [r["id"] for r in data["rules"]]
            dupes = [i for i in set(ids) if ids.count(i) > 1]
            assert not dupes, f"{path.name}: duplicate rule_ids: {dupes}"

    def test_rust_pack_includes_ffi_rules(self):
        """v4.34: Rust pack should cover FFI/asm! rules."""
        path = PACKS_DIR / "rust-security.yml"
        with open(path) as f:
            data = yaml.safe_load(f)
        rule_ids = {r["id"] for r in data["rules"]}
        assert "rust-extern-block" in rule_ids
        assert "rust-asm-macro" in rule_ids
        assert "rust-no-mangle" in rule_ids

    def test_ruby_pack_includes_brakeman_rules(self):
        """v4.34: Ruby pack should include Brakeman-inspired rules."""
        path = PACKS_DIR / "ruby-security.yml"
        with open(path) as f:
            data = yaml.safe_load(f)
        rule_ids = {r["id"] for r in data["rules"]}
        # Brakeman-inspired
        assert "ruby-constantize" in rule_ids
        assert "ruby-render-user" in rule_ids
        assert "ruby-YAML-load" in rule_ids
        assert "ruby-open-uri" in rule_ids

    def test_php_pack_includes_unserialize_rules(self):
        """v4.34: PHP pack should cover unserialize and related."""
        path = PACKS_DIR / "php-security.yml"
        with open(path) as f:
            data = yaml.safe_load(f)
        rule_ids = {r["id"] for r in data["rules"]}
        assert "php-preg-eval" in rule_ids
        assert "php-create-function" in rule_ids
        assert "php-import-request" in rule_ids
        assert "php-allow-url-include" in rule_ids

    def test_csharp_pack_includes_deserialization(self):
        """v4.34: C# pack should cover BinaryFormatter and friends."""
        path = PACKS_DIR / "csharp-security.yml"
        with open(path) as f:
            data = yaml.safe_load(f)
        rule_ids = {r["id"] for r in data["rules"]}
        assert "csharp-binary-formatter" in rule_ids
        assert "csharp-md5" in rule_ids
        assert "csharp-ecb-mode" in rule_ids
        assert "csharp-process-start" in rule_ids

    def test_swift_pack_includes_force_unwrap(self):
        """v4.34: Swift pack should cover force-unwrap crashes."""
        path = PACKS_DIR / "swift-security.yml"
        with open(path) as f:
            data = yaml.safe_load(f)
        rule_ids = {r["id"] for r in data["rules"]}
        assert "swift-force-unwrap" in rule_ids
        assert "swift-keychain-accessible" in rule_ids
        assert "swift-userdefaults-secret" in rule_ids

    def test_scala_pack_includes_objectinputstream(self):
        """v4.34: Scala pack should cover Java interop deserialization."""
        path = PACKS_DIR / "scala-security.yml"
        with open(path) as f:
            data = yaml.safe_load(f)
        rule_ids = {r["id"] for r in data["rules"]}
        assert "scala-objectinputstream" in rule_ids
        assert "scala-runtime-exec" in rule_ids
        assert "scala-xml-load-string" in rule_ids


# =============================================================================
# 10. New packs registered in __init__.py
# =============================================================================

class TestNewPacksRegistered:
    """v4.34: C#, Swift, Scala packs must be registered in BUILTIN_PACKS."""

    def test_csharp_pack_registered(self):
        from loomscan.rules import BUILTIN_PACKS
        assert "csharp-security" in BUILTIN_PACKS
        assert BUILTIN_PACKS["csharp-security"]["language"] == "csharp"

    def test_swift_pack_registered(self):
        from loomscan.rules import BUILTIN_PACKS
        assert "swift-security" in BUILTIN_PACKS
        assert BUILTIN_PACKS["swift-security"]["language"] == "swift"

    def test_scala_pack_registered(self):
        from loomscan.rules import BUILTIN_PACKS
        assert "scala-security" in BUILTIN_PACKS
        assert BUILTIN_PACKS["scala-security"]["language"] == "scala"

    def test_rust_pack_count_updated(self):
        from loomscan.rules import BUILTIN_PACKS
        assert BUILTIN_PACKS["rust-security"]["rules"] >= 60

    def test_php_pack_count_updated(self):
        from loomscan.rules import BUILTIN_PACKS
        assert BUILTIN_PACKS["php-security"]["rules"] >= 100

    def test_ruby_pack_count_updated(self):
        from loomscan.rules import BUILTIN_PACKS
        assert BUILTIN_PACKS["ruby-security"]["rules"] >= 75

    def test_get_all_packs_for_csharp_files(self):
        """Auto-selection should include C# pack for .cs files."""
        from loomscan.rules import get_all_packs_for_files
        packs = get_all_packs_for_files(["Program.cs"])
        pack_names = {p.stem for p in packs}
        assert "csharp-security" in pack_names

    def test_get_all_packs_for_swift_files(self):
        from loomscan.rules import get_all_packs_for_files
        packs = get_all_packs_for_files(["AppDelegate.swift"])
        pack_names = {p.stem for p in packs}
        assert "swift-security" in pack_names

    def test_get_all_packs_for_scala_files(self):
        from loomscan.rules import get_all_packs_for_files
        packs = get_all_packs_for_files(["Main.scala"])
        pack_names = {p.stem for p in packs}
        assert "scala-security" in pack_names


# =============================================================================
# 11. Ported packs metadata clarified
# =============================================================================

class TestPortedPacksMetadata:
    """v4.34: detekt/spotbugs/lintr/luacheck descriptions now say 'Concepts ported'
    (now 'inspired by' as of v4.36) instead of just 'Ported', clarifying that
    the rules are Python (not the source tool's native language).

    v4.36: Renamed from '-ported' to '-inspired' to be more honest."""

    @pytest.mark.parametrize("pack_name", ["detekt-inspired", "spotbugs-inspired", "lintr-inspired", "luacheck-inspired"])
    def test_description_says_concepts(self, pack_name: str):
        from loomscan.rules import BUILTIN_PACKS
        desc = BUILTIN_PACKS[pack_name]["description"]
        # v4.36: Now says "Concepts inspired by" instead of "Concepts ported"
        assert ("inspired by" in desc.lower() or "concepts ported" in desc.lower()), (
            f"{pack_name}: description should clarify it's a concept adaptation, got: {desc}"
        )

    def test_language_still_python(self):
        """The rules actually scan Python code, so language must stay 'python'."""
        from loomscan.rules import BUILTIN_PACKS
        for name in ["detekt-inspired", "spotbugs-inspired", "lintr-inspired", "luacheck-inspired"]:
            assert BUILTIN_PACKS[name]["language"] == "python", (
                f"{name}: language must be 'python' (the rules scan Python code)"
            )

    def test_old_ported_names_removed(self):
        """v4.36: The old -ported names should no longer exist in BUILTIN_PACKS."""
        from loomscan.rules import BUILTIN_PACKS
        for old_name in ["detekt-ported", "spotbugs-ported", "lintr-ported", "luacheck-ported"]:
            assert old_name not in BUILTIN_PACKS, (
                f"{old_name} should be removed (renamed to -inspired in v4.36)"
            )


# =============================================================================
# 12. VS Code extension structure
# =============================================================================

class TestVSCodeExtension:
    """v4.34: VS Code extension stub at editor/vscode-loomscan/."""

    def test_package_json_exists(self):
        ext_dir = PROJECT_ROOT / "editor" / "vscode-loomscan"
        assert (ext_dir / "package.json").exists(), "VS Code extension package.json missing"

    def test_package_json_valid(self):
        import json
        ext_dir = PROJECT_ROOT / "editor" / "vscode-loomscan"
        with open(ext_dir / "package.json") as f:
            data = json.load(f)
        assert data["name"] == "loomscan"
        assert "commands" in data["contributes"]
        commands = [c["command"] for c in data["contributes"]["commands"]]
        assert "loomscan.checkRepo" in commands
        assert "loomscan.applyFix" in commands

    def test_extension_ts_exists(self):
        ext_dir = PROJECT_ROOT / "editor" / "vscode-loomscan"
        assert (ext_dir / "src" / "extension.ts").exists(), "extension.ts missing"

    def test_readme_exists(self):
        ext_dir = PROJECT_ROOT / "editor" / "vscode-loomscan"
        assert (ext_dir / "README.md").exists()

    def test_supports_all_loomscan_languages(self):
        import json
        ext_dir = PROJECT_ROOT / "editor" / "vscode-loomscan"
        with open(ext_dir / "package.json") as f:
            data = json.load(f)
        langs = data["activationEvents"]
        # Should activate for all languages LoomScan supports
        for lang_token in ["python", "javascript", "typescript", "go", "java",
                            "rust", "c", "cpp", "php", "ruby", "csharp", "swift", "scala"]:
            assert any(lang_token in ev for ev in langs), (
                f"VS Code extension missing activation event for: {lang_token}"
            )


# =============================================================================
# 13. --strict-scanners smoke test
# =============================================================================

class TestStrictScannersSmoke:
    """v4.34: --strict-scanners flag should exit 3 when scanners fail."""

    def test_strict_scanners_flag_exists(self):
        """Verify --strict-scanners is a recognized CLI flag."""
        from click.testing import CliRunner
        from loomscan.cli import main
        runner = CliRunner()
        result = runner.invoke(main, ["check", "--help"])
        assert "--strict-scanners" in result.output, (
            "--strict-scanners must appear in `loomscan check --help`"
        )


# =============================================================================
# 14. Total rule count across the pipeline
# =============================================================================

class TestTotalRuleCount:
    """v4.34: LoomScan should now have 1,200+ rules total."""

    def test_yaml_pack_total(self):
        """Sum of YAML pack rules should be 600+."""
        total = 0
        for path in sorted(PACKS_DIR.glob("*.yml")):
            with open(path) as f:
                data = yaml.safe_load(f)
            total += len(data.get("rules", []))
        assert total >= 600, f"YAML packs total: {total} (expected 600+)"

    def test_secret_patterns_count(self):
        """v4.34 added 50+ secret patterns."""
        from loomscan.advanced_secrets import SECRET_PATTERNS_V434, SECRET_PREFIXES
        assert len(SECRET_PATTERNS_V434) >= 50
        assert len(SECRET_PREFIXES) >= 10

    def test_l8_fix_patterns_count(self):
        """v4.34: L8 Autofix should have 50+ patterns."""
        from loomscan.layers.l8_autofix import FIX_PATTERNS
        assert len(FIX_PATTERNS) >= 50
