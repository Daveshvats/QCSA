"""Tests for new layers: taint tracker, suppressions, behavioral, IaC, commit risk."""
import pytest
import os
import sys
import subprocess
from pathlib import Path

# Make sure we can import loomscan
sys.path.insert(0, str(Path(__file__).parent.parent))

from loomscan.taint_tracker import track_taint_python, TaintFlow
from loomscan.suppressions import find_suppressions, is_suppressed, filter_suppressed
from loomscan.layers.l0d_behavioral import L0dBehavioral
from loomscan.layers.l0e_iac import L0eIaC
from loomscan.layers.l0f_commit_risk import L0fCommitRisk
from loomscan.layers.l8_autofix import L8AutoFix, FIX_PATTERNS
from loomscan.brain.tuner import compute_adjustments
from loomscan.models import Finding, Severity, BlastRadius, LayerID


# === Taint tracker ===

def test_taint_tracker_finds_eval_flow(tmp_path):
    """Should detect taint flow: request → eval."""
    src = tmp_path / "app.py"
    src.write_text("""
def handle(request):
    data = request
    return eval(data)
""")
    flows = track_taint_python(src)
    assert len(flows) >= 1
    assert any(f.sink_call == "eval" for f in flows)
    assert any(f.source_param == "request" for f in flows)


def test_taint_tracker_finds_sql_injection(tmp_path):
    """Should detect taint flow: user_id → execute."""
    src = tmp_path / "app.py"
    src.write_text("""
def get_user(cursor, user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return cursor.execute(query)
""")
    flows = track_taint_python(src)
    # should find execute as a sink with user_id as source
    assert any("execute" in f.sink_call for f in flows)


def test_taint_tracker_no_false_positive_on_safe_code(tmp_path):
    """Should NOT flag code with no source-like params."""
    src = tmp_path / "safe.py"
    src.write_text("""
def add(a, b):
    return a + b
""")
    flows = track_taint_python(src)
    assert len(flows) == 0


# === Suppressions ===

def test_suppression_inline_all_rules(tmp_path):
    src = tmp_path / "app.py"
    src.write_text("eval(x)  # loomscan: ignore\n")
    sups = find_suppressions(src)
    assert len(sups) == 1
    assert sups[0].rule_id is None


def test_suppression_specific_rule(tmp_path):
    src = tmp_path / "app.py"
    src.write_text("eval(x)  # loomscan: ignore[L0.sast.mini:py-eval]\n")
    sups = find_suppressions(src)
    assert len(sups) == 1
    assert sups[0].rule_id == "L0.sast.mini:py-eval"


def test_is_suppressed_same_line(tmp_path):
    src = tmp_path / "app.py"
    src.write_text("eval(x)  # loomscan: ignore\n")
    sups = find_suppressions(src, tmp_path)  # v4.15: pass repo_root for relative paths
    finding = Finding(layer=LayerID.L0_FAST, rule_id="L0.sast.mini:py-eval",
                      message="eval()", file="app.py", start_line=1)  # v4.15: relative path
    is_sup, _ = is_suppressed(finding.file, finding.start_line, finding.rule_id, sups)
    assert is_sup


def test_is_suppressed_line_above(tmp_path):
    """Comment on line N suppresses finding on line N+1."""
    src = tmp_path / "app.py"
    src.write_text("# loomscan: ignore\neval(x)\n")
    sups = find_suppressions(src, tmp_path)  # v4.15: pass repo_root
    is_sup, _ = is_suppressed("app.py", 2, "L0.sast.mini:py-eval", sups)  # v4.15: relative
    assert is_sup


def test_filter_suppressed_returns_kept_and_suppressed(tmp_path):
    src = tmp_path / "app.py"
    src.write_text("eval(x)  # loomscan: ignore\nprint('safe')\n")
    findings = [
        Finding(layer=LayerID.L0_FAST, rule_id="L0.sast.mini:py-eval",
                message="eval()", file="app.py", start_line=1),  # v4.15: relative
        Finding(layer=LayerID.L0_FAST, rule_id="L0.print",
                message="print", file="app.py", start_line=2),  # v4.15: relative
    ]
    kept, suppressed = filter_suppressed(findings, tmp_path)
    # the loomscan: ignore on line 1 suppresses BOTH findings on that line
    # (because rule_id=None means "all rules")
    # But the print() finding is on line 2 — the suppression on line 1
    # only covers line 1 and line 2 (line above rule)
    # So both get suppressed here. That's correct behavior.
    assert len(suppressed) == 2
    assert len(kept) == 0


def test_filter_suppressed_specific_rule(tmp_path):
    """A specific rule suppression should only suppress that rule, not others."""
    src = tmp_path / "app.py"
    src.write_text("eval(x)  # loomscan: ignore[L0.sast.mini:py-eval]\n")
    findings = [
        Finding(layer=LayerID.L0_FAST, rule_id="L0.sast.mini:py-eval",
                message="eval()", file="app.py", start_line=1),  # v4.15: relative
        Finding(layer=LayerID.L0_FAST, rule_id="L0.some-other-rule",
                message="other", file="app.py", start_line=1),  # v4.15: relative
    ]
    kept, suppressed = filter_suppressed(findings, tmp_path)
    assert len(suppressed) == 1
    assert len(kept) == 1
    assert kept[0].rule_id == "L0.some-other-rule"


# === L0d Behavioral ===

def test_cyclomatic_complexity_counts_ifs(tmp_path):
    """Complexity should count if/for/while/except/etc."""
    src = tmp_path / "complex.py"
    src.write_text("""
def complex_fn(x):
    if x > 0:
        if x > 10:
            return 1
        else:
            return 2
    elif x < -10:
        for i in range(10):
            if i == 5:
                try:
                    return 3
                except ValueError:
                    return 4
    return 0
""")
    layer = L0dBehavioral()
    import ast
    tree = ast.parse(src.read_text())
    fn_node = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef))
    cc = layer._function_complexity(fn_node)
    # 1 (base) + 4 ifs + 1 elif (If) + 1 for + 1 except = 8
    assert cc >= 6, f"Expected CC >= 6, got {cc}"


def test_behavioral_finds_high_complexity_function(tmp_path):
    """High-complexity functions should be flagged."""
    src = tmp_path / "complex.py"
    src.write_text("""
def complex_fn(x):
    if x > 0:
        if x > 10:
            if x > 20:
                if x > 30:
                    if x > 40:
                        if x > 50:
                            if x > 60:
                                if x > 70:
                                    if x > 80:
                                        if x > 90:
                                            if x > 100:
                                                if x > 110:
                                                    if x > 120:
                                                        if x > 130:
                                                            if x > 140:
                                                                if x > 150:
                                                                    if x > 160:
                                                                        if x > 170:
                                                                            if x > 180:
                                                                                if x > 190:
                                                                                    return 1
    return 0
""")
    layer = L0dBehavioral()
    # lower the threshold for this test to make it deterministic
    layer.HIGH_COMPLEXITY_THRESHOLD = 15
    findings = layer._detect_high_complexity(tmp_path, {"complex.py"})
    assert len(findings) >= 1
    assert any("high_complexity" in f.rule_id for f in findings)


# === L0e IaC ===

def test_iac_finds_dockerfile_latest_tag(tmp_path):
    df = tmp_path / "Dockerfile"
    df.write_text("FROM python:latest\nCMD python app.py\n")
    layer = L0eIaC()
    findings = layer._scan_dockerfiles(tmp_path, {"Dockerfile"})
    assert any("latest" in f.rule_id for f in findings)


def test_iac_finds_dockerfile_root_user(tmp_path):
    df = tmp_path / "Dockerfile"
    df.write_text("FROM python:3.12\nUSER root\n")
    layer = L0eIaC()
    findings = layer._scan_dockerfiles(tmp_path, {"Dockerfile"})
    assert any("root" in f.rule_id for f in findings)


def test_iac_finds_dockerfile_secret_env(tmp_path):
    df = tmp_path / "Dockerfile"
    df.write_text("FROM python:3.12\nENV API_KEY=sk-1234567890abcdef\n")
    layer = L0eIaC()
    findings = layer._scan_dockerfiles(tmp_path, {"Dockerfile"})
    assert any("secret" in f.rule_id.lower() for f in findings)


def test_iac_finds_k8s_privileged(tmp_path):
    k8s = tmp_path / "k8s-pod.yaml"
    k8s.write_text("""
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    image: app:latest
    securityContext:
      privileged: true
""")
    layer = L0eIaC()
    findings = layer._scan_k8s(tmp_path, {"k8s-pod.yaml"})
    assert any("privileged" in f.rule_id for f in findings)


def test_iac_finds_terraform_public_bucket(tmp_path):
    tf = tmp_path / "main.tf"
    tf.write_text('resource "aws_s3_bucket" "data" {\n  acl = "public-read"\n}\n')
    layer = L0eIaC()
    findings = layer._scan_terraform(tmp_path, {"main.tf"})
    assert any("public" in f.rule_id for f in findings)


def test_iac_finds_gha_pull_request_target(tmp_path):
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    wf = wf_dir / "ci.yml"
    wf.write_text("on: pull_request_target\njobs:\n  test:\n    runs-on: ubuntu-latest\n")
    layer = L0eIaC()
    findings = layer._scan_github_actions(tmp_path, {str(wf.relative_to(tmp_path))})
    # rule_id uses hyphens (gha-pull-request-target), not underscores
    assert any("pull-request-target" in f.rule_id or "pull_request_target" in f.rule_id
               for f in findings)


# === L0f Commit Risk ===

def test_commit_risk_finds_risky_message(tmp_path):
    """Risky commit messages (WIP, hotfix) should be flagged."""
    # init a git repo
    subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True)
    subprocess.run(["git", "config", "user.email", "t@t.com"], cwd=tmp_path, capture_output=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=tmp_path, capture_output=True)
    (tmp_path / "file.txt").write_text("hello")
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, capture_output=True)
    subprocess.run(["git", "commit", "-m", "WIP hack"], cwd=tmp_path, capture_output=True)
    layer = L0fCommitRisk()
    meta = layer._get_commit_meta(tmp_path)
    findings = layer._check_message(tmp_path, meta)
    assert any("message_risk" in f.rule_id for f in findings)


def test_commit_risk_finds_short_message(tmp_path):
    """Short commit messages should be flagged."""
    subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True)
    subprocess.run(["git", "config", "user.email", "t@t.com"], cwd=tmp_path, capture_output=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=tmp_path, capture_output=True)
    (tmp_path / "file.txt").write_text("hello")
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, capture_output=True)
    subprocess.run(["git", "commit", "-m", "fix"], cwd=tmp_path, capture_output=True)
    layer = L0fCommitRisk()
    meta = layer._get_commit_meta(tmp_path)
    findings = layer._check_message(tmp_path, meta)
    assert any("short_message" in f.rule_id for f in findings)


def test_commit_risk_finds_new_author(tmp_path):
    """Authors with <10 lifetime commits should be flagged."""
    subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True)
    subprocess.run(["git", "config", "user.email", "new@test.com"], cwd=tmp_path, capture_output=True)
    subprocess.run(["git", "config", "user.name", "new"], cwd=tmp_path, capture_output=True)
    (tmp_path / "file.txt").write_text("hello")
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, capture_output=True)
    subprocess.run(["git", "commit", "-m", "first commit"], cwd=tmp_path, capture_output=True)
    layer = L0fCommitRisk()
    meta = layer._get_commit_meta(tmp_path)
    findings = layer._check_author(tmp_path, meta)
    assert any("new_author" in f.rule_id for f in findings)


# === FIS Tuner ===

def test_tuner_widens_band_for_high_fp():
    stats = {
        "L0_fast": {"tp": 5, "fp": 10, "fn": 2, "precision": 0.33, "recall": 0.71}
    }
    adj = compute_adjustments(stats)
    assert "L0_fast" in adj
    assert adj["L0_fast"].confidence_band_widen > 0


def test_tuner_lowers_threshold_for_high_fn():
    stats = {
        "L1_property": {"tp": 2, "fp": 1, "fn": 8, "precision": 0.67, "recall": 0.20}
    }
    adj = compute_adjustments(stats)
    assert "L1_property" in adj
    assert adj["L1_property"].severity_threshold_lower > 0


def test_tuner_no_adjustment_when_balanced():
    stats = {
        "L5_policy": {"tp": 8, "fp": 2, "fn": 2, "precision": 0.80, "recall": 0.80}
    }
    adj = compute_adjustments(stats)
    assert "L5_policy" not in adj


# === Auto-Fix ===

def test_autofix_eval_to_literal_eval(tmp_path):
    """eval() with a LITERAL argument should be fixed to ast.literal_eval()."""
    src = tmp_path / "app.py"
    # Use a literal string argument — ast.literal_eval can handle this
    src.write_text("def f():\n    return eval('[1, 2, 3]')\n")
    finding = Finding(
        layer=LayerID.L0_FAST, rule_id="L0.sast.mini:py-eval",
        message="eval()", file="app.py", start_line=2,
    )
    from loomscan.layers.l8_autofix import _fix_eval_python
    patch = _fix_eval_python(finding, tmp_path)
    assert patch is not None
    assert "ast.literal_eval" in patch
    assert "import ast" in patch
    # Verify the patched code actually parses
    import ast as _ast
    _ast.parse(patch)


def test_autofix_eval_rejects_dynamic_args(tmp_path):
    """eval() with a dynamic argument (variable, f-string) should NOT be fixed.

    ast.literal_eval would crash on these — the fixer must reject them.
    """
    from loomscan.layers.l8_autofix import _fix_eval_python

    # Variable argument — should NOT be fixed
    src = tmp_path / "app.py"
    src.write_text("def f(x):\n    return eval(x)\n")
    finding = Finding(
        layer=LayerID.L0_FAST, rule_id="L0.sast.mini:py-eval",
        message="eval()", file="app.py", start_line=2,
    )
    patch = _fix_eval_python(finding, tmp_path)
    assert patch is None  # rejected — would break at runtime

    # F-string argument — should NOT be fixed
    src.write_text("def f(name):\n    return eval(f'{name}')\n")
    finding = Finding(
        layer=LayerID.L0_FAST, rule_id="L0.sast.mini:py-eval",
        message="eval()", file="app.py", start_line=2,
    )
    patch = _fix_eval_python(finding, tmp_path)
    assert patch is None  # rejected — would break at runtime


def test_autofix_hardcoded_password_produces_valid_syntax(tmp_path):
    """The password fixer must produce code that actually parses.

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
    finding = Finding(
        layer=LayerID.L0_FAST, rule_id="L0.sast.mini:py-hardcoded-password",
        message="hardcoded password", file="app.py", start_line=3,
    )
    from loomscan.layers.l8_autofix import _fix_hardcoded_password
    patch = _fix_hardcoded_password(finding, tmp_path)
    assert patch is not None
    # CRITICAL: the patched code must parse without SyntaxError
    import ast as _ast
    _ast.parse(patch)  # raises if broken
    # The if-line should be commented out
    assert '# if password == "admin123":' in patch
    # The body should also be commented out (not left dangling)
    assert '# print("authenticated")' in patch
    assert '# return True' in patch


def test_autofix_bare_except(tmp_path):
    src = tmp_path / "app.py"
    src.write_text("try:\n    x = 1\nexcept:\n    pass\n")
    finding = Finding(
        layer=LayerID.L0_FAST, rule_id="L0.sast.mini:py-bare-except",
        message="bare except", file="app.py", start_line=3,
    )
    from loomscan.layers.l8_autofix import _fix_bare_except
    patch = _fix_bare_except(finding, tmp_path)
    assert patch is not None
    assert "except Exception:" in patch
