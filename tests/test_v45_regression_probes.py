"""v4.5 Regression tests — Claude's codebase hygiene findings.

Tests:
  1. CQ-PY-EVAL must NOT match eval() inside comments/docstrings/strings
  2. CQ-PY-EXEC must NOT match exec() inside comments/docstrings/strings
  3. CQ-PY-ASSERT-PROD must NOT match assert inside comments
  4. Real eval()/exec() calls MUST still be caught
  5. pyproject.toml must include tree-sitter-typescript and tree-sitter-rust
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest


# =============================================================================
# 1. REGEX RULES MUST SKIP COMMENTS AND STRINGS
# =============================================================================

class TestCommentStringStrippingRegression:
    """Regex rules like CQ-PY-EVAL must not match inside comments/strings.

    Claude found 93 false CQ-PY-EVAL hits on STCA's self-scan — all were
    the word 'eval' appearing in comments, docstrings, or rule-definition
    strings, not actual eval() calls.
    """

    def test_eval_in_comment_not_flagged(self, tmp_path):
        """eval() in a comment must NOT be flagged."""
        from stca.code_quality import analyze_code_quality
        src = tmp_path / "app.py"
        src.write_text("""# This function uses eval() to parse user input
def parse(s):
    return int(s)
""")
        findings = analyze_code_quality(src)
        eval_findings = [f for f in findings if f.rule_id == "CQ-PY-EVAL"]
        assert len(eval_findings) == 0, (
            f"eval() in comment should not be flagged: {len(eval_findings)} findings"
        )

    def test_eval_in_docstring_not_flagged(self, tmp_path):
        """eval() in a docstring must NOT be flagged."""
        from stca.code_quality import analyze_code_quality
        src = tmp_path / "app.py"
        src.write_text('''def dangerous():
    """This function calls eval() on user input — dangerous!"""
    pass
''')
        findings = analyze_code_quality(src)
        eval_findings = [f for f in findings if f.rule_id == "CQ-PY-EVAL"]
        assert len(eval_findings) == 0, (
            f"eval() in docstring should not be flagged: {len(eval_findings)} findings"
        )

    def test_eval_in_string_literal_not_flagged(self, tmp_path):
        """eval() in a string literal must NOT be flagged."""
        from stca.code_quality import analyze_code_quality
        src = tmp_path / "app.py"
        src.write_text('''rule = r"\\beval\\s*\\("
desc = "eval() — code injection"
''')
        findings = analyze_code_quality(src)
        eval_findings = [f for f in findings if f.rule_id == "CQ-PY-EVAL"]
        assert len(eval_findings) == 0, (
            f"eval() in string literal should not be flagged: {len(eval_findings)} findings"
        )

    def test_real_eval_still_caught(self, tmp_path):
        """A real eval() call MUST still be caught."""
        from stca.code_quality import analyze_code_quality
        src = tmp_path / "app.py"
        src.write_text("""def run(user_input):
    return eval(user_input)
""")
        findings = analyze_code_quality(src)
        eval_findings = [f for f in findings if f.rule_id == "CQ-PY-EVAL"]
        assert len(eval_findings) > 0, "Real eval() call should be caught"

    def test_exec_in_comment_not_flagged(self, tmp_path):
        """exec() in a comment must NOT be flagged."""
        from stca.code_quality import analyze_code_quality
        src = tmp_path / "app.py"
        src.write_text("""# Don't use exec() in production
def run(s):
    return int(s)
""")
        findings = analyze_code_quality(src)
        exec_findings = [f for f in findings if f.rule_id == "CQ-PY-EXEC"]
        assert len(exec_findings) == 0, (
            f"exec() in comment should not be flagged: {len(exec_findings)} findings"
        )

    def test_real_exec_still_caught(self, tmp_path):
        """A real exec() call MUST still be caught."""
        from stca.code_quality import analyze_code_quality
        src = tmp_path / "app.py"
        src.write_text("""def run(code):
    exec(code)
""")
        findings = analyze_code_quality(src)
        exec_findings = [f for f in findings if f.rule_id == "CQ-PY-EXEC"]
        assert len(exec_findings) > 0, "Real exec() call should be caught"

    def test_assert_in_comment_not_flagged(self, tmp_path):
        """assert in a comment must NOT be flagged."""
        from stca.code_quality import analyze_code_quality
        src = tmp_path / "app.py"
        src.write_text("""# assert x > 0 — checked above
def process(x):
    return x + 1
""")
        findings = analyze_code_quality(src)
        assert_findings = [f for f in findings if f.rule_id == "CQ-PY-ASSERT-PROD"]
        assert len(assert_findings) == 0, (
            f"assert in comment should not be flagged: {len(assert_findings)} findings"
        )

    def test_self_scan_eval_false_positives_eliminated(self, tmp_path):
        """STCA's own source should have ~0 false CQ-PY-EVAL hits.

        Claude found 93 false hits. After the fix, only real eval() calls
        (like Z3's model.eval()) should be flagged.
        """
        from stca.code_quality import analyze_code_quality
        # Scan STCA's own code_quality.py (which contains rule definitions
        # with 'eval' in string literals)
        stca_source = Path(__file__).parent.parent / "stca" / "code_quality.py"
        if not stca_source.exists():
            pytest.skip("STCA source not found")
        findings = analyze_code_quality(stca_source)
        eval_findings = [f for f in findings if f.rule_id == "CQ-PY-EVAL"]
        assert len(eval_findings) == 0, (
            f"code_quality.py should have 0 CQ-PY-EVAL findings (all are string "
            f"literals in rule definitions). Got {len(eval_findings)}."
        )


# =============================================================================
# 2. DEPENDENCY MANIFEST CORRECTNESS
# =============================================================================

class TestDependencyManifestRegression:
    """pyproject.toml must declare all advertised language dependencies.

    Claude found that tree-sitter-typescript and tree-sitter-rust were
    missing from pyproject.toml despite being advertised in LANGUAGE_EXTENSIONS.
    """

    def test_typescript_dependency_declared(self):
        """tree-sitter-typescript must be in dependencies."""
        import tomllib
        pyproject = Path(__file__).parent.parent / "pyproject.toml"
        with open(pyproject, "rb") as f:
            data = tomllib.load(f)
        deps = data.get("project", {}).get("dependencies", [])
        assert any("tree-sitter-typescript" in d for d in deps), (
            "tree-sitter-typescript must be declared in pyproject.toml dependencies. "
            "LANGUAGE_EXTENSIONS advertises TypeScript support, so the dependency "
            "must be declared for a clean pip install to actually get it."
        )

    def test_rust_dependency_declared(self):
        """tree-sitter-rust must be in dependencies."""
        import tomllib
        pyproject = Path(__file__).parent.parent / "pyproject.toml"
        with open(pyproject, "rb") as f:
            data = tomllib.load(f)
        deps = data.get("project", {}).get("dependencies", [])
        assert any("tree-sitter-rust" in d for d in deps), (
            "tree-sitter-rust must be declared in pyproject.toml dependencies."
        )

    def test_mypy_in_dev_dependencies(self):
        """mypy must be in dev dependencies for CI type checking."""
        import tomllib
        pyproject = Path(__file__).parent.parent / "pyproject.toml"
        with open(pyproject, "rb") as f:
            data = tomllib.load(f)
        dev_deps = data.get("project", {}).get("optional-dependencies", {}).get("dev", [])
        assert any("mypy" in d for d in dev_deps), (
            "mypy must be in dev dependencies for CI type checking."
        )


# =============================================================================
# 3. CI WORKWORK EXISTENCE
# =============================================================================

class TestCIWorkflowRegression:
    """CI workflow must exist and run the test suite.

    Claude found that the only CI workflow (stca.yml) was a template for
    users, not a workflow that tests STCA itself.
    """

    def test_ci_workflow_exists(self):
        """ci.yml must exist in .github/workflows/."""
        ci_path = Path(__file__).parent.parent / ".github" / "workflows" / "ci.yml"
        assert ci_path.exists(), (
            "ci.yml must exist — Claude found no CI that tests STCA itself."
        )

    def test_ci_runs_tests(self):
        """ci.yml must run the test suite."""
        ci_path = Path(__file__).parent.parent / ".github" / "workflows" / "ci.yml"
        if not ci_path.exists():
            pytest.skip("ci.yml not found")
        content = ci_path.read_text()
        assert "pytest" in content, "ci.yml must run pytest"
        assert "self-scan" in content or "dogfood" in content.lower(), (
            "ci.yml must include a self-scan (dogfooding) step"
        )
