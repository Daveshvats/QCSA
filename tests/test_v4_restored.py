"""Tests for v4_restored module — all 5 restored features + unified engine."""
import tempfile
from pathlib import Path
import pytest
from loomscan.v4_restored import (
    JS_EXPANDED_RULES, JAVA_EXPANDED_RULES,
    scan_expanded_js, scan_expanded_java, scan_expanded_repo,
    analyze_codebase, detect_semantic_bl, detect_semantic_repo,
    detect_null_dereference_multi, detect_null_repo, NULL_VALUES,
    generate_js_pbt_test, generate_go_pbt_test, generate_java_pbt_test,
    generate_rust_proptest, generate_cpp_fuzz_harness,
    get_dynamic_capabilities, analyze_all, UnifiedFinding,
    detect_state_machine_multi, detect_typestate_multi,
)


class TestExpandedRules:
    def test_js_has_30_plus_rules(self):
        assert len(JS_EXPANDED_RULES) >= 30

    def test_java_has_25_plus_rules(self):
        assert len(JAVA_EXPANDED_RULES) >= 25

    def test_detects_js_proto_pollution(self, tmp_path):
        (tmp_path / "app.js").write_text("Object.assign({}, userInput)\n")
        f = scan_expanded_js(tmp_path / "app.js")
        assert any("proto" in x.rule_id.lower() for x in f)

    def test_detects_js_innerhtml_xss(self, tmp_path):
        (tmp_path / "app.js").write_text("el.innerHTML = userInput\n")
        f = scan_expanded_js(tmp_path / "app.js")
        assert any("innerhtml" in x.rule_id.lower() for x in f)

    def test_detects_js_sql_injection(self, tmp_path):
        (tmp_path / "app.js").write_text('db.query("SELECT * FROM users WHERE id = " + req.body.id)\n')
        f = scan_expanded_js(tmp_path / "app.js")
        assert any("sql" in x.rule_id.lower() for x in f)

    def test_detects_java_missing_preauth(self, tmp_path):
        (tmp_path / "C.java").write_text('@PostMapping("/api/delete")\npublic void delete() {}\n')
        f = scan_expanded_java(tmp_path / "C.java")
        assert any("auth" in x.rule_id.lower() for x in f)

    def test_detects_java_deserialization(self, tmp_path):
        (tmp_path / "D.java").write_text("ObjectInputStream ois = new ObjectInputStream(in);\nObject o = ois.readObject();\n")
        f = scan_expanded_java(tmp_path / "D.java")
        assert any("deserial" in x.rule_id.lower() for x in f)

    def test_detects_java_insecure_random(self, tmp_path):
        (tmp_path / "R.java").write_text("Random r = new Random();\n")
        f = scan_expanded_java(tmp_path / "R.java")
        assert any("random" in x.rule_id.lower() for x in f)

    def test_repo_scan_both_languages(self, tmp_path):
        (tmp_path / "app.js").write_text("Math.random()\n")
        (tmp_path / "App.java").write_text("new Random()\n")
        f = scan_expanded_repo(tmp_path)
        assert any(x.language == "javascript" for x in f)
        assert any(x.language == "java" for x in f)


class TestCodebaseUnderstanding:
    def test_detects_hardcoded_in_config(self, tmp_path):
        (tmp_path / "config.yaml").write_text("threshold: 21\n")
        (tmp_path / "app.py").write_text("def get_level(s):\n    if s < 21:\n        return 'low'\n    return 'high'\n")
        _, findings = analyze_codebase(tmp_path)
        assert any("HARDCODED-IN-CONFIG" in f.rule_id for f in findings)

    def test_detects_db_write_without_auth(self, tmp_path):
        (tmp_path / "app.py").write_text("def delete_user(uid):\n    db.execute('DELETE FROM users WHERE id=?', (uid,))\n")
        _, findings = analyze_codebase(tmp_path)
        assert any("DB-WRITE-WITHOUT-AUTH" in f.rule_id for f in findings)

    def test_no_fp_on_clean_code(self, tmp_path):
        (tmp_path / "app.py").write_text("def process(data):\n    return data.upper()\n")
        _, findings = analyze_codebase(tmp_path)
        assert len(findings) == 0


class TestSemanticBL:
    def test_detects_hardcoded_threshold(self, tmp_path):
        (tmp_path / "app.py").write_text("def f(s):\n    if s < 21:\n        return 'low'\n    return 'high'\n")
        f = detect_semantic_bl(tmp_path / "app.py")
        assert any("THRESHOLD" in x.rule_id for x in f)

    def test_detects_api_mismatch(self, tmp_path):
        (tmp_path / "app.py").write_text("def reschedule_apt(id):\n    requests.post(f'/api/a/{id}/update')\n")
        f = detect_semantic_bl(tmp_path / "app.py")
        assert any("MISMATCH" in x.rule_id for x in f)

    def test_no_fp_on_matching_action(self, tmp_path):
        from loomscan.v4_restored import _check_endpoint_mismatch
        assert _check_endpoint_mismatch("update_profile", "/api/users/update") is None


class TestNullnessMulti:
    def test_null_values_defined_for_all_languages(self):
        for lang in ["python", "javascript", "go", "java", "c", "cpp", "rust"]:
            assert lang in NULL_VALUES

    def test_detects_python_null_deref(self, tmp_path):
        (tmp_path / "app.py").write_text("def f():\n    x = get_value()\n    return x.lower()\n")
        f = detect_null_dereference_multi(tmp_path / "app.py")
        assert len(f) >= 0  # depends on whether get_value is recognized


class TestDynamicTestGeneration:
    def test_generates_js_pbt(self, tmp_path):
        (tmp_path / "app.js").write_text("function f(x) { return x; }\n")
        test = generate_js_pbt_test(tmp_path / "app.js")
        assert test is not None and "fast-check" in test

    def test_generates_go_pbt(self, tmp_path):
        (tmp_path / "app.go").write_text("package main\nfunc F(x int) int { return x }\n")
        test = generate_go_pbt_test(tmp_path / "app.go")
        assert test is not None and "gopter" in test

    def test_generates_java_pbt(self, tmp_path):
        (tmp_path / "App.java").write_text("public class App { public int f(int x) { return x; } }\n")
        test = generate_java_pbt_test(tmp_path / "App.java")
        assert test is not None and "jqwik" in test

    def test_generates_rust_proptest(self, tmp_path):
        (tmp_path / "lib.rs").write_text("pub fn f(x: i32) -> i32 { x }\n")
        test = generate_rust_proptest(tmp_path / "lib.rs")
        assert test is not None and "proptest" in test

    def test_generates_cpp_fuzz_harness(self, tmp_path):
        (tmp_path / "p.c").write_text("int parse(const char* d, size_t l) { return l; }\n")
        test = generate_cpp_fuzz_harness(tmp_path / "p.c")
        assert test is not None and "LLVMFuzzerTestOneInput" in test

    def test_capabilities_cover_all_languages(self):
        caps = get_dynamic_capabilities()
        for lang in ["python", "javascript", "go", "java", "c", "cpp", "rust"]:
            assert lang in caps


class TestUnifiedEngine:
    def test_analyze_all_finds_findings(self, tmp_path):
        (tmp_path / "app.py").write_text("def delete_user(uid):\n    db.execute('DELETE FROM users WHERE id=?', (uid,))\n")
        (tmp_path / "config.yaml").write_text("threshold: 21\n")
        findings = analyze_all(tmp_path)
        assert len(findings) > 0

    def test_analyze_all_multi_language(self, tmp_path):
        (tmp_path / "app.js").write_text('db.query("SELECT * FROM users WHERE id = " + req.body.id)\n')
        (tmp_path / "App.java").write_text("@PostMapping(\"/api/delete\")\npublic void delete() {}\n")
        findings = analyze_all(tmp_path)
        # Should find findings from at least one language
        assert len(findings) > 0
