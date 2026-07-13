"""v4.4 Regression tests — Claude's second round of findings.

Tests the 4 new issues Claude identified:
  1. engine= field not wired to production (corroboration fix unwired)
  2. Java method_invocation → no attribute node (typestate blind on Java)
  3. State machine camelCase naming (blind on Java/camelCase JS)
  4. Cross-file taint f-string/composite expression support
"""
from __future__ import annotations

import tempfile
import shutil
from pathlib import Path

import pytest


# =============================================================================
# 1. ENGINE FIELD WIRED: corroboration must work on real orchestrator output
# =============================================================================

class TestEngineFieldWiredRegression:
    """The engine= field must be set on findings produced by the orchestrator.

    Claude found that engine= was added to the Finding dataclass and
    precision.py was updated, but none of the 29 call sites set it.
    The v4.4 fix uses a _tag_engines() post-processing step.
    """

    def test_engine_set_on_orchestrator_findings(self, tmp_path):
        """Orchestrator-produced findings must have engine= set."""
        from loomscan.orchestrator import Orchestrator
        from loomscan.config import STCAConfig
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / ".git").mkdir()
        (repo / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
        (repo / "app.py").write_text("""
def handler(request):
    user_input = request.GET.get("id")
    eval(user_input)
""")

        config = STCAConfig()
        orch = Orchestrator(repo, config)
        result = orch.run_full()

        # At least some findings should have engine= set (not empty)
        findings_with_engine = [f for f in result.findings if f.engine]
        assert len(findings_with_engine) > 0, (
            "No findings have engine= set. The _tag_engines() fix is not wired."
        )
        # Verify engines are diverse (not all "orchestrator")
        engines = {f.engine for f in findings_with_engine}
        assert len(engines) > 1, (
            f"All findings have the same engine: {engines}. "
            f"Expected diverse engines from different detectors."
        )


# =============================================================================
# 2. JAVA TYPESTATE: method_invocation must synthesize attribute node
# =============================================================================

class TestJavaTypestateRegression:
    """Java typestate analysis must actually work (was completely blind).

    Claude found that Java's method_invocation comes through as a 'call'
    node with no obj/attr, so the typestate detector (which checks
    node.kind == "attribute") was completely blind on Java.
    """

    def test_java_real_violation_caught(self, tmp_path):
        """Java session.get() without login() MUST be caught (was 0 before fix)."""
        from loomscan.v4_restored import detect_typestate_multi
        from loomscan.normalized_ast import parse_file
        src = tmp_path / "App.java"
        src.write_text("""public class App {
    void handleSession(Session session) {
        session.get("key");
        session.post("data");
    }
}
""")
        tree = parse_file(src)
        findings = detect_typestate_multi(tree) if tree else []
        assert len(findings) > 0, (
            "Java typestate is blind — session.get() without login() not caught. "
            "This is the exact bug Claude identified: Java method_invocation "
            "doesn't synthesize an attribute node."
        )

    def test_java_cache_get_no_fp(self, tmp_path):
        """Java cache.get() must NOT be flagged (type-evidence gating works)."""
        from loomscan.v4_restored import detect_typestate_multi
        from loomscan.normalized_ast import parse_file
        src = tmp_path / "App.java"
        src.write_text("""public class App {
    void syncData(ApiClient apiClient, Cache cache) {
        String data = apiClient.get("/users");
        cache.get("key");
        apiClient.post("/sync", data);
    }
}
""")
        tree = parse_file(src)
        findings = detect_typestate_multi(tree) if tree else []
        assert len(findings) == 0, (
            f"Java cache.get() FP: {len(findings)} findings. "
            f"Type-evidence gating should prevent this."
        )

    def test_java_use_after_close_caught(self, tmp_path):
        """Java conn.execute() after conn.close() MUST be caught."""
        from loomscan.v4_restored import detect_typestate_multi
        from loomscan.normalized_ast import parse_file
        src = tmp_path / "App.java"
        src.write_text("""public class App {
    void handleConn(Connection conn) {
        conn.close();
        conn.execute("SELECT 1");
    }
}
""")
        tree = parse_file(src)
        findings = detect_typestate_multi(tree) if tree else []
        use_after_close = [f for f in findings if "USE-AFTER-CLOSE" in f.rule_id]
        assert len(use_after_close) > 0, "Java use-after-close should be caught"


# =============================================================================
# 3. STATE MACHINE CAMELCASE: processOrder must be detected
# =============================================================================

class TestStateMachineCamelCaseRegression:
    """State machine detector must match camelCase function names.

    Claude found that only snake_case was matched (process_order), making
    the detector blind on Java/camelCase JS codebases (processOrder).
    """

    def test_camel_case_java_detected(self, tmp_path):
        """Java processOrder with double-pay MUST be caught."""
        from loomscan.v4_restored import detect_state_machine_multi
        from loomscan.normalized_ast import parse_file
        src = tmp_path / "App.java"
        src.write_text("""public class App {
    void processOrder(Order order) {
        order.pay();
        order.pay();
    }
}
""")
        tree = parse_file(src)
        findings = detect_state_machine_multi(tree) if tree else []
        assert len(findings) > 0, (
            "camelCase processOrder not detected — state machine is blind on Java. "
            "This is the exact bug Claude identified."
        )

    def test_camel_case_js_detected(self, tmp_path):
        """JS processOrder with double-pay MUST be caught."""
        from loomscan.v4_restored import detect_state_machine_multi
        from loomscan.normalized_ast import parse_file
        src = tmp_path / "app.js"
        src.write_text("""function processOrder(order) {
    order.pay();
    order.pay();
}
""")
        tree = parse_file(src)
        findings = detect_state_machine_multi(tree) if tree else []
        assert len(findings) > 0, "camelCase processOrder not detected in JS"

    def test_snake_case_still_works(self, tmp_path):
        """snake_case process_order must still be detected (no regression)."""
        from loomscan.v4_restored import detect_state_machine_multi
        from loomscan.normalized_ast import parse_file
        src = tmp_path / "app.js"
        src.write_text("""function process_order(order) {
    order.create();
    order.create();
}
""")
        tree = parse_file(src)
        findings = detect_state_machine_multi(tree) if tree else []
        assert len(findings) > 0, "snake_case process_order should still work"


# =============================================================================
# 4. CROSS-FILE TAINT F-STRING: composite expressions must propagate taint
# =============================================================================

class TestCrossFileTaintFStringRegression:
    """Cross-file taint must flow through f-strings and composite expressions.

    Claude found that only bare-copy assignments (sql = user_id) propagated
    taint, but composite expressions (sql = f"...{user_id}...") broke the
    def-use chain.
    """

    def test_f_string_cross_file_taint(self, tmp_path):
        """Taint must flow: request → user_id → f-string sql → execute_query → execute."""
        from loomscan.cpg import build_cpg_for_repo
        from loomscan.taint_cross_file import track_taint_cross_file
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.py").write_text("""
from db import execute_query
def handler(request):
    user_id = request.GET.get("id")
    sql = f"SELECT * FROM users WHERE id = {user_id}"
    result = execute_query(sql)
    return result
""")
        (repo / "db.py").write_text("""
def execute_query(query):
    return cursor.execute(query)
""")

        cpg = build_cpg_for_repo(repo)
        flows = track_taint_cross_file(cpg)

        # Should find at least one cross-file flow
        cross_flows = [f for f in flows if f.cross_file]
        assert len(cross_flows) > 0, (
            "f-string cross-file taint not detected. "
            "The composite-expression data_dep edge is missing."
        )

    def test_bare_copy_cross_file_still_works(self, tmp_path):
        """Bare-copy cross-file taint (sql = user_id) must still work."""
        from loomscan.cpg import build_cpg_for_repo
        from loomscan.taint_cross_file import track_taint_cross_file
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.py").write_text("""
from db import execute_query
def handler(request):
    user_id = request.GET.get("id")
    sql = user_id
    result = execute_query(sql)
    return result
""")
        (repo / "db.py").write_text("""
def execute_query(query):
    return cursor.execute(query)
""")

        cpg = build_cpg_for_repo(repo)
        flows = track_taint_cross_file(cpg)
        cross_flows = [f for f in flows if f.cross_file]
        assert len(cross_flows) > 0, "Bare-copy cross-file taint should still work"

    def test_string_concat_cross_file_taint(self, tmp_path):
        """Taint must flow through string concatenation: sql = "..." + user_id."""
        from loomscan.cpg import build_cpg_for_repo
        from loomscan.taint_cross_file import track_taint_cross_file
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.py").write_text("""
from db import execute_query
def handler(request):
    user_id = request.GET.get("id")
    sql = "SELECT * FROM users WHERE id = " + user_id
    result = execute_query(sql)
    return result
""")
        (repo / "db.py").write_text("""
def execute_query(query):
    return cursor.execute(query)
""")

        cpg = build_cpg_for_repo(repo)
        flows = track_taint_cross_file(cpg)
        cross_flows = [f for f in flows if f.cross_file]
        assert len(cross_flows) > 0, (
            "String concatenation cross-file taint not detected. "
            "Composite expressions should propagate taint."
        )
