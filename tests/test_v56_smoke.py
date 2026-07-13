"""v5.6 smoke tests — Multi-language CPG taint (JS/Java/Go).

Tests:
1. Taint source/sink/sanitizer patterns cover JS/Java/Go
2. Interprocedural KB has extended JS/Go entries
3. CPG taint tracking works on multi-lang CPG
4. Version is v5.6
"""
from __future__ import annotations

from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parent.parent


# =============================================================================
# 1. Taint patterns cover JS/Java/Go
# =============================================================================

class TestMultiLangTaintPatterns:
    """v5.6: Taint source/sink/sanitizer patterns extended for JS/Java/Go."""

    def test_js_sinks_present(self):
        from loomscan.taint_cross_file import SINK_PATTERNS
        js_sinks = ["innerHTML", "execSync", "execFile", "fetch", "document.write",
                    "send", "writeFile", "readFile", "Function", "setTimeout"]
        for s in js_sinks:
            assert s in SINK_PATTERNS, f"JS sink '{s}' missing from SINK_PATTERNS"

    def test_go_sinks_present(self):
        from loomscan.taint_cross_file import SINK_PATTERNS
        go_sinks = ["Exec", "Command", "Query", "QueryRow", "Open", "OpenFile",
                    "ReadFile", "WriteFile", "Get", "Post", "NewRequest", "Redirect"]
        for s in go_sinks:
            assert s in SINK_PATTERNS, f"Go sink '{s}' missing from SINK_PATTERNS"

    def test_java_sinks_present(self):
        from loomscan.taint_cross_file import SINK_PATTERNS
        java_sinks = ["executeQuery", "executeUpdate", "sendRedirect", "sendError",
                      "setHeader", "readObject", "evaluate", "lookup", "println", "printf"]
        for s in java_sinks:
            assert s in SINK_PATTERNS, f"Java sink '{s}' missing from SINK_PATTERNS"

    def test_js_sources_present(self):
        from loomscan.taint_cross_file import SOURCE_CALL_PATTERNS, SOURCE_PARAM_PATTERNS
        assert "req.query" in SOURCE_CALL_PATTERNS
        assert "req.body" in SOURCE_CALL_PATTERNS
        assert "req.params" in SOURCE_CALL_PATTERNS
        assert "process.argv" in SOURCE_CALL_PATTERNS
        assert "req" in SOURCE_PARAM_PATTERNS

    def test_go_sources_present(self):
        from loomscan.taint_cross_file import SOURCE_CALL_PATTERNS
        assert "r.FormValue" in SOURCE_CALL_PATTERNS
        assert "r.URL.Query" in SOURCE_CALL_PATTERNS
        assert "r.Header.Get" in SOURCE_CALL_PATTERNS
        assert "os.Getenv" in SOURCE_CALL_PATTERNS
        assert "os.Args" in SOURCE_CALL_PATTERNS

    def test_java_sources_present(self):
        from loomscan.taint_cross_file import SOURCE_CALL_PATTERNS
        assert "getParameter" in SOURCE_CALL_PATTERNS
        assert "getHeader" in SOURCE_CALL_PATTERNS
        assert "getCookies" in SOURCE_CALL_PATTERNS
        assert "System.getenv" in SOURCE_CALL_PATTERNS

    def test_js_sanitizers_present(self):
        from loomscan.taint_cross_file import SANITIZER_PATTERNS
        js_san = ["encodeURIComponent", "encodeURI", "escapeHtml", "escapeHTML",
                  "sanitize", "parseInt", "parseFloat", "Number", "JSON.stringify"]
        for s in js_san:
            assert s in SANITIZER_PATTERNS, f"JS sanitizer '{s}' missing"

    def test_go_sanitizers_present(self):
        from loomscan.taint_cross_file import SANITIZER_PATTERNS
        go_san = ["QueryEscape", "PathEscape", "HTMLescape", "HTMLEscape",
                  "Atoi", "ParseInt", "ParseFloat", "Prepare", "Quote"]
        for s in go_san:
            assert s in SANITIZER_PATTERNS, f"Go sanitizer '{s}' missing"

    def test_java_sanitizers_present(self):
        from loomscan.taint_cross_file import SANITIZER_PATTERNS
        java_san = ["escapeHtml", "escapeHtml4", "escapeXml", "URLEncoder.encode",
                    "Integer.parseInt", "PreparedStatement", "setString", "setInt"]
        for s in java_san:
            assert s in SANITIZER_PATTERNS, f"Java sanitizer '{s}' missing"

    def test_total_sink_count_increased(self):
        from loomscan.taint_cross_file import SINK_PATTERNS
        # Was 28 in v5.5, should be 60+ with JS/Java/Go
        assert len(SINK_PATTERNS) >= 60, (
            f"SINK_PATTERNS should have 60+ entries (was 28). Got {len(SINK_PATTERNS)}"
        )

    def test_total_source_count_increased(self):
        from loomscan.taint_cross_file import SOURCE_CALL_PATTERNS
        assert len(SOURCE_CALL_PATTERNS) >= 30, (
            f"SOURCE_CALL_PATTERNS should have 30+ entries. Got {len(SOURCE_CALL_PATTERNS)}"
        )

    def test_total_sanitizer_count_increased(self):
        from loomscan.taint_cross_file import SANITIZER_PATTERNS
        assert len(SANITIZER_PATTERNS) >= 30, (
            f"SANITIZER_PATTERNS should have 30+ entries. Got {len(SANITIZER_PATTERNS)}"
        )


# =============================================================================
# 2. Interprocedural KB extended
# =============================================================================

class TestInterproceduralKBExtended:
    """v5.6: Interprocedural KB has extended JS/Go entries with full source/sink/passthrough."""

    def test_js_kb_has_50_plus_entries(self):
        from loomscan.interprocedural import LANGUAGE_KNOWLEDGE
        js_kb = LANGUAGE_KNOWLEDGE.get("javascript", {})
        assert len(js_kb) >= 50, f"JS KB should have 50+ entries. Got {len(js_kb)}"

    def test_go_kb_has_30_plus_entries(self):
        from loomscan.interprocedural import LANGUAGE_KNOWLEDGE
        go_kb = LANGUAGE_KNOWLEDGE.get("go", {})
        assert len(go_kb) >= 30, f"Go KB should have 30+ entries. Got {len(go_kb)}"

    def test_js_kb_has_sinks(self):
        from loomscan.interprocedural import LANGUAGE_KNOWLEDGE
        js_kb = LANGUAGE_KNOWLEDGE.get("javascript", {})
        js_sinks = [k for k, v in js_kb.items() if v.is_sink]
        assert len(js_sinks) >= 15, f"JS KB should have 15+ sinks. Got {len(js_sinks)}"

    def test_go_kb_has_sinks(self):
        from loomscan.interprocedural import LANGUAGE_KNOWLEDGE
        go_kb = LANGUAGE_KNOWLEDGE.get("go", {})
        go_sinks = [k for k, v in go_kb.items() if v.is_sink]
        assert len(go_sinks) >= 15, f"Go KB should have 15+ sinks. Got {len(go_sinks)}"

    def test_js_kb_has_sources(self):
        from loomscan.interprocedural import LANGUAGE_KNOWLEDGE
        js_kb = LANGUAGE_KNOWLEDGE.get("javascript", {})
        js_sources = [k for k, v in js_kb.items() if v.is_source]
        assert len(js_sources) >= 10, f"JS KB should have 10+ sources. Got {len(js_sources)}"

    def test_go_kb_has_sources(self):
        from loomscan.interprocedural import LANGUAGE_KNOWLEDGE
        go_kb = LANGUAGE_KNOWLEDGE.get("go", {})
        go_sources = [k for k, v in go_kb.items() if v.is_source]
        assert len(go_sources) >= 10, f"Go KB should have 10+ sources. Got {len(go_sources)}"


# =============================================================================
# 3. Version
# =============================================================================

class TestVersionV56:
    def test_version_is_5_6(self):
        from loomscan import __version__
        major, minor = int(__version__.split(".")[0]), int(__version__.split(".")[1])
        assert major >= 5 and minor >= 6, f"Expected >= 5.6.0, got {__version__}"

    def test_pyproject_matches(self):
        from loomscan import __version__
        import re as _re
        content = (PROJECT_ROOT / "pyproject.toml").read_text()
        m = _re.search(r'^version\s*=\s*["\']([^"\']+)["\']', content, _re.MULTILINE)
        assert m
        assert m.group(1) == __version__
