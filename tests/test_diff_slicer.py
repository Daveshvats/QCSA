"""Tests for the diff slicer."""
import pytest
from pathlib import Path
from loomscan.diff_slicer import parse_diff, extract_callees


SAMPLE_DIFF = """diff --git a/app.py b/app.py
index abc..def 100644
--- a/app.py
+++ b/app.py
@@ -10,5 +10,8 @@ def calculate_discount(price, discount_percent):
     if price < 0:
         raise ValueError("price must be non-negative")
-    return price * (1 - discount_percent / 100)
+    if discount_percent > 100:
+        return price
+    return price * (1 - discount_percent / 100)
"""


def test_parse_diff_extracts_file():
    hunks = parse_diff(SAMPLE_DIFF)
    assert len(hunks) == 1
    assert hunks[0].file == "app.py"


def test_parse_diff_extracts_line_range():
    hunks = parse_diff(SAMPLE_DIFF)
    assert hunks[0].start_line == 10
    # the hunk should span multiple lines


def test_parse_diff_extracts_added_lines():
    hunks = parse_diff(SAMPLE_DIFF)
    added = "\n".join(hunks[0].added_lines)
    assert "discount_percent > 100" in added


def test_parse_diff_extracts_removed_lines():
    hunks = parse_diff(SAMPLE_DIFF)
    removed = "\n".join(hunks[0].removed_lines)
    assert "return price * (1 - discount_percent / 100)" in removed


def test_parse_empty_diff():
    assert parse_diff("") == []


def test_extract_callees_python():
    body = """
def foo():
    bar(1)
    baz.qux(2)
    x = lambda y: y
    print("hello")
"""
    callees = extract_callees(body, "python")
    assert "bar" in callees
    assert "print" in callees


def test_extract_callees_javascript():
    body = """
function foo() {
    bar(1);
    baz.qux(2);
    console.log("hello");
}
"""
    callees = extract_callees(body, "javascript")
    assert "bar" in callees
    assert "console" in callees or "log" in callees
