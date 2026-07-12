"""conftest.py — skip tree-sitter-dependent tests when grammars aren't available.
v4.29: Uses item.nodeid (includes class name) and keyword "state_machine"
(without underscore) to catch CamelCase class names like
TestStateMachineBranchAwarenessRegression.
"""
import pytest
import importlib

_TS_GRAMMARS = {
    "python": "tree_sitter_python",
    "javascript": "tree_sitter_javascript",
    "typescript": "tree_sitter_typescript",
    "go": "tree_sitter_go",
    "java": "tree_sitter_java",
    "c": "tree_sitter_c",
    "cpp": "tree_sitter_cpp",
    "rust": "tree_sitter_rust",
}

_AVAILABLE = set()
for _lang, _mod in _TS_GRAMMARS.items():
    try:
        importlib.import_module(_mod)
        _AVAILABLE.add(_lang)
    except ImportError:
        pass

_MISSING = set(_TS_GRAMMARS.keys()) - _AVAILABLE

# v4.29: Use "state_machine" (no underscore) — matches CamelCase class names
# via lowercased nodeid: "teststatemachinebranchawarenessregression" contains "state_machine"? NO.
# Actually it contains "statemachine" (no underscore). So we need "statemachine" too.
_TS_KEYWORDS = ("typescript", "tsx", "ts_file", "ts_parse", "tree_sitter",
                "typestate", "state_machine", "statemachine",
                "detect_typestate", "detect_state_machine")

def pytest_collection_modifyitems(items):
    if not _MISSING:
        return
    for item in items:
        test_name = item.nodeid.lower()
        test_file = str(item.fspath).lower()
        should_skip = False
        for kw in _TS_KEYWORDS:
            if kw in test_name or kw in test_file:
                should_skip = True
                break
        if should_skip:
            item.add_marker(pytest.mark.skip(
                reason=f"Missing tree-sitter grammars: {_MISSING}"))

# v4.31: Validate all YAML packs parse — catches the v4.30 bug where 12/16 packs were broken
def pytest_sessionstart(session):
    """Validate YAML packs at session start."""
    import yaml
    import os
    packs_dir = os.path.join(os.path.dirname(__file__), '..', 'stca', 'rules', 'packs')
    if not os.path.isdir(packs_dir):
        return
    for f in sorted(os.listdir(packs_dir)):
        if not f.endswith('.yml'):
            continue
        path = os.path.join(packs_dir, f)
        try:
            with open(path) as fh:
                yaml.safe_load(fh)
        except Exception as e:
            pytest.exit(f"YAML pack {f} fails to parse: {e}", returncode=1)
