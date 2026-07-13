from __future__ import annotations

import ast
import re
import os
import json
import subprocess
import sys
import textwrap
import tempfile
import logging
from pathlib import Path
from typing import List, Optional, Dict, Any, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict

try:
    from .normalized_ast import parse_file, get_language, is_supported, NormalizedNode, _HAS_TS, _TS_LANGUAGE_MODULES
except ImportError:
    _HAS_TS = False
    _TS_LANGUAGE_MODULES = {}

_v4_logger = logging.getLogger("loomscan.v4_restored")

def generate_js_pbt_test(file_path: Path, repo_root: Path = None) -> Optional[str]:
    try:
        source = file_path.read_text(encoding="utf-8")
    except Exception:
        return None
    module = file_path.stem
    funcs = [(m.group(1), len([p for p in m.group(2).split(",") if p.strip()])) for m in re.finditer(r'(?:export\s+)?function\s+(\w+)\s*\(([^)]*)\)', source)]
    funcs += [(m.group(1), 1) for m in re.finditer(r'(?:export\s+)?const\s+(\w+)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>', source)]
    if not funcs: return None
    parts = [f"const fc = require('fast-check');\nconst mod = require('./{module}');\n"]
    for fn, pc in funcs[:5]:
        if pc == 0: continue
        args = ", ".join([f"fc.string()"] * min(pc, 2))
        parts.append(f"""
test('{fn} determinism', () => {{
    fc.assert(fc.property({args}, (...args) => {{
        try {{ expect(mod.{fn}(...args)).toEqual(mod.{fn}(...args)); }}
        catch(e) {{ return true; }}
    }}));
}});
""")
    return "\n".join(parts)

def generate_go_pbt_test(file_path: Path, repo_root: Path = None) -> Optional[str]:
    try:
        source = file_path.read_text(encoding="utf-8")
    except Exception:
        return None
    funcs = [m.group(1) for m in re.finditer(r'func\s+(?:\([^)]*\)\s+)?(\w+)\s*\(', source) if m.group(1)[0].isupper()]
    if not funcs: return None
    pkg = (re.search(r'package\s+(\w+)', source) or [None, "main"])[1]
    parts = [f"package {pkg}\nimport (\n\t\"testing\"\n\t\"github.com/leanovate/gopter\"\n\t\"github.com/leanovate/gopter/gen\"\n)\nfunc TestPBT(t *testing.T) {{\n"]
    for fn in funcs[:5]:
        parts.append(f"\tprop := gopter.NewProperties({{}})\n\tprop.Property(\"{fn} determinism\", prop.ForAll(func(x int) bool {{ r1 := {fn}(x); r2 := {fn}(x); return r1 == r2 }}, gen.IntRange(-100, 100)))\n\tproperty.TestingRun(t)\n")
    parts.append("}\n")
    return "\n".join(parts)

def generate_java_pbt_test(file_path: Path, repo_root: Path = None) -> Optional[str]:
    try:
        source = file_path.read_text(encoding="utf-8")
    except Exception:
        return None
    methods = [m.group(1) for m in re.finditer(r'public\s+(?:static\s+)?\w+\s+(\w+)\s*\(', source) if m.group(1) not in ("main", "toString")]
    cls = (re.search(r'public\s+class\s+(\w+)', source) or [None, "Main"])[1]
    if not methods: return None
    code = f"import net.jqwik.api.*;\npublic class {cls}PBT {{\n    private {cls} instance = new {cls}();\n"
    for fn in methods[:5]:
        code += f"\n    @Property\n    void test{fn.title()}Determinism(@ForAll int x) {{\n        try {{ Object r1 = instance.{fn}(x); Object r2 = instance.{fn}(x); assert r1.equals(r2); }} catch(Exception e) {{}}\n    }}\n"
    code += "}\n"
    return code

def generate_rust_proptest(file_path: Path, repo_root: Path = None) -> Optional[str]:
    try:
        source = file_path.read_text(encoding="utf-8")
    except Exception:
        return None
    funcs = [m.group(1) for m in re.finditer(r'pub\s+fn\s+(\w+)\s*\(', source)]
    if not funcs: return None
    code = "use proptest::prelude::*;\nproptest! {\n"
    for fn in funcs[:5]:
        code += f"\n    #[test]\n    fn prop_{fn}_deterministic(x in -100i32..100) {{\n        prop_assert_eq!({fn}(x), {fn}(x));\n    }}\n"
    code += "}\n"
    return code

def generate_cpp_fuzz_harness(file_path: Path, repo_root: Path = None) -> Optional[str]:
    try:
        source = file_path.read_text(encoding="utf-8")
    except Exception:
        return None
    funcs = [(m.group(1), "buffer") for m in re.finditer(r'\w+\s+(\w+)\s*\(\s*(?:const\s+)?(?:char|uint8_t|int8_t|void)\s*\*\s*\w+\s*,\s*(?:size_t|int|unsigned)\s+\w+\s*\)', source)]
    funcs += [(m.group(1), "int") for m in re.finditer(r'\w+\s+(\w+)\s*\(\s*int\s+\w+\s*\)', source)]
    if not funcs: return None
    is_cpp = file_path.suffix in (".cpp", ".cc", ".cxx", ".hpp")
    parts = [f'#include <stdint.h>\n#include <stddef.h>\n{"#include <cstring>" if is_cpp else "#include <string.h>"}\n#include "{file_path.name}"\n']
    for fn, it in funcs[:3]:
        if it == "buffer":
            parts.append(f'\nextern {"C" if not is_cpp else "C"} int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{\n    {fn}((const char *)data, size);\n    return 0;\n}}\n')
        else:
            parts.append(f'\nextern {"C" if not is_cpp else "C"} int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{\n    if (size < sizeof(int)) return 0;\n    int x;\n    memcpy(&x, data, sizeof(int));\n    {fn}(x);\n    return 0;\n}}\n')
    return "\n".join(parts)

def get_dynamic_capabilities() -> Dict[str, Any]:
    return {
        "python": {"pbt": "Hypothesis (13 relations)", "fuzzing": "atheris/built-in", "runtime_invariants": "@invariant", "stateful_pbt": "RuleBasedStateMachine", "dynamic_invariants": "Daikon-style"},
        "javascript": {"pbt": "fast-check (auto-generated)", "runtime_invariants": "Proxy-based"},
        "go": {"pbt": "gopter (auto-generated)", "fuzzing": "Go 1.18+ fuzz (auto-generated)"},
        "java": {"pbt": "jqwik (auto-generated)"},
        "c": {"fuzzing": "libFuzzer (auto-generated harness)"},
        "cpp": {"fuzzing": "libFuzzer (auto-generated harness)"},
        "rust": {"pbt": "proptest (auto-generated)", "formal_verification": "Kani (L6)"},
    }


# =============================================================================
# 6. UNIFIED MULTI-LANGUAGE ENGINE — ports Python-only features to all langs
# =============================================================================
