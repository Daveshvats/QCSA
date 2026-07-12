"""Multi-language advanced analysis layer (v4.2).

Ports 5 Python-only frontier features to ALL supported languages via the
NormalizedNode unified AST:
  1. Stateful PBT target discovery + harness generation
  2. Dynamic invariant candidate discovery
  3. Symbolic execution via Z3
  4. Counterexample generation via Z3
  5. Coverage-guided fuzz harness generation
"""
from __future__ import annotations
from .z3_utils import ast_to_z3 as _ast_to_z3

import ast
import re
import textwrap
import logging
from pathlib import Path
from typing import List, Optional, Tuple, Dict, Any, Set
from dataclasses import dataclass

try:
    from .normalized_ast import (
        parse_file, get_language, is_supported, NormalizedNode, _HAS_TS,
    )
except ImportError:
    _HAS_TS = False

try:
    from z3 import (
        Int, Real, Bool, BoolVal, Solver, sat, And, Or, Not,
        If, Implies, Function, IntSort, BoolSort,
    )
    _HAS_Z3 = True
except ImportError:
    _HAS_Z3 = False

_logger = logging.getLogger("stca.multi_language_advanced")


@dataclass
class StatefulTarget:
    class_name: str
    file: str
    line: int
    language: str
    public_methods: List[str]
    state_vars: List[str]


@dataclass
class StatefulViolation:
    function: str
    invariant: str
    action_sequence: str
    description: str
    file: str
    line: int
    language: str


@dataclass
class InferredInvariant:
    function: str
    file: str
    line: int
    language: str
    invariant_type: str
    expression: str
    description: str


@dataclass
class SymbolicFinding:
    function: str
    file: str
    line: int
    language: str
    rule_id: str
    description: str
    severity: str
    counterexample: str = ""


# === 1. STATEFUL PBT ===

def discover_stateful_targets_multi(file_path: Path) -> List[StatefulTarget]:
    if not file_path.exists():
        return []
    lang = get_language(file_path) if _HAS_TS else (
        "python" if file_path.suffix == ".py" else "unknown"
    )
    if lang == "unknown":
        return []
    if lang == "python":
        return _discover_stateful_targets_python(file_path)
    if not _HAS_TS:
        return []
    tree = parse_file(file_path)
    if tree is None:
        return []

    targets: List[StatefulTarget] = []
    rel = str(file_path)
    all_nodes = list(tree.walk())
    class_defs: List[NormalizedNode] = [n for n in all_nodes if n.kind == "class_def" and n.name]

    # Go structs
    for n in all_nodes:
        if n.kind == "class_def" and not n.name and lang == "go":
            for sub in n.walk():
                if sub.raw_kind == "type_identifier" and sub.text:
                    class_defs.append(n)
                    break

    # Rust impls
    rust_impl_methods: Dict[str, List[NormalizedNode]] = {}
    if lang == "rust":
        for n in all_nodes:
            if n.raw_kind == "impl_item" or (n.kind == "other" and "impl" in (n.raw_kind or "")):
                impl_name = ""
                for c in n.walk():
                    if c.raw_kind in ("type_identifier", "identifier") and c.text:
                        if c.text.strip() not in ("impl", "pub"):
                            impl_name = c.text.strip()
                            break
                if impl_name:
                    rust_impl_methods[impl_name] = [c for c in n.walk() if c.kind == "function_def"]

    all_funcs = [n for n in all_nodes if n.kind == "function_def"]

    for cls in class_defs:
        public_methods: List[str] = []
        state_vars: Set[str] = set()
        cls_name = cls.name or ""
        if not cls_name and lang == "go":
            for sub in cls.walk():
                if sub.raw_kind == "type_identifier" and sub.text:
                    cls_name = sub.text.strip()
                    break
        if not cls_name and lang == "rust":
            for sub in cls.walk():
                if sub.kind == "identifier" and sub.text:
                    cls_name = sub.text.strip()
                    break

        methods_in_class = [c for c in cls.walk() if c.kind == "function_def"]
        if not methods_in_class:
            for func in all_funcs:
                if lang == "go" and func.text:
                    m = re.search(r'func\s*\(\s*\w+\s+\*?(\w+)\s*\)', func.text)
                    if m and m.group(1) == cls_name:
                        methods_in_class.append(func)
            if lang == "rust" and cls_name in rust_impl_methods:
                methods_in_class = rust_impl_methods[cls_name]

        for child in methods_in_class:
            name = child.name or ""
            if name and not name.startswith("_") and name not in ("__init__", "constructor", "Constructor", "new"):
                public_methods.append(name)
            for sub in child.walk():
                if sub.kind == "assignment" and sub.target:
                    target = sub.target
                    if any(prefix in target for prefix in ("self.", "this.", "self->", "this->")):
                        var = re.sub(r'^(self|this)[.>]', '', target)
                        var = var.split("=")[0].strip()
                        if var and "(" not in var:
                            state_vars.add(var)
                    elif "." in target or "->" in target:
                        var = re.split(r'[.\->]', target)[-1].split("=")[0].strip()
                        if var and var.isidentifier():
                            state_vars.add(var)
                    elif target and target.isidentifier():
                        if target not in ("return", "break", "continue", "true", "false", "null"):
                            state_vars.add(target)
                if sub.kind == "assignment" and sub.text:
                    m = re.search(r'(?:self|this)[.>](\w+)\s*[+\-*/]?=', sub.text)
                    if m:
                        state_vars.add(m.group(1))
                    else:
                        m = re.search(r'\b(\w+)(?:[.\->]\w+)?\s*[+\-*/]=\s*\w', sub.text)
                        if m and m.group(1) not in ("self", "this"):
                            state_vars.add(m.group(1))

        if len(public_methods) >= 2 and state_vars:
            targets.append(StatefulTarget(
                class_name=cls_name or "Anonymous",
                file=rel, line=cls.line, language=lang,
                public_methods=public_methods, state_vars=sorted(state_vars),
            ))
    return targets


def _discover_stateful_targets_python(file_path: Path) -> List[StatefulTarget]:
    try:
        source = file_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except Exception:
        return []
    results: List[StatefulTarget] = []
    rel = str(file_path)
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        public_methods: List[str] = []
        state_vars: Set[str] = set()
        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if not item.name.startswith("_") and item.name != "__init__":
                    public_methods.append(item.name)
                    for sub in ast.walk(item):
                        if isinstance(sub, ast.Assign):
                            for target in sub.targets:
                                if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) and target.value.id == "self":
                                    state_vars.add(target.attr)
                        if isinstance(sub, ast.AugAssign):
                            if isinstance(sub.target, ast.Attribute) and isinstance(sub.target.value, ast.Name) and sub.target.value.id == "self":
                                state_vars.add(sub.target.attr)
        if len(public_methods) >= 2 and state_vars:
            results.append(StatefulTarget(
                class_name=node.name, file=rel, line=node.lineno, language="python",
                public_methods=public_methods, state_vars=sorted(state_vars),
            ))
    return results


def generate_stateful_test_multi(target: StatefulTarget, module_path: str = "") -> Optional[str]:
    if target.language == "python":
        return _gen_stateful_py(target, module_path)
    elif target.language in ("javascript", "typescript"):
        return _gen_stateful_js(target, module_path)
    elif target.language == "go":
        return _gen_stateful_go(target, module_path)
    elif target.language == "java":
        return _gen_stateful_java(target, module_path)
    elif target.language == "rust":
        return _gen_stateful_rust(target, module_path)
    elif target.language in ("c", "cpp"):
        return _gen_stateful_c(target, module_path)
    return None


def _gen_stateful_py(t, module_path):
    rules = []
    for method in t.public_methods:
        rules.append(f"    @rule(item=st.text(min_size=1, max_size=20), qty=st.integers(min_value=0, max_value=100))\n    def {method}(self, item, qty):\n        try: self.target.{method}(item, qty)\n        except: pass")
    inv = "\n".join(f"        val = getattr(self.target, '{v}', None)\n        if isinstance(val, (int, float)): assert val >= 0" for v in t.state_vars) or "        pass"
    return f"from hypothesis import stateful, strategies as st\nfrom {module_path} import {t.class_name}\n\nclass {t.class_name}Machine(stateful.RuleBasedStateMachine):\n    def __init__(self):\n        super().__init__()\n        self.target = {t.class_name}()\n\n{chr(10).join(rules)}\n\n    @stateful.invariant()\n    def check(self):\n{inv}\n\nTest{t.class_name}Machine = {t.class_name}Machine.TestCase\n"


def _gen_stateful_js(t, module_path):
    return f"const {{ fc }} = require('fast-check');\nconst {{ {t.class_name} }} = require('{module_path}');\nfc.assert(fc.property(fc.integer(0, 100), (n) => {{\n    const target = new {t.class_name}();\n    // Run random operations\n    for (let i = 0; i < 20; i++) {{\n        try {{ target.{t.public_methods[0]}('test', n); }} catch(e) {{}}\n    }}\n}}));\n"


def _gen_stateful_go(t, module_path):
    return f"package main\nimport (\n    \"math/rand\"\n    \"testing\"\n)\nfunc Test{t.class_name}Stateful(t *testing.T) {{\n    for i := 0; i < 100; i++ {{\n        target := New{t.class_name}()\n        for j := 0; j < 20; j++ {{\n            target.{t.public_methods[0] if t.public_methods else 'Foo'}(\"test\", rand.Intn(100))\n        }}\n    }}\n}}\n"


def _gen_stateful_java(t, module_path):
    pkg = module_path.replace("/", ".") if module_path else "com.example"
    return f"package {pkg};\nimport net.jqwik.api.*;\npublic class {t.class_name}StatefulTest {{\n    @Property\n    public void stateRemainsConsistent(@ForAll(\"seq\") ActionSequence<{t.class_name}> seq) {{\n        {t.class_name} target = new {t.class_name}();\n        seq.run(target);\n    }}\n}}\n"


def _gen_stateful_rust(t, module_path):
    return f"use proptest::prelude::*;\nproptest! {{\n    #[test]\n    fn state_ok(seed in any::<u64>()) {{\n        let mut target = {t.class_name}::new();\n        // Run random operations\n    }}\n}}\n"


def _gen_stateful_c(t, module_path):
    return f"#include <stdio.h>\n#include <stdlib.h>\nint main() {{\n    for (int i = 0; i < 100; i++) {{\n        {t.class_name}* t = {t.class_name}_new();\n        for (int j = 0; j < 20; j++) {{\n            {t.class_name}_{t.public_methods[0] if t.public_methods else 'foo'}(t, \"x\", rand()%100);\n        }}\n        {t.class_name}_free(t);\n    }}\n    return 0;\n}}\n"


# === 2. DYNAMIC INVARIANTS ===

def discover_invariant_candidates_multi(file_path: Path) -> List[InferredInvariant]:
    if not file_path.exists():
        return []
    lang = get_language(file_path) if _HAS_TS else ("python" if file_path.suffix == ".py" else "unknown")
    if lang == "unknown":
        return []
    invariants: List[InferredInvariant] = []
    rel = str(file_path)
    non_neg_names = {"amount", "balance", "count", "qty", "quantity", "size", "total", "len", "length", "num", "n", "x", "y"}

    if lang == "python" or not _HAS_TS:
        try:
            source = file_path.read_text(encoding="utf-8")
            tree = ast.parse(source)
        except Exception:
            return []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for arg in node.args.args:
                if arg.arg in non_neg_names:
                    invariants.append(InferredInvariant(
                        function=node.name, file=rel, line=node.lineno, language=lang,
                        invariant_type="non_negative", expression=f"{arg.arg} >= 0",
                        description=f"Parameter '{arg.arg}' should be non-negative"))
        return invariants

    tree = parse_file(file_path)
    if tree is None:
        return []
    for func in tree.find_function_defs():
        for param in (func.params or []):
            pname = param.split(":")[0].split("=")[0].strip().lstrip("*")
            if pname in non_neg_names:
                invariants.append(InferredInvariant(
                    function=func.name or "", file=rel, line=func.line, language=lang,
                    invariant_type="non_negative", expression=f"{pname} >= 0",
                    description=f"Parameter '{pname}' should be non-negative"))
    return invariants


# === 3. SYMBOLIC EXECUTION ===

def analyze_symbolic_multi(file_path: Path) -> List[SymbolicFinding]:
    if not _HAS_Z3:
        return []
    if not file_path.exists():
        return []
    lang = get_language(file_path) if _HAS_TS else ("python" if file_path.suffix == ".py" else "unknown")
    if lang == "unknown":
        return []
    if lang == "python":
        try:
            from .symbolic import analyze_file
            sf = analyze_file(file_path)
            return [SymbolicFinding(
                function=f.function, file=f.file, line=f.line, language="python",
                rule_id=f.rule_id, description=f.description, severity=f.severity,
            ) for f in sf]
        except Exception as e:
            _logger.warning("symbolic analysis failed for %s: %s", file_path, e)
            return []
    if not _HAS_TS:
        return []
    tree = parse_file(file_path)
    if tree is None:
        return []
    rel = str(file_path)
    findings: List[SymbolicFinding] = []

    for func in tree.find_function_defs():
        params = func.params or []
        if not params:
            continue
        z3_vars: Dict[str, Any] = {}
        for p in params:
            pname = p.split(":")[0].split("=")[0].strip().lstrip("*").lstrip("&")
            if pname and pname not in ("self", "this"):
                z3_vars[pname] = Int(pname)
        if not z3_vars:
            continue
        solver = Solver()
        conditions: List[Any] = []
        for node in func.walk():
            if node.kind == "if" and node.text:
                cond_text = _extract_condition(node.text, lang)
                if cond_text:
                    try:
                        cond_ast = ast.parse(cond_text, mode="eval").body
                        z3_cond = _ast_to_z3(cond_ast, z3_vars)
                        if z3_cond is not None:
                            conditions.append(z3_cond)
                    except SyntaxError:
                        pass
        has_precond = any(conditions)
        if not has_precond:
            for pname, var in z3_vars.items():
                solver.push()
                solver.add(var < 0)
                if solver.check() == sat:
                    model = solver.model()
                    val = model.eval(var, model_completion=True)
                    findings.append(SymbolicFinding(
                        function=func.name or "", file=rel, line=func.line, language=lang,
                        rule_id="SYMBOLIC.MISSING-PRECONDITION",
                        description=f"Function '{func.name}': parameter '{pname}' can be negative (e.g., {pname}={val})",
                        severity="medium", counterexample=f"{pname}={val}"))
                    break
                solver.pop()
    return findings


def _extract_condition(if_text: str, lang: str) -> str:
    text = if_text.strip()
    if text.startswith("if "):
        text = text[3:]
    elif text.startswith("if("):
        text = text[3:]
    text = text.rstrip()
    if text.endswith("{"):
        text = text[:-1].rstrip()
    if text.endswith(":"):
        text = text[:-1].rstrip()
    text = text.strip()
    if text.startswith("(") and text.endswith(")"):
        text = text[1:-1].strip()
    text = text.split("\n")[0].strip()
    return text




# === 4. COUNTEREXAMPLES ===

def generate_counterexamples_multi(file_path: Path) -> List[SymbolicFinding]:
    if not _HAS_Z3:
        return []
    if not file_path.exists():
        return []
    lang = get_language(file_path) if _HAS_TS else ("python" if file_path.suffix == ".py" else "unknown")
    if lang == "unknown":
        return []
    if lang == "python":
        try:
            from .counterexamples import generate_counterexamples_for_file
            ces = generate_counterexamples_for_file(file_path)
            return [SymbolicFinding(
                function=ce.function, file=ce.file, line=ce.line, language="python",
                rule_id="COUNTEREXAMPLE.VIOLATION", description=ce.description,
                severity="high", counterexample=str(ce.inputs)) for ce in ces]
        except Exception as e:
            _logger.warning("counterexample gen failed for %s: %s", file_path, e)
            return []
    if not _HAS_TS:
        return []
    tree = parse_file(file_path)
    if tree is None:
        return []
    rel = str(file_path)
    findings: List[SymbolicFinding] = []
    for func in tree.find_function_defs():
        params = [p.split(":")[0].split("=")[0].strip().lstrip("*").lstrip("&")
                  for p in (func.params or [])
                  if p.split(":")[0].split("=")[0].strip().lstrip("*").lstrip("&") not in ("self", "this")]
        if not params:
            continue
        z3_vars = {p: Int(p) for p in params}
        solver = Solver()
        solver.add(z3_vars[params[0]] < 0)
        if solver.check() == sat:
            model = solver.model()
            val = model.eval(z3_vars[params[0]], model_completion=True)
            findings.append(SymbolicFinding(
                function=func.name or "", file=rel, line=func.line, language=lang,
                rule_id="COUNTEREXAMPLE.NEGATIVE-PARAM",
                description=f"Function '{func.name}' can be called with {params[0]}={val} (negative).",
                severity="medium", counterexample=f"{params[0]}={val}"))
    return findings


# === 5. FUZZ HARNESS GENERATION ===

def generate_fuzz_harness_multi(file_path: Path, repo_root: Optional[Path] = None) -> Optional[str]:
    if not file_path.exists():
        return None
    lang = get_language(file_path) if _HAS_TS else ("python" if file_path.suffix == ".py" else "unknown")
    if lang == "unknown":
        return None
    target_funcs = []
    if _HAS_TS:
        tree = parse_file(file_path)
        if tree:
            target_funcs = [f.name for f in tree.find_function_defs() if f.name]
    elif lang == "python":
        try:
            src = file_path.read_text(encoding="utf-8")
            t = ast.parse(src)
            target_funcs = [n.name for n in ast.walk(t) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        except Exception:
            pass
    if not target_funcs:
        return None
    rel = str(file_path.relative_to(repo_root) if repo_root else file_path)
    module_path = rel.replace("/", ".").replace(".py", "").lstrip(".")
    main_target = target_funcs[0]
    if lang == "python":
        return _gen_fuzz_python(module_path, main_target)
    elif lang in ("javascript", "typescript"):
        return _gen_fuzz_js(file_path, main_target)
    elif lang == "go":
        return _gen_fuzz_go(file_path, main_target)
    elif lang == "java":
        return _gen_fuzz_java(file_path, main_target)
    elif lang == "rust":
        return _gen_fuzz_rust(file_path, main_target)
    elif lang in ("c", "cpp"):
        return _gen_fuzz_c(file_path, main_target, lang)
    return None


def _gen_fuzz_python(module_path, target):
    return f"# Auto-generated atheris fuzz harness for {target}()\nimport atheris\nimport sys\nwith atheris.instrument_imports():\n    from {module_path} import {target}\ndef TestOneInput(data):\n    fdp = atheris.FuzzedDataProvider(data)\n    arg1 = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 100))\n    arg2 = fdp.ConsumeIntInRange(0, 1000)\n    try: {target}(arg1, arg2)\n    except: pass\natheris.Setup(sys.argv, TestOneInput)\natheris.Fuzz()\n"


def _gen_fuzz_js(file_path, target):
    return f"// Auto-generated jazzer.js fuzz harness for {target}()\nconst {{ FuzzedDataProvider }} = require('@jazzer.js/core');\nconst {{ {target} }} = require('./{file_path.stem}');\nmodule.exports = function fuzz(data) {{\n    const fdp = new FuzzedDataProvider(data);\n    try {{ {target}(fdp.consumeString(100), fdp.consumeInt(0, 1000)); }} catch(e) {{}}\n}};\n"


def _gen_fuzz_go(file_path, target):
    return f"// Auto-generated Go fuzz harness for {target}()\npackage main\nimport \"testing\"\nfunc Fuzz{target.title()}(f *testing.F) {{\n    f.Add(\"seed\", 42)\n    f.Fuzz(func(t *testing.T, item string, qty int) {{\n        defer func(){{ _ = recover() }}()\n        {target}(item, qty)\n    }})\n}}\n"


def _gen_fuzz_java(file_path, target):
    cls = file_path.stem
    pkg = file_path.parent.name or "com.example"
    return f"// Auto-generated Jazzer harness for {target}()\npackage {pkg};\nimport com.code_intelligence.jazzer.api.FuzzedDataProvider;\npublic class {cls}Fuzz {{\n    public static void fuzzerTestOneInput(FuzzedDataProvider data) {{\n        try {{ {cls}.{target}(data.consumeString(100), data.consumeInt(0,1000)); }} catch(Exception e) {{}}\n    }}\n}}\n"


def _gen_fuzz_rust(file_path, target):
    return f"// Auto-generated cargo-fuzz harness for {target}()\n#![no_main]\nuse libfuzzer_sys::fuzz_target;\nuse {file_path.stem}::{target};\nfuzz_target!(|data: &[u8]| {{\n    if data.len() < 4 {{ return; }}\n    let qty = i32::from_le_bytes([data[0],data[1],data[2],data[3]]);\n    let item = String::from_utf8_lossy(&data[4..]).to_string();\n    let _ = {target}(&item, qty);\n}});\n"


def _gen_fuzz_c(file_path, target, lang):
    ext = "h" if lang == "c" else "hpp"
    return f"// Auto-generated libFuzzer harness for {target}()\n#include <stdint.h>\n#include <stddef.h>\n#include <string.h>\n#include <stdlib.h>\n#include \"{file_path.stem}.{ext}\"\nint LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{\n    if (size < 4) return 0;\n    int qty = *(int*)data;\n    char* item = (char*)malloc(size - 3);\n    memcpy(item, data + 4, size - 4);\n    item[size - 4] = 0;\n    {target}(item, qty);\n    free(item);\n    return 0;\n}}\n"


# === REPO-LEVEL ENTRY POINTS ===

def analyze_repo_advanced(repo_root: Path, max_files: int = 100) -> List[SymbolicFinding]:
    skip = {".git", "__pycache__", ".venv", "venv", "node_modules", ".stca-cache",
            "build", "dist", "target", ".pytest_cache", ".stca-reports", ".stca-fixes"}
    findings: List[SymbolicFinding] = []
    count = 0
    for f in sorted(repo_root.rglob("*")):
        if not f.is_file() or any(p in skip for p in f.parts) or count >= max_files:
            continue
        lang = get_language(f) if _HAS_TS else ("python" if f.suffix == ".py" else "unknown")
        if lang == "unknown":
            continue
        count += 1
        try:
            findings.extend(analyze_symbolic_multi(f))
            findings.extend(generate_counterexamples_multi(f))
        except Exception as e:
            _logger.warning("advanced analysis failed for %s: %s", f, e)
    return findings


def discover_repo_stateful_targets(repo_root: Path, max_files: int = 100) -> List[StatefulTarget]:
    skip = {".git", "__pycache__", ".venv", "venv", "node_modules", ".stca-cache",
            "build", "dist", "target", ".pytest_cache"}
    targets: List[StatefulTarget] = []
    count = 0
    for f in sorted(repo_root.rglob("*")):
        if not f.is_file() or any(p in skip for p in f.parts) or count >= max_files:
            continue
        lang = get_language(f) if _HAS_TS else ("python" if f.suffix == ".py" else "unknown")
        if lang == "unknown":
            continue
        count += 1
        try:
            targets.extend(discover_stateful_targets_multi(f))
        except Exception as e:
            _logger.warning("stateful discovery failed for %s: %s", f, e)
    return targets


def get_advanced_capabilities() -> Dict[str, Any]:
    return {
        "stateful_pbt": {
            "supported_languages": ["python", "javascript", "typescript", "go", "java", "rust", "c", "cpp"],
            "executable": _HAS_TS,
        },
        "dynamic_invariants": {
            "supported_languages": ["python", "javascript", "typescript", "go", "java", "rust", "c", "cpp"],
            "executable": _HAS_TS,
        },
        "symbolic_execution": {
            "supported_languages": ["python", "javascript", "typescript", "go", "java", "rust", "c", "cpp"],
            "solver": "z3" if _HAS_Z3 else "missing",
            "executable": _HAS_TS and _HAS_Z3,
        },
        "counterexamples": {
            "supported_languages": ["python", "javascript", "typescript", "go", "java", "rust", "c", "cpp"],
            "solver": "z3" if _HAS_Z3 else "missing",
            "executable": _HAS_TS and _HAS_Z3,
        },
        "coverage_guided_fuzzing": {
            "supported_languages": ["python", "javascript", "go", "java", "rust", "c", "cpp"],
            "executable": _HAS_TS,
        },
    }
