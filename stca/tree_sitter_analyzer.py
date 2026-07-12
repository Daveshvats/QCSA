"""Tree-sitter AST analyzer — Optional.get without isPresent, unused imports, etc."""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from .multi_lang import get_language, ALL_SOURCE_EXTS

import logging
_logger = logging.getLogger(__name__.replace('stca.', ''))

@dataclass
class ASTFinding:
    file: str; line: int; column: int; rule_id: str; severity: str; category: str
    description: str; fix: str; cwe: str = ""; confidence: float = 0.7; language: str = ""

_parsers: Dict[str, object] = {}

def _get_parser(lang: str):
    if lang in _parsers: return _parsers[lang]
    try:
        import tree_sitter
        mod_map = {"java":"tree_sitter_java","python":"tree_sitter_python",
                   "javascript":"tree_sitter_javascript","go":"tree_sitter_go","cpp":"tree_sitter_cpp"}
        if lang not in mod_map: return None
        mod = __import__(mod_map[lang])
        language = tree_sitter.Language(mod.language())
        parser = tree_sitter.Parser(language)
        _parsers[lang] = parser
        return parser
    except Exception:
        return None

def _parse_file(file_path, lang):
    parser = _get_parser(lang)
    if parser is None: return None
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
        tree = parser.parse(source.encode("utf-8"))
        return tree, source
    except: return None

def _node_text(node, source):
    return source.encode("utf-8")[node.start_byte:node.end_byte].decode("utf-8", errors="replace")

def _walk(node, callback):
    callback(node)
    for child in node.children: _walk(child, callback)

def analyze_java_ast(file_path, repo_root=None):
    result = _parse_file(file_path, "java")
    if result is None: return []
    tree, source = result
    rel = str(file_path.relative_to(repo_root)) if repo_root else str(file_path)
    findings = []
    optional_vars = {}; optional_checked = set()

    def visit(node):
        if node.type == "local_variable_declaration":
            text = _node_text(node, source)
            if "Optional" in text:
                for child in node.children:
                    if child.type == "variable_declarator":
                        for gc in child.children:
                            if gc.type == "identifier":
                                optional_vars[_node_text(gc, source)] = (node.start_point[0]+1, node.start_point[1])
        if node.type == "method_invocation":
            text = _node_text(node, source)
            if ".isPresent()" in text or "isPresent()" in text:
                children = node.children
                if len(children) >= 2 and children[0].type == "identifier":
                    optional_checked.add(_node_text(children[0], source))
        if node.type == "method_invocation":
            text = _node_text(node, source)
            if ".get()" in text:
                children = node.children
                if children and children[0].type == "identifier":
                    var_name = _node_text(children[0], source)
                    if var_name in optional_vars and var_name not in optional_checked:
                        findings.append(ASTFinding(file=rel, line=node.start_point[0]+1, column=node.start_point[1],
                            rule_id="AST-JAVA-OPTIONAL-GET-WITHOUT-ISPRESENT", severity="high", category="correctness",
                            description=f"Optional.get() on '{var_name}' without isPresent() check",
                            fix=f"Check: if ({var_name}.isPresent()) {{...}}", cwe="CWE-755", confidence=0.85, language="java"))
    _walk(tree.root_node, visit)
    return findings

def analyze_python_ast(file_path, repo_root=None):
    import ast as pyast
    try: source = file_path.read_text(encoding="utf-8"); tree = pyast.parse(source)
    except: return []
    rel = str(file_path.relative_to(repo_root)) if repo_root else str(file_path)
    findings = []
    imported_names = {}
    for node in pyast.walk(tree):
        if isinstance(node, pyast.Import):
            for alias in node.names: imported_names[alias.asname or alias.name.split(".")[0]] = node.lineno
        elif isinstance(node, pyast.ImportFrom):
            for alias in node.names: imported_names[alias.asname or alias.name] = node.lineno
    used_names = set()
    for node in pyast.walk(tree):
        if isinstance(node, pyast.Name): used_names.add(node.id)
        elif isinstance(node, pyast.Attribute):
            cur = node
            while isinstance(cur, pyast.Attribute): cur = cur.value
            if isinstance(cur, pyast.Name): used_names.add(cur.id)
    for name, line in imported_names.items():
        if name not in used_names and name != "*":
            findings.append(ASTFinding(file=rel, line=line, column=0, rule_id="AST-PY-UNUSED-IMPORT",
                severity="low", category="maintainability", description=f"Unused import: '{name}'",
                fix=f"Remove: import {name}", confidence=0.9, language="python"))
    for node in pyast.walk(tree):
        if isinstance(node, (pyast.FunctionDef, pyast.AsyncFunctionDef)):
            for default in node.args.defaults + node.args.kw_defaults:
                if default and isinstance(default, (pyast.List, pyast.Dict, pyast.Set)):
                    findings.append(ASTFinding(file=rel, line=node.lineno, column=0, rule_id="AST-PY-MUTABLE-DEFAULT",
                        severity="high", category="correctness", description=f"Mutable default in '{node.name}()'",
                        fix="Use None", cwe="CWE-733", confidence=0.95, language="python"))
    for node in pyast.walk(tree):
        if isinstance(node, pyast.ExceptHandler) and node.type is None:
            findings.append(ASTFinding(file=rel, line=node.lineno, column=0, rule_id="AST-PY-BARE-EXCEPT",
                severity="high", category="correctness", description="Bare except",
                fix="Use except Exception:", cwe="CWE-396", confidence=0.95, language="python"))
    return findings

def analyze_with_ast(file_path, repo_root=None):
    if not file_path.exists(): return []
    lang = get_language(file_path)
    if lang == "python": return analyze_python_ast(file_path, repo_root)
    if lang == "java": return analyze_java_ast(file_path, repo_root)
    return []

def analyze_repo_with_ast(repo_root, max_files=150):
    findings = []
    skip_dirs = {".git","__pycache__",".venv","venv","node_modules",".stca-cache","build","dist","target"}
    count = 0
    for p in repo_root.rglob("*"):
        if not p.is_file() or any(part in skip_dirs for part in p.parts): continue
        if p.suffix.lower() not in {".py",".js",".jsx",".ts",".tsx",".java",".go",".c",".cpp"}: continue
        try:
            if p.stat().st_size > 200000: continue
        except: continue
        try: findings += analyze_with_ast(p, repo_root)
        except Exception: pass  # v4.5: suppressed — add logging
        count += 1
        if count >= max_files: break
    return findings
