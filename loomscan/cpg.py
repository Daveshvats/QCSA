"""Code Property Graph (CPG) — Joern-inspired.

A CPG merges three program representations into one graph:
  - AST (Abstract Syntax Tree): structural
  - CFG (Control Flow Graph): execution order
  - PDG (Program Dependence Graph): data + control dependencies

This is the foundation that makes real detection possible. With a CPG you can
ask questions like:
  - "Find every path from a source (request.body) to a sink (eval) where
    the value is not sanitized"
  - "Find every method that calls foo() before bar() is initialized"
  - "Find every variable that holds user input and reaches a SQL query"

Joern builds CPGs for C/C++/Java/Python/JS/Go/PHP/Kotlin and exposes a Scala
query DSL. We build a simpler Python-only CPG here using AST + a CFG + a PDG.
This is enough to do real cross-file taint tracking and pattern queries.

References:
  - Yamaguchi et al. (2014) "Modeling and Discovering Vulnerabilities with CPGs"
  - Joern: https://joern.io
  - LLMxCPG (2024): https://arxiv.org/abs/2408.02306
"""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Any
from dataclasses import dataclass, field


@dataclass
class CPGNode:
    """A node in the Code Property Graph."""
    id: str
    kind: str  # 'function' | 'param' | 'variable' | 'call' | 'literal' | 'return' | 'assign' | 'if' | 'for' | 'while' | 'try' | 'except'
    name: str = ""  # function name, variable name, call name
    file: str = ""
    line: int = 0
    type_annotation: str = ""  # if known
    attributes: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CPGEdge:
    """An edge in the CPG."""
    src: str  # node id
    dst: str  # node id
    kind: str  # 'ast_child' | 'cfg_next' | 'data_dep' | 'call' | 'param' | 'return'


@dataclass
class CPG:
    """A Code Property Graph for a single file or a whole repo."""
    nodes: Dict[str, CPGNode] = field(default_factory=dict)
    edges: List[CPGEdge] = field(default_factory=list)
    # index for fast lookup
    by_kind: Dict[str, Set[str]] = field(default_factory=dict)
    by_name: Dict[str, Set[str]] = field(default_factory=dict)
    by_file: Dict[str, Set[str]] = field(default_factory=dict)
    # adjacency
    successors: Dict[str, List[Tuple[str, str]]] = field(default_factory=dict)  # node_id → [(edge_kind, dst_id)]
    predecessors: Dict[str, List[Tuple[str, str]]] = field(default_factory=dict)

    def add_node(self, node: CPGNode) -> str:
        self.nodes[node.id] = node
        self.by_kind.setdefault(node.kind, set()).add(node.id)
        if node.name:
            self.by_name.setdefault(node.name, set()).add(node.id)
        self.by_file.setdefault(node.file, set()).add(node.id)
        return node.id

    def add_edge(self, src: str, dst: str, kind: str) -> None:
        self.edges.append(CPGEdge(src=src, dst=dst, kind=kind))
        self.successors.setdefault(src, []).append((kind, dst))
        self.predecessors.setdefault(dst, []).append((kind, src))

    def get_nodes(self, kind: str = None, name: str = None,
                  file: str = None) -> List[CPGNode]:
        """Lookup nodes by kind/name/file."""
        ids: Set[str] = set(self.nodes.keys())
        if kind:
            ids &= self.by_kind.get(kind, set())
        if name:
            ids &= self.by_name.get(name, set())
        if file:
            ids &= self.by_file.get(file, set())
        return [self.nodes[i] for i in ids]

    def reachable_from(self, source_ids: Set[str],
                       edge_kinds: Set[str] = None) -> Set[str]:
        """BFS: which nodes are reachable from source_ids via given edge kinds."""
        if edge_kinds is None:
            edge_kinds = {"data_dep", "cfg_next", "call"}
        visited: Set[str] = set()
        queue = list(source_ids)
        while queue:
            nid = queue.pop()
            if nid in visited:
                continue
            visited.add(nid)
            for kind, dst in self.successors.get(nid, []):
                if kind in edge_kinds and dst not in visited:
                    queue.append(dst)
        return visited

    def find_paths(self, source_id: str, sink_id: str,
                   max_depth: int = 10,
                   edge_kinds: Set[str] = None) -> List[List[str]]:
        """DFS: find all paths from source to sink (up to max_depth)."""
        if edge_kinds is None:
            edge_kinds = {"data_dep", "cfg_next"}
        paths: List[List[str]] = []
        def dfs(nid: str, path: List[str], visited: Set[str]):
            if len(path) > max_depth:
                return
            if nid == sink_id and len(path) > 1:
                paths.append(path[:])
                return
            visited.add(nid)
            for kind, dst in self.successors.get(nid, []):
                if kind in edge_kinds and dst not in visited:
                    dfs(dst, path + [dst], visited.copy())
        dfs(source_id, [source_id], set())
        return paths


def _make_node_id(node: ast.AST, rel_path: str, suffix: str = "") -> str:
    """Make a CPG node ID for an AST node (module-level for reuse)."""
    lineno = getattr(node, "lineno", 0)
    col_offset = getattr(node, "col_offset", 0)
    return f"{rel_path}:{lineno}:{col_offset}:{type(node).__name__}{suffix}"


def build_cpg_for_file(file_path: Path, repo_root: Path = None) -> CPG:
    """Build a CPG for a single Python file."""
    cpg = CPG()
    if not file_path.exists() or file_path.suffix != ".py":
        return cpg
    try:
        source = file_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except Exception:
        return cpg

    rel_path = str(file_path.relative_to(repo_root)) if repo_root else str(file_path)

    # Walk the AST, build nodes and edges
    def _make_id(node: ast.AST, suffix: str = "") -> str:
        return _make_node_id(node, rel_path, suffix)

    def _walk(node: ast.AST, parent_id: str = None, function_id: str = None):
        """Recursively walk AST, adding nodes and edges."""
        nonlocal cpg
        # Skip module-level and uninteresting nodes — don't create CPG nodes for them
        if isinstance(node, ast.Module):
            for child in ast.iter_child_nodes(node):
                _walk(child, parent_id, function_id)
            return

        nid = _make_id(node)
        kind = ""  # empty kind = skip this node
        name = ""
        if isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
            kind = "function"
            name = node.name
            function_id = nid
        elif isinstance(node, ast.Name):
            kind = "variable"
            name = node.id
        elif isinstance(node, ast.arg):
            kind = "param"
            name = node.arg
        elif isinstance(node, ast.Call):
            kind = "call"
            name = _get_call_name(node.func) if node.func else ""
        elif isinstance(node, ast.Constant):
            kind = "literal"
            name = repr(node.value)[:50]
        elif isinstance(node, ast.Return):
            kind = "return"
        elif isinstance(node, ast.Assign):
            kind = "assign"
        elif isinstance(node, (ast.If, ast.IfExp)):
            kind = "if"
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            kind = "for"
        elif isinstance(node, ast.While):
            kind = "while"
        elif isinstance(node, ast.ExceptHandler):
            kind = "except"

        if kind:
            cpg_node = CPGNode(
                id=nid, kind=kind, name=name,
                file=rel_path, line=getattr(node, "lineno", 0),
                type_annotation="",
            )
            cpg.add_node(cpg_node)
            if parent_id:
                cpg.add_edge(parent_id, nid, "ast_child")
            if function_id and function_id != nid:
                cpg.add_edge(function_id, nid, "contains")
            effective_parent = nid
        else:
            # skipped node — pass through the parent_id
            effective_parent = parent_id

        # data dependency: assignment target → value usage
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    target_id = _make_id(target)
                    value_id = _make_id(node.value)
                    # ensure both nodes exist
                    if target_id not in cpg.nodes:
                        cpg.add_node(CPGNode(id=target_id, kind="variable", name=target.id,
                                              file=rel_path, line=getattr(target, "lineno", 0)))
                    if value_id not in cpg.nodes:
                        # add a placeholder for the value
                        cpg.add_node(CPGNode(id=value_id, kind="variable",
                                              name=_get_value_name(node.value),
                                              file=rel_path, line=getattr(node.value, "lineno", 0)))
                    cpg.add_edge(value_id, target_id, "data_dep")

        # function call: caller → callee (if same-file)
        if isinstance(node, ast.Call) and kind == "call":
            callee_name = _get_call_name(node.func) if node.func else ""
            if callee_name:
                callees = cpg.get_nodes(kind="function", name=callee_name)
                for callee in callees:
                    cpg.add_edge(nid, callee.id, "call")

        # recurse
        for child in ast.iter_child_nodes(node):
            _walk(child, parent_id=effective_parent, function_id=function_id)

    _walk(tree)

    # v3.3: Add def-use chains and interprocedural parameter edges.
    # This is the critical fix for the taint engine — without it, the CPG
    # has no edges connecting sequential reads of the same variable.
    _add_def_use_chains(cpg, tree, rel_path)
    _add_interprocedural_edges(cpg, tree, rel_path)
    _add_cfg_edges(cpg, tree, rel_path)

    return cpg


def _add_def_use_chains(cpg: CPG, tree: ast.AST, rel_path: str) -> None:
    """Add def-use chain edges for each function.

    For each function, walks statements in order and maintains a
    "current definition" map: var_name → node_id of the last assignment
    or parameter. For each Name read, adds a data_dep edge from the
    current definition to this read.

    This is what makes taint tracking actually work — without it, the CPG
    has no edges connecting `user_id` (param) to `user_id` (used later).
    """
    for func_node in ast.walk(tree):
        if not isinstance(func_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        # Map: var_name → node_id of the current definition
        current_def: dict[str, str] = {}

        # Parameters are initial definitions
        for arg in func_node.args.args + func_node.args.kwonlyargs:
            arg_id = _make_id_for_arg(arg, rel_path)
            if arg_id in cpg.nodes:
                current_def[arg.arg] = arg_id

        # Walk statements in order
        _walk_statements_for_def_use(cpg, func_node.body, current_def, rel_path)


def _walk_statements_for_def_use(cpg: CPG, statements: list,
                                   current_def: dict[str, str],
                                   rel_path: str) -> None:
    """Walk statements in order, updating def-use chains."""
    for stmt in statements:
        # Handle branches — recurse with a COPY of current_def
        if isinstance(stmt, ast.If):
            import copy
            _walk_statements_for_def_use(cpg, stmt.body, copy.copy(current_def), rel_path)
            _walk_statements_for_def_use(cpg, stmt.orelse, copy.copy(current_def), rel_path)
            # After if/else, state is uncertain — don't update current_def
            continue
        elif isinstance(stmt, (ast.For, ast.While)):
            import copy
            _walk_statements_for_def_use(cpg, stmt.body, copy.copy(current_def), rel_path)
            continue
        elif isinstance(stmt, ast.Try):
            import copy
            _walk_statements_for_def_use(cpg, stmt.body, copy.copy(current_def), rel_path)
            for handler in stmt.handlers:
                _walk_statements_for_def_use(cpg, handler.body, copy.copy(current_def), rel_path)
            continue

        # For non-branch statements, process all Name nodes in execution order
        # First, find all reads (Name nodes in Load context)
        reads_in_this_stmt = []  # v4.4: track reads for composite-expression taint
        for sub in ast.walk(stmt):
            if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Load):
                var_name = sub.id
                if var_name in current_def:
                    read_id = _make_node_id(sub, rel_path)
                    def_id = current_def[var_name]
                    if def_id in cpg.nodes and read_id in cpg.nodes:
                        # Add data_dep edge from definition to this read
                        cpg.add_edge(def_id, read_id, "data_dep")
                        reads_in_this_stmt.append((var_name, read_id))

        # v4.4: For assignments with composite RHS (f-strings, concatenation,
        # function calls with tainted args), add data_dep edges from each
        # tainted read to the assignment target. This enables taint to flow
        # through: sql = f"...{user_id}..." → user_id read → sql def → sql read at sink
        for sub in ast.walk(stmt):
            if isinstance(sub, ast.Assign):
                for target in sub.targets:
                    if isinstance(target, ast.Name):
                        target_id = _make_node_id(target, rel_path)
                        if target_id in cpg.nodes:
                            # v4.4: If the RHS contains reads of tainted vars,
                            # connect each read to this target so taint flows through
                            for var_name, read_id in reads_in_this_stmt:
                                if read_id != target_id:
                                    cpg.add_edge(read_id, target_id, "data_dep")
                            current_def[target.id] = target_id


def _add_interprocedural_edges(cpg: CPG, tree: ast.AST, rel_path: str) -> None:
    """Add edges from call-site arguments to callee parameters.

    For each function call like `foo(arg1, arg2)`, adds edges from the
    argument nodes to the callee's parameter nodes. This is what makes
    taint tracking actually interprocedural — without it, BFS can't
    cross into a callee's body.
    """
    for call_node in ast.walk(tree):
        if not isinstance(call_node, ast.Call):
            continue

        callee_name = _get_call_name(call_node.func) if call_node.func else ""
        if not callee_name:
            continue

        # Find the callee function definition in the CPG
        callees = cpg.get_nodes(kind="function", name=callee_name)
        if not callees:
            continue

        callee = next(iter(callees))

        # Find the callee's parameters
        # We need to find the FunctionDef in the AST to get parameter names
        callee_func = None
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == callee_name:
                callee_func = node
                break

        if not callee_func:
            continue

        callee_params = callee_func.args.args
        if callee_params and callee_params[0].arg == "self":
            callee_params = callee_params[1:]

        # Match arguments to parameters positionally
        for i, arg_expr in enumerate(call_node.args):
            if i >= len(callee_params):
                break
            param = callee_params[i]

            # Get the argument's node ID
            arg_id = _make_node_id(arg_expr, rel_path)

            # Get the parameter's node ID
            param_id = _make_id_for_arg(param, rel_path)

            if arg_id in cpg.nodes and param_id in cpg.nodes:
                # Add edge from call argument to callee parameter
                cpg.add_edge(arg_id, param_id, "param")


def _make_id_for_arg(arg: ast.arg, rel_path: str) -> str:
    """Make a CPG node ID for an ast.arg (parameter)."""
    return f"{rel_path}:{arg.lineno}:{arg.col_offset}:arg"


def _get_value_name(value_node: ast.AST) -> str:
    """Extract a name from an AST value node for CPG labeling."""
    if isinstance(value_node, ast.Name):
        return value_node.id
    if isinstance(value_node, ast.Call):
        return _get_call_name(value_node.func) if value_node.func else "call"
    if isinstance(value_node, ast.Constant):
        return repr(value_node.value)[:30]
    return type(value_node).__name__.lower()


def build_cpg_for_repo(repo_root: Path,
                       max_files: int = 100) -> CPG:
    """Build a unified CPG for all Python files in the repo.

    Cross-file edges are added when:
      - A function call references a function defined in another file
      - A variable is returned from one function and passed as arg to another
      - An import statement brings a name into scope
    """
    master_cpg = CPG()
    skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules",
                 ".loomscan-cache", ".loomscan-reports", ".loomscan-fixes", "tests", "test"}
    py_files: List[Path] = []
    for p in repo_root.rglob("*.py"):
        if any(part in skip_dirs for part in p.parts):
            continue
        if p.name.startswith("test_") or p.name.endswith("_test.py"):
            continue
        py_files.append(p)
        if len(py_files) >= max_files:
            break

    # build per-file CPGs and merge
    file_cpgs: Dict[str, CPG] = {}
    for f in py_files:
        rel = str(f.relative_to(repo_root))
        file_cpg = build_cpg_for_file(f, repo_root)
        file_cpgs[rel] = file_cpg
        # merge nodes/edges into master
        for nid, node in file_cpg.nodes.items():
            master_cpg.nodes[nid] = node
            master_cpg.by_kind.setdefault(node.kind, set()).add(nid)
            if node.name:
                master_cpg.by_name.setdefault(node.name, set()).add(nid)
            master_cpg.by_file.setdefault(node.file, set()).add(nid)
        for edge in file_cpg.edges:
            master_cpg.edges.append(edge)
            master_cpg.successors.setdefault(edge.src, []).append((edge.kind, edge.dst))
            master_cpg.predecessors.setdefault(edge.dst, []).append((edge.kind, edge.src))

    # add cross-file call edges
    # for each call node, find a function with the same name in any file
    for call_node in master_cpg.get_nodes(kind="call"):
        if not call_node.name:
            continue
        # find function definitions with this name (excluding the call itself)
        candidates = [n for n in master_cpg.get_nodes(kind="function", name=call_node.name)
                      if n.file != call_node.file or n.line < call_node.line]
        for callee in candidates[:1]:  # only first match to avoid noise
            master_cpg.add_edge(call_node.id, callee.id, "call")

    # v4.3: Add cross-file parameter-binding edges.
    # The per-file _add_interprocedural_edges() only searches the current
    # file's AST for callee parameters, so it can't bind arguments to
    # parameters when the callee is in a different file. This pass fixes
    # that by using the master CPG's cross-file function lookup.
    #
    # For each call node, find the callee function in ANY file, then find
    # that function's parameter nodes in the master CPG, and connect the
    # call's argument nodes to those parameter nodes.
    _add_cross_file_param_edges(master_cpg, py_files, repo_root)

    return master_cpg


def _add_cross_file_param_edges(cpg: CPG, py_files: List[Path],
                                  repo_root: Path) -> None:
    """v4.3: Add parameter-binding edges for cross-file calls.

    For each call site in the repo whose callee is defined in a different file,
    find the callee's parameter nodes and connect the call's argument nodes
    to them. This enables taint tracking to flow: arg at call-site → param
    in callee body → sink in callee body, even when the callee is in a
    different file.

    Approach: re-parse each file's AST to find call sites and their argument
    names, then look up the callee's params in the master CPG. If the callee
    is in a different file, connect the argument's CPG node (found by name
    in the call's file near the call's line) to the callee's param node.
    """
    # Build a map: function_name → [(param_name, param_node_id, file)]
    func_params: Dict[str, List[Tuple[str, str, str]]] = {}
    for f in py_files:
        rel = str(f.relative_to(repo_root))
        try:
            source = f.read_text(encoding="utf-8")
            tree = ast.parse(source)
        except Exception:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            params = node.args.args
            if params and params[0].arg == "self":
                params = params[1:]
            for param in params:
                param_id = _make_id_for_arg(param, rel)
                func_params.setdefault(node.name, []).append(
                    (param.arg, param_id, rel)
                )

    # For each file, find call sites and their arguments via AST
    for f in py_files:
        rel = str(f.relative_to(repo_root))
        try:
            source = f.read_text(encoding="utf-8")
            tree = ast.parse(source)
        except Exception:
            continue

        for call_ast in ast.walk(tree):
            if not isinstance(call_ast, ast.Call):
                continue
            callee_name = _get_call_name(call_ast.func) if call_ast.func else ""
            if not callee_name:
                continue

            callee_param_info = func_params.get(callee_name, [])
            if not callee_param_info:
                continue

            # Skip if callee is in the same file (already handled intra-file)
            same_file = [p for p in callee_param_info if p[2] == rel]
            if same_file:
                continue

            # Get argument names from the AST call site
            arg_names = []
            for arg_expr in call_ast.args:
                if isinstance(arg_expr, ast.Name):
                    arg_names.append(arg_expr.id)
                elif isinstance(arg_expr, ast.Attribute):
                    arg_names.append(arg_expr.attr)
                else:
                    arg_names.append("")

            call_line = call_ast.lineno
            for i, arg_name in enumerate(arg_names):
                if i >= len(callee_param_info):
                    break
                if not arg_name:
                    continue
                param_name, param_id, param_file = callee_param_info[i]

                # Find the argument node in the CPG by name in the call's file.
                # Node kind may be 'variable', 'identifier', or 'name'.
                arg_node = None
                for n in cpg.nodes.values():
                    if n.name == arg_name and n.file == rel:
                        if abs(n.line - call_line) <= 3:
                            arg_node = n
                            break
                if arg_node and param_id in cpg.nodes:
                    cpg.add_edge(arg_node.id, param_id, "param_cross_file")


def _get_call_name(func: ast.AST) -> str:
    """Extract the name from a Call.func AST node."""
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def save_cpg(cpg: CPG, path: Path) -> None:
    """Serialize CPG to JSON for inspection or incremental builds."""
    data = {
        "nodes": [{**n.__dict__} for n in cpg.nodes.values()],
        "edges": [{**e.__dict__} for e in cpg.edges],
    }
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")


def cpg_stats(cpg: CPG) -> dict:
    """Return stats about a CPG for debugging."""
    return {
        "total_nodes": len(cpg.nodes),
        "total_edges": len(cpg.edges),
        "by_kind": {k: len(v) for k, v in cpg.by_kind.items()},
        "files": len(cpg.by_file),
    }


# =============================================================================
# v4.24: CFG construction + multi-language CPG
# =============================================================================

def _add_cfg_edges(cpg: CPG, tree: ast.AST, rel_path: str) -> None:
    """v4.24: Add control-flow-graph (cfg_next) edges to the CPG."""
    for func_node in ast.walk(tree):
        if not isinstance(func_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        _add_cfg_edges_for_statements(cpg, func_node.body, rel_path, None)


def _add_cfg_edges_for_statements(cpg: CPG, statements: list,
                                    rel_path: str, prev_id) -> str:
    """Walk statements in order, adding cfg_next edges."""
    last_id = prev_id
    for stmt in statements:
        stmt_id = _make_node_id(stmt, rel_path)
        if stmt_id in cpg.nodes:
            if last_id is not None and last_id in cpg.nodes:
                cpg.add_edge(last_id, stmt_id, "cfg_next")
            last_id = stmt_id
        if isinstance(stmt, ast.If):
            body_last = _add_cfg_edges_for_statements(cpg, stmt.body, rel_path, last_id)
            orelse_last = _add_cfg_edges_for_statements(cpg, stmt.orelse, rel_path, last_id)
            last_id = body_last or orelse_last or last_id
        elif isinstance(stmt, (ast.For, ast.While, ast.AsyncFor)):
            body_last = _add_cfg_edges_for_statements(cpg, stmt.body, rel_path, last_id)
            orelse_last = _add_cfg_edges_for_statements(cpg, stmt.orelse, rel_path, body_last or last_id)
            if body_last is not None and last_id is not None and body_last in cpg.nodes:
                cpg.add_edge(body_last, last_id, "cfg_back_edge")
            last_id = orelse_last or body_last or last_id
        elif isinstance(stmt, ast.Try):
            body_last = _add_cfg_edges_for_statements(cpg, stmt.body, rel_path, last_id)
            handler_lasts = []
            for handler in stmt.handlers:
                hl = _add_cfg_edges_for_statements(cpg, handler.body, rel_path, last_id)
                if hl: handler_lasts.append(hl)
            else_last = _add_cfg_edges_for_statements(cpg, stmt.orelse, rel_path, body_last or last_id)
            pre_finally = [body_last, else_last] + handler_lasts
            pre_fid = next((p for p in pre_finally if p), last_id)
            finally_last = None
            if stmt.finalbody:
                finally_last = _add_cfg_edges_for_statements(cpg, stmt.finalbody, rel_path, pre_fid)
            possible = [body_last, else_last] + handler_lasts
            if finally_last: possible = [finally_last]
            last_id = next((p for p in possible if p), last_id)
        elif isinstance(stmt, (ast.With, ast.AsyncWith)):
            body_last = _add_cfg_edges_for_statements(cpg, stmt.body, rel_path, last_id)
            last_id = body_last or last_id
    return last_id


def build_cpg_for_file_multi(file_path: Path, repo_root: Path = None) -> CPG:
    """v4.24: Build a CPG for ANY language file using NormalizedNode.

    Python delegates to build_cpg_for_file (has def-use chains + CFG).
    Other languages get AST + param edges + CFG via NormalizedNode.
    """
    if not file_path.exists():
        return CPG()
    rel_path = str(file_path.relative_to(repo_root)) if repo_root else str(file_path)
    try:
        from .normalized_ast import get_language, parse_file
    except Exception:
        if file_path.suffix == ".py":
            return build_cpg_for_file(file_path, repo_root)
        return CPG()
    lang = get_language(file_path)
    if lang == "python":
        return build_cpg_for_file(file_path, repo_root)
    if lang == "unknown":
        return CPG()
    ntree = parse_file(file_path)
    if ntree is None:
        return CPG()
    cpg = CPG()

    def _norm_id(nn):
        return f"{rel_path}:{nn.line}:{nn.col}:{nn.kind}"

    def _walk_norm(nn, parent_id=None, function_id=None):
        kind = ""
        name = nn.name or ""
        nk = nn.kind
        if nk == "function_def": kind = "function"; function_id = _norm_id(nn)
        elif nk == "variable": kind = "variable"
        elif nk == "param": kind = "param"
        elif nk == "call": kind = "call"
        elif nk == "literal": kind = "literal"
        elif nk == "return": kind = "return"
        elif nk == "assignment": kind = "assign"
        elif nk == "if": kind = "if"
        elif nk == "for": kind = "for"
        elif nk == "while": kind = "while"
        elif nk == "try": kind = "try"
        elif nk == "except": kind = "except"
        nid = _norm_id(nn)
        if kind:
            cpg.add_node(CPGNode(id=nid, kind=kind, name=name, file=rel_path, line=nn.line))
            if parent_id: cpg.add_edge(parent_id, nid, "ast_child")
            if function_id and function_id != nid: cpg.add_edge(function_id, nid, "contains")
            effective_parent = nid
        else:
            effective_parent = parent_id
        if nk == "assignment" and nn.target:
            target_id = f"{rel_path}:{nn.line}:{nn.col}:assign_target"
            if target_id not in cpg.nodes:
                cpg.add_node(CPGNode(id=target_id, kind="variable", name=nn.target, file=rel_path, line=nn.line))
            for child in nn.children:
                if child.kind == "call":
                    cpg.add_edge(_norm_id(child), target_id, "data_dep")
        if nk == "call" and kind == "call" and name:
            callees = cpg.get_nodes(kind="function", name=name)
            for callee in callees:
                cpg.add_edge(nid, callee.id, "call")
        for child in nn.children:
            _walk_norm(child, parent_id=effective_parent, function_id=function_id)

    root = ntree.root if hasattr(ntree, "root") else ntree
    _walk_norm(root)

    # Add CFG edges for multi-lang
    def _add_multi_cfg(nn, prev_id=None):
        """v4.25: Fixed recursion — descend into ALL children (was only
        visiting if/for/while/try/return/assignment/call, missing
        variable_declaration, expression_statement, etc. that wrap calls
        and assignments in JS/TS/Go/Java)."""
        last_id = prev_id
        for child in nn.children:
            # v4.25: Visit ALL children, not just specific kinds.
            # For nodes that have CPG entries, add cfg_next edges.
            cid = _norm_id(child)
            if cid in cpg.nodes:
                if last_id and last_id in cpg.nodes:
                    cpg.add_edge(last_id, cid, "cfg_next")
                last_id = cid
            # Always recurse into children (even "other"-kind nodes
            # like expression_statement wrap calls/assignments)
            child_result = _add_multi_cfg(child, last_id)
            if child_result:
                last_id = child_result
        return last_id
    _add_multi_cfg(root)

    # Add params
    for fn_node in cpg.get_nodes(kind="function"):
        def _find_fn(nn):
            if nn.kind == "function_def" and nn.name == fn_node.name and nn.line == fn_node.line:
                return nn
            for c in nn.children:
                r = _find_fn(c)
                if r is not None: return r
            return None
        fn_norm = _find_fn(root)
        if fn_norm is not None:
            for i, param_name in enumerate(fn_norm.params):
                param_id = f"{fn_node.id}:param:{i}:{param_name}"
                if param_id not in cpg.nodes:
                    cpg.add_node(CPGNode(id=param_id, kind="param", name=param_name, file=rel_path, line=fn_node.line))
                    cpg.add_edge(fn_node.id, param_id, "param")

    # v5.4: Add def-use chains for multi-lang CPG
    # For each variable node, check if it's used in subsequent calls/assignments
    _add_multi_lang_def_use_chains(cpg, ntree, root, rel_path, _norm_id)

    return cpg


def _add_multi_lang_def_use_chains(cpg: CPG, ntree, root, rel_path: str, _norm_id) -> None:
    """v5.4: Add data_dep edges for variable reads in multi-language CPG.

    For Python, the build_cpg_for_file function already adds these edges.
    For JS/Java/Go/Rust, we need to detect variable reads and connect them
    to the corresponding variable definitions.

    Strategy: Walk the NormalizedNode tree, track variable definitions
    (assignments), and when a variable is used in a call expression,
    add a data_dep edge from the definition to the call.
    """
    # Collect all variable definitions: name → node_id
    var_defs: dict = {}

    def _walk_for_def_use(nn, fn_id=None):
        nk = nn.kind
        nid = _norm_id(nn)

        # Track variable definitions
        if nk == "assignment" and nn.target:
            target_id = f"{rel_path}:{nn.line}:{nn.col}:assign_target"
            var_defs[nn.target] = target_id

        # Track parameter definitions
        if nk == "function_def" and fn_id is None:
            fn_id = nid
            for i, param_name in enumerate(nn.params):
                param_id = f"{nid}:param:{i}:{param_name}"
                var_defs[param_name] = param_id

        # When a call uses a variable, add data_dep edge
        if nk == "call" and nid in cpg.nodes:
            # Check if any argument is a variable reference
            for child in nn.children:
                if child.kind == "variable" and child.name in var_defs:
                    def_id = var_defs[child.name]
                    child_nid = _norm_id(child)
                    # Add data_dep edge from variable def to the call
                    if def_id in cpg.nodes and nid in cpg.nodes:
                        # Avoid duplicate edges
                        existing = any(e.src == def_id and e.dst == nid and e.kind == "data_dep"
                                      for e in cpg.edges)
                        if not existing:
                            cpg.add_edge(def_id, nid, "data_dep")

        # Also add data_dep for variable-to-variable assignments
        if nk == "assignment" and nn.target:
            target_id = f"{rel_path}:{nn.line}:{nn.col}:assign_target"
            for child in nn.children:
                if child.kind == "variable" and child.name in var_defs and child.name != nn.target:
                    def_id = var_defs[child.name]
                    if def_id in cpg.nodes and target_id in cpg.nodes:
                        existing = any(e.src == def_id and e.dst == target_id and e.kind == "data_dep"
                                      for e in cpg.edges)
                        if not existing:
                            cpg.add_edge(def_id, target_id, "data_dep")

        for child in nn.children:
            _walk_for_def_use(child, fn_id)

    try:
        walk_root = ntree.root if hasattr(ntree, "root") else ntree
        _walk_for_def_use(walk_root)
    except Exception:
        pass  # Don't crash CPG build if def-use chain extraction fails


def build_cpg_for_repo_multi(repo_root: Path, max_files: int = 100) -> CPG:
    """v4.24: Build a unified CPG for ALL language files in the repo.

    v5.4: Added incremental CPG caching. CPG is cached per-file based on
    file mtime + size hash. When a file hasn't changed, its CPG nodes/edges
    are loaded from cache instead of re-parsing. This gives 10-50× speedup
    on subsequent scans of large monorepos.
    """
    # v5.4: Check for cached CPG
    cache_dir = repo_root / ".loomscan-cache" / "cpg"
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_manifest = cache_dir / "manifest.json"

    # Load cache manifest (file → {mtime, size, node_count})
    import json, hashlib
    cache = {}
    if cache_manifest.exists():
        try:
            cache = json.loads(cache_manifest.read_text())
        except Exception:
            cache = {}

    # Determine which files need re-parsing
    skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules",
                 ".loomscan-cache", ".loomscan-reports", ".loomscan-fixes", "tests", "test"}
    try:
        from .multi_lang import ALL_SOURCE_EXTS
    except Exception:
        ALL_SOURCE_EXTS = {".py", ".js", ".ts", ".go", ".java", ".c", ".cpp"}
    all_files = []
    for p in repo_root.rglob("*"):
        if not p.is_file(): continue
        if any(d in p.parts for d in skip_dirs): continue
        if p.name.startswith("test_") or p.name.endswith("_test.py"): continue
        if p.suffix.lower() not in ALL_SOURCE_EXTS: continue
        all_files.append(p)
        if len(all_files) >= max_files: break

    # v5.4: Incremental caching — only re-parse changed files
    master_cpg = CPG()
    cache_hits = 0
    cache_misses = 0
    updated_cache = {}
    for f in all_files:
        rel = str(f.relative_to(repo_root))
        stat = f.stat()
        file_key = f"{rel}:{stat.st_mtime}:{stat.st_size}"
        cache_file = cache_dir / f"{hashlib.md5(rel.encode()).hexdigest()}.json"

        # Check if cache is valid
        cached_entry = cache.get(rel)
        if cached_entry and cached_entry.get("key") == file_key and cache_file.exists():
            # Load from cache
            try:
                cached_cpg_data = json.loads(cache_file.read_text())
                for node_data in cached_cpg_data.get("nodes", []):
                    node = CPGNode(**node_data)
                    master_cpg.nodes[node.id] = node
                    master_cpg.by_kind.setdefault(node.kind, set()).add(node.id)
                    if node.name: master_cpg.by_name.setdefault(node.name, set()).add(node.id)
                    master_cpg.by_file.setdefault(node.file, set()).add(node.id)
                for edge_data in cached_cpg_data.get("edges", []):
                    edge = CPGEdge(**edge_data)
                    master_cpg.edges.append(edge)
                    master_cpg.successors.setdefault(edge.src, []).append((edge.kind, edge.dst))
                    master_cpg.predecessors.setdefault(edge.dst, []).append((edge.kind, edge.src))
                cache_hits += 1
                updated_cache[rel] = cached_entry
                continue
            except Exception:
                pass  # Cache corrupt, re-parse

        # Cache miss — parse the file
        cache_misses += 1
        file_cpg = build_cpg_for_file_multi(f, repo_root)
        for nid, node in file_cpg.nodes.items():
            master_cpg.nodes[nid] = node
            master_cpg.by_kind.setdefault(node.kind, set()).add(nid)
            if node.name: master_cpg.by_name.setdefault(node.name, set()).add(nid)
            master_cpg.by_file.setdefault(node.file, set()).add(nid)
        for edge in file_cpg.edges:
            master_cpg.edges.append(edge)
            master_cpg.successors.setdefault(edge.src, []).append((edge.kind, edge.dst))
            master_cpg.predecessors.setdefault(edge.dst, []).append((edge.kind, edge.src))

        # Save to cache
        try:
            cache_data = {
                "nodes": [{"id": n.id, "kind": n.kind, "name": n.name,
                           "file": n.file, "line": n.line} for n in file_cpg.nodes.values()],
                "edges": [{"src": e.src, "dst": e.dst, "kind": e.kind} for e in file_cpg.edges],
            }
            cache_file.write_text(json.dumps(cache_data))
            updated_cache[rel] = {"key": file_key, "nodes": len(file_cpg.nodes), "edges": len(file_cpg.edges)}
        except Exception:
            pass

    # Save updated cache manifest
    try:
        cache_manifest.write_text(json.dumps(updated_cache, indent=2))
    except Exception:
        pass

    # Add cross-file call edges
    for call_node in master_cpg.get_nodes(kind="call"):
        if not call_node.name: continue
        candidates = [n for n in master_cpg.get_nodes(kind="function", name=call_node.name)
                      if n.file != call_node.file or n.line < call_node.line]
        for callee in candidates[:1]:
            master_cpg.add_edge(call_node.id, callee.id, "call")

    import logging
    _logger = logging.getLogger("loomscan.cpg")
    if cache_hits + cache_misses > 0:
        _logger.info(f"CPG cache: {cache_hits} hits, {cache_misses} misses ({cache_hits/(cache_hits+cache_misses)*100:.0f}% hit rate)")

    return master_cpg
