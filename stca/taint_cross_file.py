"""Cross-file taint tracking on top of the CPG.

Replaces the single-file AST-based taint tracker with a CPG-based one that
can follow data flows across function calls and file boundaries.

Sources (user input):
  - Function parameters named like user input (request, input, payload, data,
    user_id, query, body, params, args, form, cookies, session, etc.)
  - Calls to known source functions (request.POST, request.GET, request.body,
    sys.argv, os.environ, input(), open(filename).read())

Sinks (dangerous operations):
  - eval, exec, os.system, subprocess.*, cursor.execute, open, render,
    render_template, innerHTML, logger.*, print, pickle.loads, yaml.load,
    redirect, etc.

Flow propagation:
  - Direct: source param → used in sink call
  - Through assignment: x = source; sink(x)
  - Through function call: f(source); inside f, the param reaches a sink
  - Through return: x = f(source); sink(x)
  - Sanitizers stop flow: int(source), html.escape(source), etc.

This catches what CodeQL catches, but in pure Python with no database.
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import List, Set, Dict, Tuple, Optional
from dataclasses import dataclass, field

from .cpg import CPG, CPGNode, build_cpg_for_repo, build_cpg_for_file, build_cpg_for_repo_multi, build_cpg_for_file_multi


# Source patterns: parameter names that are likely user input (case-insensitive)
SOURCE_PARAM_PATTERNS = [
    "request", "input", "payload", "data", "user_id", "userid", "query",
    "body", "params", "args", "form", "cookies", "session",
    "filename", "file", "path", "url", "uri", "auth", "token",
]

# Source call patterns: function calls that return user input
SOURCE_CALL_PATTERNS = {
    "request.POST": "form_post_data",
    "request.GET": "query_string_data",
    "request.body": "raw_request_body",
    "request.headers": "request_headers",
    "request.cookies": "request_cookies",
    "sys.argv": "command_line_args",
    "os.environ": "environment_variables",
    "os.getenv": "environment_variable",
    "input": "stdin_input",
    "flask.request": "flask_request",
    "Open(_).read": "file_contents",
}

# Sink patterns: dangerous call sites (call name → CWE)
SINK_PATTERNS = {
    "eval": ("CWE-95", "Code injection"),
    "exec": ("CWE-95", "Code injection"),
    "system": ("CWE-78", "OS command injection"),
    "popen": ("CWE-78", "OS command injection"),
    "call": ("CWE-78", "OS command injection"),
    "run": ("CWE-78", "OS command injection"),
    "Popen": ("CWE-78", "OS command injection"),
    "execute": ("CWE-89", "SQL injection"),
    "executemany": ("CWE-89", "SQL injection"),
    "executescript": ("CWE-89", "SQL injection"),
    "raw": ("CWE-89", "SQL injection"),
    "open": ("CWE-22", "Path traversal"),
    "render": ("CWE-79", "XSS"),
    "render_template": ("CWE-79", "XSS"),
    "render_template_string": ("CWE-79", "XSS"),
    "mark_safe": ("CWE-79", "XSS bypass"),
    "Markup": ("CWE-79", "XSS bypass"),
    "info": ("CWE-532", "Secret in log"),
    "debug": ("CWE-532", "Secret in log"),
    "warn": ("CWE-532", "Secret in log"),
    "error": ("CWE-532", "Secret in log"),
    "critical": ("CWE-532", "Secret in log"),
    "print": ("CWE-532", "Secret in log"),
    "loads": ("CWE-502", "Deserialization"),
    "load": ("CWE-502", "Deserialization"),
    "redirect": ("CWE-601", "Open redirect"),
    "subprocess": ("CWE-78", "OS command injection"),
    "pickle": ("CWE-502", "Deserialization"),
}

# Sanitizers: calls that "clean" tainted data, breaking the flow
SANITIZER_PATTERNS = {
    "int", "float", "bool",  # type conversion strips injection
    "escape", "html_escape", "html.escape",  # HTML escape
    "quote", "shlex_quote", "shlex.quote",  # shell escape
    "escape_string", "mysql_escape_string",
    "prepare",  # prepared statements
    "bind_param", "bindparam",
    "Literal",  # literal_eval-able
    "literal_eval",
    "urlparse",  # URL canonicalization
    "urllib.parse.quote",
}


@dataclass
class TaintFlow:
    """A detected taint flow from source to sink."""
    source: str          # source description (e.g., "param 'request' of handle()")
    sink: str            # sink call name
    sink_file: str
    sink_line: int
    sink_function: str
    cwe: str
    description: str
    path: List[str]      # node IDs in the CPG, source → ... → sink
    cross_file: bool = False
    intermediate_functions: List[str] = field(default_factory=list)


def track_taint_cross_file(cpg: CPG,
                            source_params: Set[str] = None,
                            sink_names: Set[str] = None,
                            max_depth: int = 8) -> List[TaintFlow]:
    """Track taint flows across the entire repo CPG.

    Args:
        cpg: the code property graph for the repo
        source_params: override the default source param name patterns
        sink_names: override the default sink patterns
        max_depth: max BFS depth (prevents runaway analysis on large CPGs)

    Returns:
        List of TaintFlow objects, one per detected flow.
    """
    if source_params is None:
        source_params = set(SOURCE_PARAM_PATTERNS)
    if sink_names is None:
        sink_names = set(SINK_PATTERNS.keys())

    # Step 1: identify source nodes (params with source-like names)
    source_nodes: List[CPGNode] = []
    for param in cpg.get_nodes(kind="param"):
        if any(p in param.name.lower() for p in source_params):
            source_nodes.append(param)

    # also: source call patterns (request.POST, sys.argv, etc.)
    for call in cpg.get_nodes(kind="call"):
        if call.name in source_params:
            source_nodes.append(call)

    if not source_nodes:
        return []

    # Step 2: identify sink nodes (calls to dangerous functions)
    sink_nodes: List[CPGNode] = []
    for call in cpg.get_nodes(kind="call"):
        if call.name in sink_names:
            sink_nodes.append(call)

    if not sink_nodes:
        return []

    sink_ids: Set[str] = {n.id for n in sink_nodes}

    # Step 3: for each source, BFS through data_dep + call edges to find sinks
    flows: List[TaintFlow] = []
    seen_pairs: Set[Tuple[str, str]] = set()

    for source in source_nodes:
        # BFS from source, following data_dep and call edges
        visited: Dict[str, int] = {source.id: 0}
        parent: Dict[str, Optional[str]] = {source.id: None}
        queue: List[str] = [source.id]

        while queue:
            nid = queue.pop(0)
            depth = visited[nid]
            if depth >= max_depth:
                continue

            # check if this node is a sink
            if nid in sink_ids and nid != source.id:
                sink_node = cpg.nodes[nid]
                # check if any predecessor is a sanitizer — if so, flow is broken
                if _is_sanitized(cpg, nid):
                    continue

                # reconstruct path
                path: List[str] = []
                cur: Optional[str] = nid
                while cur is not None:
                    path.append(cur)
                    cur = parent.get(cur)
                path.reverse()

                # dedupe by (source, sink) pair
                pair = (source.id, nid)
                if pair in seen_pairs:
                    continue
                seen_pairs.add(pair)

                # find which function the sink is in
                sink_function = _find_enclosing_function(cpg, nid)

                # is the flow cross-file?
                cross_file = len({cpg.nodes[p].file for p in path}) > 1

                # collect intermediate function names
                intermediate_funcs = [cpg.nodes[p].name for p in path
                                       if cpg.nodes[p].kind == "function"
                                       and p not in (source.id, nid)]

                cwe, desc = SINK_PATTERNS.get(sink_node.name, ("CWE-Other", "Vulnerable sink"))

                flows.append(TaintFlow(
                    source=f"param '{source.name}' in {source.file}:{source.line}",
                    sink=sink_node.name,
                    sink_file=sink_node.file,
                    sink_line=sink_node.line,
                    sink_function=sink_function,
                    cwe=cwe,
                    description=desc,
                    path=path,
                    cross_file=cross_file,
                    intermediate_functions=intermediate_funcs,
                ))
                continue  # don't expand past a sink

            # v3.3: Also check if this tainted variable is an ARGUMENT to a sink call.
            # If a tainted variable is an ast_child of a sink call node, that's a flow.
            # BUT: for SQL sinks (execute, executemany), only the FIRST argument
            # (the query) is dangerous — subsequent arguments are bound params
            # which are safe from injection.
            current_node = cpg.nodes.get(nid)
            if current_node and current_node.kind == "variable":
                for call_id, call_node in cpg.nodes.items():
                    if call_node.kind != "call" or call_node.name not in sink_names:
                        continue
                    if call_id == source.id:
                        continue
                    # Check if this variable is an ast_child of the call node
                    for edge_kind, dst in cpg.successors.get(call_id, []):
                        if edge_kind == "ast_child" and dst == nid:
                            # v3.3: For SQL sinks, check if this is the query
                            # argument (first arg) or a bound param (subsequent arg).
                            # Parameterized queries are safe.
                            if call_node.name in ("execute", "executemany", "executescript"):
                                # The FIRST ast_child is the method receiver
                                # (e.g., 'cursor' in cursor.execute(...)).
                                # Subsequent ast_children are the arguments.
                                # arg_position 0 = first argument (the query)
                                # arg_position 1+ = bound params (safe)
                                ast_children = [dst2 for e2, dst2 in cpg.successors.get(call_id, [])
                                                if e2 == "ast_child"]
                                if len(ast_children) > 0:
                                    # Find this variable's position among ast_children
                                    try:
                                        child_idx = ast_children.index(nid)
                                        # First child is receiver (index 0)
                                        # Second child is first arg (index 1 → arg_position 0)
                                        # Third child is second arg (index 2 → arg_position 1)
                                        arg_position = child_idx - 1  # subtract receiver
                                        if arg_position > 0:
                                            # This is a bound parameter (2nd+ arg) — safe
                                            continue
                                    except ValueError:
                                        pass
                            if _is_sanitized(cpg, call_id):
                                continue
                            pair = (source.id, call_id)
                            if pair in seen_pairs:
                                continue
                            seen_pairs.add(pair)
                            # Reconstruct path
                            path: List[str] = []
                            cur: Optional[str] = nid
                            while cur is not None:
                                path.append(cur)
                                cur = parent.get(cur)
                            path.reverse()
                            path.append(call_id)
                            sink_function = _find_enclosing_function(cpg, call_id)
                            source_file = source.file
                            sink_file = call_node.file
                            cross_file = source_file != sink_file
                            intermediate_funcs: List[str] = []
                            for pid in path:
                                pnode = cpg.nodes.get(pid)
                                if pnode and pnode.kind == "function":
                                    intermediate_funcs.append(pnode.name)
                            cwe, desc = SINK_PATTERNS.get(call_node.name, ("CWE-Other", "Vulnerable sink"))
                            flows.append(TaintFlow(
                                source=f"param '{source.name}'" if source.kind == "param" else source.name,
                                sink=call_node.name,
                                sink_file=call_node.file,
                                sink_line=call_node.line,
                                sink_function=sink_function,
                                cwe=cwe,
                                description=desc,
                                path=path,
                                cross_file=cross_file,
                                intermediate_functions=intermediate_funcs,
                            ))
                            break

            # expand — v3.3: also follow 'param' edges for interprocedural analysis
            # v4.3: also follow 'param_cross_file' edges for genuine cross-file
            # taint propagation (arg at call-site → param in callee body in
            # a different file)
            for edge_kind, dst in cpg.successors.get(nid, []):
                if edge_kind in ("data_dep", "call", "param", "param_cross_file") and dst not in visited:
                    visited[dst] = depth + 1
                    parent[dst] = nid
                    queue.append(dst)

    return flows


def _is_sanitized(cpg: CPG, sink_node_id: str) -> bool:
    """Check if a sink's argument has been sanitized (passed through a sanitizer)."""
    sink_node = cpg.nodes[sink_node_id]
    # check predecessors — if any is a sanitizer call, flow is broken
    for kind, pred_id in cpg.predecessors.get(sink_node_id, []):
        if kind == "data_dep":
            pred = cpg.nodes.get(pred_id)
            if pred and pred.kind == "call" and pred.name in SANITIZER_PATTERNS:
                return True
    return False


def _find_enclosing_function(cpg: CPG, node_id: str) -> str:
    """Find the name of the function that contains a node."""
    # walk up via "contains" edges (function → node)
    for kind, pred_id in cpg.predecessors.get(node_id, []):
        if kind == "contains":
            pred = cpg.nodes.get(pred_id)
            if pred and pred.kind == "function":
                return pred.name
        if kind == "ast_child":
            # also check ast parents
            result = _find_enclosing_function(cpg, pred_id)
            if result != "<unknown>":
                return result
    return "<unknown>"


def track_taint_for_files(files: List[Path],
                           repo_root: Path = None) -> List[TaintFlow]:
    """Build a CPG for the given files and run taint tracking."""
    if not files:
        return []
    # use the repo-level CPG if we have one, else build per-file
    if repo_root and len(files) > 1:
        cpg = build_cpg_for_repo_multi(repo_root)  # v4.24: multi-lang CPG
    else:
        cpg = CPG()
        for f in files:
            file_cpg = build_cpg_for_file_multi(f, repo_root)  # v4.25: multi-lang
            # merge
            for nid, node in file_cpg.nodes.items():
                cpg.nodes[nid] = node
                cpg.by_kind.setdefault(node.kind, set()).add(nid)
                if node.name:
                    cpg.by_name.setdefault(node.name, set()).add(nid)
                cpg.by_file.setdefault(node.file, set()).add(nid)
            for edge in file_cpg.edges:
                cpg.edges.append(edge)
                cpg.successors.setdefault(edge.src, []).append((edge.kind, edge.dst))
                cpg.predecessors.setdefault(edge.dst, []).append((edge.kind, edge.src))

    return track_taint_cross_file(cpg)
