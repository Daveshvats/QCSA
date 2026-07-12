"""Advanced interprocedural taint analysis engine.

Combines 4 Kunlun-M-inspired techniques:

1. **Function Summary Generator** — Uses tree-sitter AST to pre-compute
   data-flow summaries for every function:
     - Which parameters flow to the return value
     - Which parameters flow to sinks (and what sink type)
     - Which parameters are sanitized before use

2. **Cross-File Function Call Resolution** — Builds a call graph across
   the entire repo. When function A calls function B, looks up B's summary
   to determine taint propagation without re-analyzing B's body.

3. **Branch Constraint Tracker** — Path-sensitive analysis that tracks
   if/else conditions to suppress false positives:
     - `if (x == null) return;` → after if, x is non-null
     - `if (isValid(x)) { sink(x); }` → x is safe inside the if block
     - `if (!isValid(x)) throw ...;` → after if, x is validated

4. **Trace Cache** — File-hash-based caching of function summaries.
   Unchanged files skip re-analysis entirely.

Architecture:
    File → AST Parse → Function Summaries → Registry
                                        ↓
    Source Discovery → Taint Tracker ← Call Graph Resolution
                    ↓               ← Branch Constraints
              Taint Flows → Findings
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# Self-contained — no external v2 module dependencies
# Inline language detection
PYTHON_EXTS = {".py"}
JS_TS_EXTS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
GO_EXTS = {".go"}
JAVA_EXTS = {".java"}
C_CPP_EXTS = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hxx"}
ALL_SOURCE_EXTS = PYTHON_EXTS | JS_TS_EXTS | GO_EXTS | JAVA_EXTS | C_CPP_EXTS

def get_language(file_path: Path) -> str:
    ext = file_path.suffix.lower()
    if ext in PYTHON_EXTS: return "python"
    if ext in JS_TS_EXTS: return "javascript"
    if ext in GO_EXTS: return "go"
    if ext in JAVA_EXTS: return "java"
    if ext in C_CPP_EXTS: return "cpp"
    return "unknown"


# ============================================================================
# Inline knowledge base (minimal — function behavior database)
# ============================================================================

@dataclass
class FunctionBehavior:
    passthrough: List[int] = field(default_factory=list)
    safe: bool = False
    is_source: bool = False
    is_sink: bool = False
    sink_type: str = ""
    notes: str = ""

LANGUAGE_KNOWLEDGE: Dict[str, Dict[str, FunctionBehavior]] = {
    "java": {
        "toUpperCase": FunctionBehavior(passthrough=[0]),
        "toLowerCase": FunctionBehavior(passthrough=[0]),
        "trim": FunctionBehavior(passthrough=[0]),
        "substring": FunctionBehavior(passthrough=[0]),
        "replace": FunctionBehavior(passthrough=[0]),
        "toString": FunctionBehavior(passthrough=[0]),
        "valueOf": FunctionBehavior(passthrough=[0]),
        "length": FunctionBehavior(safe=True),
        "equals": FunctionBehavior(safe=True),
        "isEmpty": FunctionBehavior(safe=True),
        "contains": FunctionBehavior(safe=True),
        "StringEscapeUtils.escapeHtml4": FunctionBehavior(passthrough=[0], safe=True),
        "URLEncoder.encode": FunctionBehavior(passthrough=[0], safe=True),
        "HtmlUtils.htmlEscape": FunctionBehavior(passthrough=[0], safe=True),
        "Integer.parseInt": FunctionBehavior(safe=True),
        "Long.parseLong": FunctionBehavior(safe=True),
        "StringUtils.isNumeric": FunctionBehavior(safe=True),
        "getParameter": FunctionBehavior(is_source=True, passthrough=[0]),
        "getHeader": FunctionBehavior(is_source=True, passthrough=[0]),
        "getQueryString": FunctionBehavior(is_source=True, passthrough=[0]),
        "getRequestURI": FunctionBehavior(is_source=True, passthrough=[0]),
        "getInputStream": FunctionBehavior(is_source=True, passthrough=[0]),
        "System.getenv": FunctionBehavior(is_source=True, passthrough=[0]),
        "Runtime.exec": FunctionBehavior(is_sink=True, sink_type="command_injection", passthrough=[0]),
        "Statement.execute": FunctionBehavior(is_sink=True, sink_type="sql_injection", passthrough=[0]),
        "Statement.executeQuery": FunctionBehavior(is_sink=True, sink_type="sql_injection"),
        "Class.forName": FunctionBehavior(is_sink=True, sink_type="reflection", passthrough=[0]),
        "ObjectInputStream.readObject": FunctionBehavior(is_sink=True, sink_type="deserialization"),
        "response.sendRedirect": FunctionBehavior(is_sink=True, sink_type="open_redirect", passthrough=[0]),
        "response.getWriter().print": FunctionBehavior(is_sink=True, sink_type="xss", passthrough=[0]),
    },
    "python": {
        "upper": FunctionBehavior(passthrough=[0]),
        "lower": FunctionBehavior(passthrough=[0]),
        "strip": FunctionBehavior(passthrough=[0]),
        "replace": FunctionBehavior(passthrough=[0]),
        "format": FunctionBehavior(passthrough=[0]),
        "html.escape": FunctionBehavior(passthrough=[0], safe=True),
        "urllib.parse.quote": FunctionBehavior(passthrough=[0], safe=True),
        "len": FunctionBehavior(safe=True),
        "int": FunctionBehavior(safe=True),
        "os.system": FunctionBehavior(is_sink=True, sink_type="command_injection", passthrough=[0]),
        "eval": FunctionBehavior(is_sink=True, sink_type="code_injection", passthrough=[0]),
        "exec": FunctionBehavior(is_sink=True, sink_type="code_injection", passthrough=[0]),
        "pickle.loads": FunctionBehavior(is_sink=True, sink_type="deserialization", passthrough=[0]),
        "cursor.execute": FunctionBehavior(is_sink=True, sink_type="sql_injection", passthrough=[0]),
        "input": FunctionBehavior(is_source=True, passthrough=[0]),
        "os.getenv": FunctionBehavior(is_source=True, passthrough=[0]),
        "request.args.get": FunctionBehavior(is_source=True, passthrough=[0]),
        "request.form.get": FunctionBehavior(is_source=True, passthrough=[0]),
    },
    "javascript": {
        "toUpperCase": FunctionBehavior(passthrough=[0]),
        "toLowerCase": FunctionBehavior(passthrough=[0]),
        "trim": FunctionBehavior(passthrough=[0]),
        "replace": FunctionBehavior(passthrough=[0]),
        "toString": FunctionBehavior(passthrough=[0]),
        "encodeURIComponent": FunctionBehavior(passthrough=[0], safe=True),
        "DOMPurify.sanitize": FunctionBehavior(passthrough=[0], safe=True),
        "length": FunctionBehavior(safe=True),
        "eval": FunctionBehavior(is_sink=True, sink_type="code_injection", passthrough=[0]),
        "document.write": FunctionBehavior(is_sink=True, sink_type="xss", passthrough=[0]),
        "localStorage.getItem": FunctionBehavior(is_source=True),
        "req.params": FunctionBehavior(is_source=True),
        "req.query": FunctionBehavior(is_source=True),
        "req.body": FunctionBehavior(is_source=True),
    },
    "go": {
        "strings.ToUpper": FunctionBehavior(passthrough=[0]),
        "strings.TrimSpace": FunctionBehavior(passthrough=[0]),
        "html.EscapeString": FunctionBehavior(passthrough=[0], safe=True),
        "exec.Command": FunctionBehavior(is_sink=True, sink_type="command_injection", passthrough=[0]),
        "db.Exec": FunctionBehavior(is_sink=True, sink_type="sql_injection", passthrough=[0]),
        "db.Query": FunctionBehavior(is_sink=True, sink_type="sql_injection", passthrough=[0]),
        "r.URL.Query().Get": FunctionBehavior(is_source=True),
        "r.FormValue": FunctionBehavior(is_source=True),
        "os.Getenv": FunctionBehavior(is_source=True),
    },
    "cpp": {
        "strcpy": FunctionBehavior(passthrough=[1]),
        "system": FunctionBehavior(is_sink=True, sink_type="command_injection", passthrough=[0]),
        "gets": FunctionBehavior(is_sink=True, sink_type="buffer_overflow", passthrough=[0]),
        "sprintf": FunctionBehavior(is_sink=True, sink_type="buffer_overflow", passthrough=[1]),
        "getenv": FunctionBehavior(is_source=True, passthrough=[0]),
    },
}

def lookup_function(language: str, func_name: str) -> Optional[FunctionBehavior]:
    kb = LANGUAGE_KNOWLEDGE.get(language, {})
    if func_name in kb:
        return kb[func_name]
    short_name = func_name.split(".")[-1] if "." in func_name else func_name
    return kb.get(short_name)


# ============================================================================
# Inline source discovery (minimal)
# ============================================================================

@dataclass
class SourceInfo:
    file: str
    line: int
    param_name: str
    source_type: str
    framework: str
    method_name: str = ""

SPRING_SOURCE_PATTERNS = [
    ("RequestParam", r'@RequestParam\s*(?:\([^)]*\))?\s+(?:\w+\s+)?(\w+)', "request_param", "spring"),
    ("PathVariable", r'@PathVariable\s*(?:\([^)]*\))?\s+(?:\w+\s+)?(\w+)', "path_variable", "spring"),
    ("RequestBody", r'@RequestBody\s+(?:\w+\s+)?(\w+)', "request_body", "spring"),
    ("RequestHeader", r'@RequestHeader\s*(?:\([^)]*\))?\s+(?:\w+\s+)?(\w+)', "header", "spring"),
]

def discover_sources_in_file(file_path: Path, repo_root: Optional[Path] = None) -> List[SourceInfo]:
    lang = get_language(file_path)
    if lang == "unknown":
        return []
    rel = str(file_path.relative_to(repo_root)) if repo_root else str(file_path)
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []
    sources: List[SourceInfo] = []
    lines = source.splitlines()
    current_method = ""
    patterns = SPRING_SOURCE_PATTERNS if lang == "java" else []
    for i, line in enumerate(lines, 1):
        if lang == "java":
            m = re.match(r'\s*(?:public|private|protected)\s+\w+\s+(\w+)\s*\(', line)
            if m:
                current_method = m.group(1)
        for _, regex, source_type, framework in patterns:
            m = re.search(regex, line)
            if m:
                sources.append(SourceInfo(
                    file=rel, line=i, param_name=m.group(1) if m.lastindex else "",
                    source_type=source_type, framework=framework, method_name=current_method,
                ))
    return sources

def discover_sources_in_repo(repo_root: Path, max_files: int = 600) -> List[SourceInfo]:
    all_sources: List[SourceInfo] = []
    skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules", "build", "dist", "target", "test", "tests"}
    count = 0
    for p in repo_root.rglob("*"):
        if not p.is_file() or any(part in skip_dirs for part in p.parts):
            continue
        if p.suffix.lower() in ALL_SOURCE_EXTS:
            try:
                all_sources += discover_sources_in_file(p, repo_root)
            except Exception:
                pass
            count += 1
            if count >= max_files:
                break
    return all_sources


# ============================================================================
# 1. FUNCTION SUMMARY — data-flow summary for a single function
# ============================================================================

@dataclass
class ParamFlow:
    """How a single parameter flows through a function."""
    param_position: int  # 0-indexed position in the parameter list
    param_name: str
    flows_to_return: bool = False  # does this param reach the return statement?
    flows_to_sinks: List[Tuple[str, str, int]] = field(default_factory=list)  # [(sink_func, sink_type, line)]
    is_sanitized: bool = False  # is this param sanitized before any use?
    sanitizer_function: str = ""  # what sanitized it?


@dataclass
class FunctionSummaryV2:
    """Complete data-flow summary for a function (v2 — AST-based)."""
    name: str
    file: str
    line: int
    params: List[str] = field(default_factory=list)  # parameter names in order
    param_flows: Dict[str, ParamFlow] = field(default_factory=dict)  # param_name → flow
    return_depends_on: Set[str] = field(default_factory=set)  # which params flow to return
    is_source: bool = False  # does this function return user input?
    source_type: str = ""  # if is_source, what type
    is_sink: bool = False  # does this function call a sink?
    sink_type: str = ""  # if is_sink, what type
    calls: List[str] = field(default_factory=list)  # other functions this calls
    has_branch_constraint: bool = False  # does it have if/return guards?

    def get_flow(self, param_name: str) -> Optional[ParamFlow]:
        return self.param_flows.get(param_name)

    def to_dict(self) -> dict:
        """Serialize for caching."""
        return {
            "name": self.name,
            "file": self.file,
            "line": self.line,
            "params": self.params,
            "return_depends_on": list(self.return_depends_on),
            "is_source": self.is_source,
            "source_type": self.source_type,
            "is_sink": self.is_sink,
            "sink_type": self.sink_type,
            "calls": self.calls,
            "param_flows": {
                k: {
                    "param_position": v.param_position,
                    "flows_to_return": v.flows_to_return,
                    "flows_to_sinks": v.flows_to_sinks,
                    "is_sanitized": v.is_sanitized,
                    "sanitizer_function": v.sanitizer_function,
                }
                for k, v in self.param_flows.items()
            },
        }

    @classmethod
    def from_dict(cls, d: dict) -> "FunctionSummaryV2":
        """Deserialize from cache."""
        summary = cls(
            name=d["name"], file=d["file"], line=d["line"],
            params=d.get("params", []),
            return_depends_on=set(d.get("return_depends_on", [])),
            is_source=d.get("is_source", False),
            source_type=d.get("source_type", ""),
            is_sink=d.get("is_sink", False),
            sink_type=d.get("sink_type", ""),
            calls=d.get("calls", []),
        )
        for pname, pf in d.get("param_flows", {}).items():
            summary.param_flows[pname] = ParamFlow(
                param_position=pf["param_position"],
                param_name=pname,
                flows_to_return=pf.get("flows_to_return", False),
                flows_to_sinks=[tuple(s) for s in pf.get("flows_to_sinks", [])],
                is_sanitized=pf.get("is_sanitized", False),
                sanitizer_function=pf.get("sanitizer_function", ""),
            )
        return summary


# ============================================================================
# 2. FUNCTION SUMMARY GENERATOR — tree-sitter AST based
# ============================================================================

class FunctionSummaryGenerator:
    """Generates data-flow summaries for functions using tree-sitter AST.

    For each function, tracks:
      - Which parameters appear in return statements → flows_to_return
      - Which parameters reach sink calls → flows_to_sinks
      - Which parameters are passed through sanitizers → is_sanitized
      - What other functions this function calls → calls
    """

    def __init__(self, language: str):
        self.language = language
        self._parser = None

    def _get_parser(self):
        if self._parser:
            return self._parser
        try:
            import tree_sitter
            if self.language == "java":
                import tree_sitter_java
                lang = tree_sitter.Language(tree_sitter_java.language())
            elif self.language == "python":
                import tree_sitter_python
                lang = tree_sitter.Language(tree_sitter_python.language())
            elif self.language == "javascript":
                import tree_sitter_javascript
                lang = tree_sitter.Language(tree_sitter_javascript.language())
            else:
                return None
            self._parser = tree_sitter.Parser(lang)
            return self._parser
        except Exception:
            return None

    def generate_for_file(self, file_path: Path,
                          repo_root: Optional[Path] = None) -> List[FunctionSummaryV2]:
        """Generate summaries for all functions in a file."""
        parser = self._get_parser()
        if parser is None:
            return []

        # Skip very large files
        try:
            if file_path.stat().st_size > 200000:
                return []
        except Exception:
            return []

        rel = str(file_path.relative_to(repo_root)) if repo_root else str(file_path)
        try:
            source = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return []

        try:
            tree = parser.parse(source.encode("utf-8"))
        except Exception:
            return []

        # Find all function/method definitions
        functions = self._find_functions(tree.root_node, source)
        summaries: List[FunctionSummaryV2] = []

        for func_name, func_node, params, line in functions:
            summary = self._analyze_function(func_name, func_node, params, source, rel, line)
            summaries.append(summary)

        return summaries

    def _find_functions(self, root_node, source: str) -> List[Tuple[str, object, List[str], int]]:
        """Find all function/method definitions in the AST."""
        functions = []

        def walk(node):
            node_type = node.type

            if self.language == "java":
                if node_type == "method_declaration":
                    name = self._get_child_text(node, "identifier", source)
                    params = self._extract_params_java(node, source)
                    if name and name not in ("if", "for", "while", "switch"):
                        functions.append((name, node, params, node.start_point[0] + 1))
            elif self.language == "python":
                if node_type == "function_definition":
                    name = self._get_child_text(node, "identifier", source)
                    params = self._extract_params_python(node, source)
                    if name:
                        functions.append((name, node, params, node.start_point[0] + 1))
            elif self.language == "javascript":
                if node_type in ("function_declaration", "function_expression"):
                    name = self._get_child_text(node, "identifier", source)
                    params = self._extract_params_js(node, source)
                    if name:
                        functions.append((name, node, params, node.start_point[0] + 1))
                elif node_type == "variable_declarator":
                    # const foo = (params) => { ... }
                    name_node = self._get_child_node(node, "identifier")
                    if name_node:
                        name = self._node_text(name_node, source)
                        params = self._extract_params_js(node, source)
                        # Check if there's a function body
                        has_body = any(
                            child.type in ("statement_block", "arrow_function")
                            for child in node.children
                        )
                        if has_body and name:
                            functions.append((name, node, params, node.start_point[0] + 1))

            for child in node.children:
                walk(child)

        walk(root_node)
        return functions

    def _analyze_function(self, name: str, func_node, params: List[str],
                          source: str, file: str, line: int) -> FunctionSummaryV2:
        """Analyze a function's AST to determine data flow."""
        summary = FunctionSummaryV2(
            name=name, file=file, line=line,
            params=params,
        )

        # Initialize param flows
        for i, param in enumerate(params):
            summary.param_flows[param] = ParamFlow(
                param_position=i, param_name=param
            )

        # Track if params are sanitized
        sanitized_params: Set[str] = set()

        # Track what functions are called
        called_functions: Set[str] = set()

        # Walk the function body
        def walk(node):
            node_type = node.type
            node_text = self._node_text(node, source)

            # Check for return statements that reference params
            if node_type == "return_statement" or (self.language == "javascript" and "return" in node_text.lower()):
                for param in params:
                    if param in node_text:
                        summary.return_depends_on.add(param)
                        summary.param_flows[param].flows_to_return = True

            # Check for method/function calls
            if node_type == "method_invocation" or node_type == "call_expression":
                func_name = self._extract_call_name(node, source)
                if func_name:
                    called_functions.add(func_name)

                    # Check if this is a sink
                    behavior = lookup_function(self.language, func_name)
                    if behavior and behavior.is_sink:
                        summary.is_sink = True
                        summary.sink_type = behavior.sink_type
                        # Check which params flow to this sink
                        for param in params:
                            if param in node_text:
                                summary.param_flows[param].flows_to_sinks.append(
                                    (func_name, behavior.sink_type, node.start_point[0] + 1)
                                )

                    # Check if this is a sanitizer
                    if behavior and behavior.safe:
                        for param in params:
                            if param in node_text:
                                sanitized_params.add(param)
                                summary.param_flows[param].is_sanitized = True
                                summary.param_flows[param].sanitizer_function = func_name

                    # Check if this is a source
                    if behavior and behavior.is_source:
                        summary.is_source = True
                        summary.source_type = behavior.notes or "source"

            for child in node.children:
                walk(child)

        walk(func_node)

        summary.calls = list(called_functions)

        # Mark sanitized params
        for param in sanitized_params:
            if param in summary.param_flows:
                summary.param_flows[param].is_sanitized = True

        return summary

    # --- AST helper methods ---

    def _node_text(self, node, source: str) -> str:
        start = node.start_byte
        end = node.end_byte
        return source.encode("utf-8")[start:end].decode("utf-8", errors="replace")

    def _get_child_text(self, node, child_type: str, source: str) -> Optional[str]:
        for child in node.children:
            if child.type == child_type:
                return self._node_text(child, source)
        return None

    def _get_child_node(self, node, child_type: str):
        for child in node.children:
            if child.type == child_type:
                return child
        return None

    def _extract_params_java(self, node, source: str) -> List[str]:
        """Extract parameter names from a Java method declaration."""
        params = []
        for child in node.children:
            if child.type == "formal_parameters":
                for param in child.children:
                    if param.type == "formal_parameter":
                        # Last identifier in the formal_parameter is the name
                        identifiers = [c for c in param.children if c.type == "identifier"]
                        if identifiers:
                            params.append(self._node_text(identifiers[-1], source))
        return params

    def _extract_params_python(self, node, source: str) -> List[str]:
        """Extract parameter names from a Python function definition."""
        params = []
        for child in node.children:
            if child.type == "parameters":
                for param in child.children:
                    if param.type == "identifier":
                        params.append(self._node_text(param, source))
        return params

    def _extract_params_js(self, node, source: str) -> List[str]:
        """Extract parameter names from a JS function."""
        params = []
        for child in node.children:
            if child.type in ("formal_parameters", "parameter_list"):
                for param in child.children:
                    if param.type == "identifier":
                        params.append(self._node_text(param, source))
                    elif param.type == "required_parameter":
                        for sub in param.children:
                            if sub.type == "identifier":
                                params.append(self._node_text(sub, source))
            elif child.type == "identifier" and not params:
                # Arrow function: (a, b) => ...
                pass
        return params

    def _extract_call_name(self, node, source: str) -> str:
        """Extract the function name from a call/method_invocation node."""
        text = self._node_text(node, source)
        # For method_invocation: "obj.method(args)" → extract "method"
        # For call_expression: "func(args)" → extract "func"
        # Get the function name part (before the argument list)
        paren_idx = text.find("(")
        if paren_idx > 0:
            name_part = text[:paren_idx].strip()
            # Get the last segment after dots
            if "." in name_part:
                parts = name_part.split(".")
                return ".".join(parts[-2:]) if len(parts) >= 2 else parts[-1]
            return name_part
        return ""


# ============================================================================
# 3. CROSS-FILE CALL GRAPH + SUMMARY REGISTRY
# ============================================================================

class CallGraphResolver:
    """Resolves function calls across files using a summary registry.

    Maintains a registry of all function summaries in the project.
    When analyzing a call, looks up the callee's summary to determine
    taint propagation without re-analyzing the callee's body.
    """

    def __init__(self, language: str):
        self.language = language
        self.summaries: Dict[str, FunctionSummaryV2] = {}  # function_name → summary
        self.summaries_by_file: Dict[str, List[FunctionSummaryV2]] = {}
        self.generator = FunctionSummaryGenerator(language)

    def register_summary(self, summary: FunctionSummaryV2):
        """Register a function summary."""
        # Register by name (last one wins for overloads)
        self.summaries[summary.name] = summary
        # Also register by file
        self.summaries_by_file.setdefault(summary.file, []).append(summary)

    def build_from_repo(self, repo_root: Path, max_files: int = 300,
                        cache: Optional["TraceCache"] = None) -> int:
        """Build the call graph by scanning all files in the repo.

        Returns: number of functions summarized.
        """
        skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules",
                     ".stca-cache", "build", "dist", "target", "test", "tests"}
        count = 0
        func_count = 0

        for p in repo_root.rglob("*"):
            if not p.is_file():
                continue
            if any(part in skip_dirs for part in p.parts):
                continue
            if get_language(p) != self.language:
                continue
            if p.stat().st_size > 200000:
                continue

            # Check cache
            if cache:
                cached = cache.get_summaries(p)
                if cached is not None:
                    for s in cached:
                        self.register_summary(s)
                    func_count += len(cached)
                    count += 1
                    if count >= max_files:
                        break
                    continue

            # Generate new summaries
            summaries = self.generator.generate_for_file(p, repo_root)
            for s in summaries:
                self.register_summary(s)
            func_count += len(summaries)

            # Cache the summaries
            if cache:
                cache.put_summaries(p, summaries)

            count += 1
            if count >= max_files:
                break

        return func_count

    def lookup(self, func_name: str) -> Optional[FunctionSummaryV2]:
        """Look up a function summary by name."""
        # Exact match
        if func_name in self.summaries:
            return self.summaries[func_name]
        # Short name match
        if "." in func_name:
            short = func_name.split(".")[-1]
            if short in self.summaries:
                return self.summaries[short]
        if "::" in func_name:
            short = func_name.split("::")[-1]
            if short in self.summaries:
                return self.summaries[short]
        return None

    def resolve_taint_through_call(self, func_name: str,
                                    tainted_arg_positions: Set[int]) -> Tuple[bool, bool, str]:
        """Resolve taint propagation through a function call.

        Args:
            func_name: The called function's name
            tainted_arg_positions: Which argument positions are tainted

        Returns:
            (return_is_tainted, reaches_sink, sink_type)
        """
        # Check builtin knowledge first
        behavior = lookup_function(self.language, func_name)
        if behavior:
            # Check if function is a sink
            if behavior.is_sink:
                # Check if any tainted position is in passthrough
                if any(pos in behavior.passthrough for pos in tainted_arg_positions):
                    return False, True, behavior.sink_type
                return False, True, behavior.sink_type  # sink is reached regardless

            # Check if function sanitizes
            if behavior.safe:
                return False, False, ""

            # Check passthrough
            if behavior.passthrough:
                for pos in tainted_arg_positions:
                    if pos in behavior.passthrough:
                        return True, False, ""
                return False, False, ""

            # Non-passthrough (e.g., length()) — taint is removed
            return False, False, ""

        # Check user-defined function summaries
        summary = self.lookup(func_name)
        if summary:
            return_is_tainted = False
            reaches_sink = False
            sink_type = ""

            for pos in tainted_arg_positions:
                if pos < len(summary.params):
                    param_name = summary.params[pos]
                    flow = summary.get_flow(param_name)
                    if flow:
                        if flow.flows_to_return:
                            return_is_tainted = True
                        if flow.flows_to_sinks:
                            reaches_sink = True
                            sink_type = flow.flows_to_sinks[0][1]  # first sink type
                        if flow.is_sanitized:
                            # Sanitized — taint is removed for this param
                            pass

            return return_is_tainted, reaches_sink, sink_type

        # Unknown function — assume passthrough (conservative for taint, may cause FPs)
        return True, False, ""


# ============================================================================
# 4. BRANCH CONSTRAINT TRACKER — path-sensitive analysis
# ============================================================================

@dataclass
class BranchConstraint:
    """A constraint on a variable from an if/else branch."""
    var_name: str
    constraint_type: str  # 'not_null', 'validated', 'equals', 'not_equals'
    value: str = ""  # for equals/not_equals
    sanitizer: str = ""  # for validated
    line: int = 0
    is_guard: bool = False  # True = this is a guard (if returns/throws, so after = safe)


class BranchConstraintTracker:
    """Tracks branch constraints to suppress false positives.

    Patterns recognized:
      1. `if (x == null) return;` → after if, x is not_null
      2. `if (x == null) throw ...;` → after if, x is not_null
      3. `if (isValid(x)) { sink(x); }` → x is validated inside block
      4. `if (!isValid(x)) throw ...;` → after if, x is validated
      5. `if (x != null && x.length() > 0)` → x is not_null inside block
    """

    # Validation function patterns
    VALIDATION_PATTERNS = {
        "isValid", "validate", "checkValid", "verify", "isSafe",
        "StringUtils.isNumeric", "StringUtils.isAlpha", "StringUtils.isAlphanumeric",
        "NumberUtils.isDigits", "NumberUtils.isCreatable",
        "matches", "isEmpty", "isBlank",
    }

    def __init__(self):
        self.constraints: List[BranchConstraint] = []

    def analyze_branch(self, line: str, line_num: int) -> List[BranchConstraint]:
        """Analyze a single line for branch constraints.

        Returns constraints that are active after this line.
        """
        constraints = []

        # Pattern 1: if (x == null) return/throw
        m = re.match(r'\s*if\s*\(\s*(\w+)\s*==\s*null\s*\)\s*(?:return|throw)', line)
        if m:
            constraints.append(BranchConstraint(
                var_name=m.group(1),
                constraint_type="not_null",
                line=line_num,
                is_guard=True,
            ))

        # Pattern 2: if (x != null) — x is not_null inside the block
        m = re.match(r'\s*if\s*\(\s*(\w+)\s*!=\s*null', line)
        if m:
            constraints.append(BranchConstraint(
                var_name=m.group(1),
                constraint_type="not_null",
                line=line_num,
            ))

        # Pattern 3: if (isValid(x)) — x is validated inside the block
        for val_func in self.VALIDATION_PATTERNS:
            m = re.match(rf'\s*if\s*\(\s*{re.escape(val_func)}\s*\(\s*(\w+)\s*\)', line)
            if m:
                constraints.append(BranchConstraint(
                    var_name=m.group(1),
                    constraint_type="validated",
                    sanitizer=val_func,
                    line=line_num,
                ))

        # Pattern 4: if (!isValid(x)) throw/return — after if, x is validated
        for val_func in self.VALIDATION_PATTERNS:
            m = re.match(rf'\s*if\s*\(\s*!\s*{re.escape(val_func)}\s*\(\s*(\w+)\s*\)\s*\)\s*(?:return|throw)', line)
            if m:
                constraints.append(BranchConstraint(
                    var_name=m.group(1),
                    constraint_type="validated",
                    sanitizer=val_func,
                    line=line_num,
                    is_guard=True,
                ))

        # Pattern 5: if (x == "constant") — x equals constant inside block
        m = re.match(r'\s*if\s*\(\s*(\w+)\s*==\s*["\']([^"\']+)["\']', line)
        if m:
            constraints.append(BranchConstraint(
                var_name=m.group(1),
                constraint_type="equals",
                value=m.group(2),
                line=line_num,
            ))

        # Pattern 6: Optional.isPresent() check
        m = re.match(r'\s*if\s*\(\s*(\w+)\.isPresent\s*\(\s*\)\s*\)', line)
        if m:
            constraints.append(BranchConstraint(
                var_name=m.group(1),
                constraint_type="not_null",
                line=line_num,
            ))

        return constraints

    def is_safe_at_line(self, var_name: str, line: int,
                        constraints: List[BranchConstraint]) -> Tuple[bool, str]:
        """Check if a variable is safe (constrained) at a given line.

        Returns (is_safe, reason).
        """
        for c in constraints:
            if c.var_name != var_name:
                continue
            if c.line >= line:
                continue  # constraint hasn't happened yet
            if c.is_guard:
                # Guard constraint — applies after the if block
                if c.constraint_type == "not_null":
                    return True, f"guarded against null at line {c.line}"
                if c.constraint_type == "validated":
                    return True, f"validated by {c.sanitizer} at line {c.line}"
            else:
                # Block constraint — only applies inside the if block
                # We'd need block scope tracking to be precise
                if c.constraint_type == "validated":
                    return True, f"validated by {c.sanitizer} at line {c.line}"
                if c.constraint_type == "not_null":
                    return True, f"checked non-null at line {c.line}"
        return False, ""


# ============================================================================
# 5. TRACE CACHE — file-hash-based caching for performance
# ============================================================================

class TraceCache:
    """Caches function summaries by file content hash.

    On re-analysis, files that haven't changed are loaded from cache
    instead of being re-parsed.
    """

    def __init__(self, cache_dir: Path):
        self.cache_dir = cache_dir / "trace_cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.index: Dict[str, dict] = {}  # file_path → {hash, summaries}
        self._load_index()

    def _index_file(self) -> Path:
        return self.cache_dir / "index.json"

    def _load_index(self):
        idx = self._index_file()
        if idx.exists():
            try:
                self.index = json.loads(idx.read_text())
            except Exception:
                self.index = {}

    def _save_index(self):
        self._index_file().write_text(json.dumps(self.index, indent=2))

    @staticmethod
    def _file_hash(file_path: Path) -> str:
        try:
            return hashlib.sha256(file_path.read_bytes()).hexdigest()[:32]
        except Exception:
            return ""

    def get_summaries(self, file_path: Path) -> Optional[List[FunctionSummaryV2]]:
        """Get cached summaries for a file, or None if not cached / changed."""
        key = str(file_path)
        entry = self.index.get(key)
        if not entry:
            return None

        current_hash = self._file_hash(file_path)
        if current_hash != entry.get("hash"):
            return None  # file changed

        # Load from cache file
        cache_file = self.cache_dir / f"{current_hash}.json"
        if not cache_file.exists():
            return None

        try:
            data = json.loads(cache_file.read_text())
            return [FunctionSummaryV2.from_dict(s) for s in data.get("summaries", [])]
        except Exception:
            return None

    def put_summaries(self, file_path: Path, summaries: List[FunctionSummaryV2]):
        """Cache summaries for a file."""
        key = str(file_path)
        file_hash = self._file_hash(file_path)
        if not file_hash:
            return

        cache_file = self.cache_dir / f"{file_hash}.json"
        cache_file.write_text(json.dumps({
            "file": key,
            "hash": file_hash,
            "summaries": [s.to_dict() for s in summaries],
        }, indent=2))

        self.index[key] = {
            "hash": file_hash,
            "summary_count": len(summaries),
        }
        self._save_index()

    def invalidate(self, file_path: Optional[Path] = None):
        """Invalidate cache for a file (or all files)."""
        if file_path:
            self.index.pop(str(file_path), None)
        else:
            self.index = {}
            for f in self.cache_dir.glob("*.json"):
                if f.name != "index.json":
                    f.unlink()
        self._save_index()

    def stats(self) -> dict:
        return {
            "cached_files": len(self.index),
            "cache_dir": str(self.cache_dir),
            "size_bytes": sum(f.stat().st_size for f in self.cache_dir.glob("*.json")),
        }


# ============================================================================
# 6. INTERPROCEDURAL TAINT ANALYZER — ties everything together
# ============================================================================

@dataclass
class InterproceduralTaintFlow:
    """A taint flow that may span multiple functions/files."""
    source_file: str
    source_line: int
    source_param: str
    source_type: str
    sink_file: str
    sink_line: int
    sink_function: str
    sink_type: str
    flow_path: List[str] = field(default_factory=list)
    interprocedural: bool = False  # does the flow cross function boundaries?
    sanitized_by: str = ""  # was it sanitized? by what?
    branch_guarded: bool = False  # was it protected by a branch constraint?


class InterproceduralTaintAnalyzer:
    """Full interprocedural taint analysis with:
      - Function summaries (AST-based)
      - Cross-file call resolution
      - Branch constraint tracking
      - Trace caching
    """

    def __init__(self, language: str, cache_dir: Optional[Path] = None):
        self.language = language
        self.call_graph = CallGraphResolver(language)
        self.branch_tracker = BranchConstraintTracker()
        self.cache = TraceCache(cache_dir) if cache_dir else None
        self.sources: List[SourceInfo] = []

    def analyze_repo(self, repo_root: Path, max_files: int = 300) -> List[InterproceduralTaintFlow]:
        """Run full interprocedural taint analysis on a repo.

        Steps:
          1. Build function summaries (with cache)
          2. Discover sources
          3. For each file, track taint from sources to sinks
          4. Use call graph for interprocedural resolution
          5. Use branch constraints to suppress FPs
        """
        # Step 1: Build function summaries
        func_count = self.call_graph.build_from_repo(repo_root, max_files, self.cache)

        # Step 2: Discover sources
        self.sources = discover_sources_in_repo(repo_root, max_files)

        # Step 3: Track taint in each file
        flows: List[InterproceduralTaintFlow] = []
        skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules",
                     ".stca-cache", "build", "dist", "target", "test", "tests"}
        count = 0

        for p in repo_root.rglob("*"):
            if not p.is_file():
                continue
            if any(part in skip_dirs for part in p.parts):
                continue
            if get_language(p) != self.language:
                continue
            if p.stat().st_size > 200000:
                continue

            try:
                flows += self._analyze_file(p, repo_root)
            except Exception:
                pass

            count += 1
            if count >= max_files:
                break

        return flows

    def _analyze_file(self, file_path: Path,
                      repo_root: Optional[Path] = None) -> List[InterproceduralTaintFlow]:
        """Analyze a single file for taint flows."""
        rel = str(file_path.relative_to(repo_root)) if repo_root else str(file_path)
        try:
            source = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return []

        flows: List[InterproceduralTaintFlow] = []
        lines = source.splitlines()

        # Track tainted variables: var_name → (source_line, source_param, source_type)
        tainted_vars: Dict[str, Tuple[int, str, str]] = {}

        # Track active branch constraints
        active_constraints: List[BranchConstraint] = []

        # Initialize with discovered sources
        file_sources = [s for s in self.sources if s.file == rel]
        for src in file_sources:
            if src.param_name:
                tainted_vars[src.param_name] = (src.line, src.param_name, src.source_type)

        # Also check for source functions in the knowledge base
        kb = LANGUAGE_KNOWLEDGE.get(self.language, {})
        source_functions = {k for k, v in kb.items() if v.is_source}
        sink_functions = {k: v for k, v in kb.items() if v.is_sink}
        safe_functions = {k for k, v in kb.items() if v.safe}

        # Scan line by line
        for i, line in enumerate(lines, 1):
            # Collect branch constraints
            new_constraints = self.branch_tracker.analyze_branch(line, i)
            active_constraints.extend(new_constraints)

            # Check for source assignments
            for src_func in source_functions:
                if src_func in line:
                    m = re.match(r'\s*(?:\w+\s+)?(\w+)\s*=\s*.*' + re.escape(src_func), line)
                    if m:
                        tainted_vars[m.group(1)] = (i, m.group(1), "source")

            # Check for taint propagation through assignments
            m = re.match(r'\s*(?:\w+\s+)?(\w+)\s*=\s*(\w+)(?:\.(\w+)\s*\([^)]*\))?', line)
            if m:
                target_var = m.group(1)
                source_var = m.group(2)
                method_name = m.group(3) if m.group(3) else ""

                if source_var in tainted_vars:
                    # Check if method sanitizes
                    if method_name and method_name in safe_functions:
                        pass  # sanitized — don't propagate
                    else:
                        src_line, src_param, src_type = tainted_vars[source_var]
                        tainted_vars[target_var] = (src_line, src_param, src_type)

            # Check for interprocedural calls
            for call_match in re.finditer(r'(\w+(?:\.\w+)*)\s*\(', line):
                func_name = call_match.group(1)
                # v4.15 BUG FIX: Was passing set() (empty) as tainted_arg_positions,
                # which disabled ALL interprocedural taint through user functions.
                # Now we compute which argument positions are actually tainted
                # by checking if any tainted variable appears in each argument.
                call_start = call_match.start()
                call_end = call_match.end()
                args_text = line[call_end:]  # text after the opening paren
                # Find the matching close paren
                paren_depth = 1
                args_end = 0
                for ci, ch in enumerate(args_text):
                    if ch == '(':
                        paren_depth += 1
                    elif ch == ')':
                        paren_depth -= 1
                        if paren_depth == 0:
                            args_end = ci
                            break
                args_text = args_text[:args_end]
                # Split by comma (top-level only)
                arg_parts = []
                current_arg = ""
                pdepth = 0
                for ch in args_text:
                    if ch == '(' or ch == '[' or ch == '{':
                        pdepth += 1
                    elif ch == ')' or ch == ']' or ch == '}':
                        pdepth -= 1
                    elif ch == ',' and pdepth == 0:
                        arg_parts.append(current_arg.strip())
                        current_arg = ""
                        continue
                    current_arg += ch
                if current_arg.strip():
                    arg_parts.append(current_arg.strip())
                # Check which arg positions contain tainted vars
                tainted_positions: Set[int] = set()
                for arg_idx, arg_text in enumerate(arg_parts):
                    for var_name in tainted_vars:
                        if var_name in arg_text:
                            tainted_positions.add(arg_idx)
                            break
                # Try to resolve through call graph with actual tainted positions
                return_tainted, reaches_sink, sink_type = self.call_graph.resolve_taint_through_call(
                    func_name, tainted_positions  # v4.15: actual positions, not empty set
                )

                # Check if any tainted var is in the arguments
                for var_name, (src_line, src_param, src_type) in list(tainted_vars.items()):
                    if var_name in line[line.find(func_name):]:
                        # Check branch constraints — is this var safe?
                        is_safe, reason = self.branch_tracker.is_safe_at_line(
                            var_name, i, active_constraints
                        )
                        if is_safe:
                            continue  # suppressed by branch constraint

                        # Check if it reaches a sink
                        if reaches_sink:
                            flows.append(InterproceduralTaintFlow(
                                source_file=rel,
                                source_line=src_line,
                                source_param=src_param,
                                source_type=src_type,
                                sink_file=rel,
                                sink_line=i,
                                sink_function=func_name,
                                sink_type=sink_type,
                                flow_path=[f"{src_param} → {func_name}"],
                                interprocedural=True,
                                branch_guarded=False,
                            ))

            # Check for direct sink calls with tainted vars
            for sink_name, behavior in sink_functions.items():
                if sink_name not in line:
                    continue

                for var_name, (src_line, src_param, src_type) in list(tainted_vars.items()):
                    if var_name not in line:
                        continue

                    # Check branch constraints
                    is_safe, reason = self.branch_tracker.is_safe_at_line(
                        var_name, i, active_constraints
                    )
                    if is_safe:
                        continue  # suppressed

                    # Check if the sink call actually uses the tainted var
                    sink_pos = line.find(sink_name)
                    if sink_pos >= 0:
                        after_sink = line[sink_pos + len(sink_name):]
                        if var_name in after_sink:
                            flows.append(InterproceduralTaintFlow(
                                source_file=rel,
                                source_line=src_line,
                                source_param=src_param,
                                source_type=src_type,
                                sink_file=rel,
                                sink_line=i,
                                sink_function=sink_name,
                                sink_type=behavior.sink_type,
                                flow_path=[f"{src_param} → {sink_name}"],
                                interprocedural=False,
                                branch_guarded=is_safe,
                            ))

            # Check for sanitization
            for safe_name in safe_functions:
                if safe_name not in line:
                    continue
                m = re.match(r'\s*(?:\w+\s+)?(\w+)\s*=\s*' + re.escape(safe_name) + r'\s*\(\s*(\w+)', line)
                if m:
                    tainted_vars.pop(m.group(2), None)
                    tainted_vars.pop(m.group(1), None)

        return flows

    def stats(self) -> dict:
        return {
            "language": self.language,
            "functions_summarized": len(self.call_graph.summaries),
            "sources_discovered": len(self.sources),
            "cache_stats": self.cache.stats() if self.cache else None,
        }
