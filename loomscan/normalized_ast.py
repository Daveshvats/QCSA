"""Normalized AST layer — language-agnostic code representation.

Maps tree-sitter ASTs (for Python, JS/TS, Go, Java, C, C++) and Python's
built-in ast module to a common NormalizedNode structure. This lets all
business logic detectors work on a single representation regardless of
the source language.

When tree-sitter IS available: full multi-language support (6 languages)
When tree-sitter is NOT available: Python-only via built-in ast module

The NormalizedNode kinds:
  function_def  — function/method declaration
  call          — function/method call
  assignment    — variable assignment
  if            — if/else statement
  class_def     — class/struct/interface declaration
  attribute     — attribute/field access (obj.method)
  decorator     — decorator/annotation (@login_required, @PreAuthorize)
  return        — return statement
  parameter     — function parameter
  string        — string literal
  number        — numeric literal
  identifier    — variable/identifier reference
  block         — code block (function body, if body, etc.)
  other         — anything else (kept for structural completeness)
"""
from __future__ import annotations

import ast as py_ast
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple

_logger = logging.getLogger(__name__.replace('loomscan.', ''))

# Check what's available
try:
    from tree_sitter import Language, Parser, Node as TSNode
    _HAS_TS = True
except ImportError:
    _HAS_TS = False

# Tree-sitter language modules
_TS_LANGUAGE_MODULES = {}
for _mod_name, _lang_key in [
    ("tree_sitter_python", "python"),
    ("tree_sitter_javascript", "javascript"),
    ("tree_sitter_go", "go"),
    ("tree_sitter_java", "java"),
    ("tree_sitter_c", "c"),
    ("tree_sitter_cpp", "cpp"),
    ("tree_sitter_rust", "rust"),
    ("tree_sitter_typescript", "typescript"),
]:
    try:
        _TS_LANGUAGE_MODULES[_lang_key] = __import__(_mod_name)
    except ImportError:
        pass

# v4.6: TypeScript has TWO grammars (typescript and tsx) exposed via
# different functions, not a plain .language() attribute like other modules.
# Map file extensions to the correct grammar function.
_TS_TYPESCRIPT_GRAMMARS = {}
if "typescript" in _TS_LANGUAGE_MODULES:
    _ts_mod = _TS_LANGUAGE_MODULES["typescript"]
    if hasattr(_ts_mod, "language_typescript"):
        _TS_TYPESCRIPT_GRAMMARS["typescript"] = _ts_mod.language_typescript
    if hasattr(_ts_mod, "language_tsx"):
        _TS_TYPESCRIPT_GRAMMARS["tsx"] = _ts_mod.language_tsx


# Language detection from file extension
LANGUAGE_EXTENSIONS = {
    ".py": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "tsx",
    ".go": "go",
    ".java": "java",
    ".c": "c", ".h": "c",
    ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp", ".hxx": "cpp",
    ".rs": "rust",
}

# Tree-sitter node type → normalized kind, per language
# Each language has different tree-sitter grammar node names
LANGUAGE_NODE_MAPS: Dict[str, Dict[str, str]] = {
    "python": {
        "function_definition": "function_def",
        "call": "call",
        "assignment": "assignment",
        "augmented_assignment": "assignment",
        "if_statement": "if",
        "class_definition": "class_def",
        "attribute": "attribute",
        "decorator": "decorator",
        "return_statement": "return",
        "identifier": "identifier",
        "string": "string",
        "integer": "number",
        "float": "number",
        "block": "block",
        "parameters": "parameters",
        "argument_list": "argument_list",
    },
    "javascript": {
        "function_declaration": "function_def",
        "method_definition": "function_def",
        "arrow_function": "function_def",
        "call_expression": "call",
        "assignment_expression": "assignment",
        "if_statement": "if",
        "class_declaration": "class_def",
        "member_expression": "attribute",
        "decorator": "decorator",
        "return_statement": "return",
        "identifier": "identifier",
        "string": "string",
        "number": "number",
        "statement_block": "block",
        "formal_parameters": "parameters",
        "arguments": "argument_list",
    },
    "typescript": {
        "function_declaration": "function_def",
        "method_definition": "function_def",
        "arrow_function": "function_def",
        "call_expression": "call",
        "assignment_expression": "assignment",
        "if_statement": "if",
        "class_declaration": "class_def",
        "member_expression": "attribute",
        "decorator": "decorator",
        "return_statement": "return",
        "identifier": "identifier",
        "string": "string",
        "number": "number",
        "statement_block": "block",
        "formal_parameters": "parameters",
        "arguments": "argument_list",
    },
    "go": {
        "function_declaration": "function_def",
        "method_declaration": "function_def",
        "call_expression": "call",
        "assignment_statement": "assignment",
        "short_var_declaration": "assignment",
        "if_statement": "if",
        "type_declaration": "class_def",
        "selector_expression": "attribute",
        "return_statement": "return",
        "identifier": "identifier",
        "interpreted_string_literal": "string",
        "int_literal": "number",
        "float_literal": "number",
        "block": "block",
        "parameter_list": "parameters",
        "argument_list": "argument_list",
    },
    "java": {
        "method_declaration": "function_def",
        "constructor_declaration": "function_def",
        "method_invocation": "call",
        "assignment_expression": "assignment",
        "if_statement": "if",
        "class_declaration": "class_def",
        "field_access": "attribute",
        "annotation": "decorator",
        "return_statement": "return",
        "identifier": "identifier",
        "string_literal": "string",
        "decimal_integer_literal": "number",
        "decimal_floating_point_literal": "number",
        "block": "block",
        "formal_parameters": "parameters",
        "argument_list": "argument_list",
    },
    "c": {
        "function_definition": "function_def",
        "call_expression": "call",
        "assignment_expression": "assignment",
        "if_statement": "if",
        "struct_specifier": "class_def",
        "member_expression": "attribute",
        "return_statement": "return",
        "identifier": "identifier",
        "string_literal": "string",
        "number_literal": "number",
        "compound_statement": "block",
        "parameter_declaration": "parameters",
        "argument_list": "argument_list",
    },
    "cpp": {
        "function_definition": "function_def",
        "call_expression": "call",
        "assignment_expression": "assignment",
        "if_statement": "if",
        "class_specifier": "class_def",
        "struct_specifier": "class_def",
        "member_expression": "attribute",
        "field_expression": "attribute",
        "return_statement": "return",
        "identifier": "identifier",
        "string_literal": "string",
        "number_literal": "number",
        "compound_statement": "block",
        "parameter_declaration": "parameters",
        "argument_list": "argument_list",
    },
    "rust": {
        "function_item": "function_def",
        "call_expression": "call",
        "assignment_expression": "assignment",
        "compound_assignment_expr": "assignment",
        "let_declaration": "assignment",
        "if_expression": "if",
        "match_expression": "if",
        "struct_item": "class_def",
        "enum_item": "class_def",
        "trait_item": "class_def",
        "impl_item": "class_def",
        "field_expression": "attribute",
        "return_expression": "return",
        "identifier": "identifier",
        "string_literal": "string",
        "integer_literal": "number",
        "float_literal": "number",
        "block": "block",
        "parameters": "parameters",
        "arguments": "argument_list",
    },
}


@dataclass
class NormalizedNode:
    """A language-agnostic AST node.

    All business logic detectors operate on this representation,
    not on language-specific ASTs.
    """
    kind: str  # 'function_def' | 'call' | 'assignment' | 'if' | etc.
    name: str  # function name, variable name, method name, etc.
    children: List["NormalizedNode"] = field(default_factory=list)
    line: int = 0
    col: int = 0
    file: str = ""
    language: str = ""  # 'python' | 'javascript' | 'go' | etc.
    raw_kind: str = ""  # original tree-sitter node type (for debugging)
    # Extra metadata for specific kinds
    text: str = ""  # source text of this node (for string/number literals)
    # For 'call': the arguments
    args: List[str] = field(default_factory=list)
    # For 'assignment': the target variable
    target: str = ""
    # For 'attribute': the object expression and attribute name
    obj: str = ""
    attr: str = ""
    # For 'function_def': the parameters
    params: List[str] = field(default_factory=list)
    # For 'decorator': the decorator name
    decorator_name: str = ""
    # For 'if': the condition text
    condition: str = ""
    # For 'class_def': whether it's a struct/interface
    is_struct: bool = False
    # Parent reference (for walking up)
    parent: Optional["NormalizedNode"] = None

    def walk(self) -> List["NormalizedNode"]:
        """Walk this node and all descendants in pre-order."""
        result = [self]
        for child in self.children:
            result.extend(child.walk())
        return result

    def find_all(self, kind: str) -> List["NormalizedNode"]:
        """Find all descendant nodes of a specific kind."""
        return [n for n in self.walk() if n.kind == kind]

    def find_calls(self) -> List["NormalizedNode"]:
        """Find all function/method calls in this subtree."""
        return self.find_all("call")

    def find_function_defs(self) -> List["NormalizedNode"]:
        """Find all function/method definitions in this subtree."""
        return self.find_all("function_def")

    def find_class_defs(self) -> List["NormalizedNode"]:
        """Find all class/struct definitions in this subtree."""
        return self.find_all("class_def")

    def find_assignments(self) -> List["NormalizedNode"]:
        """Find all assignments in this subtree."""
        return self.find_all("assignment")

    def find_decorators(self) -> List["NormalizedNode"]:
        """Find all decorators/annotations in this subtree."""
        return self.find_all("decorator")


def get_language(file_path: Path) -> str:
    """Detect the programming language from file extension."""
    ext = file_path.suffix.lower()
    return LANGUAGE_EXTENSIONS.get(ext, "unknown")


def is_supported(file_path: Path) -> bool:
    """Check if we can parse this file."""
    lang = get_language(file_path)
    if lang == "python":
        return True  # always supported via built-in ast
    if lang in _TS_LANGUAGE_MODULES:
        return True  # supported via tree-sitter
    # v4.6: TSX uses the typescript module's language_tsx() grammar
    if lang == "tsx" and "typescript" in _TS_LANGUAGE_MODULES:
        return True
    return False


# v4.3: Track unsupported languages for startup-time warning.
# v4.6: TSX is supported via the typescript module, not separately.
_UNSUPPORTED_ADVERTISED_LANGS: Set[str] = set()
for _ext, _lang in LANGUAGE_EXTENSIONS.items():
    if _lang == "python":
        continue
    if _lang in _TS_LANGUAGE_MODULES:
        continue
    # TSX is supported via the typescript module
    if _lang == "tsx" and "typescript" in _TS_LANGUAGE_MODULES:
        continue
    _UNSUPPORTED_ADVERTISED_LANGS.add(_lang)

# Track files that were skipped due to missing language support
_SKIPPED_FILES: List[str] = []
_SKIPPED_LANG_COUNTS: Dict[str, int] = {}


def get_unsupported_languages() -> Set[str]:
    """Return the set of languages advertised but not actually parseable.

    v4.3: This lets the orchestrator surface a warning like:
        "WARNING: 47 TypeScript files skipped — tree_sitter_typescript not installed.
         Install with: pip install tree_sitter_typescript"
    """
    return set(_UNSUPPORTED_ADVERTISED_LANGS)


def record_skipped_file(file_path: Path) -> None:
    """Record that a file was skipped due to missing language support.

    Called by parse_file() when it returns None for an advertised-but-unsupported
    language. The orchestrator can then surface these counts in the report.
    """
    lang = get_language(file_path)
    if lang in _UNSUPPORTED_ADVERTISED_LANGS:
        _SKIPPED_FILES.append(str(file_path))
        _SKIPPED_LANG_COUNTS[lang] = _SKIPPED_LANG_COUNTS.get(lang, 0) + 1


def get_skipped_file_stats() -> Dict[str, int]:
    """Return a dict of {language: count} for files skipped due to missing support."""
    return dict(_SKIPPED_LANG_COUNTS)


def reset_skipped_file_stats() -> None:
    """Reset the skipped-file tracking (call at the start of each scan)."""
    _SKIPPED_FILES.clear()
    _SKIPPED_LANG_COUNTS.clear()


def parse_file(file_path: Path) -> Optional[NormalizedNode]:
    """Parse a source file into a NormalizedNode tree.

    Uses tree-sitter if available (for all supported languages).
    Falls back to Python's built-in ast module for Python files
    when tree-sitter is not installed.

    v4.3: If the language is advertised in LANGUAGE_EXTENSIONS but the
    tree-sitter module is not installed, records the skip via
    record_skipped_file() so the orchestrator can surface a warning.
    """
    lang = get_language(file_path)
    if lang == "unknown":
        return None

    # v4.3: Record files skipped due to missing language support
    # v4.6: TSX is supported via the typescript module
    # v4.31: Log a warning when parse fails for non-Python (was silent)
    if lang != "python" and lang not in _TS_LANGUAGE_MODULES:
        if not (lang == "tsx" and "typescript" in _TS_LANGUAGE_MODULES):
            record_skipped_file(file_path)
            _logger.warning("parse_file: %s (lang=%s) skipped — tree_sitter_%s not installed. "
                           "Install with: pip install tree_sitter_%s",
                           file_path, lang, lang, lang)
            return None

    try:
        source = file_path.read_text(encoding="utf-8")
    except Exception:
        return None

    rel_path = str(file_path)

    # Try tree-sitter first (for all languages including Python)
    if _HAS_TS and (lang in _TS_LANGUAGE_MODULES or
                     (lang == "tsx" and "typescript" in _TS_LANGUAGE_MODULES)):
        return _parse_with_tree_sitter(source, lang, rel_path)

    # Fall back to Python's built-in ast for Python files
    if lang == "python":
        return _parse_python_with_ast(source, rel_path)

    return None


def _parse_with_tree_sitter(source: str, language: str,
                              file_path: str) -> Optional[NormalizedNode]:
    """Parse source code using tree-sitter and normalize the AST."""
    try:
        # v4.6: TypeScript has separate grammar functions for TS and TSX.
        # Other languages expose a plain .language() attribute.
        if language in ("typescript", "tsx") and language in _TS_TYPESCRIPT_GRAMMARS:
            grammar_fn = _TS_TYPESCRIPT_GRAMMARS[language]
            ts_lang = Language(grammar_fn())
        else:
            lang_mod = _TS_LANGUAGE_MODULES[language]
            ts_lang = Language(lang_mod.language())
        parser = Parser(ts_lang)
        tree = parser.parse(source.encode("utf-8"))
        # v4.6: Get the correct node map for this language.
        # For TSX, use the typescript node map (same grammar structure).
        if language == "tsx":
            node_map = LANGUAGE_NODE_MAPS.get("typescript", {})
        else:
            node_map = LANGUAGE_NODE_MAPS.get(language, {})
        root = _normalize_ts_node(tree.root_node, source, language, file_path, node_map)
        # Post-process: associate decorators with their adjacent function/class defs
        _associate_decorators(root)
        return root
    except Exception:
        return None


def _associate_decorators(node: NormalizedNode) -> None:
    """Associate decorator nodes with their adjacent function/class definitions.

    In tree-sitter, decorators are siblings of function_def (inside
    decorated_definition), not children. This function moves them to be
    children of the function_def so detectors can find them.
    """
    # Walk all nodes and find decorated_definition patterns
    for n in node.walk():
        if n.kind == "other" and n.raw_kind == "decorated_definition":
            # Find decorator and function_def children
            decorators = [c for c in n.children if c.kind == "decorator"]
            func_defs = [c for c in n.children if c.kind in ("function_def", "class_def")]
            # Move decorators to be children of the function_def
            for func_def in func_defs:
                for dec in decorators:
                    dec.parent = func_def
                    func_def.children.insert(0, dec)
                # Remove decorators from the decorated_definition node
                n.children = [c for c in n.children if c.kind != "decorator"]

    # Also check for direct decorator → function_def sibling patterns
    # (some languages don't use decorated_definition)
    for n in node.walk():
        if n.kind in ("module", "block", "class_def"):
            children = n.children
            new_children = []
            i = 0
            while i < len(children):
                if children[i].kind == "decorator" and \
                   i + 1 < len(children) and \
                   children[i + 1].kind in ("function_def", "class_def"):
                    # Associate this decorator with the next function_def
                    dec = children[i]
                    func = children[i + 1]
                    dec.parent = func
                    func.children.insert(0, dec)
                    new_children.append(func)
                    i += 2
                else:
                    new_children.append(children[i])
                    i += 1
            n.children = new_children


def _normalize_ts_node(ts_node: TSNode, source: str, language: str,
                        file_path: str, node_map: Dict[str, str],
                        parent: Optional[NormalizedNode] = None) -> NormalizedNode:
    """Convert a tree-sitter node to a NormalizedNode."""
    raw_kind = ts_node.type
    kind = node_map.get(raw_kind, "other")

    # Extract name based on node type
    name = ""
    text = _get_ts_text(ts_node, source)

    # Extract name for function definitions, calls, etc.
    if kind == "function_def":
        name = _get_ts_function_name(ts_node, source)
    elif kind == "call":
        name = _get_ts_call_name(ts_node, source)
    elif kind == "class_def":
        name = _get_ts_class_name(ts_node, source)
    elif kind == "decorator":
        name = text.strip("@").split("(")[0].strip()
    elif kind == "identifier":
        name = text

    node = NormalizedNode(
        kind=kind,
        name=name,
        line=ts_node.start_point[0] + 1,  # tree-sitter is 0-indexed
        col=ts_node.start_point[1],
        file=file_path,
        language=language,
        raw_kind=raw_kind,
        text=text[:200],  # limit text length
    )

    # Extract specific metadata
    if kind == "call":
        node.args = _get_ts_call_args(ts_node, source)
        # v4.4: For Java/C++ method_invocation, also extract obj and attr
        # so typestate detectors (which check node.kind == "attribute" with
        # node.obj and node.attr) can work. Java's method_invocation comes
        # through as a "call" node but the receiver object is in the
        # "object" field — we synthesize the attribute info here.
        if language in ("java", "cpp") and raw_kind in ("method_invocation",
                                                          "method_call",
                                                          "member_call_expression"):
            obj_node = ts_node.child_by_field_name("object")
            if obj_node:
                node.obj = _get_ts_text(obj_node, source).strip()
                node.attr = name  # the method name
    elif kind == "assignment":
        node.target = _get_ts_assignment_target(ts_node, source)
    elif kind == "attribute":
        node.obj, node.attr = _get_ts_attribute_parts(ts_node, source)
    elif kind == "function_def":
        node.params = _get_ts_function_params(ts_node, source)
    elif kind == "if":
        node.condition = _get_ts_if_condition(ts_node, source)
    elif kind == "class_def":
        node.is_struct = "struct" in raw_kind
    elif kind == "decorator":
        node.decorator_name = name

    # Recurse into children
    for i in range(ts_node.child_count):
        child = ts_node.child(i)
        if child and not child.is_extra:
            child_node = _normalize_ts_node(child, source, language, file_path,
                                              node_map, node)
            child_node.parent = node
            node.children.append(child_node)

    return node


def _get_ts_text(ts_node: TSNode, source: str) -> str:
    """Get the source text of a tree-sitter node."""
    try:
        start = ts_node.start_byte
        end = ts_node.end_byte
        return source[start:end]
    except Exception:
        return ""


def _get_ts_function_name(ts_node: TSNode, source: str) -> str:
    """Extract function name from a tree-sitter function definition node.

    v4.25: Fixed pointer-returning C/C++ functions — for `char *foo(int a)`,
    the declarator chain is: function_definition → function_declarator →
    pointer_declarator → identifier. Was returning the full text including
    the pointer and params. Now properly unwraps all declarator levels.
    """
    # v4.25: Helper to unwrap nested declarators (pointer_declarator,
    # function_declarator, array_declarator, etc.) down to the identifier.
    def _unwrap_declarator(node):
        """Recursively unwrap declarator nodes until we find an identifier."""
        if node is None:
            return ""
        if node.type == "identifier":
            return _get_ts_text(node, source).strip()
        # Try the "declarator" field (covers function_declarator, pointer_declarator)
        inner = node.child_by_field_name("declarator")
        if inner:
            return _unwrap_declarator(inner)
        # Some grammars nest differently — try first identifier child
        for i in range(node.child_count):
            child = node.child(i)
            if child and child.type == "identifier":
                return _get_ts_text(child, source).strip()
        return ""

    # C/C++: try declarator field (may be function_declarator wrapping pointer_declarator)
    decl_node = ts_node.child_by_field_name("declarator")
    if decl_node:
        name = _unwrap_declarator(decl_node)
        if name:
            return name
    # Try "name" field (Java/JS/Go/Python/Rust)
    name_node = ts_node.child_by_field_name("name")
    if name_node:
        return _get_ts_text(name_node, source).strip()
    # v4.25: C/C++ fallback — look for function_declarator child and unwrap
    for i in range(ts_node.child_count):
        child = ts_node.child(i)
        if child and child.type == "function_declarator":
            name = _unwrap_declarator(child)
            if name:
                return name
    # Fall back to first identifier child (skip return types)
    for i in range(ts_node.child_count):
        child = ts_node.child(i)
        if child and child.type in ("identifier", "property_identifier", "type_identifier"):
            txt = _get_ts_text(child, source).strip()
            if txt in ("int", "void", "char", "float", "double", "long", "short",
                        "unsigned", "signed", "bool", "size_t", "auto", "static",
                        "const", "struct", "enum", "union", "extern", "inline"):
                continue
            return txt
    return ""


def _get_ts_call_name(ts_node: TSNode, source: str) -> str:
    """Extract the called function/method name from a tree-sitter call node.

    v4.25: Actually fixed Rust :: handling (v4.24 comment lied — said it
    split on :: but returned the full path verbatim). Now:
    - For Rust paths like `std::process::Command::new`, returns the LAST
      2 segments joined by :: (e.g. "Command::new") so it matches the
      sink dict key. Falls back to last segment if only 1 segment.
    - For JS/Java dotted calls (obj.method), returns just the method name.
    - For simple calls (func), returns the name as-is.
    """
    func_node = ts_node.child_by_field_name("function")
    if func_node:
        text = _get_ts_text(func_node, source).strip()
        # v4.25: Rust path expressions — split on :: and return last 2 segments
        if "::" in text:
            parts = text.split("::")
            # Return last 2 segments (e.g. "Command::new" from "std::process::Command::new")
            if len(parts) >= 2:
                return "::".join(parts[-2:])
            return parts[-1]
        # For method calls (obj.method), extract just the method name
        if "." in text:
            return text.split(".")[-1]
        return text
    # Fallback: for Java method_invocation, try to find the name field
    name_node = ts_node.child_by_field_name("name")
    if name_node:
        return _get_ts_text(name_node, source).strip()
    # Fallback: look for first identifier child
    for i in range(ts_node.child_count):
        child = ts_node.child(i)
        if child and child.type in ("identifier", "property_identifier",
                                      "type_identifier", "field_identifier"):
            return _get_ts_text(child, source).strip()
    return ""


def _get_ts_call_args(ts_node: TSNode, source: str) -> List[str]:
    """Extract argument names from a tree-sitter call node."""
    args_node = ts_node.child_by_field_name("arguments")
    if not args_node:
        return []
    args = []
    for i in range(args_node.child_count):
        child = args_node.child(i)
        if child and child.type not in ("(", ")", ",", "[", "]"):
            args.append(_get_ts_text(child, source).strip()[:50])
    return args


def _get_ts_class_name(ts_node: TSNode, source: str) -> str:
    """Extract class/struct name from a tree-sitter class definition node."""
    name_node = ts_node.child_by_field_name("name")
    if name_node:
        return _get_ts_text(name_node, source).strip()
    return ""


def _get_ts_assignment_target(ts_node: TSNode, source: str) -> str:
    """Extract the target variable name from an assignment node."""
    left = ts_node.child_by_field_name("left")
    if left:
        return _get_ts_text(left, source).strip()
    pattern = ts_node.child_by_field_name("pattern")
    if pattern:
        return _get_ts_text(pattern, source).strip()
    name = ts_node.child_by_field_name("name")
    if name:
        return _get_ts_text(name, source).strip()
    return ""


def _get_ts_attribute_parts(ts_node: TSNode, source: str) -> Tuple[str, str]:
    """Extract (object, attribute) from an attribute/member access node."""
    # Different languages use different field names
    obj_node = ts_node.child_by_field_name("object") or ts_node.child_by_field_name("operand")
    prop_node = (ts_node.child_by_field_name("property") or
                 ts_node.child_by_field_name("field") or
                 ts_node.child_by_field_name("attribute"))
    obj = _get_ts_text(obj_node, source).strip() if obj_node else ""
    attr = _get_ts_text(prop_node, source).strip() if prop_node else ""
    return obj, attr


def _get_ts_function_params(ts_node: TSNode, source: str) -> List[str]:
    """Extract parameter names from a tree-sitter function definition.

    v4.25: Fixed C/C++ pointer-returning functions — for `char *foo(int a)`,
    the parameter_list is inside function_declarator which is inside
    pointer_declarator. Now recursively searches for function_declarator.
    """
    params_node = ts_node.child_by_field_name("parameters")
    if not params_node:
        # v4.25: Recursively search for function_declarator (may be nested
        # inside pointer_declarator for pointer-returning functions)
        def _find_function_declarator(node):
            if node is None: return None
            if node.type == "function_declarator": return node
            # Try declarator field
            inner = node.child_by_field_name("declarator")
            if inner:
                r = _find_function_declarator(inner)
                if r: return r
            # Try children
            for i in range(node.child_count):
                child = node.child(i)
                if child and not child.is_extra:
                    r = _find_function_declarator(child)
                    if r: return r
            return None

        fd = _find_function_declarator(ts_node)
        if fd:
            params_node = fd.child_by_field_name("parameters")
    if not params_node:
        return []
    params = []
    for i in range(params_node.child_count):
        child = params_node.child(i)
        if child and child.type not in ("(", ")", ",", "[", "]", ";"):
            # Try "name" field (Python/JS/Go/Java)
            name_node = child.child_by_field_name("name") if hasattr(child, "child_by_field_name") else None
            if name_node:
                params.append(_get_ts_text(name_node, source).strip())
            else:
                # v4.24: C/C++ — try "declarator" field (may be pointer_declarator)
                decl = child.child_by_field_name("declarator")
                if decl:
                    if decl.type == "pointer_declarator":
                        inner = decl.child_by_field_name("declarator")
                        if inner:
                            params.append(_get_ts_text(inner, source).strip())
                    elif decl.type == "identifier":
                        params.append(_get_ts_text(decl, source).strip())
                    else:
                        text = _get_ts_text(decl, source).strip()
                        if text and text not in ("(", ")", ","):
                            params.append(text)
                else:
                    text = _get_ts_text(child, source).strip()
                    if text and text not in ("(", ")", ","):
                        # Strip type annotation for Rust
                        if ":" in text and not text.startswith(":"):
                            text = text.split(":")[0].strip()
                        params.append(text)
    return params


def _get_ts_if_condition(ts_node: TSNode, source: str) -> str:
    """Extract the condition text from an if statement."""
    cond_node = ts_node.child_by_field_name("condition")
    if cond_node:
        return _get_ts_text(cond_node, source).strip()[:200]
    return ""


# === Python fallback (when tree-sitter is not available) ===

def _parse_python_with_ast(source: str, file_path: str) -> Optional[NormalizedNode]:
    """Parse Python source using the built-in ast module.

    This is a fallback when tree-sitter is not installed. Only works for Python.
    """
    try:
        tree = py_ast.parse(source)
    except SyntaxError:
        return None

    root = NormalizedNode(
        kind="module",
        name="<module>",
        line=1,
        file=file_path,
        language="python",
        raw_kind="Module",
    )

    for child in py_ast.iter_child_nodes(tree):
        normalized = _normalize_py_node(child, file_path, root)
        if normalized:
            normalized.parent = root
            root.children.append(normalized)

    return root


def _normalize_py_node(node: py_ast.AST, file_path: str,
                        parent: Optional[NormalizedNode] = None) -> Optional[NormalizedNode]:
    """Convert a Python ast node to a NormalizedNode."""
    kind = "other"
    name = ""
    line = getattr(node, "lineno", 0)
    col = getattr(node, "col_offset", 0)

    if isinstance(node, (py_ast.FunctionDef, py_ast.AsyncFunctionDef)):
        kind = "function_def"
        name = node.name
    elif isinstance(node, py_ast.Call):
        kind = "call"
        if isinstance(node.func, py_ast.Name):
            name = node.func.id
        elif isinstance(node.func, py_ast.Attribute):
            name = node.func.attr
    elif isinstance(node, py_ast.Assign):
        kind = "assignment"
        if node.targets and isinstance(node.targets[0], py_ast.Name):
            name = node.targets[0].id
    elif isinstance(node, py_ast.AugAssign):
        kind = "assignment"
        if isinstance(node.target, py_ast.Name):
            name = node.target.id
        elif isinstance(node.target, py_ast.Attribute):
            name = node.target.attr
    elif isinstance(node, py_ast.If):
        kind = "if"
        try:
            name = py_ast.unparse(node.test)[:200]
        except Exception:
            name = ""
    elif isinstance(node, py_ast.ClassDef):
        kind = "class_def"
        name = node.name
    elif isinstance(node, py_ast.Attribute):
        kind = "attribute"
        name = node.attr
        if isinstance(node.value, py_ast.Name):
            name = f"{node.value.id}.{node.attr}"
    elif isinstance(node, py_ast.Return):
        kind = "return"
    elif isinstance(node, py_ast.Name):
        kind = "identifier"
        name = node.id
    elif isinstance(node, py_ast.Constant):
        if isinstance(node.value, str):
            kind = "string"
        elif isinstance(node.value, (int, float)):
            kind = "number"
        name = repr(node.value)[:50]
    elif isinstance(node, (py_ast.Module,)):
        kind = "module"

    norm = NormalizedNode(
        kind=kind,
        name=name,
        line=line,
        col=col,
        file=file_path,
        language="python",
        raw_kind=type(node).__name__,
    )

    # Extract specific metadata
    if kind == "call":
        norm.args = []
        for arg in getattr(node, "args", []):
            try:
                norm.args.append(py_ast.unparse(arg)[:50])
            except Exception:
                norm.args.append("<expr>")
    elif kind == "assignment":
        if hasattr(node, "targets") and node.targets:
            if isinstance(node.targets[0], py_ast.Name):
                norm.target = node.targets[0].id
            elif isinstance(node.targets[0], py_ast.Attribute):
                norm.target = node.targets[0].attr
                if isinstance(node.targets[0].value, py_ast.Name):
                    norm.obj = node.targets[0].value.id
        elif hasattr(node, "target"):  # AugAssign
            if isinstance(node.target, py_ast.Name):
                norm.target = node.target.id
            elif isinstance(node.target, py_ast.Attribute):
                norm.target = node.target.attr
                if isinstance(node.target.value, py_ast.Name):
                    norm.obj = node.target.value.id
        # Also store the full text for reentrancy detection
        try:
            norm.text = py_ast.unparse(node)[:200]
        except Exception:
            pass
    elif kind == "attribute":
        if isinstance(node, py_ast.Attribute):
            if isinstance(node.value, py_ast.Name):
                norm.obj = node.value.id
            norm.attr = node.attr
    elif kind == "function_def":
        norm.params = [arg.arg for arg in node.args.args]
    elif kind == "if":
        try:
            norm.condition = py_ast.unparse(node.test)[:200]
        except Exception:
            pass
    elif kind == "class_def":
        norm.is_struct = False

    # Handle decorators on functions/classes
    if isinstance(node, (py_ast.FunctionDef, py_ast.ClassDef)):
        for dec in node.decorator_list:
            dec_name = ""
            if isinstance(dec, py_ast.Name):
                dec_name = dec.id
            elif isinstance(dec, py_ast.Attribute):
                dec_name = dec.attr
            elif isinstance(dec, py_ast.Call):
                if isinstance(dec.func, py_ast.Name):
                    dec_name = dec.func.id
                elif isinstance(dec.func, py_ast.Attribute):
                    dec_name = dec.func.attr
            if dec_name:
                dec_node = NormalizedNode(
                    kind="decorator",
                    name=dec_name,
                    decorator_name=dec_name,
                    line=getattr(dec, "lineno", line),
                    file=file_path,
                    language="python",
                    parent=norm,
                )
                norm.children.append(dec_node)

    # Recurse into children
    for child in py_ast.iter_child_nodes(node):
        # Skip docstrings (they're Constants that are the first statement)
        child_norm = _normalize_py_node(child, file_path, norm)
        if child_norm:
            child_norm.parent = norm
            norm.children.append(child_norm)

    return norm
