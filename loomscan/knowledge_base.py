"""Builtin function behavior database — inspired by Kunlun-M.

Kunlun-M (https://github.com/LoRexxar/Kunlun-M) maintains a curated database
of builtin/library function behavior per language so that the static taint
analyzer knows, without re-analyzing a function body:

  * Which argument indices flow to the return value (``passthrough``).
  * Whether the function is a known sanitizer (``safe=True``).
  * Whether the function is a taint source (``is_source=True``).
  * Whether the function is a sink, and what kind (``is_sink=True`` +
    ``sink_type``).

This module extracts and substantially expands that concept into a
standalone, dependency-free knowledge base. It is the single source of
truth consulted by the interprocedural taint tracker, the rule compiler,
and the LLM verifier whenever a call site needs to be classified.

The schema is deliberately tiny so it can be serialized, diffed, and
extended by users without touching analyzer code. Each entry is a
``FunctionBehavior`` dataclass; the database itself is a plain
``Dict[str, Dict[str, FunctionBehavior]]`` keyed by language then by
fully-qualified (or short) function name.

Lookup policy (see ``lookup_function``):
  1. Try an exact match on the supplied name (e.g.
     ``"StringEscapeUtils.escapeHtml4"``).
  2. Fall back to the short name (everything after the last dot, e.g.
     ``"escapeHtml4"``).

This dual lookup lets the analyzer pass either the dotted form produced
by a tree-sitter AST (``obj.method`` → ``obj.method``) or the bare
attribute name (``method``) and still resolve the same entry.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


# ============================================================================
# Schema
# ============================================================================

@dataclass
class FunctionBehavior:
    """Behavior of a builtin/library function for taint analysis.

    Attributes:
        passthrough: Indices of arguments that propagate taint to the
            return value. ``[0]`` means "the receiver/first argument
            flows to the result" (e.g. ``str.toUpperCase()``). ``[1]``
            means the second argument flows through (e.g. C ``strcpy``
            returns its ``dst`` argument, which is argument 1 in
            0-indexed positional terms after the receiver). An empty
            list means the function does not propagate taint via its
            return value.
        safe: ``True`` if the function is a known sanitizer/validator.
            Calls to safe functions break taint chains (the result is
            considered clean). Some safe functions (e.g.
            ``URLEncoder.encode``) also have ``passthrough=[0]`` because
            they conceptually transform their input, but the output is
            safe to use in a sink.
        is_source: ``True`` if the function returns attacker-controlled
            data (e.g. ``request.getParameter``). Sources with
            ``passthrough=[0]`` also propagate taint from the source
            itself — useful when the receiver carries request context.
        is_sink: ``True`` if the function is a dangerous sink.
        sink_type: When ``is_sink`` is set, a short label identifying
            the vulnerability class — e.g. ``"command_injection"``,
            ``"sql_injection"``, ``"xss"``, ``"deserialization"``,
            ``"reflection"``, ``"open_redirect"``, ``"code_injection"``,
            ``"buffer_overflow"``, ``"path_traversal"``,
            ``"header_injection"``.
        notes: Free-form documentation for humans debugging the rule
            set. Never used by the analyzer.
    """
    passthrough: List[int] = field(default_factory=list)
    safe: bool = False
    is_source: bool = False
    is_sink: bool = False
    sink_type: str = ""
    notes: str = ""


# ============================================================================
# Knowledge base
# ============================================================================
#
# Each language section is organized into clearly commented groups:
#   - String passthroughs (transformations that propagate taint)
#   - Safe sanitizers/validators (break taint chains)
#   - Safe non-passthrough queries (length, equals, contains, ...)
#   - Sources (attacker-controlled inputs)
#   - Sinks (dangerous call sites)
#
# Counts:
#   java       → 114
#   python     → 60
#   javascript → 56
#   go         → 31
#   cpp        → 25
# ============================================================================

LANGUAGE_KNOWLEDGE: Dict[str, Dict[str, FunctionBehavior]] = {

    # ======================================================================
    # Java (114)
    # ======================================================================
    "java": {
        # ---- String passthroughs (25) ------------------------------------
        "toUpperCase":     FunctionBehavior(passthrough=[0], notes="java.lang.String"),
        "toLowerCase":     FunctionBehavior(passthrough=[0], notes="java.lang.String"),
        "trim":            FunctionBehavior(passthrough=[0], notes="java.lang.String"),
        "strip":           FunctionBehavior(passthrough=[0], notes="Java 11+ String"),
        "stripLeading":    FunctionBehavior(passthrough=[0], notes="Java 11+ String"),
        "stripTrailing":   FunctionBehavior(passthrough=[0], notes="Java 11+ String"),
        "replace":         FunctionBehavior(passthrough=[0], notes="java.lang.String"),
        "replaceAll":      FunctionBehavior(passthrough=[0], notes="regex replace; taint propagates"),
        "replaceFirst":    FunctionBehavior(passthrough=[0], notes="regex replace; taint propagates"),
        "substring":       FunctionBehavior(passthrough=[0], notes="java.lang.String"),
        "subSequence":     FunctionBehavior(passthrough=[0], notes="java.lang.String"),
        "toString":        FunctionBehavior(passthrough=[0], notes="Object.toString"),
        "valueOf":         FunctionBehavior(passthrough=[0], notes="String.valueOf"),
        "concat":          FunctionBehavior(passthrough=[0], notes="java.lang.String"),
        "format":          FunctionBehavior(passthrough=[0], notes="String.format — format string itself flows through"),
        "intern":          FunctionBehavior(passthrough=[0], notes="java.lang.String"),
        "toCharArray":     FunctionBehavior(passthrough=[0], notes="java.lang.String"),
        "getBytes":        FunctionBehavior(passthrough=[0], notes="java.lang.String"),
        "split":           FunctionBehavior(passthrough=[0], notes="java.lang.String"),
        "repeat":          FunctionBehavior(passthrough=[0], notes="Java 11+ String"),
        "lines":           FunctionBehavior(passthrough=[0], notes="Java 11+ String"),
        "indent":          FunctionBehavior(passthrough=[0], notes="Java 12+ String"),
        "chars":           FunctionBehavior(passthrough=[0], notes="java.lang.String"),
        "codePoints":      FunctionBehavior(passthrough=[0], notes="java.lang.String"),
        "copyValueOf":     FunctionBehavior(passthrough=[0], notes="String.copyValueOf"),

        # ---- Safe non-passthrough queries (20) ---------------------------
        "length":              FunctionBehavior(safe=True, notes="returns int — no taint"),
        "charAt":              FunctionBehavior(safe=True, notes="returns char — no taint"),
        "isEmpty":             FunctionBehavior(safe=True, notes="returns boolean"),
        "isBlank":             FunctionBehavior(safe=True, notes="Java 11+ — returns boolean"),
        "equals":              FunctionBehavior(safe=True, notes="boolean comparison"),
        "equalsIgnoreCase":    FunctionBehavior(safe=True, notes="boolean comparison"),
        "contains":            FunctionBehavior(safe=True, notes="boolean query"),
        "hashCode":            FunctionBehavior(safe=True, notes="returns int"),
        "compareTo":           FunctionBehavior(safe=True, notes="returns int"),
        "compareToIgnoreCase": FunctionBehavior(safe=True, notes="returns int"),
        "indexOf":             FunctionBehavior(safe=True, notes="returns int"),
        "lastIndexOf":         FunctionBehavior(safe=True, notes="returns int"),
        "startsWith":          FunctionBehavior(safe=True, notes="boolean query"),
        "endsWith":            FunctionBehavior(safe=True, notes="boolean query"),
        "matches":             FunctionBehavior(safe=True, notes="boolean regex match"),
        "codePointAt":         FunctionBehavior(safe=True, notes="returns int"),
        "codePointBefore":     FunctionBehavior(safe=True, notes="returns int"),
        "codePointCount":      FunctionBehavior(safe=True, notes="returns int"),
        "offsetByCodePoints":  FunctionBehavior(safe=True, notes="returns int"),
        "regionMatches":       FunctionBehavior(safe=True, notes="boolean query"),

        # ---- Sanitizers / validators (20) -------------------------------
        "StringEscapeUtils.escapeHtml4":       FunctionBehavior(passthrough=[0], safe=True, notes="apache commons-text"),
        "StringEscapeUtils.escapeHtml3":       FunctionBehavior(passthrough=[0], safe=True, notes="apache commons-text"),
        "StringEscapeUtils.escapeJava":        FunctionBehavior(passthrough=[0], safe=True, notes="apache commons-text"),
        "StringEscapeUtils.escapeJavaScript":  FunctionBehavior(passthrough=[0], safe=True, notes="apache commons-text"),
        "StringEscapeUtils.escapeXml":         FunctionBehavior(passthrough=[0], safe=True, notes="apache commons-text"),
        "StringEscapeUtils.escapeSql":         FunctionBehavior(passthrough=[0], safe=True, notes="apache commons-text — SQL escape"),
        "URLEncoder.encode":                   FunctionBehavior(passthrough=[0], safe=True, notes="java.net.URLEncoder"),
        "URLDecoder.decode":                   FunctionBehavior(passthrough=[0], safe=True, notes="java.net.URLDecoder"),
        "HtmlUtils.htmlEscape":                FunctionBehavior(passthrough=[0], safe=True, notes="spring web util"),
        "HtmlUtils.htmlUnescape":              FunctionBehavior(passthrough=[0], safe=True, notes="spring web util"),
        "Integer.parseInt":                    FunctionBehavior(safe=True, notes="returns primitive int — sanitized"),
        "Long.parseLong":                      FunctionBehavior(safe=True, notes="returns primitive long — sanitized"),
        "Double.parseDouble":                  FunctionBehavior(safe=True, notes="returns primitive double — sanitized"),
        "Float.parseFloat":                    FunctionBehavior(safe=True, notes="returns primitive float — sanitized"),
        "Boolean.parseBoolean":                FunctionBehavior(safe=True, notes="returns primitive boolean — sanitized"),
        "StringUtils.isNumeric":               FunctionBehavior(safe=True, notes="apache commons-lang validator"),
        "StringUtils.isAlpha":                 FunctionBehavior(safe=True, notes="apache commons-lang validator"),
        "StringUtils.isAlphanumeric":          FunctionBehavior(safe=True, notes="apache commons-lang validator"),
        "StringUtils.isBlank":                 FunctionBehavior(safe=True, notes="apache commons-lang validator"),
        "StringUtils.isEmpty":                 FunctionBehavior(safe=True, notes="apache commons-lang validator"),

        # ---- Sources (22) ------------------------------------------------
        "getParameter":          FunctionBehavior(is_source=True, passthrough=[0], notes="javax.servlet.ServletRequest"),
        "getParameterValues":    FunctionBehavior(is_source=True, passthrough=[0], notes="javax.servlet.ServletRequest"),
        "getParameterMap":       FunctionBehavior(is_source=True, passthrough=[0], notes="javax.servlet.ServletRequest"),
        "getParameterNames":     FunctionBehavior(is_source=True, passthrough=[0], notes="javax.servlet.ServletRequest"),
        "getHeader":             FunctionBehavior(is_source=True, passthrough=[0], notes="javax.servlet.http.HttpServletRequest"),
        "getHeaders":            FunctionBehavior(is_source=True, passthrough=[0], notes="javax.servlet.http.HttpServletRequest"),
        "getHeaderNames":        FunctionBehavior(is_source=True, passthrough=[0], notes="javax.servlet.http.HttpServletRequest"),
        "getQueryString":        FunctionBehavior(is_source=True, passthrough=[0], notes="javax.servlet.http.HttpServletRequest"),
        "getRequestURI":         FunctionBehavior(is_source=True, passthrough=[0], notes="javax.servlet.http.HttpServletRequest"),
        "getRequestURL":         FunctionBehavior(is_source=True, passthrough=[0], notes="javax.servlet.http.HttpServletRequest"),
        "getInputStream":        FunctionBehavior(is_source=True, passthrough=[0], notes="javax.servlet.ServletRequest"),
        "getReader":             FunctionBehavior(is_source=True, passthrough=[0], notes="javax.servlet.ServletRequest"),
        "getRemoteAddr":         FunctionBehavior(is_source=True, passthrough=[0], notes="javax.servlet.ServletRequest"),
        "getRemoteHost":         FunctionBehavior(is_source=True, passthrough=[0], notes="javax.servlet.ServletRequest"),
        "getRemoteUser":         FunctionBehavior(is_source=True, passthrough=[0], notes="javax.servlet.http.HttpServletRequest"),
        "getCookies":            FunctionBehavior(is_source=True, passthrough=[0], notes="javax.servlet.http.HttpServletRequest"),
        "getMethod":             FunctionBehavior(is_source=True, passthrough=[0], notes="HTTP method — attacker controlled"),
        "getProtocol":           FunctionBehavior(is_source=True, passthrough=[0], notes="HTTP protocol string"),
        "getScheme":             FunctionBehavior(is_source=True, passthrough=[0], notes="URL scheme"),
        "getServerName":         FunctionBehavior(is_source=True, passthrough=[0], notes="Host header derived"),
        "getServletPath":        FunctionBehavior(is_source=True, passthrough=[0], notes="javax.servlet.http.HttpServletRequest"),
        "System.getenv":         FunctionBehavior(is_source=True, passthrough=[0], notes="java.lang.System — environment"),

        # ---- Sinks (17) --------------------------------------------------
        "Runtime.exec":                   FunctionBehavior(is_sink=True, sink_type="command_injection", passthrough=[0], notes="java.lang.Runtime"),
        "ProcessBuilder.start":           FunctionBehavior(is_sink=True, sink_type="command_injection", notes="java.lang.ProcessBuilder"),
        "Statement.execute":              FunctionBehavior(is_sink=True, sink_type="sql_injection", passthrough=[0], notes="java.sql.Statement — raw SQL"),
        "Statement.executeQuery":         FunctionBehavior(is_sink=True, sink_type="sql_injection", notes="java.sql.Statement — raw SQL"),
        "Statement.executeUpdate":        FunctionBehavior(is_sink=True, sink_type="sql_injection", notes="java.sql.Statement — raw SQL"),
        "Statement.addBatch":             FunctionBehavior(is_sink=True, sink_type="sql_injection", notes="java.sql.Statement — raw SQL"),
        "Class.forName":                  FunctionBehavior(is_sink=True, sink_type="reflection", passthrough=[0], notes="java.lang.Class — class loading"),
        "Class.newInstance":              FunctionBehavior(is_sink=True, sink_type="reflection", notes="java.lang.Class — reflective instantiation"),
        "Constructor.newInstance":        FunctionBehavior(is_sink=True, sink_type="reflection", notes="java.lang.reflect.Constructor"),
        "Method.invoke":                  FunctionBehavior(is_sink=True, sink_type="reflection", notes="java.lang.reflect.Method"),
        "ObjectInputStream.readObject":   FunctionBehavior(is_sink=True, sink_type="deserialization", notes="java.io.ObjectInputStream"),
        "ObjectInputStream.readUnshared": FunctionBehavior(is_sink=True, sink_type="deserialization", notes="java.io.ObjectInputStream"),
        "response.sendRedirect":          FunctionBehavior(is_sink=True, sink_type="open_redirect", passthrough=[0], notes="javax.servlet.http.HttpServletResponse"),
        "response.getWriter().print":     FunctionBehavior(is_sink=True, sink_type="xss", passthrough=[0], notes="HttpServletResponse writer"),
        "response.getWriter().println":   FunctionBehavior(is_sink=True, sink_type="xss", passthrough=[0], notes="HttpServletResponse writer"),
        "response.getWriter().write":     FunctionBehavior(is_sink=True, sink_type="xss", passthrough=[0], notes="HttpServletResponse writer"),
        "response.setHeader":             FunctionBehavior(is_sink=True, sink_type="header_injection", notes="HttpServletResponse — header injection / CRLF"),

        # ---- PreparedStatement methods (safe) (10) ----------------------
        "PreparedStatement.execute":        FunctionBehavior(safe=True, notes="parameterized SQL — safe"),
        "PreparedStatement.executeQuery":   FunctionBehavior(safe=True, notes="parameterized SQL — safe"),
        "PreparedStatement.executeUpdate":  FunctionBehavior(safe=True, notes="parameterized SQL — safe"),
        "PreparedStatement.addBatch":       FunctionBehavior(safe=True, notes="parameterized SQL — safe"),
        "PreparedStatement.setInt":         FunctionBehavior(safe=True, notes="binds primitive int — safe"),
        "PreparedStatement.setLong":        FunctionBehavior(safe=True, notes="binds primitive long — safe"),
        "PreparedStatement.setString":      FunctionBehavior(safe=True, notes="binds string parameter — safe"),
        "PreparedStatement.setBoolean":     FunctionBehavior(safe=True, notes="binds primitive boolean — safe"),
        "PreparedStatement.setDate":        FunctionBehavior(safe=True, notes="binds java.sql.Date — safe"),
        "PreparedStatement.setObject":      FunctionBehavior(safe=True, notes="binds typed parameter — safe"),
    },

    # ======================================================================
    # Python (60)
    # ======================================================================
    "python": {
        # ---- String passthroughs (15) ------------------------------------
        "upper":      FunctionBehavior(passthrough=[0], notes="str.upper"),
        "lower":      FunctionBehavior(passthrough=[0], notes="str.lower"),
        "strip":      FunctionBehavior(passthrough=[0], notes="str.strip"),
        "lstrip":     FunctionBehavior(passthrough=[0], notes="str.lstrip"),
        "rstrip":     FunctionBehavior(passthrough=[0], notes="str.rstrip"),
        "replace":    FunctionBehavior(passthrough=[0], notes="str.replace"),
        "format":     FunctionBehavior(passthrough=[0], notes="str.format — format string flows through"),
        "format_map": FunctionBehavior(passthrough=[0], notes="str.format_map"),
        "join":       FunctionBehavior(passthrough=[0], notes="str.join — iterable elements flow through"),
        "split":      FunctionBehavior(passthrough=[0], notes="str.split — returns list of substrings"),
        "rsplit":     FunctionBehavior(passthrough=[0], notes="str.rsplit"),
        "splitlines": FunctionBehavior(passthrough=[0], notes="str.splitlines"),
        "title":      FunctionBehavior(passthrough=[0], notes="str.title"),
        "capitalize": FunctionBehavior(passthrough=[0], notes="str.capitalize"),
        "swapcase":   FunctionBehavior(passthrough=[0], notes="str.swapcase"),

        # ---- Sanitizers / validators (15) --------------------------------
        "html.escape":         FunctionBehavior(passthrough=[0], safe=True, notes="html module — XSS escape"),
        "html.unescape":       FunctionBehavior(passthrough=[0], safe=True, notes="html module"),
        "urllib.parse.quote":  FunctionBehavior(passthrough=[0], safe=True, notes="URL encoding"),
        "urllib.parse.quote_plus":   FunctionBehavior(passthrough=[0], safe=True, notes="URL form encoding"),
        "urllib.parse.urlencode":    FunctionBehavior(passthrough=[0], safe=True, notes="URL query encoding"),
        "markupsafe.escape":   FunctionBehavior(passthrough=[0], safe=True, notes="jinja2/markupsafe"),
        "bleach.clean":        FunctionBehavior(passthrough=[0], safe=True, notes="bleach HTML sanitizer"),
        "len":                 FunctionBehavior(safe=True, notes="returns int — no taint"),
        "int":                 FunctionBehavior(safe=True, notes="int() conversion — sanitized"),
        "float":               FunctionBehavior(safe=True, notes="float() conversion — sanitized"),
        "bool":                FunctionBehavior(safe=True, notes="bool() conversion — sanitized"),
        "str":                 FunctionBehavior(safe=True, notes="str() conversion — sanitized"),
        "repr":                FunctionBehavior(safe=True, notes="repr — produces literal form"),
        "abs":                 FunctionBehavior(safe=True, notes="abs — returns numeric"),
        "round":               FunctionBehavior(safe=True, notes="round — returns numeric"),

        # ---- Safe non-passthrough queries (10) ---------------------------
        "count":     FunctionBehavior(safe=True, notes="str.count — returns int"),
        "find":      FunctionBehavior(safe=True, notes="str.find — returns int"),
        "rfind":     FunctionBehavior(safe=True, notes="str.rfind — returns int"),
        "index":     FunctionBehavior(safe=True, notes="str.index — returns int"),
        "rindex":    FunctionBehavior(safe=True, notes="str.rindex — returns int"),
        "startswith": FunctionBehavior(safe=True, notes="str.startswith — boolean"),
        "endswith":  FunctionBehavior(safe=True, notes="str.endswith — boolean"),
        "isdigit":   FunctionBehavior(safe=True, notes="str.isdigit — boolean validator"),
        "isalpha":   FunctionBehavior(safe=True, notes="str.isalpha — boolean validator"),
        "isalnum":   FunctionBehavior(safe=True, notes="str.isalnum — boolean validator"),

        # ---- Sources (10) ------------------------------------------------
        "input":              FunctionBehavior(is_source=True, passthrough=[0], notes="builtin input() — stdin"),
        "os.getenv":          FunctionBehavior(is_source=True, passthrough=[0], notes="os.environ lookup"),
        "os.environ.get":     FunctionBehavior(is_source=True, passthrough=[0], notes="os.environ lookup"),
        "request.args.get":   FunctionBehavior(is_source=True, passthrough=[0], notes="flask — query string"),
        "request.form.get":   FunctionBehavior(is_source=True, passthrough=[0], notes="flask — POST body"),
        "request.values.get": FunctionBehavior(is_source=True, passthrough=[0], notes="flask — args+form"),
        "request.cookies.get": FunctionBehavior(is_source=True, passthrough=[0], notes="flask — cookies"),
        "request.headers.get": FunctionBehavior(is_source=True, passthrough=[0], notes="flask — headers"),
        "request.json.get":   FunctionBehavior(is_source=True, passthrough=[0], notes="flask — JSON body"),
        "request.get_json":   FunctionBehavior(is_source=True, passthrough=[0], notes="flask — JSON body"),

        # ---- Sinks (10) --------------------------------------------------
        "os.system":         FunctionBehavior(is_sink=True, sink_type="command_injection", passthrough=[0], notes="shell command"),
        "os.popen":          FunctionBehavior(is_sink=True, sink_type="command_injection", passthrough=[0], notes="shell command via pipe"),
        "eval":              FunctionBehavior(is_sink=True, sink_type="code_injection", passthrough=[0], notes="python eval"),
        "exec":              FunctionBehavior(is_sink=True, sink_type="code_injection", passthrough=[0], notes="python exec"),
        "pickle.loads":      FunctionBehavior(is_sink=True, sink_type="deserialization", passthrough=[0], notes="pickle deserialization"),
        "pickle.load":       FunctionBehavior(is_sink=True, sink_type="deserialization", passthrough=[0], notes="pickle deserialization from file"),
        "cursor.execute":    FunctionBehavior(is_sink=True, sink_type="sql_injection", passthrough=[0], notes="DB-API cursor — raw SQL"),
        "subprocess.call":   FunctionBehavior(is_sink=True, sink_type="command_injection", passthrough=[0], notes="subprocess"),
        "subprocess.run":    FunctionBehavior(is_sink=True, sink_type="command_injection", passthrough=[0], notes="subprocess"),
        "subprocess.Popen":  FunctionBehavior(is_sink=True, sink_type="command_injection", passthrough=[0], notes="subprocess"),
    },

    # ======================================================================
    # JavaScript (56)
    # ======================================================================
    "javascript": {
        # ---- String passthroughs (15) ------------------------------------
        "toUpperCase":  FunctionBehavior(passthrough=[0], notes="String.prototype.toUpperCase"),
        "toLowerCase":  FunctionBehavior(passthrough=[0], notes="String.prototype.toLowerCase"),
        "trim":         FunctionBehavior(passthrough=[0], notes="String.prototype.trim"),
        "trimStart":    FunctionBehavior(passthrough=[0], notes="String.prototype.trimStart"),
        "trimEnd":      FunctionBehavior(passthrough=[0], notes="String.prototype.trimEnd"),
        "replace":      FunctionBehavior(passthrough=[0], notes="String.prototype.replace"),
        "replaceAll":   FunctionBehavior(passthrough=[0], notes="String.prototype.replaceAll"),
        "toString":     FunctionBehavior(passthrough=[0], notes="Object.prototype.toString"),
        "substring":    FunctionBehavior(passthrough=[0], notes="String.prototype.substring"),
        "substr":       FunctionBehavior(passthrough=[0], notes="String.prototype.substr"),
        "slice":        FunctionBehavior(passthrough=[0], notes="String.prototype.slice"),
        "concat":       FunctionBehavior(passthrough=[0], notes="String.prototype.concat"),
        "padStart":     FunctionBehavior(passthrough=[0], notes="String.prototype.padStart"),
        "padEnd":       FunctionBehavior(passthrough=[0], notes="String.prototype.padEnd"),
        "repeat":       FunctionBehavior(passthrough=[0], notes="String.prototype.repeat"),

        # ---- Sanitizers / validators (10) --------------------------------
        "encodeURIComponent":   FunctionBehavior(passthrough=[0], safe=True, notes="global URL encoder"),
        "encodeURI":            FunctionBehavior(passthrough=[0], safe=True, notes="global URL encoder"),
        "decodeURIComponent":   FunctionBehavior(passthrough=[0], safe=True, notes="global URL decoder"),
        "decodeURI":            FunctionBehavior(passthrough=[0], safe=True, notes="global URL decoder"),
        "DOMPurify.sanitize":   FunctionBehavior(passthrough=[0], safe=True, notes="DOMPurify HTML sanitizer"),
        "parseInt":             FunctionBehavior(safe=True, notes="returns integer — sanitized"),
        "parseFloat":           FunctionBehavior(safe=True, notes="returns number — sanitized"),
        "Number":               FunctionBehavior(safe=True, notes="numeric coercion — sanitized"),
        "isNaN":                FunctionBehavior(safe=True, notes="returns boolean"),
        "isFinite":             FunctionBehavior(safe=True, notes="returns boolean"),

        # ---- Safe non-passthrough queries (10) ---------------------------
        "length":        FunctionBehavior(safe=True, notes="String/Array length — numeric"),
        "charAt":        FunctionBehavior(safe=True, notes="returns single char"),
        "charCodeAt":    FunctionBehavior(safe=True, notes="returns integer code unit"),
        "indexOf":       FunctionBehavior(safe=True, notes="returns integer index"),
        "lastIndexOf":   FunctionBehavior(safe=True, notes="returns integer index"),
        "includes":      FunctionBehavior(safe=True, notes="returns boolean"),
        "startsWith":    FunctionBehavior(safe=True, notes="returns boolean"),
        "endsWith":      FunctionBehavior(safe=True, notes="returns boolean"),
        "localeCompare": FunctionBehavior(safe=True, notes="returns integer"),
        "split":         FunctionBehavior(safe=True, notes="returns array — delimiter not tainted"),

        # ---- Sources (10) ------------------------------------------------
        "localStorage.getItem":   FunctionBehavior(is_source=True, notes="browser localStorage"),
        "sessionStorage.getItem": FunctionBehavior(is_source=True, notes="browser sessionStorage"),
        "req.params":             FunctionBehavior(is_source=True, notes="express — route params"),
        "req.query":              FunctionBehavior(is_source=True, notes="express — query string"),
        "req.body":               FunctionBehavior(is_source=True, notes="express — request body"),
        "req.headers":            FunctionBehavior(is_source=True, notes="express — headers"),
        "req.cookies":            FunctionBehavior(is_source=True, notes="express — cookies"),
        "document.cookie":        FunctionBehavior(is_source=True, notes="browser cookies"),
        "location.hash":          FunctionBehavior(is_source=True, notes="URL fragment — attacker controlled"),
        "location.search":        FunctionBehavior(is_source=True, notes="URL query string — attacker controlled"),

        # ---- Sinks (11) --------------------------------------------------
        "eval":                       FunctionBehavior(is_sink=True, sink_type="code_injection", passthrough=[0], notes="global eval"),
        "Function":                   FunctionBehavior(is_sink=True, sink_type="code_injection", passthrough=[0], notes="Function constructor — eval-like"),
        "setTimeout":                 FunctionBehavior(is_sink=True, sink_type="code_injection", passthrough=[0], notes="string arg evals as code"),
        "setInterval":                FunctionBehavior(is_sink=True, sink_type="code_injection", passthrough=[0], notes="string arg evals as code"),
        "document.write":             FunctionBehavior(is_sink=True, sink_type="xss", passthrough=[0], notes="writes raw HTML to document"),
        "document.writeln":           FunctionBehavior(is_sink=True, sink_type="xss", passthrough=[0], notes="writes raw HTML to document"),
        "element.innerHTML":          FunctionBehavior(is_sink=True, sink_type="xss", passthrough=[0], notes="raw HTML assignment"),
        "element.outerHTML":          FunctionBehavior(is_sink=True, sink_type="xss", passthrough=[0], notes="raw HTML assignment"),
        "element.insertAdjacentHTML": FunctionBehavior(is_sink=True, sink_type="xss", passthrough=[0], notes="raw HTML insertion"),
        "document.location":          FunctionBehavior(is_sink=True, sink_type="open_redirect", passthrough=[0], notes="navigation sink"),
        "window.location":            FunctionBehavior(is_sink=True, sink_type="open_redirect", passthrough=[0], notes="navigation sink"),
    },

    # ======================================================================
    # Go (31)
    # ======================================================================
    "go": {
        # ---- String passthroughs (12) ------------------------------------
        "strings.ToUpper":    FunctionBehavior(passthrough=[0], notes="strings package"),
        "strings.ToLower":    FunctionBehavior(passthrough=[0], notes="strings package"),
        "strings.TrimSpace":  FunctionBehavior(passthrough=[0], notes="strings package"),
        "strings.Trim":       FunctionBehavior(passthrough=[0], notes="strings package"),
        "strings.TrimLeft":   FunctionBehavior(passthrough=[0], notes="strings package"),
        "strings.TrimRight":  FunctionBehavior(passthrough=[0], notes="strings package"),
        "strings.TrimPrefix": FunctionBehavior(passthrough=[0], notes="strings package"),
        "strings.TrimSuffix": FunctionBehavior(passthrough=[0], notes="strings package"),
        "strings.Replace":    FunctionBehavior(passthrough=[0], notes="strings package"),
        "strings.ReplaceAll": FunctionBehavior(passthrough=[0], notes="strings package"),
        "strings.Title":      FunctionBehavior(passthrough=[0], notes="strings package — deprecated in 1.18+"),
        "strings.Repeat":     FunctionBehavior(passthrough=[0], notes="strings package"),

        # ---- Sanitizers / encoders (8) -----------------------------------
        "html.EscapeString":    FunctionBehavior(passthrough=[0], safe=True, notes="html package — XSS escape"),
        "html.UnescapeString":  FunctionBehavior(passthrough=[0], safe=True, notes="html package"),
        "url.QueryEscape":      FunctionBehavior(passthrough=[0], safe=True, notes="net/url — query encoding"),
        "url.PathEscape":       FunctionBehavior(passthrough=[0], safe=True, notes="net/url — path encoding"),
        "url.QueryUnescape":    FunctionBehavior(passthrough=[0], safe=True, notes="net/url — query decoding"),
        "url.PathUnescape":     FunctionBehavior(passthrough=[0], safe=True, notes="net/url — path decoding"),
        "strconv.Atoi":         FunctionBehavior(safe=True, notes="strconv — parses int, sanitized"),
        "strconv.ParseInt":     FunctionBehavior(safe=True, notes="strconv — parses int, sanitized"),

        # ---- Safe non-passthrough queries (5) ----------------------------
        "len":               FunctionBehavior(safe=True, notes="builtin len — returns int"),
        "strings.Contains":  FunctionBehavior(safe=True, notes="returns boolean"),
        "strings.HasPrefix": FunctionBehavior(safe=True, notes="returns boolean"),
        "strings.HasSuffix": FunctionBehavior(safe=True, notes="returns boolean"),
        "strings.Index":     FunctionBehavior(safe=True, notes="returns int index"),

        # ---- Sources (3) -------------------------------------------------
        "r.URL.Query().Get": FunctionBehavior(is_source=True, notes="net/http — query string param"),
        "r.FormValue":       FunctionBehavior(is_source=True, notes="net/http — form/post field"),
        "os.Getenv":         FunctionBehavior(is_source=True, notes="os package — environment variable"),

        # ---- Sinks (3) ---------------------------------------------------
        "exec.Command": FunctionBehavior(is_sink=True, sink_type="command_injection", passthrough=[0], notes="os/exec — command execution"),
        "db.Exec":      FunctionBehavior(is_sink=True, sink_type="sql_injection", passthrough=[0], notes="database/sql — raw SQL"),
        "db.Query":     FunctionBehavior(is_sink=True, sink_type="sql_injection", passthrough=[0], notes="database/sql — raw SQL"),
    },

    # ======================================================================
    # C / C++ (25)
    # ======================================================================
    "cpp": {
        # ---- Passthroughs (3) --------------------------------------------
        "strcpy":  FunctionBehavior(passthrough=[1], notes="returns dst (arg 1) — buffer overflow risk"),
        "strcat":  FunctionBehavior(passthrough=[1], notes="returns dst (arg 1) — buffer overflow risk"),
        "strncpy": FunctionBehavior(passthrough=[1], notes="returns dst (arg 1) — bounded but still propagates"),

        # ---- Sinks (15) --------------------------------------------------
        "system":    FunctionBehavior(is_sink=True, sink_type="command_injection", passthrough=[0], notes="stdlib — shell invocation"),
        "popen":     FunctionBehavior(is_sink=True, sink_type="command_injection", passthrough=[0], notes="stdio — shell invocation"),
        "gets":      FunctionBehavior(is_sink=True, sink_type="buffer_overflow", passthrough=[0], notes="stdio — unbounded read, removed in C11"),
        "sprintf":   FunctionBehavior(is_sink=True, sink_type="buffer_overflow", passthrough=[1], notes="stdio — no bounds check"),
        "vsprintf":  FunctionBehavior(is_sink=True, sink_type="buffer_overflow", passthrough=[1], notes="stdio — no bounds check"),
        "scanf":     FunctionBehavior(is_sink=True, sink_type="buffer_overflow", passthrough=[0], notes="stdio — %s overflow"),
        "sscanf":    FunctionBehavior(is_sink=True, sink_type="buffer_overflow", passthrough=[0], notes="stdio — %s overflow"),
        "fscanf":    FunctionBehavior(is_sink=True, sink_type="buffer_overflow", passthrough=[0], notes="stdio — %s overflow"),
        "execve":    FunctionBehavior(is_sink=True, sink_type="command_injection", passthrough=[0], notes="unistd.h — process execution"),
        "execl":     FunctionBehavior(is_sink=True, sink_type="command_injection", passthrough=[0], notes="unistd.h — process execution"),
        "execvp":    FunctionBehavior(is_sink=True, sink_type="command_injection", passthrough=[0], notes="unistd.h — process execution, PATH lookup"),
        "memcpy":    FunctionBehavior(is_sink=True, sink_type="buffer_overflow", passthrough=[1], notes="string.h — size not checked against dst"),
        "memmove":   FunctionBehavior(is_sink=True, sink_type="buffer_overflow", passthrough=[1], notes="string.h — size not checked against dst"),
        "realloc":   FunctionBehavior(is_sink=True, sink_type="memory_corruption", passthrough=[0], notes="stdlib — use-after-free on failure"),
        "alloca":    FunctionBehavior(is_sink=True, sink_type="stack_overflow", passthrough=[0], notes="alloca — stack allocation, unbounded"),

        # ---- Sources (7) -------------------------------------------------
        "getenv":  FunctionBehavior(is_source=True, passthrough=[0], notes="stdlib — environment variable"),
        "fgets":   FunctionBehavior(is_source=True, passthrough=[0], notes="stdio — bounded stdin/file read"),
        "read":    FunctionBehavior(is_source=True, passthrough=[0], notes="unistd.h — file descriptor read"),
        "recv":    FunctionBehavior(is_source=True, passthrough=[0], notes="sys/socket.h — socket receive"),
        "fread":   FunctionBehavior(is_source=True, passthrough=[0], notes="stdio — bounded file read"),
        "getchar": FunctionBehavior(is_source=True, passthrough=[0], notes="stdio — single char from stdin"),
        "getc":    FunctionBehavior(is_source=True, passthrough=[0], notes="stdio — single char from stream"),
    },
}


# ============================================================================
# Lookup helpers
# ============================================================================

def lookup_function(language: str, func_name: str) -> Optional[FunctionBehavior]:
    """Resolve a function name against the knowledge base.

    Tries an exact match first (e.g. ``"StringEscapeUtils.escapeHtml4"``
    or ``"req.query"``). If no exact match is found, falls back to the
    short name — everything after the last dot — so that
    ``"obj.escapeHtml4"`` and ``"escapeHtml4"`` resolve to the same
    entry. Returns ``None`` when the language is unknown or the name
    cannot be resolved.
    """
    if not language or not func_name:
        return None
    kb = LANGUAGE_KNOWLEDGE.get(language, {})
    if not kb:
        return None
    if func_name in kb:
        return kb[func_name]
    short_name = func_name.split(".")[-1] if "." in func_name else func_name
    return kb.get(short_name)


def is_safe_function(language: str, func_name: str) -> bool:
    """Return ``True`` if ``func_name`` is a known sanitizer/validator.

    A safe function breaks the taint chain: even if its argument is
    attacker-controlled, the return value is considered clean.
    """
    behavior = lookup_function(language, func_name)
    return bool(behavior and behavior.safe)


def is_source_function(language: str, func_name: str) -> bool:
    """Return ``True`` if ``func_name`` returns attacker-controlled data."""
    behavior = lookup_function(language, func_name)
    return bool(behavior and behavior.is_source)


def is_sink_function(language: str, func_name: str) -> bool:
    """Return ``True`` if ``func_name`` is a dangerous sink."""
    behavior = lookup_function(language, func_name)
    return bool(behavior and behavior.is_sink)


def get_passthrough(language: str, func_name: str) -> List[int]:
    """Return the list of passthrough argument indices for ``func_name``.

    Returns an empty list (rather than raising) when the function is
    unknown or does not propagate taint.
    """
    behavior = lookup_function(language, func_name)
    if behavior is None:
        return []
    return list(behavior.passthrough)


def get_sink_type(language: str, func_name: str) -> str:
    """Return the sink type label for ``func_name`` (empty if not a sink)."""
    behavior = lookup_function(language, func_name)
    if behavior is None or not behavior.is_sink:
        return ""
    return behavior.sink_type


# ============================================================================
# Introspection
# ============================================================================

def knowledge_stats() -> Dict[str, int]:
    """Return per-language function counts plus a ``total``.

    Example::

        {
            "java":       114,
            "python":      60,
            "javascript":  56,
            "go":          31,
            "cpp":         25,
            "total":      286,
        }
    """
    counts: Dict[str, int] = {}
    total = 0
    for lang, entries in LANGUAGE_KNOWLEDGE.items():
        n = len(entries)
        counts[lang] = n
        total += n
    counts["total"] = total
    return counts


__all__ = [
    "FunctionBehavior",
    "LANGUAGE_KNOWLEDGE",
    "lookup_function",
    "is_safe_function",
    "is_source_function",
    "is_sink_function",
    "get_passthrough",
    "get_sink_type",
    "knowledge_stats",
]
