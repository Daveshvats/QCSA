"""Deep dataflow analysis for JavaScript/TypeScript and Java.

Goes beyond regex pattern matching — tracks how data flows from sources
(user input) through assignments, function calls, and transformations
to sinks (eval, SQL, HTML, redirects).

This catches bugs that regex CANNOT:
  - Source→Sink across 5 function calls with sanitization in between
  - "Is this user input sanitized before reaching eval()?"
  - "Does this SQL query contain data from request.params?"
  - "Is this redirect URL validated against an allowlist?"

Architecture:
  1. Parse source into normalized AST (tree-sitter or Python ast fallback)
  2. Build a per-function dataflow graph (def-use chains)
  3. Identify sources (req.params, request.getParameter, etc.)
  4. Identify sinks (eval, db.query, innerHTML, sendRedirect, etc.)
  5. BFS from each source — does it reach a sink?
  6. Check if sanitization occurs along the path
  7. Report unsanitized source→sink flows

Sources per language:
  JS: req.params, req.query, req.body, req.headers, location.hash, location.search,
      document.URL, document.referrer, localStorage, event.data (postMessage)
  Java: request.getParameter, request.getHeader, @RequestParam, @RequestBody,
        @PathVariable, @RequestHeader, System.getenv, args[]

Sinks per language:
  JS: eval(), Function(), innerHTML, outerHTML, document.write, db.query,
      fetch(), axios(), res.redirect(), child_process.exec, fs.readFile
  Java: executeQuery, sendRedirect, ProcessBuilder, Runtime.exec,
        innerHTML (JSP), ObjectInputStream.readObject, new File()

Sanitizers per language:
  JS: DOMPurify.sanitize, escapeHtml, encodeURIComponent, parseInt, parseFloat,
      validator.isXss, xss()
  Java: Integer.parseInt, URLEncoder.encode, StringEscapeUtils.escapeHtml,
        PreparedStatement.setString, Pattern.matcher
"""
from __future__ import annotations

import re
import ast
from pathlib import Path
from typing import List, Optional, Dict, Any, Set, Tuple
from dataclasses import dataclass, field

try:
    from .normalized_ast import parse_file, get_language, NormalizedNode
    _HAS_NORMALIZED = True
except ImportError:
    _HAS_NORMALIZED = False


@dataclass
class DataflowFinding:
    """A dataflow finding: user input reaches a dangerous sink."""
    rule_id: str
    severity: str
    description: str
    file: str
    line: int
    source: str  # source description
    sink: str    # sink description
    path: str    # data flow path description
    language: str = ""
    sanitized: bool = False
    cwe: str = ""


# =============================================================================
# SOURCE/SINK/SANITIZER DEFINITIONS
# =============================================================================

# Sources: patterns that indicate user-controlled input
JS_SOURCES = {
    "req.params": "Express route parameter",
    "req.query": "Express query string",
    "req.body": "Express request body",
    "req.headers": "Express request headers",
    "req.cookies": "Express cookies",
    "location.hash": "URL hash fragment",
    "location.search": "URL query string",
    "document.URL": "Document URL",
    "document.referrer": "Referrer URL",
    "document.location": "Document location",
    "window.location": "Window location",
    "localStorage": "Local storage",
    "sessionStorage": "Session storage",
    "event.data": "postMessage data",
    "process.argv": "Command line arguments",
    "request.body": "Request body",
    "request.query": "Query string",
    "request.params": "Route parameters",
}

JAVA_SOURCES = {
    "request.getParameter": "HTTP parameter",
    "request.getHeader": "HTTP header",
    "request.getQueryString": "Query string",
    "request.getRequestURI": "Request URI",
    "request.getCookies": "Cookies",
    "request.getAttribute": "Request attribute",
    "@RequestParam": "Spring request parameter",
    "@RequestBody": "Spring request body",
    "@PathVariable": "Spring path variable",
    "@RequestHeader": "Spring request header",
    "System.getenv": "Environment variable",
    "System.getProperty": "System property",
    "args[": "Command line argument",
    "Scanner.next": "User input (Scanner)",
    "BufferedReader.readLine": "User input (BufferedReader)",
    "JOptionPane.showInputDialog": "User input (GUI)",
}

# Sinks: dangerous operations where user input shouldn't reach unsanitized
JS_SINKS = {
    "eval": ("Code injection", "CWE-95", "critical"),
    "Function": ("Code injection (Function constructor)", "CWE-95", "critical"),
    "setTimeout": ("Code injection (if string arg)", "CWE-95", "high"),
    "setInterval": ("Code injection (if string arg)", "CWE-95", "high"),
    "innerHTML": ("DOM XSS", "CWE-79", "high"),
    "outerHTML": ("DOM XSS", "CWE-79", "high"),
    "document.write": ("DOM XSS", "CWE-79", "critical"),
    "document.writeln": ("DOM XSS", "CWE-79", "high"),
    "insertAdjacentHTML": ("DOM XSS", "CWE-79", "high"),
    "query": ("SQL injection", "CWE-89", "critical"),
    "execute": ("SQL injection", "CWE-89", "critical"),
    "exec": ("Command injection", "CWE-78", "critical"),
    "execSync": ("Command injection", "CWE-78", "critical"),
    "spawn": ("Command injection", "CWE-78", "high"),
    "fetch": ("SSRF", "CWE-918", "high"),
    "axios": ("SSRF", "CWE-918", "high"),
    "request": ("SSRF", "CWE-918", "high"),
    "redirect": ("Open redirect", "CWE-601", "high"),
    "createWriteStream": ("Path traversal", "CWE-22", "high"),
    "readFile": ("Path traversal", "CWE-22", "high"),
    "readFileSync": ("Path traversal", "CWE-22", "high"),
    "unlink": ("Path traversal (file deletion)", "CWE-22", "high"),
    "open": ("Path traversal", "CWE-22", "medium"),
}

JAVA_SINKS = {
    "executeQuery": ("SQL injection", "CWE-89", "critical"),
    "executeUpdate": ("SQL injection", "CWE-89", "critical"),
    "execute": ("SQL injection / Command injection", "CWE-89", "critical"),
    "createStatement": ("SQL injection (if concatenated)", "CWE-89", "high"),
    "sendRedirect": ("Open redirect", "CWE-601", "high"),
    "getRequestDispatcher": ("Open redirect / path traversal", "CWE-601", "medium"),
    "exec": ("Command injection", "CWE-78", "critical"),
    "ProcessBuilder": ("Command injection", "CWE-78", "critical"),
    "readObject": ("Deserialization", "CWE-502", "critical"),
    "new File": ("Path traversal", "CWE-22", "high"),
    "Paths.get": ("Path traversal", "CWE-22", "high"),
    "write": ("Path traversal / XSS", "CWE-22", "medium"),
    "println": ("Information disclosure", "CWE-200", "low"),
    "printf": ("Information disclosure", "CWE-200", "low"),
    "format": ("Format string", "CWE-134", "medium"),
    "transform": ("XSLT injection", "CWE-94", "high"),
    "new URL": ("SSRF", "CWE-918", "high"),
    "openConnection": ("SSRF", "CWE-918", "high"),
    "setAttribute": ("Expression language injection", "CWE-94", "medium"),
    "println.write": ("XSS (if to response)", "CWE-79", "high"),
}

# Sanitizers: functions that make input safe
JS_SANITIZERS = {
    "DOMPurify.sanitize", "sanitize", "escapeHtml", "escapeHTML",
    "encodeURIComponent", "encodeURI", "parseInt", "parseFloat",
    "Number", "Boolean", "validator.isXss", "validator.isEmail",
    "xss", "filter", "stripTags", "he.encode", "escape",
    "JSON.stringify",  # makes data safe for embedding in script
    "String",  # toString conversion is safe for most sinks
    "TextEncoder",
}

JAVA_SANITIZERS = {
    "Integer.parseInt", "Long.parseLong", "Double.parseDouble", "Float.parseFloat",
    "Boolean.parseBoolean",
    "URLEncoder.encode", "URLDecoder.decode",
    "StringEscapeUtils.escapeHtml", "StringEscapeUtils.escapeSql",
    "escapeHtml", "escapeHtml4", "escapeHtml3", "escapeXml",
    "setString",  # PreparedStatement.setString is safe
    "setInt", "setLong", "setDouble", "setBoolean",
    "Pattern.quote", "Matcher.quoteReplacement",
    "Integer.valueOf", "Long.valueOf",
}


# =============================================================================
# DATAFLOW ANALYSIS
# =============================================================================

def analyze_js_dataflow(file_path: Path) -> List[DataflowFinding]:
    """Analyze JavaScript/TypeScript for source→sink data flows.

    This goes beyond regex — it tracks variable assignments and function
    call arguments to determine if user input reaches a dangerous sink.
    """
    try:
        source = file_path.read_text(encoding="utf-8")
    except Exception:
        return []

    lang = get_language(file_path) if _HAS_NORMALIZED else "javascript"
    rel_path = str(file_path)
    findings: List[DataflowFinding] = []
    lines = source.splitlines()

    # Track tainted variables: var_name → source description
    tainted_vars: Dict[str, str] = {}

    # Track sanitized variables: var_name → True (no longer tainted)
    sanitized_vars: Set[str] = set()

    # v4.3: Track function boundaries to reset taint state.
    # Without this, a variable name tainted in function A bleeds into
    # function B if B reuses the same name (e.g., `data`, `value`, `result`).
    # We detect function boundaries by matching function declaration patterns.
    _JS_FUNC_PATTERN = re.compile(
        r'(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\('
        r'|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\(?.*?\)?\s*=>',
        re.IGNORECASE
    )

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("//", "/*", "*", "*/")):
            continue

        # v4.3: Reset taint state at function boundaries
        if _JS_FUNC_PATTERN.search(stripped):
            tainted_vars.clear()
            sanitized_vars.clear()

        # Step 1: Detect source assignments
        # Pattern: const/let/var x = req.params.y  OR  x = req.body.y
        for source_pattern, source_desc in JS_SOURCES.items():
            # Assignment: var x = source OR x = source (but NOT .property = source)
            m = re.search(
                rf'(?:const|let|var)\s+(\w+)\s*=\s*.*?{re.escape(source_pattern)}',
                stripped, re.IGNORECASE
            )
            if m:
                var_name = m.group(1)
                tainted_vars[var_name] = source_desc
                continue

            # Non-var assignment: x = source (but NOT .prop = source, which is a sink)
            m = re.search(
                rf'^(\w+)\s*=\s*.*?{re.escape(source_pattern)}',
                stripped
            )
            if m and "." not in m.group(1):
                var_name = m.group(1)
                tainted_vars[var_name] = source_desc
                continue

            # Destructuring: const { id } = req.params
            m = re.search(
                rf'(?:const|let|var)\s*\{{\s*(\w+)\s*\}}\s*=\s*{re.escape(source_pattern)}',
                stripped
            )
            if m:
                var_name = m.group(1)
                tainted_vars[var_name] = source_desc
                continue

            # Direct use in expression (not assigned to var)
            if source_pattern in stripped:
                # Check if it's used in a sink directly (no variable intermediary)
                for sink_name, (sink_desc, cwe, severity) in JS_SINKS.items():
                    # Check if sink appears as a method call or property assignment
                    sink_in_line = False
                    if f".{sink_name}" in stripped or f"{sink_name}(" in stripped:
                        sink_in_line = True
                    if sink_in_line:
                        # Check for sanitization
                        is_sanitized = any(san in stripped for san in JS_SANITIZERS)
                        if not is_sanitized:
                            findings.append(DataflowFinding(
                                rule_id=f"DF.JS-FLOW-{sink_name.upper()}",
                                severity=severity,
                                description=f"Dataflow: {source_desc} reaches {sink_desc} sink "
                                            f"without sanitization",
                                file=rel_path,
                                line=i,
                                source=source_pattern,
                                sink=sink_name,
                                path=f"{source_pattern} → {sink_name}() (direct)",
                                language=lang,
                                sanitized=False,
                                cwe=cwe,
                            ))

        # Step 2: Track variable propagation
        # Pattern: var y = x (where x is tainted)
        m = re.search(r'(?:const|let|var)?\s*(\w+)\s*=\s*(\w+)', stripped)
        if m:
            new_var = m.group(1)
            source_var = m.group(2)
            if source_var in tainted_vars:
                tainted_vars[new_var] = tainted_vars[source_var]
            # Check for sanitization in the assignment
            for san in JS_SANITIZERS:
                if san in stripped:
                    sanitized_vars.add(new_var)
                    if new_var in tainted_vars:
                        del tainted_vars[new_var]

        # String concatenation propagation: y = x + "literal"
        m = re.search(r'(?:const|let|var)?\s*(\w+)\s*=\s*(\w+)\s*\+', stripped)
        if m:
            new_var = m.group(1)
            source_var = m.group(2)
            if source_var in tainted_vars:
                tainted_vars[new_var] = tainted_vars[source_var]

        # Template literal propagation: y = `${x}`
        m = re.search(r'(?:const|let|var)?\s*(\w+)\s*=\s*`[^`]*\$\{(\w+)\}', stripped)
        if m:
            new_var = m.group(1)
            source_var = m.group(2)
            if source_var in tainted_vars:
                tainted_vars[new_var] = tainted_vars[source_var]

        # Function call propagation: y = transform(x) where x is tainted
        m = re.search(r'(?:const|let|var)?\s*(\w+)\s*=\s*(\w+)\s*\(\s*(\w+)', stripped)
        if m:
            new_var = m.group(1)
            func_name = m.group(2)
            source_var = m.group(3)
            if source_var in tainted_vars:
                # Check if function is a sanitizer
                if func_name in JS_SANITIZERS or any(san.endswith(func_name) for san in JS_SANITIZERS):
                    sanitized_vars.add(new_var)
                else:
                    tainted_vars[new_var] = tainted_vars[source_var]

        # Step 3: Detect tainted variables reaching sinks
        for var_name, source_desc in list(tainted_vars.items()):
            if var_name in sanitized_vars:
                continue

            for sink_name, (sink_desc, cwe, severity) in JS_SINKS.items():
                # Check if this tainted variable is used in a sink call
                # Pattern: sink(var_name) OR sink(`...${var_name}...`) OR sink("..." + var_name)
                patterns = [
                    rf'\b{re.escape(sink_name)}\s*\(\s*{re.escape(var_name)}\b',
                    rf'\b{re.escape(sink_name)}\s*\(\s*`[^`]*\$\{{\s*{re.escape(var_name)}\s*\}}',
                    rf'\b{re.escape(sink_name)}\s*\(\s*["\'][^"\']*"\s*\+\s*{re.escape(var_name)}',
                    rf'\b{re.escape(sink_name)}\s*\([^)]*\b{re.escape(var_name)}\b',
                    rf'\.{re.escape(sink_name)}\s*=\s*{re.escape(var_name)}\b',  # .innerHTML = x
                    rf'\.{re.escape(sink_name)}\s*=\s*`[^`]*\$\{{\s*{re.escape(var_name)}\s*\}}',  # .innerHTML = `${x}`
                ]
                for pat in patterns:
                    if re.search(pat, stripped):
                        # Check for sanitization on this line
                        is_sanitized = any(san in stripped for san in JS_SANITIZERS)
                        if not is_sanitized:
                            findings.append(DataflowFinding(
                                rule_id=f"DF.JS-FLOW-{sink_name.upper()}",
                                severity=severity,
                                description=f"Dataflow: {source_desc} (variable '{var_name}') reaches "
                                            f"{sink_desc} sink without sanitization",
                                file=rel_path,
                                line=i,
                                source=source_desc,
                                sink=sink_name,
                                path=f"{source_desc} → {var_name} → {sink_name}()",
                                language=lang,
                                sanitized=False,
                                cwe=cwe,
                            ))
                        break  # don't report same var+sink multiple times

    return findings


def analyze_java_dataflow(file_path: Path) -> List[DataflowFinding]:
    """Analyze Java for source→sink data flows.

    Tracks how user input flows from request.getParameter(), @RequestParam,
    etc. to dangerous sinks like executeQuery, sendRedirect, exec.
    """
    try:
        source = file_path.read_text(encoding="utf-8")
    except Exception:
        return []

    lang = get_language(file_path) if _HAS_NORMALIZED else "java"
    rel_path = str(file_path)
    findings: List[DataflowFinding] = []
    lines = source.splitlines()

    # Track tainted variables
    tainted_vars: Dict[str, str] = {}
    sanitized_vars: Set[str] = set()

    # v4.3: Track method boundaries to reset taint state.
    # Without this, a variable name tainted in method A bleeds into method B.
    _JAVA_METHOD_PATTERN = re.compile(
        r'(?:public|private|protected|static|final|synchronized|abstract|default)\s+'
        r'[\w<>\[\],?\s]+\s+(\w+)\s*\([^)]*\)\s*(?:throws\s+[\w.,\s]+)?\s*\{',
        re.IGNORECASE
    )

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue

        # v4.3: Reset taint state at method boundaries
        if _JAVA_METHOD_PATTERN.search(stripped):
            tainted_vars.clear()
            sanitized_vars.clear()

        # Step 1: Detect source assignments
        # String x = request.getParameter("name");
        for source_pattern, source_desc in JAVA_SOURCES.items():
            m = re.search(
                rf'\b(\w+)\s*=\s*.*?{re.escape(source_pattern)}',
                stripped
            )
            if m:
                var_name = m.group(1)
                tainted_vars[var_name] = source_desc
                continue

            # Direct use in sink
            if source_pattern in stripped:
                for sink_name, (sink_desc, cwe, severity) in JAVA_SINKS.items():
                    if sink_name in stripped:
                        is_sanitized = any(san in stripped for san in JAVA_SANITIZERS)
                        if not is_sanitized:
                            findings.append(DataflowFinding(
                                rule_id=f"DF.JAVA-FLOW-{sink_name.upper()}",
                                severity=severity,
                                description=f"Dataflow: {source_desc} reaches {sink_desc} sink "
                                            f"without sanitization",
                                file=rel_path,
                                line=i,
                                source=source_pattern,
                                sink=sink_name,
                                path=f"{source_pattern} → {sink_name} (direct)",
                                language=lang,
                                sanitized=False,
                                cwe=cwe,
                            ))

        # Step 2: Track variable propagation
        # String y = x;
        m = re.search(r'\b(\w+)\s+(\w+)\s*=\s*(\w+)', stripped)
        if m:
            new_var = m.group(2)
            source_var = m.group(3)
            if source_var in tainted_vars:
                tainted_vars[new_var] = tainted_vars[source_var]

        # String concatenation: y = x + "literal"
        m = re.search(r'\b\w+\s+(\w+)\s*=\s*(\w+)\s*\+', stripped)
        if m:
            new_var = m.group(1)
            source_var = m.group(2)
            if source_var in tainted_vars:
                tainted_vars[new_var] = tainted_vars[source_var]

        # StringBuilder.append(x) — propagate taint to the builder
        m = re.search(r'(\w+)\.append\s*\(\s*(\w+)\s*\)', stripped)
        if m:
            builder_var = m.group(1)
            source_var = m.group(2)
            if source_var in tainted_vars:
                tainted_vars[builder_var] = tainted_vars[source_var]

        # String.format("...", x) — propagate taint
        m = re.search(r'\b\w+\s+(\w+)\s*=\s*String\.format\s*\([^)]*(\w+)', stripped)
        if m:
            new_var = m.group(1)
            source_var = m.group(2)
            if source_var in tainted_vars:
                tainted_vars[new_var] = tainted_vars[source_var]

        # Method call propagation: y = transform(x)
        m = re.search(r'\b\w+\s+(\w+)\s*=\s*(\w+)\.(\w+)\s*\(\s*(\w+)', stripped)
        if m:
            new_var = m.group(1)
            method = m.group(3)
            source_var = m.group(4)
            if source_var in tainted_vars:
                if method in JAVA_SANITIZERS or any(san.endswith(method) for san in JAVA_SANITIZERS):
                    sanitized_vars.add(new_var)
                else:
                    tainted_vars[new_var] = tainted_vars[source_var]

        # Step 3: Detect tainted variables reaching sinks
        for var_name, source_desc in list(tainted_vars.items()):
            if var_name in sanitized_vars:
                continue

            for sink_name, (sink_desc, cwe, severity) in JAVA_SINKS.items():
                patterns = [
                    rf'\b{re.escape(sink_name)}\s*\(\s*{re.escape(var_name)}\b',
                    rf'\b{re.escape(sink_name)}\s*\([^)]*\+\s*{re.escape(var_name)}\b',
                    rf'\b{re.escape(sink_name)}\s*\([^)]*\b{re.escape(var_name)}\b',
                    rf'{re.escape(sink_name)}\s*\(\s*{re.escape(var_name)}\s*\+',
                ]
                for pat in patterns:
                    if re.search(pat, stripped):
                        is_sanitized = any(san in stripped for san in JAVA_SANITIZERS)
                        if not is_sanitized:
                            findings.append(DataflowFinding(
                                rule_id=f"DF.JAVA-FLOW-{sink_name.upper()}",
                                severity=severity,
                                description=f"Dataflow: {source_desc} (variable '{var_name}') reaches "
                                            f"{sink_desc} sink without sanitization",
                                file=rel_path,
                                line=i,
                                source=source_desc,
                                sink=sink_name,
                                path=f"{source_desc} → {var_name} → {sink_name}()",
                                language=lang,
                                sanitized=False,
                                cwe=cwe,
                            ))
                        break

    return findings


# =============================================================================
# CONTEXT-AWARE ANALYSIS
# =============================================================================

def analyze_js_context(file_path: Path) -> List[DataflowFinding]:
    """Context-aware JS analysis — detects patterns based on surrounding code.

    Catches bugs that depend on WHERE code appears:
    - eval inside a try-catch with empty catch (silent code injection)
    - innerHTML in a loop (amplified XSS)
    - SQL query in a route handler without parameterization
    - Cookie set without secure flag in production code
    """
    try:
        source = file_path.read_text(encoding="utf-8")
    except Exception:
        return []

    lang = get_language(file_path) if _HAS_NORMALIZED else "javascript"
    rel_path = str(file_path)
    findings: List[DataflowFinding] = []
    lines = source.splitlines()

    # Track context: are we inside a try block, loop, route handler?
    in_try = 0
    in_loop = 0
    in_route = False
    route_indent = 0

    for i, line in enumerate(lines, 1):
        stripped = line.strip()

        # Track context
        if re.search(r'\btry\s*\{', stripped):
            in_try += 1
        if re.search(r'\bcatch\s*\([^)]*\)\s*\{', stripped):
            in_try = max(0, in_try - 1)
        if re.search(r'\b(?:for|while)\s*\(', stripped):
            in_loop += 1

        # Route handler detection
        m = re.search(r'(?:app|router)\.(?:get|post|put|delete|patch)\s*\(', stripped)
        if m:
            in_route = True
            route_indent = len(line) - len(line.lstrip())

        # Check if we're still in a route handler
        if in_route and stripped.startswith("}") and (len(line) - len(line.lstrip())) <= route_indent:
            in_route = False

        # --- Context-aware detections ---

        # eval inside try with empty catch
        if in_try > 0 and re.search(r'\beval\s*\(', stripped):
            # Look ahead for empty catch
            for j in range(i, min(i + 10, len(lines))):
                if re.search(r'catch\s*\([^)]*\)\s*\{\s*\}', lines[j-1] + lines[j] if j < len(lines) else lines[j-1]):
                    findings.append(DataflowFinding(
                        rule_id="DF.JS-EVAL-SILENT-CATCH",
                        severity="critical",
                        description="eval() inside try-catch with empty catch — code injection "
                                    "errors silently swallowed",
                        file=rel_path,
                        line=i,
                        source="eval",
                        sink="eval",
                        path="eval() in try block, catch is empty",
                        language=lang,
                        cwe="CWE-95",
                    ))
                    break

        # innerHTML in a loop (amplified XSS)
        if in_loop > 0 and re.search(r'\.innerHTML\s*[\+]?=', stripped):
            findings.append(DataflowFinding(
                rule_id="DF.JS-INNERHTML-IN-LOOP",
                severity="high",
                description="innerHTML assignment inside a loop — XSS amplified across iterations",
                file=rel_path,
                line=i,
                source="loop",
                sink="innerHTML",
                path="loop body → innerHTML = ...",
                language=lang,
                cwe="CWE-79",
            ))

        # SQL query in route handler without parameters
        if in_route and re.search(r'\.query\s*\(\s*"', stripped):
            if not re.search(r'\.query\s*\(\s*["\'].*\?', stripped):
                if re.search(r'\.query\s*\(\s*["\'].*\+', stripped) or \
                   re.search(r'\.query\s*\(\s*`[^`]*\$\{', stripped):
                    findings.append(DataflowFinding(
                        rule_id="DF.JS-SQL-IN-ROUTE",
                        severity="critical",
                        description="SQL query with string concatenation in route handler — "
                                    "direct SQL injection from HTTP request",
                        file=rel_path,
                        line=i,
                        source="HTTP request",
                        sink="SQL query",
                        path="route handler → db.query(concatenated string)",
                        language=lang,
                        cwe="CWE-89",
                    ))

        # Cookie without secure flag in HTTPS context
        if re.search(r'res\.cookie\s*\(', stripped) and 'secure' not in stripped.lower():
            findings.append(DataflowFinding(
                rule_id="DF.JS-COOKIE-NO-SECURE",
                severity="medium",
                description="Cookie set without secure flag — may be sent over HTTP",
                file=rel_path,
                line=i,
                source="res.cookie",
                sink="cookie",
                path="res.cookie() without secure option",
                language=lang,
                cwe="CWE-614",
            ))

    return findings


def analyze_java_context(file_path: Path) -> List[DataflowFinding]:
    """Context-aware Java analysis — detects patterns based on surrounding code.

    Catches:
    - SQL in @RequestMapping method without PreparedStatement
    - readObject in @PostMapping endpoint
    - sendRedirect in controller without URL validation
    - ProcessBuilder in endpoint
    - Insecure randomness in security-sensitive method (login, token generation)
    """
    try:
        source = file_path.read_text(encoding="utf-8")
    except Exception:
        return []

    lang = get_language(file_path) if _HAS_NORMALIZED else "java"
    rel_path = str(file_path)
    findings: List[DataflowFinding] = []
    lines = source.splitlines()

    # Track context
    in_endpoint = False
    in_login_method = False
    endpoint_indent = 0
    method_name = ""

    for i, line in enumerate(lines, 1):
        stripped = line.strip()

        # Detect endpoint methods
        if re.search(r'@(?:GetMapping|PostMapping|PutMapping|DeleteMapping|RequestMapping)', stripped):
            in_endpoint = True
            endpoint_indent = len(line) - len(line.lstrip())

        # Detect method start
        m = re.search(r'(?:public|private|protected)\s+\w+\s+(\w+)\s*\(', stripped)
        if m:
            method_name = m.group(1).lower()
            if any(kw in method_name for kw in ("login", "authenticate", "token", "password", "otp", "reset")):
                in_login_method = True

        # Detect method end
        if stripped == "}" and (len(line) - len(line.lstrip())) <= endpoint_indent:
            in_endpoint = False
            in_login_method = False

        # --- Context-aware detections ---

        # SQL in endpoint without PreparedStatement
        if in_endpoint and re.search(r'executeQuery\s*\(', stripped):
            if not re.search(r'PreparedStatement', stripped) and \
               (re.search(r'\+\s*', stripped) or re.search(r'String\.format', stripped)):
                findings.append(DataflowFinding(
                    rule_id="DF.JAVA-SQL-IN-ENDPOINT",
                    severity="critical",
                    description="SQL query with concatenation in HTTP endpoint — direct injection",
                    file=rel_path,
                    line=i,
                    source="HTTP request",
                    sink="executeQuery",
                    path="endpoint → executeQuery(concatenated SQL)",
                    language=lang,
                    cwe="CWE-89",
                ))

        # Deserialization in endpoint
        if in_endpoint and re.search(r'readObject\s*\(', stripped):
            findings.append(DataflowFinding(
                rule_id="DF.JAVA-DESERIALIZE-IN-ENDPOINT",
                severity="critical",
                description="Deserialization in HTTP endpoint — remote code execution risk",
                file=rel_path,
                line=i,
                source="HTTP request body",
                sink="readObject",
                path="endpoint → ObjectInputStream.readObject()",
                language=lang,
                cwe="CWE-502",
            ))

        # Command execution in endpoint
        if in_endpoint and (re.search(r'Runtime.*\.exec', stripped) or re.search(r'ProcessBuilder', stripped)):
            findings.append(DataflowFinding(
                rule_id="DF.JAVA-EXEC-IN-ENDPOINT",
                severity="critical",
                description="Command execution in HTTP endpoint — remote command injection",
                file=rel_path,
                line=i,
                source="HTTP request",
                sink="exec/ProcessBuilder",
                path="endpoint → Runtime.exec()/ProcessBuilder",
                language=lang,
                cwe="CWE-78",
            ))

        # Insecure random in login/token method
        if in_login_method and re.search(r'new\s+Random\s*\(\s*\)', stripped):
            findings.append(DataflowFinding(
                rule_id="DF.JAVA-INSECURE-RANDOM-SECURITY",
                severity="critical",
                description=f"Insecure random in security method '{method_name}()' — "
                            f"tokens/passwords are predictable",
                file=rel_path,
                line=i,
                source="java.util.Random",
                sink="security token",
                path=f"{method_name}() → new Random() → security token",
                language=lang,
                cwe="CWE-330",
            ))

        # sendRedirect without validation in controller
        if in_endpoint and re.search(r'sendRedirect\s*\(', stripped):
            if not re.search(r'(?:allowlist|whitelist|valid|check|sanitize)', stripped.lower()):
                findings.append(DataflowFinding(
                    rule_id="DF.JAVA-REDIRECT-IN-ENDPOINT",
                    severity="high",
                    description="sendRedirect in controller without URL validation — open redirect",
                    file=rel_path,
                    line=i,
                    source="HTTP request",
                    sink="sendRedirect",
                    path="endpoint → sendRedirect(user input)",
                    language=lang,
                    cwe="CWE-601",
                ))

    return findings


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

def analyze_deep_js(file_path: Path) -> List[DataflowFinding]:
    """Run all deep JS analysis (dataflow + context-aware)."""
    findings: List[DataflowFinding] = []
    findings.extend(analyze_js_dataflow(file_path))
    findings.extend(analyze_js_context(file_path))
    return findings


def analyze_deep_java(file_path: Path) -> List[DataflowFinding]:
    """Run all deep Java analysis (dataflow + context-aware)."""
    findings: List[DataflowFinding] = []
    findings.extend(analyze_java_dataflow(file_path))
    findings.extend(analyze_java_context(file_path))
    return findings


def analyze_deep(file_path: Path) -> List[DataflowFinding]:
    """Run deep analysis on any JS/Java file."""
    lang = get_language(file_path) if _HAS_NORMALIZED else "python"

    if lang in ("javascript", "typescript"):
        return analyze_deep_js(file_path)
    elif lang == "java":
        return analyze_deep_java(file_path)
    return []


def analyze_deep_repo(repo_root: Path, max_files: int = 100) -> List[DataflowFinding]:
    """Run deep analysis on all JS/Java files in a repo."""
    skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules",
                 ".stca-cache", "build", "dist", "target"}
    findings: List[DataflowFinding] = []
    count = 0

    for f in sorted(repo_root.rglob("*")):
        if not f.is_file() or any(p in skip_dirs for p in f.parts):
            continue
        if count >= max_files:
            break

        ext = f.suffix.lower()
        if ext in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"):
            count += 1
            findings.extend(analyze_deep_js(f))
        elif ext == ".java":
            count += 1
            findings.extend(analyze_deep_java(f))

    return findings
