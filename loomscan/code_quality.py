"""Code quality analyzer — multi-language (111+ rules across 5 languages).

v4.5 fix: Regex rules now skip comments, docstrings, and string literals.
Previously, rules like CQ-PY-EVAL would match the word 'eval' inside a
comment or docstring, producing false positives on the tool's own source
code (93 false CQ-PY-EVAL hits on LoomScan's self-scan). The fix uses a cheap
tokenize pass to identify and strip comment/string regions before regex
matching, while preserving the original line numbers.
"""
from __future__ import annotations
import re

# v4.42: Use fast_regex (re2-backed) if available for ReDoS protection
try:
    from .fast_regex import is_re2_available
    _FAST_REGEX_AVAILABLE = is_re2_available()
except ImportError:
    _FAST_REGEX_AVAILABLE = False
import tokenize
import io
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from .multi_lang import get_language, ALL_SOURCE_EXTS

import logging
_logger = logging.getLogger(__name__.replace('loomscan.', ''))

@dataclass
class CodeQualityIssue:
    file: str; line: int; rule_id: str; severity: str; category: str
    description: str; fix: str; cwe: str = ""; confidence: float = 0.7; language: str = ""

JS_RULES: List[Tuple] = [
    ("CQ-CONSOLE-ERROR-LOG", r'console\.(?:log|error|warn)\s*\(\s*(?:error|err|e)\b', "low", "security", "Error logged to console — may leak internals", "Log to Sentry", "CWE-532", 0.7),
    ("CQ-ERROR-SWALLOW-EMPTY", r'catch\s*\([^)]*\)\s*\{\s*\}', "medium", "correctness", "Empty catch — errors silently swallowed", "Log the error", "CWE-755", 0.8),
    ("CQ-ERROR-SWALLOW-RETURN-NULL", r'catch\s*\([^)]*\)\s*\{\s*return\s+(?:null|undefined|void\s+0|false)', "medium", "correctness", "catch returns null — can't distinguish error", "Throw or return error object", "CWE-755", 0.7),
    ("CQ-WINDOW-RELOAD", r'window\.location\.reload\s*\(', "low", "ux", "window.location.reload() — breaks SPA", "Use React state", "", 0.7),
    ("CQ-HREF-NAVIGATION", r'href\s*=\s*\{(?:page\.url|url|to|path)', "low", "performance", "href={...} — full page reload", "Use navigate()", "", 0.6),
    ("CQ-HARDCODED-COLOR", r'#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})\b', "low", "maintainability", "Hardcoded hex color", "Use theme.palette", "", 0.4),
    ("CQ-DEFAULT-PARAM-SIDEEFFECT", r'=\s*localStorage\.getItem', "low", "correctness", "localStorage in default param — runs every render", "Use useMemo/useEffect", "", 0.7),
    ("CQ-USESTATE-DEFAULT-PARAM", r'\w+\s*=\s*useState\s*\(', "low", "correctness", "useState in default param", "Move inside component", "", 0.5),
    ("CQ-INLINE-STYLE", r'style\s*=\s*\{\{', "low", "maintainability", "Inline style", "Use className", "", 0.3),
    ("CQ-HARDCODED-URL", r'[\'"]https?://[a-zA-Z0-9.-]+\.[a-z]{2,}[^\'"]*[\'"]', "low", "maintainability", "Hardcoded URL", "Use constant/env var", "", 0.4),
    ("CQ-CONSOLE-LOG-PROD", r'\bconsole\.(?:log|debug|info)\s*\(', "low", "maintainability", "console.log in production", "Use logger", "CWE-532", 0.4),
    ("CQ-SETTIMEOUT-NO-CLEAR", r'setTimeout\s*\(', "low", "performance", "setTimeout without cleanup", "clearTimeout in cleanup", "CWE-404", 0.4),
    ("CQ-GLOBAL-MUTATION-FLAG", r'\b(?:let|var)\s+(?:logoutInProgress|loginInProgress|refreshInProgress|requestInProgress)\b', "medium", "concurrency", "Global mutation flag — race conditions", "Use queue/mutex", "CWE-362", 0.7),
    ("CQ-MODULE-MUTABLE-FLAG", r'^(?:let|var)\s+\w*(?:InProgress|Pending|Loading|Busy|Active)\w*\s*=', "low", "concurrency", "Module-level mutable flag", "Use ref/state machine", "CWE-362", 0.5),
    ("CQ-REPLACEALL-REGEX-NO-G", r'\.replaceAll\s*\(\s*/[^/]*[^g]/[gimuy]*\s*,', "low", "correctness", "replaceAll without 'g' flag", "Use .replace(/g)", "", 0.7),
    ("CQ-LOCALSTORAGE-SET-NULL", r'localStorage\.setItem\s*\([^,]+,\s*(?:null|undefined)\s*\)', "low", "correctness", "setItem with null → 'null' string", "Check null first", "", 0.8),
    ("CQ-QUERYCLIENT-NO-DEFAULTS", r'new\s+QueryClient\s*\(\s*\)', "medium", "performance", "QueryClient without defaultOptions", "Set staleTime, retry, refetchOnWindowFocus", "", 0.8),
    ("CQ-DEVTOOLS-IN-PROD", r'<ReactQueryDevtools', "medium", "maintainability", "ReactQueryDevtools in prod", "Conditionally render", "CWE-489", 0.7),
    ("CQ-EVAL-USAGE", r'\beval\s*\(', "high", "security", "eval() — code injection", "Use JSON.parse()", "CWE-95", 0.95),
    ("CQ-INNER-HTML", r'\.innerHTML\s*=', "high", "security", "innerHTML — XSS risk", "Use textContent/DOMPurify", "CWE-79", 0.85),
    ("CQ-DOCUMENT-WRITE", r'\bdocument\.write\s*\(', "high", "security", "document.write — XSS", "Use DOM methods", "CWE-79", 0.9),
    ("CQ-VAR-DECLARATION", r'\bvar\s+\w+', "low", "maintainability", "var — use let/const", "Use let/const", "", 0.5),
    ("CQ-LOOSE-EQUALITY", r'[^=!<>]==[^=]', "low", "correctness", "== instead of ===", "Use ===", "", 0.4),
    ("CQ-ANY-TYPE", r':\s*any\b', "low", "maintainability", "TypeScript 'any'", "Use specific types", "", 0.6),
    ("CQ-AS-ASSERTION", r'\bas\s+any\b', "low", "maintainability", "'as any'", "Fix type", "", 0.6),
    ("CQ-TS-IGNORE", r'//\s*@ts-ignore', "medium", "maintainability", "@ts-ignore", "Fix error", "", 0.7),
    ("CQ-ESLINT-DISABLE", r'//\s*eslint-disable', "low", "maintainability", "eslint-disable", "Fix lint error", "", 0.4),
    ("CQ-NO-KEY-IN-LIST", r'\.map\s*\([^)]*\)\s*=>\s*<\w+[^>]*>(?![^<]*key=)', "medium", "correctness", ".map() without key prop", "Add key={item.id}", "", 0.5),
    ("CQ-INDEX-AS-KEY", r'key\s*=\s*\{(?:index|i|idx)\}', "medium", "correctness", "Index as key", "Use stable id", "", 0.6),
    ("CQ-ALERT-USAGE", r'\balert\s*\(', "low", "ux", "alert() blocks UI", "Use toast/modal", "", 0.4),
    ("CQ-CONFIRM-USAGE", r'\bconfirm\s*\(', "low", "ux", "confirm() blocks UI", "Use modal", "", 0.4),
    ("CQ-NEW-PROMISE-CTOR", r'new\s+Promise\s*\(\s*\(', "low", "maintainability", "Promise constructor anti-pattern", "Use async/await", "", 0.5),
    ("CQ-FUNCTION-PROP-DRILL", r'props\.\w+\.\w+\.\w+', "low", "maintainability", "Deep prop access — prop drilling", "Use Context", "", 0.3),
]

PY_RULES: List[Tuple] = [
    ("CQ-PY-EXCEPT-PASS", r'except[^:]*:\s*$', "medium", "correctness", "Empty except", "Log the error", "CWE-755", 0.8),
    ("CQ-PY-BARE-EXCEPT", r'^\s*except\s*:', "high", "correctness", "Bare except — catches SystemExit", "Use except Exception:", "CWE-396", 0.9),
    ("CQ-PY-PRINT-LOG", r'^\s*print\s*\(', "low", "maintainability", "print() — use logging", "Use logger", "", 0.4),
    ("CQ-PY-MUTABLE-DEFAULT", r'def\s+\w+\([^)]*=\s*(?:\[\]|\{\}|set\(\))', "high", "correctness", "Mutable default argument", "Use None", "CWE-733", 0.95),
    ("CQ-PY-GLOBAL", r'^\s*global\s+\w+', "medium", "concurrency", "global — stateful, hard to test", "Use class/param", "", 0.5),
    ("CQ-PY-LONG-LINE", r'^.{121,}$', "low", "maintainability", "Line >120 chars", "Wrap", "", 0.4),
    # v4.6: Use negative lookbehind for '.' to avoid matching obj.eval()
    # (e.g., Z3's model.eval()). Only flag bare eval() / exec() calls.
    ("CQ-PY-EVAL", r'(?<!\.)\beval\s*\(', "high", "security", "eval() — injection", "Use ast.literal_eval()", "CWE-95", 0.95),
    ("CQ-PY-EXEC", r'(?<!\.)\bexec\s*\(', "high", "security", "exec() — injection", "Refactor", "CWE-95", 0.95),
    ("CQ-PY-OS-SYSTEM", r'\bos\.system\s*\(', "high", "security", "os.system() — injection", "Use subprocess.run()", "CWE-78", 0.9),
    ("CQ-PY-PICKLE-LOAD", r'\bpickle\.load\s*\(', "high", "security", "pickle.load() — RCE", "Use JSON", "CWE-502", 0.9),
    ("CQ-PY-ASSERT-PROD", r'^\s*assert\s+\w', "medium", "correctness", "assert removed with -O", "Use raise", "CWE-617", 0.6),
    ("CQ-PY-STAR-IMPORT", r'^\s*from\s+\S+\s+import\s+\*', "medium", "maintainability", "Star import", "Import specific names", "", 0.7),
    ("CQ-PY-F-STRING-LOG", r'logging\.\w+\(f["\']', "low", "performance", "f-string in logging — eager", "Use logging.info('%s', val)", "", 0.5),
    ("CQ-PY-TYPE-IGNORE", r'#\s*type:\s*ignore', "low", "maintainability", "type: ignore", "Fix type error", "", 0.5),
    ("CQ-PY-NOQA", r'#\s*noqa', "low", "maintainability", "# noqa", "Fix lint error", "", 0.4),
    ("CQ-PY-TODO", r'#\s*(?:TODO|FIXME|HACK|XXX|BUG)', "low", "maintainability", "TODO comment", "Track in issue tracker", "", 0.3),
    ("CQ-PY-EXCEPT-EXCEPTION-PASS", r'except\s+Exception[^:]*:\s*\n\s*pass', "medium", "correctness", "except Exception: pass", "Log or handle", "CWE-755", 0.8),
    ("CQ-PY-STRING-CONCAT-LOG", r'logging\.\w+\([^,)]*\+', "low", "performance", "String concat in logging", "Use logging.info('%s%s', a, b)", "", 0.4),
]

GO_RULES: List[Tuple] = [
    ("CQ-GO-IGNORE-ERROR", r'_\s*=\s*\w+\([^)]*\)\s*$', "low", "correctness", "Error return ignored", "Check error", "CWE-755", 0.5),
    ("CQ-GO-EMPTY-ERR-CHECK", r'if\s+err\s*!=\s*nil\s*\{\s*\}', "medium", "correctness", "Empty error check", "Log error", "CWE-755", 0.8),
    ("CQ-GO-PANIC", r'\bpanic\s*\(', "high", "correctness", "panic() — crashes program", "Return error", "CWE-248", 0.7),
    ("CQ-GO-LOG-FATAL", r'\blog\.Fatal\w*\s*\(', "high", "correctness", "log.Fatal — skips defers", "Return error", "CWE-248", 0.7),
    ("CQ-GO-INIT-ABUSE", r'^\s*func\s+init\s*\(\s*\)', "medium", "maintainability", "init() — hidden side effects", "Use explicit init", "", 0.6),
    ("CQ-GO-GLOBAL-MUTABLE", r'^\s*var\s+\w+\s*(?:=\s*|map\[|\[\])', "medium", "concurrency", "Global mutable var", "Use sync.Mutex", "CWE-362", 0.6),
    ("CQ-GO-DEFER-IN-LOOP", r'for\s+[^{]*\{[^}]*\bdefer\s+', "medium", "performance", "defer in loop — accumulates", "Extract to function", "", 0.7),
    ("CQ-GO-NAKED-RETURN-LONG", r'^\s*return\s*$', "low", "maintainability", "Naked return — unclear", "Use explicit returns", "", 0.4),
    # v4.9: Fixed — use [\s\S] instead of [^}]* to span newlines (was missing multi-line loop bodies)
    ("CQ-GO-STRING-CONCAT-LOOP", r'for\s[\s\S]*?\{[\s\S]*?\+=\s*["\']', "low", "performance", "String concat in loop — O(n²)", "Use strings.Builder", "", 0.6),
    ("CQ-GO-UNUSED-VAR", r'\b_\s*=\s*\w+', "low", "maintainability", "Variable to _ — verify", "Remove if unused", "", 0.3),
    ("CQ-GO-EXEC-COMMAND", r'exec\.Command\s*\(\s*["\']sh["\']', "high", "security", "exec.Command('sh') — injection", "Use explicit args", "CWE-78", 0.9),
    ("CQ-GO-UNSAFE-PACKAGE", r'"unsafe"', "high", "security", "unsafe package", "Avoid unsafe", "CWE-119", 0.85),
    ("CQ-GO-GOROUTINE-NO-WAIT", r'\bgo\s+\w+\(', "medium", "concurrency", "Goroutine without WaitGroup", "Use WaitGroup/context", "CWE-404", 0.5),
    ("CQ-GO-CHANNEL-NO-CLOSE", r'make\s*\(\s*chan\s+', "low", "concurrency", "Channel — verify close", "Close when done", "CWE-404", 0.3),
    ("CQ-GO-INTERFACE-POLLUTION", r'^\s*type\s+\w+\s+interface\s*\{[^}]*\}', "low", "maintainability", "Interface — verify needed", "Keep small", "", 0.3),
    ("CQ-GO-UNUSED-IMPORT", r'^\s*_\s*"[^"]+"', "low", "maintainability", "Side-effect import", "Verify intentional", "", 0.4),
    # v4.8: Fixed — was Java syntax (Thread.sleep) instead of Go (time.Sleep)
    ("CQ-GO-THREAD-SLEEP", r'time\.Sleep\s*\(', "low", "performance", "time.Sleep — polling anti-pattern", "Use wait/notify or channels", "", 0.4),
]

JAVA_RULES: List[Tuple] = [
    ("CQ-JAVA-EMPTY-CATCH", r'catch\s*\([^)]*\)\s*\{\s*\}', "medium", "correctness", "Empty catch", "Log error", "CWE-755", 0.8),
    ("CQ-JAVA-CATCH-PRINT-STACK", r'catch\s*\([^)]*\)\s*\{\s*e\.printStackTrace', "medium", "correctness", "catch + printStackTrace", "Log AND handle", "CWE-755", 0.7),
    ("CQ-JAVA-CATCH-EXCEPTION", r'catch\s*\(\s*(?:Exception|Throwable)\s+\w+\s*\)', "medium", "correctness", "Catching Exception/Throwable — too broad", "Catch specific", "CWE-396", 0.6),
    ("CQ-JAVA-SYSOUT", r'System\.(?:out|err)\.(?:print|println)\s*\(', "low", "maintainability", "System.out.println — use logger", "Use SLF4J", "", 0.5),
    ("CQ-JAVA-PRINT-STACK", r'\.printStackTrace\s*\(', "low", "maintainability", "printStackTrace()", "Use logger.error()", "", 0.5),
    ("CQ-JAVA-SYSTEM-EXIT", r'System\.exit\s*\(', "high", "correctness", "System.exit() — kills JVM", "Throw exception", "CWE-248", 0.7),
    ("CQ-JAVA-RUNTIME-EXEC", r'Runtime\.getRuntime\(\)\.exec\s*\(', "high", "security", "Runtime.exec() — injection", "Use ProcessBuilder", "CWE-78", 0.9),
    ("CQ-JAVA-THREAD-SLEEP-IN-LOOP", r'Thread\.sleep\s*\(', "low", "performance", "Thread.sleep — polling", "Use wait/notify", "", 0.4),
    ("CQ-JAVA-NEW-THREAD", r'new\s+Thread\s*\(', "medium", "concurrency", "new Thread() — no pool", "Use ExecutorService", "CWE-404", 0.6),
    ("CQ-JAVA-SYNCHRONIZED-THIS", r'synchronized\s*\(\s*this\s*\)', "medium", "concurrency", "synchronized(this)", "Use private lock", "CWE-667", 0.5),
    ("CQ-JAVA-RAW-TYPE", r'\b(?:List|Map|Set|Collection)\s*(?:<\s*>\s*)?(?!\s*<)\s+\w+\s*=', "medium", "maintainability", "Raw type", "Use generics", "", 0.6),
    ("CQ-JAVA-USE-VECTOR", r'\bnew\s+Vector\s*\(', "medium", "performance", "Vector — use ArrayList", "Use ArrayList", "", 0.6),
    ("CQ-JAVA-USE-HASHTABLE", r'\bnew\s+Hashtable\s*\(', "medium", "performance", "Hashtable — use HashMap", "Use HashMap", "", 0.6),
    ("CQ-JAVA-USE-STACK", r'\bnew\s+Stack\s*\(', "medium", "correctness", "Stack — use Deque", "Use ArrayDeque", "", 0.7),
    ("CQ-JAVA-USE-STRINGBUFFER", r'\bnew\s+StringBuffer\s*\(', "low", "performance", "StringBuffer — use StringBuilder", "Use StringBuilder", "", 0.5),
    ("CQ-JAVA-FINALIZE", r'protected\s+void\s+finalize\s*\(', "high", "correctness", "finalize() deprecated", "Use AutoCloseable", "CWE-586", 0.85),
    ("CQ-JAVA-REFLECTION", r'Class\.forName\s*\(', "medium", "security", "Reflection — access control bypass", "Use interfaces", "CWE-470", 0.5),
    ("CQ-JAVA-DESERIALIZATION", r'new\s+ObjectInputStream\s*\(', "high", "security", "Deserialization RCE", "Use JSON", "CWE-502", 0.85),
    ("CQ-JAVA-SCRIPT-ENGINE", r'new\s+ScriptEngineManager\s*\(', "high", "security", "ScriptEngine — injection", "Avoid eval", "CWE-95", 0.85),
    ("CQ-JAVA-URL-OPEN-STREAM", r'\.openStream\s*\(\s*\)', "medium", "security", "URL.openStream — no timeout, SSRF", "Use HttpURLConnection", "CWE-400", 0.5),
    ("CQ-JAVA-AUTOWIRED-FIELD", r'@Autowired\s+private', "medium", "maintainability", "@Autowired field injection", "Use constructor injection", "CWE-1078", 0.6),
    ("CQ-JAVA-SYSTEM-GETENV", r'System\.getenv\s*\(', "low", "maintainability", "System.getenv() — use @Value", "Use @Value/${var}", "", 0.4),
    ("CQ-JAVA-STRING-VALUE-OF", r'String\.valueOf\s*\(\s*null\s*\)', "low", "correctness", "String.valueOf(null) → 'null' string", "Check null first", "", 0.6),
    ("CQ-JAVA-INSTANCEOF", r'\binstanceof\s+\w+', "low", "maintainability", "instanceof — use polymorphism", "Use polymorphism", "", 0.3),
    ("CQ-JAVA-PUBLIC-FIELD", r'^\s*public\s+(?!class|interface|enum|void|static|final\s+static|int|String|boolean|long|double|float|char|byte)\w+\s+\w+\s*[=;]', "medium", "maintainability", "Public field — breaks encapsulation", "Use getter/setter", "CWE-1059", 0.5),
    ("CQ-JAVA-ASSERT", r'\bassert\s+\w', "medium", "correctness", "assert disabled by default", "Use IllegalArgumentException", "CWE-617", 0.6),
    ("CQ-JAVA-EQUALS-NULL", r'\.equals\s*\(\s*null\s*\)', "low", "correctness", ".equals(null) always false", "Use == null", "", 0.7),
    ("CQ-JAVA-HASHCODE-WITHOUT-EQUALS", r'public\s+int\s+hashCode\s*\(\)', "medium", "correctness", "hashCode without equals — breaks contract", "Override both", "CWE-581", 0.5),
    # v4.9: Fixed — use [\s\S] to span newlines (was missing multi-line loop bodies)
    ("CQ-JAVA-STRING-CONCAT-LOOP", r'for\s*\([^)]*\)\s*\{[\s\S]*?\+=\s*["\']', "medium", "performance", "String concat in loop — O(n²)", "Use StringBuilder", "", 0.7),
    ("CQ-JAVA-NEW-STRING-EMPTY", r'new\s+String\s*\(\s*\)', "low", "performance", "new String()", "Use \"\"", "", 0.5),
    ("CQ-JAVA-INTEGER-PARSE", r'Integer\.parseInt\s*\(', "low", "correctness", "parseInt — NumberFormatException", "Wrap in try-catch", "CWE-755", 0.3),
    ("CQ-JAVA-DATE-DEPRECATED", r'\bnew\s+(?:Date|java\.util\.Date)\s*\(\s*\)', "medium", "correctness", "new Date() deprecated", "Use Instant.now()", "", 0.5),
    ("CQ-JAVA-CALENDAR", r'\bCalendar\.getInstance', "medium", "correctness", "Calendar — use LocalDate", "Use LocalDate.now()", "", 0.5),
    ("CQ-JAVA-SIMPLE-DATE-FORMAT", r'new\s+SimpleDateFormat\s*\(', "medium", "concurrency", "SimpleDateFormat not thread-safe", "Use DateTimeFormatter", "CWE-362", 0.6),
    ("CQ-JAVA-FILE-INPUT-STREAM", r'new\s+FileInputStream\s*\(', "low", "maintainability", "FileInputStream — use Files.newInputStream", "Use Files API", "", 0.4),
    ("CQ-JAVA-FILE-OUTPUT-STREAM", r'new\s+FileOutputStream\s*\(', "low", "maintainability", "FileOutputStream — use Files.newOutputStream", "Use Files API", "", 0.4),
    ("CQ-JAVA-IO-FILE", r'\bnew\s+File\s*\(', "low", "maintainability", "java.io.File — use Path", "Use Path.of()", "", 0.4),
    ("CQ-JAVA-SCANNER-FILE", r'new\s+Scanner\s*\(\s*new\s+File', "low", "maintainability", "Scanner on File — use try-with-resources", "Use try-with-resources", "CWE-404", 0.5),
    ("CQ-JAVA-RANDOM-NEXTINT", r'\bnew\s+Random\s*\(', "low", "correctness", "new Random() not CSPRNG", "Use SecureRandom/ThreadLocalRandom", "", 0.4),
    ("CQ-JAVA-COLLECTIONS-SYNC", r'Collections\.synchronized(?:List|Map|Set)', "low", "concurrency", "Collections.synchronized — coarse locking", "Use CopyOnWrite/ConcurrentHashMap", "", 0.4),
    ("CQ-JAVA-VECTOR-ADD", r'\.addElement\s*\(', "low", "maintainability", "Vector.addElement — legacy", "Use add()", "", 0.4),
    ("CQ-JAVA-ENUM-VALUES", r'\.values\s*\(\s*\)', "low", "performance", ".values() creates new array", "Cache it", "", 0.3),
    ("CQ-JAVA-STRING-FORMAT-NO-LOCALE", r'String\.format\s*\(\s*["\']', "low", "correctness", "String.format without Locale", "Use String.format(Locale.US, ...)", "", 0.3),
    ("CQ-JAVA-TOUPPERCASE-NO-LOCALE", r'\.toUpperCase\s*\(\s*\)', "low", "correctness", ".toUpperCase() — locale-dependent (Turkish 'i')", "Use .toUpperCase(Locale.US)", "", 0.4),
    ("CQ-JAVA-TOLOWERCASE-NO-LOCALE", r'\.toLowerCase\s*\(\s*\)', "low", "correctness", ".toLowerCase() — locale-dependent", "Use .toLowerCase(Locale.US)", "", 0.4),
    ("CQ-JAVA-NULL-CHECK-VERBOSE", r'if\s*\(\s*\w+\s*==\s*null\s*\)\s*\{\s*throw\s+new\s+(?:NullPointerException|IllegalArgumentException)', "low", "maintainability", "Manual null check — use Objects.requireNonNull", "Use Objects.requireNonNull()", "", 0.4),
    ("CQ-JAVA-COMPARE-RETURN", r'compareTo\s*\([^)]*\)\s*==\s*-?\d+', "low", "correctness", "compareTo == value — fragile", "Use > 0 or < 0", "", 0.4),
    ("CQ-JAVA-LAMBDA-THIS", r'\(\s*\)\s*->\s*this\.', "low", "maintainability", "Lambda capturing 'this'", "Use method references", "", 0.3),
    ("CQ-JAVA-SLEEP-NO-INTERRUPT", r'Thread\.sleep\s*\([^)]*\)\s*;(?!.*catch.*InterruptedException)', "low", "concurrency", "Thread.sleep without interrupt handling", "Catch InterruptedException", "", 0.4),
    ("CQ-JAVA-STATIC-LOGGER", r'LoggerFactory\.getLogger\s*\(\s*\w+\.class\s*\)', "info", "maintainability", "Static logger — verify class", "Use MyClass.class", "", 0.2),
]

CPP_RULES: List[Tuple] = [
    ("CQ-CPP-EMPTY-CATCH", r'catch\s*\([^)]*\)\s*\{\s*\}', "medium", "correctness", "Empty catch", "Log error", "CWE-755", 0.8),
    ("CQ-CPP-CATCH-ALL", r'catch\s*\(\s*\.\.\.\s*\)', "medium", "correctness", "catch(...) — too broad", "Catch specific", "CWE-396", 0.6),
    ("CQ-CPP-STRCPY", r'\bstrcpy\s*\(', "high", "security", "strcpy — buffer overflow", "Use strncpy/strlcpy", "CWE-120", 0.85),
    ("CQ-CPP-STRCAT", r'\bstrcat\s*\(', "high", "security", "strcat — buffer overflow", "Use strncat", "CWE-120", 0.85),
    ("CQ-CPP-GETS", r'\bgets\s*\(', "critical", "security", "gets — always vulnerable", "Use fgets()", "CWE-242", 0.95),
    ("CQ-CPP-SPRINTF", r'\bsprintf\s*\(', "high", "security", "sprintf — buffer overflow", "Use snprintf()", "CWE-120", 0.85),
    ("CQ-CPP-SCANF", r'\bscanf\s*\(', "high", "security", "scanf — buffer overflow", "Use fgets()+sscanf()", "CWE-120", 0.85),
    ("CQ-CPP-STRNCPY-NO-TERM", r'\bstrncpy\s*\([^)]*\)\s*;\s*$', "medium", "correctness", "strncpy may not null-terminate", "Manually terminate", "CWE-170", 0.5),
    ("CQ-CPP-PRINTF", r'\bprintf\s*\(', "low", "maintainability", "printf in production", "Use logger", "", 0.4),
    ("CQ-CPP-GOTO", r'\bgoto\s+\w+', "medium", "maintainability", "goto — spaghetti", "Use structured flow", "", 0.7),
    ("CQ-CPP-NULL-NOT-NULLPTR", r'\bNULL\b', "low", "maintainability", "NULL instead of nullptr", "Use nullptr", "", 0.5),
    ("CQ-CPP-USING-NAMESPACE-STD", r'using\s+namespace\s+std', "medium", "maintainability", "using namespace std", "Use std:: prefix", "", 0.6),
    ("CQ-CPP-MACRO-ABUSE", r'#define\s+\w+\s*\(.*\)\s*(?!.*_H$)', "low", "maintainability", "Function-like macro", "Use inline/template", "", 0.5),
    ("CQ-CPP-MALLOC", r'\bmalloc\s*\(', "medium", "maintainability", "malloc — manual memory", "Use RAII", "CWE-401", 0.5),
    ("CQ-CPP-FREE", r'\bfree\s*\(', "medium", "maintainability", "free — manual memory", "Use RAII", "CWE-415", 0.5),
    ("CQ-CPP-NEW-WITHOUT-SMART-PTR", r'\bnew\s+\w+(?!\s*\])', "low", "maintainability", "raw new — leak risk", "Use make_unique/make_shared", "CWE-401", 0.5),
    ("CQ-CPP-DELETE", r'\bdelete\s+\w+', "medium", "maintainability", "raw delete", "Use RAII smart pointers", "CWE-415", 0.5),
    ("CQ-CPP-C-STYLE-CAST", r'\(\s*(?:int|char|float|double|long|short|void)\s*\*?\s*\)\s*\w', "medium", "correctness", "C-style cast", "Use static_cast etc.", "", 0.6),
    ("CQ-CPP-SIGNED-UNSIGNED-COMPARE", r'\b\w+\s*[<>=!]+\s*\w+\s*\(\s*(?:size_t|unsigned)', "medium", "correctness", "Signed/unsigned compare", "Cast explicitly", "CWE-197", 0.5),
    ("CQ-CPP-AUTO-RETURN", r'\bauto\s+\w+\s*\(', "low", "maintainability", "auto return type", "Use explicit return types", "", 0.3),
    ("CQ-CPP-VOLATILE-THREAD", r'\bvolatile\s+\w+', "medium", "concurrency", "volatile for threading — not sync", "Use std::atomic", "CWE-362", 0.7),
    ("CQ-CPP-SYSTEM", r'\bsystem\s*\(', "high", "security", "system() — injection", "Use execve/fork", "CWE-78", 0.9),
]

NON_MAGIC_NUMBERS = {0,1,-1,2,-2,10,100,1000,10000,60,3600,86400,24,7,30,31,12,1024,16,32,64,128,256,512,80,443,8080,3000,5000,200,201,204,301,302,400,401,403,404,500,502,503,0.5,0.25,0.75,0.1,0.01,0.0,1.0,2.0}
INTENTIONAL_SUFFIXES = {"_timeout","_interval","_delay","_wait","_size","_limit","_max","_min","_count","_length","_width","_height","TIMEOUT","INTERVAL","DELAY","WAIT","SIZE","LIMIT","MAX","MIN","COUNT","LENGTH","WIDTH","HEIGHT","PORT","PORT_"}

def detect_magic_numbers(source, file, lang):
    findings = []
    lines = source.splitlines()
    if any(p in file.lower() for p in ['test','spec','__tests__','fixture']): return findings
    number_re = re.compile(r'(?<=[=,(\[\s:])\d+(?:\.\d+)?(?=[,)\]\s;])')
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith(('#','//','/*')): continue
        if 'import ' in stripped or 'require(' in stripped: continue
        if any(suf in stripped for suf in INTENTIONAL_SUFFIXES): continue
        if re.match(r'^\s*(?:width|height|margin|padding|top|left|right|bottom)\s*:', stripped): continue
        if re.match(r'^\s*(?:const|final|static|readonly|export\s+const)\s+\w+\s*=', stripped): continue
        if stripped.startswith('#'): continue
        for m in number_re.finditer(line):
            num_str = m.group()
            try: num = int(num_str) if '.' not in num_str else float(num_str)
            except: continue
            if num in NON_MAGIC_NUMBERS: continue
            if isinstance(num, int) and abs(num) <= 4: continue
            if line.count(',') >= 3: continue
            findings.append(CodeQualityIssue(file=file, line=i, rule_id="CQ-MAGIC-NUMBER", severity="low",
                category="maintainability", description=f"Magic number '{num_str}' — extract to constant",
                fix=f"Define: const X = {num_str}", confidence=0.4, language=lang))
            break
    return findings

def detect_complex_functions(source, file, lang):
    findings = []
    lines = source.splitlines()
    func_patterns = {
        "python": re.compile(r'^\s*def\s+(\w+)\s*\(([^)]*)\)'),
        "javascript": re.compile(r'^\s*(?:export\s+)?(?:const|let|var|function)\s+(\w+)\s*(?:=\s*(?:async\s*)?\(([^)]*)\)|\s*\(([^)]*)\))'),
        "go": re.compile(r'^func\s+(?:\([^)]+\)\s+)?(\w+)\s*\(([^)]*)\)'),
        "java": re.compile(r'^\s*(?:public|private|protected|static|final|\s)+\w+(?:<[^>]+>)?\s+(\w+)\s*\(([^)]*)\)'),
        "cpp": re.compile(r'^\s*(?:static\s+|inline\s+|extern\s+|virtual\s+)?[\w:*&<>]+\s+(\w+)\s*\(([^)]*)\)'),
    }
    func_re = func_patterns.get(lang)
    if not func_re: return findings
    for i, line in enumerate(lines, 1):
        m = func_re.match(line)
        if not m: continue
        func_name = m.group(1)
        params_str = ""
        if m.lastindex and m.lastindex >= 2:
            for g_idx in range(2, m.lastindex + 1):
                g = m.group(g_idx)
                if g: params_str = g; break
        if func_name in ("if","for","while","switch","catch","return","class","struct","enum","namespace"): continue
        if params_str.strip():
            param_count = params_str.count(",") + 1
            if param_count > 5:
                findings.append(CodeQualityIssue(file=file, line=i, rule_id="CQ-TOO-MANY-PARAMS", severity="medium",
                    category="maintainability", description=f"Function '{func_name}' has {param_count} params",
                    fix="Group into config object", confidence=0.7, language=lang))
        body_end = min(len(lines), i + 200)
        for j in range(i, min(len(lines), i + 200)):
            if j > i and func_re.match(lines[j-1]): body_end = j - 1; break
        func_length = body_end - i + 1
        if func_length > 80:
            findings.append(CodeQualityIssue(file=file, line=i, rule_id="CQ-LONG-FUNCTION", severity="medium" if func_length > 100 else "low",
                category="maintainability", description=f"Function '{func_name}' is {func_length} lines",
                fix="Extract helpers", confidence=0.6, language=lang))
        body = lines[i-1:body_end]
        max_indent = 0
        for bl in body:
            if not bl.rstrip(): continue
            max_indent = max(max_indent, len(bl) - len(bl.lstrip()))
        if max_indent >= 24:
            findings.append(CodeQualityIssue(file=file, line=i, rule_id="CQ-DEEP-NESTING", severity="medium",
                category="maintainability", description=f"Function '{func_name}' has {max_indent // 4} levels nesting",
                fix="Use early returns", confidence=0.6, language=lang))
        body_text = "\n".join(body)
        branches = (len(re.findall(r'\bif\b',body_text))+len(re.findall(r'\belse\b',body_text))+len(re.findall(r'\bfor\b',body_text))+
                    len(re.findall(r'\bwhile\b',body_text))+len(re.findall(r'\bcase\b',body_text))+len(re.findall(r'\bcatch\b',body_text))+
                    len(re.findall(r'&&|\|\|',body_text))+len(re.findall(r'\?.*:',body_text)))
        if branches > 10:
            findings.append(CodeQualityIssue(file=file, line=i, rule_id="CQ-HIGH-CYCLOMATIC", severity="medium" if branches > 15 else "low",
                category="maintainability", description=f"Function '{func_name}' cyclomatic complexity {branches+1}",
                fix="Extract branches", confidence=0.7, language=lang))
    return findings

def detect_design_smells(source, file, lang):
    findings = []
    lines = source.splitlines()
    if len(lines) > 500:
        findings.append(CodeQualityIssue(file=file, line=1, rule_id="CQ-GOD-CLASS-LONG", severity="medium",
            category="maintainability", description=f"God class — {len(lines)} lines (>500)", fix="Split", confidence=0.7, language=lang))
    func_patterns = {"python":r'^\s*def\s+\w+',"javascript":r'(?:function\s+\w+|const\s+\w+\s*=\s*(?:async\s*)?\([^)]*\)\s*=>)',
                     "go":r'^func\s+(?:\([^)]+\)\s+)?\w+',"java":r'(?:public|private|protected)\s+\w+\s+\w+\s*\(',
                     "cpp":r'\w+\s+\w+\s*\([^)]*\)\s*(?:const\s*)?\{'}
    pat = func_patterns.get(lang)
    func_count = 0
    if pat:
        for line in lines:
            if re.match(pat, line): func_count += 1
        if func_count > 20:
            findings.append(CodeQualityIssue(file=file, line=1, rule_id="CQ-GOD-CLASS-FUNCS", severity="medium",
                category="maintainability", description=f"God class — {func_count} functions (>20)", fix="Split", confidence=0.7, language=lang))
    consecutive_comments = 0
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#"):
            consecutive_comments += 1
        else:
            if consecutive_comments >= 5:
                findings.append(CodeQualityIssue(file=file, line=i-consecutive_comments, rule_id="CQ-COMMENTED-CODE",
                    severity="low", category="maintainability", description=f"{consecutive_comments} consecutive comment lines — likely dead code",
                    fix="Delete dead code", confidence=0.5, language=lang))
            consecutive_comments = 0
    todo_re = re.compile(r'(?:TODO|FIXME|HACK|XXX|BUG)\b', re.IGNORECASE)
    for i, line in enumerate(lines, 1):
        if todo_re.search(line):
            findings.append(CodeQualityIssue(file=file, line=i, rule_id="CQ-TODO-COMMENT", severity="low",
                category="maintainability", description="TODO/FIXME/HACK/XXX comment", fix="Track in issue tracker", confidence=0.6, language=lang))
    string_lits = {}
    str_re = re.compile(r'["\']([^"\']{5,})["\']')
    for i, line in enumerate(lines, 1):
        for m in str_re.finditer(line):
            s = m.group(1)
            if s.startswith("http") or "/" in s or "." in s: continue
            string_lits.setdefault(s, []).append(i)
    for s, line_nums in string_lits.items():
        if len(line_nums) >= 3:
            findings.append(CodeQualityIssue(file=file, line=line_nums[0], rule_id="CQ-DUPLICATE-STRING",
                severity="low", category="maintainability", description=f"String '{s[:30]}' appears {len(line_nums)} times",
                fix="Extract to constant", confidence=0.5, language=lang))
    return findings

def detect_test_quality_issues(source, file, lang):
    findings = []
    if not any(p in file.lower() for p in ['test','spec','__tests__']): return findings
    lines = source.splitlines()
    if lang == "python":
        for i, line in enumerate(lines, 1):
            if re.match(r'^\s*def\s+test_\w+', line):
                lookahead = "\n".join(lines[i:min(i+30, len(lines))])
                if "assert" not in lookahead and "self.assert" not in lookahead:
                    findings.append(CodeQualityIssue(file=file, line=i, rule_id="CQ-TEST-NO-ASSERT", severity="medium",
                        category="correctness", description="Test has no assertion", fix="Add assert", confidence=0.7, language=lang))
    elif lang == "javascript":
        for i, line in enumerate(lines, 1):
            if re.search(r'\b(?:it|test)\s*\(\s*["\']', line):
                lookahead = "\n".join(lines[i:min(i+20, len(lines))])
                if "expect(" not in lookahead and "assert" not in lookahead:
                    findings.append(CodeQualityIssue(file=file, line=i, rule_id="CQ-TEST-NO-ASSERT", severity="medium",
                        category="correctness", description="Test has no expect/assert", fix="Add expect()", confidence=0.6, language=lang))
    for i, line in enumerate(lines, 1):
        if re.search(r'\b(?:it|test)\.skip\b', line) or "@pytest.mark.skip" in line:
            findings.append(CodeQualityIssue(file=file, line=i, rule_id="CQ-SKIPPED-TEST", severity="low",
                category="correctness", description="Skipped test", fix="Fix or remove", confidence=0.7, language=lang))
    return findings

def _scan_resolver_pattern(source, rel):
    findings = []
    pattern = re.compile(r'try\s*\{[^}]*?[\w.]+\s*=\s*await\s+\w+[^}]*?\}\s*catch\s*\(\s*\w+\s*\)\s*\{[^}]*?[\w.]+\.error\s*=', re.DOTALL)
    for m in pattern.finditer(source):
        line_num = source[:m.start()].count("\n") + 1
        findings.append(CodeQualityIssue(file=rel, line=line_num, rule_id="CQ-RESOLVER-PATTERN", severity="medium",
            category="correctness", description="try/await/catch swallows errors into return field",
            fix="Use react-query or throw", cwe="CWE-755", confidence=0.7, language="javascript"))
    return findings

def _detect_axios_import_inconsistency(js_files, repo_root):
    findings = []
    files_default = []; files_create = []; files_auth = []
    for f in js_files:
        try: source = f.read_text(encoding="utf-8", errors="replace")
        except: continue
        rel = str(f.relative_to(repo_root)) if repo_root else str(f)
        if re.search(r'\baxios\.(?:get|post|put|delete|patch)\s*\(', source): files_default.append((rel, source))
        if re.search(r'\baxios\.create\s*\(', source): files_create.append((rel, source))
        if re.search(r'\b(?:authClient|apiClient|httpClient)\b', source): files_auth.append((rel, source))
    if len(files_default) >= 3 and len(files_create) >= 1:
        for rel, source in files_default[:20]:
            if any(rel == r for r, _ in files_create): continue
            if any(rel == r for r, _ in files_auth): continue
            for i, line in enumerate(source.splitlines(), 1):
                if re.search(r'\baxios\.(?:get|post|put|delete|patch)\s*\(', line):
                    findings.append(CodeQualityIssue(file=rel, line=i, rule_id="CQ-AXIOS-IMPORT-INCONSISTENCY", severity="low",
                        category="maintainability", description="axios.method() used directly — project also uses axios.create()",
                        fix="Use project's axios instance", confidence=0.6, language="javascript"))
                    break
    return findings

def get_rules_for_language(lang):
    return {"python":PY_RULES,"javascript":JS_RULES,"go":GO_RULES,"java":JAVA_RULES,"cpp":CPP_RULES}.get(lang, [])


# v4.5: Rules that should NOT be stripped of comments/strings — these rules
# are specifically about comments (TODO, noqa, type:ignore) or string content
# (hardcoded URLs, colors) and need to see the raw line.
_COMMENT_STRING_AWARE_RULES = {
    "CQ-PY-TODO", "CQ-PY-TYPE-IGNORE", "CQ-PY-NOQA",
    "CQ-TS-IGNORE", "CQ-ESLINT-DISABLE",
    "CQ-HARDCODED-COLOR", "CQ-HARDCODED-URL",
    "CQ-PY-EXCEPT-PASS",  # multi-line pattern, needs raw lines
    "CQ-PY-EXCEPT-EXCEPTION-PASS",  # multi-line pattern
    "CQ-PY-LONG-LINE",  # about line length, must see raw line
    "CQ-DEVTOOLS-IN-PROD",  # JSX, not Python
    "CQ-REPLACEALL-REGEX-NO-G",  # JS regex literal
    "CQ-LOCALSTORAGE-SET-NULL",  # JS
    "CQ-QUERYCLIENT-NO-DEFAULTS",  # JS
    "CQ-INDEX-AS-KEY",  # JSX
    "CQ-NO-KEY-IN-LIST",  # JSX
    "CQ-INLINE-STYLE",  # JSX
    "CQ-DEFAULT-PARAM-SIDEEFFECT",  # JS
    "CQ-USESTATE-DEFAULT-PARAM",  # JS
    "CQ-LOOSE-EQUALITY",  # JS
}


def _strip_python_comments_and_strings(source: str) -> List[str]:
    """Return source lines with comments and string literals stripped.

    v4.5: Uses Python's tokenize module to accurately identify comments,
    docstrings, and string literals. For each line, returns a version with
    comment and string content removed (replaced with empty string), so
    regex rules don't match on text inside comments/strings.
    """
    lines = source.splitlines()
    # Collect all (line_idx, start_col, end_col) ranges to remove
    removals: Dict[int, List[Tuple[int, int]]] = {}

    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(source).readline))
        for tok in tokens:
            if tok.type in (tokenize.COMMENT, tokenize.STRING):
                start_line = tok.start[0] - 1  # 0-indexed
                end_line = tok.end[0] - 1
                if start_line == end_line:
                    # Single-line: mark this range for removal
                    removals.setdefault(start_line, []).append(
                        (tok.start[1], tok.end[1])
                    )
                else:
                    # Multi-line string (docstring): mark full lines
                    for line_idx in range(start_line, min(end_line + 1, len(lines))):
                        if line_idx == start_line:
                            removals.setdefault(line_idx, []).append(
                                (tok.start[1], len(lines[line_idx]))
                            )
                        elif line_idx == end_line:
                            removals.setdefault(line_idx, []).append(
                                (0, tok.end[1])
                            )
                        else:
                            removals.setdefault(line_idx, []).append(
                                (0, len(lines[line_idx]))
                            )
    except (tokenize.TokenError, IndentationError, SyntaxError):
        pass

    # Apply removals: for each line, remove all marked ranges (in reverse order)
    stripped = list(lines)
    for line_idx, ranges in removals.items():
        if line_idx >= len(stripped):
            continue
        line = stripped[line_idx]
        # Sort ranges in reverse order so removals don't shift indices
        for start_col, end_col in sorted(ranges, key=lambda x: -x[0]):
            line = line[:start_col] + line[end_col:]
        stripped[line_idx] = line

    return stripped


def _strip_js_comments_and_strings(source: str) -> List[str]:
    """Strip JS/TS comments and string literals from source lines.

    v4.5: Simpler than Python's tokenize — uses regex to identify // comments,
    /* */ block comments, and ' " ` string literals, then blanks them out.
    """
    lines = source.splitlines()
    stripped = list(lines)
    in_block_comment = False

    for i, line in enumerate(lines):
        result = ""
        j = 0
        in_string = False
        string_char = ""
        while j < len(line):
            if in_block_comment:
                if line[j:j+2] == "*/":
                    in_block_comment = False
                    j += 2
                else:
                    j += 1
                continue
            if in_string:
                if line[j] == "\\":
                    result += line[j:j+2]
                    j += 2
                    continue
                if line[j] == string_char:
                    in_string = False
                    string_char = ""
                result += line[j]
                j += 1
                continue
            # Not in string or block comment
            if line[j:j+2] == "//":
                break  # rest of line is comment
            if line[j:j+2] == "/*":
                in_block_comment = True
                j += 2
                continue
            if line[j] in ('"', "'", "`"):
                in_string = True
                string_char = line[j]
                result += line[j]
                j += 1
                continue
            result += line[j]
            j += 1
        stripped[i] = result

    return stripped


def _get_stripped_lines(source: str, lang: str) -> List[str]:
    """Get source lines with comments and strings stripped for the language."""
    if lang == "python":
        return _strip_python_comments_and_strings(source)
    elif lang in ("javascript", "typescript"):
        return _strip_js_comments_and_strings(source)
    else:
        # For Go/Java/C/C++, use the JS stripper as a reasonable approximation
        return _strip_js_comments_and_strings(source)


def analyze_code_quality(file_path, repo_root=None):
    if not file_path.exists(): return []
    lang = get_language(file_path)
    if lang == "unknown": return []
    rel = str(file_path.relative_to(repo_root)) if repo_root else str(file_path)
    try: source = file_path.read_text(encoding="utf-8", errors="replace")
    except: return []
    findings = []
    rules = get_rules_for_language(lang)
    lines = source.splitlines()
    # v4.5: Get comment/string-stripped lines for rules that need them
    stripped_lines = _get_stripped_lines(source, lang)
    for i, line in enumerate(lines, 1):
        stripped_line = stripped_lines[i - 1] if i - 1 < len(stripped_lines) else line
        for rule_id, regex, severity, category, desc, fix, cwe, conf in rules:
            try:
                # v4.5: Use stripped line for most rules, but raw line for
                # rules that specifically check comments or string content
                if rule_id in _COMMENT_STRING_AWARE_RULES:
                    search_line = line
                else:
                    search_line = stripped_line
                if re.search(regex, search_line):
                    findings.append(CodeQualityIssue(file=rel, line=i, rule_id=rule_id, severity=severity,
                        category=category, description=desc, fix=fix, cwe=cwe, confidence=conf, language=lang))
            except re.error: continue
    findings += detect_magic_numbers(source, rel, lang)
    findings += detect_complex_functions(source, rel, lang)
    findings += detect_design_smells(source, rel, lang)
    findings += detect_test_quality_issues(source, rel, lang)
    if lang == "javascript": findings += _scan_resolver_pattern(source, rel)
    return findings

def analyze_repo_code_quality(repo_root, max_files=600):
    findings = []
    skip_dirs = {".git","__pycache__",".venv","venv","node_modules",".loomscan-cache","build","dist",".pytest_cache","coverage","target"}
    count = 0; js_files = []
    for p in repo_root.rglob("*"):
        if not p.is_file() or any(part in skip_dirs for part in p.parts): continue
        if p.suffix.lower() in ALL_SOURCE_EXTS:
            try: findings += analyze_code_quality(p, repo_root)
            except Exception: pass  # v4.5: suppressed — add logging
            if p.suffix.lower() in (".js",".jsx",".ts",".tsx",".mjs"): js_files.append(p)
            count += 1
            if count >= max_files: break
    findings += _detect_axios_import_inconsistency(js_files, repo_root)
    return findings
