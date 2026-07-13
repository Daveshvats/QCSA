"""Modern attack surfaces: LLM/AI, GraphQL, WebSocket, SSE, gRPC, WebRTC.

These are attack categories that traditional static analyzers don't cover
because they appeared in the last few years. Each is matched with curated
regex + multi-line patterns targeting the most common dangerous idioms.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple


@dataclass
class ModernAttackFinding:
    file: str
    line: int
    rule_id: str
    severity: str
    category: str        # llm | graphql | websocket | sse | grpc | webrtc
    description: str
    fix: str = ""
    cwe: str = ""
    confidence: float = 0.7
    language: str = ""


# =============================================================================
# Pattern catalogs
# =============================================================================

# Each pattern: (rule_id, regex, severity, description, fix, cwe, confidence, language_filter)
# language_filter: None = any, or set of extensions

LLM_PATTERNS: List[Tuple] = [
    ("LLM-PROMPT-INJECTION-USER", r"(?:system|prompt|instruction)\s*[:=]\s*[^,;]*?(?:user_input|user_query|input_text|message)",
     "critical",
     "User input concatenated into LLM system/prompt — prompt injection",
     "Use structured roles and validate / escape user input",
     "CWE-20", 0.85, None),
    ("LLM-PROMPT-INJECTION-FSTRING", r"(?:system|prompt)\s*[:=]\s*f['\"]",
     "critical",
     "LLM prompt built with f-string from user input — injection",
     "Use a template engine with proper escaping",
     "CWE-94", 0.8, {".py"}),
    ("LLM-PICKLE-LOAD", r"\bpickle\.loads?\s*\(",
     "critical",
     "pickle.load on possibly LLM-generated / untrusted data — RCE",
     "Use json.loads() or a restricted deserializer",
     "CWE-502", 0.9, {".py"}),
    ("LLM-OUTPUT-TO-EXEC", r"\b(?:exec|eval|os\.system|subprocess\.\w+)\s*\(\s*(?:llm|ai|model|response|output|result)\w*\.",
     "critical",
     "LLM output piped to exec/eval/os.system — indirect RCE",
     "Validate and parse the output; never execute it",
     "CWE-95", 0.9, None),
    ("LLM-NO-RATE-LIMIT", r"(?:openai|anthropic|cohere|llama)\.(?:chat|completion|generate)\w*\s*\(",
     "medium",
     "LLM call without visible rate-limit / cost guard — DoS / abuse",
     "Add rate-limiting and per-user cost caps",
     "CWE-770", 0.5, None),
    ("LLM-SQL-AGENT", r"(?:create_sql_agent|SQLDatabaseChain|SQLDatabaseSeqChain)\s*\(",
     "high",
     "LLM SQL agent — model can read/modify arbitrary DB rows",
     "Restrict with read-only credentials and table-level ACLs",
     "CWE-862", 0.8, None),
    ("LLM-FILESYSTEM-TOOL", r"(?:FilesystemTool|read_file|write_file|shell_tool)\s*[=(]",
     "high",
     "LLM agent given filesystem/shell tool — model can exfiltrate or destroy",
     "Sandbox with restricted paths and read-only mounts",
     "CWE-73", 0.75, None),
]

GRAPHQL_PATTERNS: List[Tuple] = [
    ("GRAPHQL-INTROSPECTION-ENABLED", r"introspection\s*:\s*true",
     "medium",
     "GraphQL introspection enabled — schema leak in production",
     "Set introspection: false in production",
     "CWE-200", 0.7, None),
    ("GRAPHQL-NO-DEPTH-LIMIT", r"maxDepth\s*[:=]\s*(?:null|undefined|0|Infinity)",
     "medium",
     "GraphQL has no depth limit — nested query DoS",
     "Set maxDepth (e.g. 7) in validation rules",
     "CWE-400", 0.65, None),
    ("GRAPHQL-NO-COST-ANALYSIS", r"validationRules\s*:\s*\[\s*\]",
     "low",
     "No cost-analysis rule on GraphQL server — expensive queries",
     "Add graphql-cost-analysis with per-field costs",
     "CWE-400", 0.5, None),
    ("GRAPHQL-BATCH-NO-LIMIT", r"GraphQLServer\s*\([^)]*batch\s*:\s*true",
     "medium",
     "GraphQL batching enabled without per-batch limit",
     "Add a max-batch-size limit (e.g. 10)",
     "CWE-400", 0.6, None),
]

WEBSOCKET_PATTERNS: List[Tuple] = [
    ("WS-NO-ORIGIN-CHECK", r"(?:on\(['\"]connection|wss?\.(?:on|handleUpgrade))['\"(]",
     "medium",
     "WebSocket connection handler — no origin verification seen",
     "Verify request.headers.origin against an allowlist",
     "CWE-346", 0.6, None),
    ("WS-NO-AUTH-ON-CONNECT", r"socket\.on\s*\(\s*['\"]connection['\"]\s*,\s*\([^)]*\)\s*=>\s*\{(?![^}]*auth|token)",
     "high",
     "WebSocket connect handler has no auth check",
     "Verify token before allowing the connection",
     "CWE-862", 0.7, {".js", ".ts", ".jsx", ".tsx"}),
    ("WS-BROADCAST-NO-PERMISSION", r"(?:io|socket)\.(?:emit|broadcast\.emit|to\([^)]+\)\.emit)\s*\(",
     "medium",
     "WebSocket broadcast without per-recipient permission check",
     "Filter recipients by permission before broadcasting",
     "CWE-862", 0.55, None),
]

SSE_PATTERNS: List[Tuple] = [
    ("SSE-NO-AUTH", r"text/event-stream",
     "medium",
     "SSE endpoint — verify it has auth (this rule flags the route for review)",
     "Add @login_required / session check on the SSE handler",
     "CWE-862", 0.5, None),
    ("SSE-NO-HEARTBEAT", r"EventSource\s*\(\s*['\"]",
     "low",
     "EventSource client without heartbeat — silent disconnects",
     "Server should emit :heartbeat every 15s",
     "CWE-400", 0.3, None),
]

GRPC_PATTERNS: List[Tuple] = [
    ("GRPC-NO-TLS", r"grpc\.Server\s*\(\s*\[\s*['\"][^'\"]*:\d+['\"]",
     "high",
     "gRPC server bound without TLS (plaintext port)",
     "Use grpc.ssl_server_credentials()",
     "CWE-319", 0.8, None),
    ("GRPC-NO-AUTH-INTERCEPTOR", r"interceptors\s*=\s*\[\s*\]",
     "medium",
     "gRPC server has no auth interceptor — every method is public",
     "Add an auth interceptor that validates JWT/mTLS",
     "CWE-862", 0.6, None),
    ("GRPC-REFLECTION-IN-PROD", r"grpc_reflection\.v1alpha\.serverReflectionEnabled",
     "medium",
     "gRPC reflection enabled — service schema leak in prod",
     "Disable reflection in production builds",
     "CWE-200", 0.65, None),
]

WEBRTC_PATTERNS: List[Tuple] = [
    ("WEBRTC-INSECURE-ICE", r"iceTransportPolicy\s*:\s*['\"]all['\"]",
     "medium",
     "WebRTC ICE policy 'all' — allows TURN over plaintext",
     "Use iceTransportPolicy: 'relay' for sensitive sessions",
     "CWE-319", 0.55, {".js", ".ts"}),
    ("WEBRTC-DATACHANNEL-NO-AUTH", r"createDataChannel\s*\(",
     "medium",
     "WebRTC DataChannel created — verify the peer is authenticated",
     "Authenticate peer via DTLS cert fingerprint",
     "CWE-862", 0.45, None),
    ("WEBRTC-LOGS-SDP", r"console\.\w+\s*\(\s*[^,)]*sdp",
     "medium",
     "SDP logged to console — may leak ICE candidates / IPs",
     "Do not log SDP in production",
     "CWE-532", 0.6, None),
]


_ALL_CATALOGS: List[Tuple[str, List[Tuple]]] = [
    ("llm", LLM_PATTERNS),
    ("graphql", GRAPHQL_PATTERNS),
    ("websocket", WEBSOCKET_PATTERNS),
    ("sse", SSE_PATTERNS),
    ("grpc", GRPC_PATTERNS),
    ("webrtc", WEBRTC_PATTERNS),
]


# =============================================================================
# Scanner
# =============================================================================

def scan_modern_attacks(file_path: Path) -> List[ModernAttackFinding]:
    """Scan a single file against all modern-attack catalogs."""
    if not file_path.exists():
        return []
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []
    file_str = str(file_path)
    ext = file_path.suffix.lower()
    out: List[ModernAttackFinding] = []
    lines = source.splitlines()
    for category, catalog in _ALL_CATALOGS:
        for entry in catalog:
            rule_id, pat, sev, desc, fix, cwe, conf, lang_filter = entry
            if lang_filter is not None and ext not in lang_filter:
                continue
            try:
                rx = re.compile(pat)
            except re.error:
                continue
            for i, line in enumerate(lines, 1):
                if rx.search(line):
                    out.append(ModernAttackFinding(
                        file=file_str, line=i, rule_id=rule_id, severity=sev,
                        category=category, description=desc, fix=fix, cwe=cwe,
                        confidence=conf, language=ext.lstrip(".")))
    return out


def scan_repo_modern_attacks(repo_root: Path) -> List[ModernAttackFinding]:
    """Walk a repo and scan every relevant source file."""
    out: List[ModernAttackFinding] = []
    exts = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".go", ".rb", ".java"}
    skip = {"node_modules", ".git", "vendor", "__pycache__", "dist", "build", ".venv"}
    for path in repo_root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in exts:
            continue
        if any(s in str(path) for s in skip):
            continue
        out.extend(scan_modern_attacks(path))
    return out
