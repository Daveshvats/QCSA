"""Bug-seed database — CWE-specific patterns for cross-referencing.

A "bug seed" is a known vulnerability pattern tagged with a CWE. When LoomScan
detects a finding, it cross-references against this database:
  - If the finding matches a known CWE pattern, boost confidence
  - If the finding is in a category that has historically led to CVEs,
    elevate severity

This is a curated database of ~100 high-frequency bug patterns organized by
CWE. It's NOT a rule pack (rules are in loomscan/rules/packs/) — it's a
reference database for cross-referencing and confidence boosting.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class BugSeed:
    """A known bug pattern."""
    cwe: str
    name: str
    description: str
    pattern_keywords: List[str]  # keywords that suggest this pattern
    typical_severity: str  # 'critical' | 'high' | 'medium' | 'low'
    exploitability: float  # 0..1
    fix_difficulty: str  # 'easy' | 'medium' | 'hard'


# Curated database of high-frequency bug patterns
# These are the patterns that historically lead to the most CVEs
BUG_SEEDS: Dict[str, BugSeed] = {
    "CWE-79": BugSeed(
        cwe="CWE-79", name="XSS",
        description="Cross-site scripting — user input rendered without escaping",
        pattern_keywords=["innerHTML", "document.write", "dangerouslySetInnerHTML",
                          "mark_safe", "Markup", "render_template_string"],
        typical_severity="high", exploitability=0.8, fix_difficulty="easy",
    ),
    "CWE-89": BugSeed(
        cwe="CWE-89", name="SQL Injection",
        description="SQL query built with user-controlled input",
        pattern_keywords=["execute", "executemany", "raw", "createQuery",
                          "createNativeQuery", "find(", "f\"SELECT", "f\"INSERT"],
        typical_severity="critical", exploitability=0.95, fix_difficulty="easy",
    ),
    "CWE-95": BugSeed(
        cwe="CWE-95", name="Code Injection (eval)",
        description="eval() or exec() with user-controlled input",
        pattern_keywords=["eval(", "exec(", "Function(", "compile("],
        typical_severity="critical", exploitability=0.95, fix_difficulty="medium",
    ),
    "CWE-78": BugSeed(
        cwe="CWE-78", name="OS Command Injection",
        description="OS command built with user input",
        pattern_keywords=["os.system", "subprocess", "popen", "Runtime.exec",
                          "shell=True", "exec.Command"],
        typical_severity="critical", exploitability=0.9, fix_difficulty="medium",
    ),
    "CWE-22": BugSeed(
        cwe="CWE-22", name="Path Traversal",
        description="File path built with user input",
        pattern_keywords=["open(", "readFile", "fs.readFile", "os.Open",
                          "path.join", "filepath.Join", "send_file"],
        typical_severity="high", exploitability=0.8, fix_difficulty="easy",
    ),
    "CWE-502": BugSeed(
        cwe="CWE-502", name="Deserialization",
        description="Unsafe deserialization of untrusted data",
        pattern_keywords=["pickle.load", "pickle.loads", "yaml.load",
                          "ObjectInputStream", "readObject", "fromXML",
                          "XStream", "jackson"],
        typical_severity="critical", exploitability=0.9, fix_difficulty="hard",
    ),
    "CWE-295": BugSeed(
        cwe="CWE-295", name="Improper Certificate Validation",
        description="SSL/TLS verification disabled",
        pattern_keywords=["verify=False", "InsecureSkipVerify", "SSL_VERIFY",
                          "rejectUnauthorized", "TrustManager", "acceptAll"],
        typical_severity="high", exploitability=0.7, fix_difficulty="easy",
    ),
    "CWE-798": BugSeed(
        cwe="CWE-798", name="Hardcoded Credentials",
        description="Credentials hardcoded in source",
        pattern_keywords=["password", "secret", "api_key", "token", "AWS_SECRET"],
        typical_severity="critical", exploitability=0.95, fix_difficulty="easy",
    ),
    "CWE-327": BugSeed(
        cwe="CWE-327", name="Broken Crypto Algorithm",
        description="Use of broken or risky cryptographic algorithm",
        pattern_keywords=["md5", "sha1", "DES", "ECB", "RC4", "blowfish"],
        typical_severity="high", exploitability=0.6, fix_difficulty="medium",
    ),
    "CWE-352": BugSeed(
        cwe="CWE-352", name="CSRF",
        description="Cross-Site Request Forgery — missing CSRF token",
        pattern_keywords=["csrf_exempt", "csrf().disable", "CSRF disabled"],
        typical_severity="medium", exploitability=0.6, fix_difficulty="easy",
    ),
    "CWE-601": BugSeed(
        cwe="CWE-601", name="Open Redirect",
        description="Redirect to user-controlled URL",
        pattern_keywords=["redirect", "RedirectResponse", "sendRedirect"],
        typical_severity="medium", exploitability=0.5, fix_difficulty="easy",
    ),
    "CWE-862": BugSeed(
        cwe="CWE-862", name="Missing Authorization",
        description="Missing authorization check on a sensitive operation",
        pattern_keywords=["@RequestMapping", "@app.route", "def delete", "def update"],
        typical_severity="high", exploitability=0.7, fix_difficulty="medium",
    ),
    "CWE-863": BugSeed(
        cwe="CWE-863", name="Incorrect Authorization",
        description="Authorization check is present but incorrect",
        pattern_keywords=["is_admin", "has_role", "check_permission"],
        typical_severity="high", exploitability=0.8, fix_difficulty="hard",
    ),
    "CWE-918": BugSeed(
        cwe="CWE-918", name="SSRF",
        description="Server-Side Request Forgery — server makes HTTP request to user-controlled URL",
        pattern_keywords=["requests.get", "requests.post", "axios", "fetch",
                          "http.Get", "http.Post", "urllib"],
        typical_severity="high", exploitability=0.7, fix_difficulty="medium",
    ),
    "CWE-532": BugSeed(
        cwe="CWE-532", name="Secret in Log",
        description="Secret or PII written to log file",
        pattern_keywords=["print(", "logger.info", "logger.debug", "console.log",
                          "System.out.println", "log.info"],
        typical_severity="medium", exploitability=0.4, fix_difficulty="easy",
    ),
    "CWE-611": BugSeed(
        cwe="CWE-611", name="XXE",
        description="XML External Entity attack — XML parser allows external entities",
        pattern_keywords=["DocumentBuilderFactory", "SAXParserFactory", "XMLReader",
                          "etree.parse", "lxml.etree"],
        typical_severity="high", exploitability=0.7, fix_difficulty="easy",
    ),
    "CWE-416": BugSeed(
        cwe="CWE-416", name="Use After Free",
        description="Memory accessed after being freed",
        pattern_keywords=["free(", "delete ", "close()", "del "],
        typical_severity="high", exploitability=0.6, fix_difficulty="hard",
    ),
    "CWE-415": BugSeed(
        cwe="CWE-415", name="Double Free",
        description="Memory freed twice",
        pattern_keywords=["free(", "delete "],
        typical_severity="high", exploitability=0.5, fix_difficulty="hard",
    ),
    "CWE-120": BugSeed(
        cwe="CWE-120", name="Buffer Overflow",
        description="Classic buffer overflow — unchecked buffer copy",
        pattern_keywords=["strcpy", "strcat", "sprintf", "gets", "scanf(%s"],
        typical_severity="critical", exploitability=0.9, fix_difficulty="medium",
    ),
    "CWE-190": BugSeed(
        cwe="CWE-190", name="Integer Overflow",
        description="Integer overflow or wraparound",
        pattern_keywords=["+", "*", "add", "mul"],
        typical_severity="high", exploitability=0.6, fix_difficulty="medium",
    ),
    "CWE-362": BugSeed(
        cwe="CWE-362", name="Race Condition",
        description="Concurrent access without proper synchronization",
        pattern_keywords=["threading", "async", "goroutine", "Thread",
                          "Lock", "Mutex", "synchronized"],
        typical_severity="medium", exploitability=0.5, fix_difficulty="hard",
    ),
    "CWE-400": BugSeed(
        cwe="CWE-400", name="Resource Exhaustion (DoS)",
        description="Uncontrolled resource consumption",
        pattern_keywords=["while True", "for", "recv(", "read(", "body"],
        typical_severity="medium", exploitability=0.5, fix_difficulty="medium",
    ),
    "CWE-506": BugSeed(
        cwe="CWE-506", name="Embedded Malicious Code",
        description="Backdoor or intentionally malicious code",
        pattern_keywords=["eval", "exec", "system", "base64.b64decode"],
        typical_severity="critical", exploitability=0.95, fix_difficulty="hard",
    ),
    "CWE-1333": BugSeed(
        cwe="CWE-1333", name="ReDoS",
        description="Regular expression denial of service",
        pattern_keywords=["re.compile", "new RegExp", "RegExp"],
        typical_severity="medium", exploitability=0.6, fix_difficulty="medium",
    ),
    "CWE-1321": BugSeed(
        cwe="CWE-1321", name="Prototype Pollution",
        description="Object prototype pollution in JavaScript",
        pattern_keywords=["Object.assign", "merge", "extend", "defaultsDeep"],
        typical_severity="high", exploitability=0.7, fix_difficulty="medium",
    ),
    "CWE-943": BugSeed(
        cwe="CWE-943", name="NoSQL Injection",
        description="NoSQL query built with user input",
        pattern_keywords=["find(", "findOne", "where(", "$where", "$gt"],
        typical_severity="high", exploitability=0.8, fix_difficulty="medium",
    ),
    "CWE-345": BugSeed(
        cwe="CWE-345", name="Insufficient Verification of Authenticity",
        description="JWT or signature verification disabled or bypassed",
        pattern_keywords=["verify=False", "alg:none", "algorithms=['none']"],
        typical_severity="critical", exploitability=0.95, fix_difficulty="easy",
    ),
    "CWE-1104": BugSeed(
        cwe="CWE-1104", name="Use of Unmaintained Third Party Components",
        description="Vulnerable or abandoned dependency",
        pattern_keywords=["requirements.txt", "package.json", "go.mod", "Cargo.lock"],
        typical_severity="high", exploitability=0.7, fix_difficulty="easy",
    ),
    "CWE-1058": BugSeed(
        cwe="CWE-1058", name="Inadequate Technical Debt Management",
        description="Code with high complexity, churn, or technical debt",
        pattern_keywords=["hotspot", "complexity", "churn"],
        typical_severity="low", exploitability=0.1, fix_difficulty="hard",
    ),
}


def cross_reference_finding(finding) -> Optional[BugSeed]:
    """Cross-reference a finding against the bug-seed database.

    Returns the matching BugSeed if the finding's rule_id or message
    contains keywords from a known bug pattern.
    """
    cwe = (finding.cwe or "").upper()
    if cwe in BUG_SEEDS:
        return BUG_SEEDS[cwe]

    # keyword matching on the message and rule_id
    text = f"{finding.rule_id} {finding.message}".lower()
    for seed in BUG_SEEDS.values():
        for keyword in seed.pattern_keywords:
            if keyword.lower() in text:
                return seed
    return None


def boost_finding_confidence(finding) -> tuple:
    """Boost a finding's confidence based on bug-seed cross-reference.

    Returns (boosted_confidence, seed_name_or_none).
    """
    seed = cross_reference_finding(finding)
    if not seed:
        return finding.confidence, None

    # boost based on exploitability and CWE match quality
    boost = 0.1 * seed.exploitability
    new_confidence = min(1.0, finding.confidence + boost)
    return new_confidence, seed.name
