"""Config file security scanner — Spring Boot, .env, Django, Node.js, Docker, Nginx."""
from __future__ import annotations
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

@dataclass
class ConfigIssue:
    file: str; line: int; rule_id: str; severity: str; description: str; fix: str; cwe: str; confidence: float = 0.8

CONFIG_FILES = {"application.properties","application-prod.properties","application-dev.properties",
    "application.yml","application.yaml","application-prod.yml","application-dev.yml",
    ".env",".env.production",".env.local","settings.py","config.js","config.json",
    "docker-compose.yml","docker-compose.yaml","nginx.conf","application.conf"}

def is_config_file(file_path):
    name = file_path.name.lower()
    if name in CONFIG_FILES: return True
    if name.startswith("application-") and name.endswith((".properties",".yml",".yaml")): return True
    if name.startswith(".env"): return True
    return False

PROPERTIES_RULES = [
    ("CFG-JWT-SECRET-HARDCODED", r'(?:jwt\.secret|jwt\.signing-key)\s*=\s*(?!.*\$\{).+', "critical", "Hardcoded JWT secret", "Use ${JWT_SECRET}", "CWE-321", 0.9),
    ("CFG-DB-PASSWORD-HARDCODED", r'(?:spring\.datasource\.password|db\.password)\s*=\s*(?!.*\$\{).+', "critical", "Hardcoded DB password", "Use ${DB_PASSWORD}", "CWE-798", 0.95),
    ("CFG-DB-USERNAME-HARDCODED", r'(?:spring\.datasource\.username|db\.username)\s*=\s*(?!.*\$\{).+', "medium", "Hardcoded DB username", "Use ${DB_USERNAME}", "CWE-798", 0.6),
    ("CFG-SPRING-ADMIN-PASSWORD", r'spring\.security\.user\.password\s*=\s*(?!.*\$\{).+', "high", "Spring admin password hardcoded", "Use ${ADMIN_PASSWORD}", "CWE-798", 0.85),
    ("CFG-CORS-WILDCARD", r'(?:app\.cors\.allowed-origins|cors\.allowed-origins)\s*=\s*\*', "high", "CORS wildcard", "Restrict origins", "CWE-942", 0.85),
    ("CFG-CIRCULAR-REFERENCES", r'spring\.main\.allow-circular-references\s*=\s*true', "medium", "Circular references allowed", "Refactor", "CWE-1047", 0.7),
    ("CFG-DDL-AUTO-UPDATE", r'spring\.jpa\.hibernate\.ddl-auto\s*=\s*(?:update|create|create-drop)', "high", "ddl-auto=update — dangerous in prod", "Use validate", "CWE-1188", 0.85),
    ("CFG-H2-CONSOLE", r'spring\.h2\.console\.enabled\s*=\s*true', "medium", "H2 console enabled", "Disable in prod", "CWE-489", 0.7),
    ("CFG-SWAGGER-NO-AUTH", r'springdoc\.swagger-ui\.path\s*=', "low", "Swagger UI — verify protected", "Disable in prod", "CWE-489", 0.4),
    ("CFG-SHOW-SQL", r'spring\.jpa\.show-sql\s*=\s*true', "low", "show-sql — PII in logs", "Set false", "CWE-532", 0.5),
    ("CFG-DEBUG-MODE", r'(?:debug|spring\.main\.debug)\s*=\s*true', "medium", "Debug mode enabled", "Set false", "CWE-489", 0.6),
    ("CFG-ACTUATOR-EXPOSE-ALL", r'management\.endpoints\.web\.exposure\.include\s*=\s*\*', "high", "Actuator all endpoints", "Restrict to health,info", "CWE-200", 0.85),
    ("CFG-SSL-DISABLED", r'(?:server\.ssl\.enabled|https\.enabled)\s*=\s*false', "high", "SSL disabled", "Enable SSL", "CWE-319", 0.85),
    ("CFG-API-KEY-HARDCODED", r'(?:api\.key|apikey|api-key|secret\.key)\s*=\s*(?!.*\$\{)["\'][^"\']{10,}["\']', "critical", "Hardcoded API key", "Use ${API_KEY}", "CWE-798", 0.9),
    ("CFG-AWS-CREDENTIALS", r'(?:aws\.secret-key|aws\.access-key-id)\s*=\s*(?!.*\$\{).+', "critical", "AWS credentials hardcoded", "Use IAM roles", "CWE-798", 0.95),
    ("CFG-SESSION-COOKIE-INSECURE", r'server\.servlet\.session\.cookie\.secure\s*=\s*false', "high", "Session cookie not secure", "Set true", "CWE-614", 0.85),
    ("CFG-SESSION-COOKIE-NO-HTTPONLY", r'server\.servlet\.session\.cookie\.http-only\s*=\s*false', "high", "Session cookie not httpOnly", "Set true", "CWE-1004", 0.85),
    # YAML-specific rules (v2.4 claim — restored)
    ("CFG-YAML-JWT-SECRET", r'(?:jwt|jwt-secret|secretKey)\s*:\s*(?!.*\$\{)["\'][^"\']+["\']', "critical", "Hardcoded JWT secret in YAML", "Use ${JWT_SECRET}", "CWE-321", 0.85),
    ("CFG-YAML-DB-PASSWORD", r'(?:password|db-password)\s*:\s*(?!.*\$\{)["\'][^"\']+["\']', "critical", "Hardcoded DB password in YAML", "Use ${DB_PASSWORD}", "CWE-798", 0.9),
    ("CFG-YAML-CORS-WILDCARD", r'allowed-origins\s*:\s*\*', "high", "CORS wildcard in YAML", "Restrict origins", "CWE-942", 0.85),
    ("CFG-YAML-DEBUG", r'debug\s*:\s*true', "medium", "Debug mode in YAML", "Set false", "CWE-489", 0.6),
]

def scan_config_file(file_path, repo_root=None):
    if not file_path.exists() or not is_config_file(file_path): return []
    rel = str(file_path.relative_to(repo_root)) if repo_root else str(file_path)
    try: source = file_path.read_text(encoding="utf-8", errors="replace")
    except: return []
    findings = []
    lines = source.splitlines()
    for i, line in enumerate(lines, 1):
        for rule_id, pattern, severity, desc, fix, cwe, conf in PROPERTIES_RULES:
            try:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(ConfigIssue(file=rel, line=i, rule_id=f"L0.cfg.{rule_id}", severity=severity,
                        description=desc, fix=fix, cwe=cwe, confidence=conf))
            except re.error: continue
    if file_path.name.startswith(".env"):
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"): continue
            if re.match(r'^\s*(?:PASSWORD|SECRET|KEY|TOKEN|API_KEY)\w*\s*=\s*.+', stripped, re.IGNORECASE):
                findings.append(ConfigIssue(file=rel, line=i, rule_id="L0.cfg.CFG-ENV-SECRET", severity="medium",
                    description=f"Secret in .env: {stripped.split('=')[0]}", fix="Ensure .env in .gitignore", cwe="CWE-798", confidence=0.6))
    return findings

def scan_repo_configs(repo_root, max_files=50):
    findings = []
    skip_dirs = {".git","__pycache__",".venv","venv","node_modules",".loomscan-cache","build","dist","target"}
    count = 0
    for p in repo_root.rglob("*"):
        if not p.is_file() or any(part in skip_dirs for part in p.parts): continue
        if is_config_file(p):
            findings += scan_config_file(p, repo_root)
            count += 1
            if count >= max_files: break
    return findings
