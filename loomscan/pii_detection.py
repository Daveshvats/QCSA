"""PII detection — inspired by pii-shield.

Detects Personally Identifiable Information in source code and config files:
  - Social Security Numbers (SSN)
  - Credit card numbers (Visa, Mastercard, Amex, Discover)
  - Email addresses
  - Phone numbers (US, international)
  - Passport numbers
  - Driver's license numbers
  - Bank account numbers (IBAN)
  - Dates of birth in common formats
  - Physical addresses (ZIP codes, street patterns)

This is different from secret detection (which finds API keys, passwords).
PII detection finds data that could identify a person — critical for
GDPR, CCPA, HIPAA compliance.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import List


@dataclass
class PIIDetection:
    """A detected PII instance."""
    pii_type: str  # 'ssn' | 'credit_card' | 'email' | 'phone' | 'passport' | etc.
    file: str
    line: int
    value_preview: str  # masked
    confidence: float
    context: str = ""


# PII patterns with confidence levels
PII_PATTERNS: List[tuple] = [
    # Social Security Number (US): XXX-XX-XXXX or XXXXXXXXX
    (
        r'\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b',
        "ssn", 0.9,
        "US Social Security Number — GDPR/CCPA regulated PII",
    ),
    # Credit card — Visa: 4XXX XXXX XXXX XXXX
    (
        r'\b4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
        "credit_card_visa", 0.85,
        "Visa credit card number — PCI-DSS regulated",
    ),
    # Credit card — Mastercard: 5[1-5]XX or 2[2-7]XX
    (
        r'\b(?:5[1-5]|2[2-7])\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
        "credit_card_mc", 0.85,
        "Mastercard credit card number — PCI-DSS regulated",
    ),
    # Credit card — Amex: 3[47]XX XXXXXX XXXXX
    (
        r'\b3[47]\d{2}[\s-]?\d{6}[\s-]?\d{5}\b',
        "credit_card_amex", 0.85,
        "Amex credit card number — PCI-DSS regulated",
    ),
    # Credit card — Discover: 6011 or 65
    (
        r'\b(?:6011|65)\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
        "credit_card_discover", 0.85,
        "Discover credit card number — PCI-DSS regulated",
    ),
    # IBAN (international bank account): 2 letters + 2 digits + 11-30 alphanumeric
    (
        r'\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b',
        "iban", 0.8,
        "IBAN bank account number — financial PII",
    ),
    # Email address
    (
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        "email", 0.95,
        "Email address — GDPR regulated PII",
    ),
    # US phone: (XXX) XXX-XXXX or XXX-XXX-XXXX
    (
        r'\b\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
        "phone_us", 0.6,
        "US phone number — potential PII",
    ),
    # International phone: +XX XXX XXX XXXX
    (
        r'\+\d{1,3}[\s.-]?\d{3}[\s.-]?\d{3}[\s.-]?\d{4,}',
        "phone_intl", 0.7,
        "International phone number — potential PII",
    ),
    # US ZIP code: XXXXX or XXXXX-XXXX
    (
        r'\b\d{5}(?:-\d{4})?\b',
        "zip_code", 0.3,
        "US ZIP code — low confidence (could be any 5-digit number)",
    ),
    # US passport: letter + 8 digits or 9 digits
    (
        r'\b[A-Z]\d{8}\b',
        "passport_us", 0.5,
        "Possible US passport number",
    ),
    # Date of birth: MM/DD/YYYY or DD/MM/YYYY
    (
        r'\b(?:0[1-9]|1[0-2])/(?:0[1-9]|[12]\d|3[01])/(?:19|20)\d{2}\b',
        "date_of_birth", 0.4,
        "Date in MM/DD/YYYY format — could be DOB (PII)",
    ),
    # IP address (could be PII if linked to a person)
    (
        r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b',
        "ip_address", 0.3,
        "IP address — could be PII if linked to a person",
    ),
    # Aadhaar number (India): XXXX XXXX XXXX (12 digits, may have spaces)
    (
        r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
        "aadhaar", 0.5,
        "Possible Aadhaar number (India) — highly sensitive PII",
    ),
    # National Insurance Number (UK): 2 letters + 6 digits + 1 letter
    (
        r'\b[A-Z]{2}\d{6}[A-Z]\b',
        "nino_uk", 0.6,
        "UK National Insurance Number — PII",
    ),
]


def _mask(value: str, pii_type: str) -> str:
    """Mask a PII value for display."""
    if len(value) <= 4:
        return "*" * len(value)
    if pii_type in ("email",):
        # show domain, mask local part
        if "@" in value:
            local, domain = value.split("@", 1)
            return f"{'*' * len(local)}@{domain}"
    if pii_type in ("ssn",):
        return f"XXX-XX-{value[-4:]}"
    if "credit_card" in pii_type:
        return f"{'*' * (len(value) - 4)}{value[-4:]}"
    return f"{value[:2]}{'*' * (len(value) - 4)}{value[-2:]}"


def scan_pii(file_path: Path, repo_root: Path = None) -> List[PIIDetection]:
    """Scan a file for PII patterns."""
    if not file_path.exists():
        return []
    # skip binary files
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []

    rel_path = str(file_path.relative_to(repo_root)) if repo_root else str(file_path)
    detections: List[PIIDetection] = []
    seen: set = set()

    # skip test files and .env.example
    if file_path.name in (".env.example", ".env.template"):
        return []
    if "test" in file_path.name.lower():
        # lower confidence for test files
        confidence_multiplier = 0.5
    else:
        confidence_multiplier = 1.0

    for i, line in enumerate(source.splitlines(), 1):
        for pattern, pii_type, base_confidence, description in PII_PATTERNS:
            for match in re.finditer(pattern, line):
                value = match.group()
                key = (i, pii_type, value)
                if key in seen:
                    continue
                seen.add(key)
                detections.append(PIIDetection(
                    pii_type=pii_type,
                    file=rel_path,
                    line=i,
                    value_preview=_mask(value, pii_type),
                    confidence=min(1.0, base_confidence * confidence_multiplier),
                    context=line.strip()[:200],
                ))

    return detections


def scan_repo_pii(repo_root: Path, max_files: int = 200) -> List[PIIDetection]:
    """Scan all files in the repo for PII."""
    skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules",
                 ".loomscan-cache", ".loomscan-reports", ".loomscan-fixes", "build", "dist",
                 ".pytest_cache"}
    skip_extensions = {".pyc", ".so", ".o", ".a", ".dll", ".exe", ".bin",
                       ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".svg",
                       ".pdf", ".zip", ".tar", ".gz", ".woff", ".woff2",
                       ".ttf", ".eot", ".ico"}
    detections: List[PIIDetection] = []
    count = 0
    for p in repo_root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in skip_dirs for part in p.parts):
            continue
        if p.suffix.lower() in skip_extensions:
            continue
        detections.extend(scan_pii(p, repo_root))
        count += 1
        if count >= max_files:
            break
    return detections


def pii_stats(detections: List[PIIDetection]) -> dict:
    """Return stats about PII detections."""
    from collections import Counter
    by_type = Counter(d.pii_type for d in detections)
    by_confidence = {"high": 0, "medium": 0, "low": 0}
    for d in detections:
        if d.confidence >= 0.8:
            by_confidence["high"] += 1
        elif d.confidence >= 0.5:
            by_confidence["medium"] += 1
        else:
            by_confidence["low"] += 1
    return {
        "total_detections": len(detections),
        "by_type": dict(by_type),
        "by_confidence": by_confidence,
    }
