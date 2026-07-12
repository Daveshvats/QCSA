"""SARIF 2.1.0 output — the industry standard for static analysis results.

https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
Compatible with GitHub Code Scanning, Azure DevOps, VS Code SARIF Viewer.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import List
from datetime import datetime, timezone

from ..models import PipelineResult, Finding, Severity


_SEVERITY_TO_SARIF = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}


def to_sarif(result: PipelineResult, repo_root: Path) -> dict:
    """Convert a PipelineResult to a SARIF 2.1.0 document."""
    rules = {}
    results = []

    for finding in result.findings:
        rule_id = finding.rule_id
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_id.split(":")[-1][:50],
                "shortDescription": {"text": finding.message[:200]},
                "fullDescription": {"text": finding.message},
                "defaultConfiguration": {
                    "level": _SEVERITY_TO_SARIF.get(finding.severity, "warning")
                },
                "properties": {
                    "layer": finding.layer.value,
                    "cwe": finding.cwe,
                    "fingerprint": finding.fingerprint,
                },
            }

        decision = next((d for d, f in zip(result.decisions, result.findings)
                         if f is finding), None)
        results.append({
            "ruleId": rule_id,
            "level": _SEVERITY_TO_SARIF.get(finding.severity, "warning"),
            "message": {
                "text": finding.message +
                        (f" [Decision: {decision.decision.value}]" if decision else "")
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": finding.file,
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {
                        "startLine": finding.start_line,
                        "endLine": finding.end_line or finding.start_line,
                    }
                }
            }],
            "partialFingerprints": {
                "primaryLocationLineHash": finding.fingerprint,
            },
            "properties": {
                "confidence": finding.confidence,
                "blast_radius": finding.blast_radius.value,
                "exploitability": finding.exploitability,
                "cwe": finding.cwe,
                "fix_suggestion": finding.fix_suggestion,
                "fis_decision": decision.decision.value if decision else None,
                "fis_confidence_interval": list(decision.confidence_interval) if decision else None,
                "fis_reasoning": decision.reasoning if decision else None,
            },
        })

    # Build toolExecutionNotifications from layer timings + scanner health
    notifications = [
        {"level": "note", "message": {"text": f"Layer {layer} took {t:.2f}s"}}
        for layer, t in result.layer_timings.items()
    ]
    for entry in result.scanner_health:
        level = entry.get("level", "warning")
        scanner = entry.get("scanner", "unknown")
        err = entry.get("error", "")
        err_type = entry.get("error_type", "Exception")
        text = f"Scanner '{scanner}' failed: {err_type}: {err}"
        if level == "warning":
            notifications.append({"level": "warning", "message": {"text": text}})
        else:
            notifications.append({"level": "note", "message": {"text": text}})

    execution_successful = result.scanner_error_count == 0

    return {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "STCA Pipeline",
                    "version": "0.1.0",
                    "informationUri": "https://github.com/local/stca-pipeline",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": execution_successful,
                "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                "toolExecutionNotifications": notifications,
            }],
        }],
    }


def save_sarif(result: PipelineResult, repo_root: Path, out_path: Path) -> None:
    sarif = to_sarif(result, repo_root)
    out_path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
