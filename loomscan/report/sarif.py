"""SARIF 2.1.0 output — Pro tier with threadFlow for taint paths.

v5.3: Adds:
- threadFlow for taint path findings (GitHub Code Scanning renders these
  as multi-line traces, making LoomScan's taint findings visually identical
  to CodeQL's)
- run.taxonomies[] for LoomScan's custom rule categories
- rule.metadata with CWE, confidence, FIS decision
- Higher-fidelity rule definitions

https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
Compatible with GitHub Code Scanning, Azure DevOps, VS Code SARIF Viewer.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone

from ..models import PipelineResult, Finding, Severity


_SEVERITY_TO_SARIF = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}

# v5.3: LoomScan custom taxonomies for GitHub Code Scanning
_TAXONOMIES = [
    {
        "id": "LoomScan-Layer",
        "name": "LoomScan Analysis Layer",
        "shortDescription": {"text": "LoomScan analysis layer that produced the finding"},
        "contents": ["L0", "L0b", "L0c", "L0d", "L0e", "L0f",
                     "L1", "L2", "L3", "L4", "L5", "L6", "L7", "L8"],
    },
    {
        "id": "LoomScan-Engine",
        "name": "LoomScan Detection Engine",
        "shortDescription": {"text": "LoomScan detection engine that found the issue"},
        "contents": ["SAST", "CPG", "Taint", "Secret", "IaC", "SupplyChain",
                     "Typestate", "Metamorphic", "Differential", "KnowledgeGraph",
                     "SpecMining", "CodeQuality", "Hotspot", "Nullness"],
    },
]


def _build_thread_flow(finding: Finding) -> Optional[List[dict]]:
    """v5.3: Build a threadFlow for taint path findings.

    If the finding has a taint flow in its raw data (source → sink),
    produce a SARIF threadFlow that GitHub renders as a multi-line trace.

    Returns None if the finding doesn't have taint flow data.
    """
    raw = finding.raw or {}

    # Check for taint flow data (from CPG taint tracker)
    source = raw.get("source")
    sink = raw.get("sink")
    intermediate = raw.get("intermediate_functions", [])
    cross_file = raw.get("cross_file", False)

    if not source and not sink:
        return None

    # Also check for interprocedural taint data
    source_param = raw.get("source_param")
    sink_function = raw.get("sink_function")
    if source_param and sink_function:
        source = source_param
        sink = sink_function

    if not source or not sink:
        return None

    # Build the thread flow locations
    locations = []

    # Location 1: Source (where tainted data enters)
    locations.append({
        "location": {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": finding.file,
                    "uriBaseId": "%SRCROOT%",
                },
                "region": {
                    "startLine": finding.start_line,
                }
            },
            "message": {"text": f"Source: {source}"}
        },
        "kinds": ["source"],
        "role": "untrusted",
    })

    # Intermediate locations (functions the data flows through)
    for i, func in enumerate(intermediate):
        locations.append({
            "location": {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": finding.file,
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {
                        "startLine": finding.start_line,
                    }
                },
                "message": {"text": f"Flow: {func}()"}
            },
            "kinds": ["transition"],
        })

    # Location N: Sink (where tainted data reaches a dangerous function)
    locations.append({
        "location": {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": finding.file,
                    "uriBaseId": "%SRCROOT%",
                },
                "region": {
                    "startLine": finding.start_line,
                }
            },
            "message": {"text": f"Sink: {sink}(){f' [cross-file]' if cross_file else ''}"}
        },
        "kinds": ["sink"],
        "role": "dangerous",
    })

    return locations


def _build_code_flows(finding: Finding) -> List[dict]:
    """v5.3: Build codeFlows for findings that have taint path data.

    GitHub Code Scanning renders codeFlows as expandable multi-line traces.
    """
    thread_flow_locations = _build_thread_flow(finding)
    if thread_flow_locations is None:
        return []

    return [{
        "threadFlows": [{
            "locations": thread_flow_locations,
        }]
    }]


def to_sarif(result: PipelineResult, repo_root: Path) -> dict:
    """Convert a PipelineResult to a SARIF 2.1.0 document.

    v5.3: Pro tier — includes threadFlow for taint paths, taxonomies,
    and richer rule metadata.
    """
    rules: Dict[str, dict] = {}
    results = []

    for finding in result.findings:
        rule_id = finding.rule_id
        if rule_id not in rules:
            # v5.3: Richer rule definition with metadata
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_id.split(":")[-1][:50] if ":" in rule_id else rule_id[:50],
                "shortDescription": {"text": finding.message[:200]},
                "fullDescription": {"text": finding.message},
                "defaultConfiguration": {
                    "level": _SEVERITY_TO_SARIF.get(finding.severity, "warning")
                },
                "properties": {
                    "layer": finding.layer.value,
                    "cwe": finding.cwe,
                    "fingerprint": finding.fingerprint,
                    # v5.3: Add LoomScan-specific metadata
                    "severity": finding.severity.value,
                    "confidence": finding.confidence,
                    "blast_radius": finding.blast_radius.value,
                    "exploitability": finding.exploitability,
                    "tags": [
                        f"layer:{finding.layer.value}",
                        f"cwe:{finding.cwe}" if finding.cwe else "cwe:unknown",
                    ],
                },
            }

        decision = next((d for d, f in zip(result.decisions, result.findings)
                         if f is finding), None)

        # v5.3: Build the result with optional codeFlows
        sarif_result: dict = {
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
                # v5.3: Add severity for the workflow's "Fail on critical" check
                "severity": finding.severity.value,
            },
        }

        # v5.3: Add codeFlows for taint findings
        code_flows = _build_code_flows(finding)
        if code_flows:
            sarif_result["codeFlows"] = code_flows

        results.append(sarif_result)

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

    from .. import __version__
    return {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "LoomScan",
                    "version": __version__,
                    "informationUri": "https://github.com/Daveshvats/loomscan",
                    "rules": list(rules.values()),
                    # v5.3: Custom taxonomies for GitHub Code Scanning
                    "taxonomies": _TAXONOMIES,
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
    """Save SARIF report to file."""
    sarif = to_sarif(result, repo_root)
    out_path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
