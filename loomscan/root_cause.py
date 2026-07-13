"""Root cause analysis — inspired by OpenStack Vitrage.

Vitrage correlates alarms across OpenStack services to find the root cause:
"the database is slow" + "disk is full" + "backup job running" → root cause
is the backup job filling the disk.

We do the same for LoomScan findings:
  - Group findings that share a common source (same function, same file, same pattern)
  - Identify "root cause" findings that likely caused the others
  - Present correlated findings as a tree, not a flat list

Example:
  Finding 1: eval() at line 10
  Finding 2: SQL injection at line 15
  Finding 3: Missing input validation at line 8

  RCA: Finding 3 (missing validation) is the root cause — if input were
  validated at line 8, the eval() at line 10 and SQL injection at line 15
  would both be mitigated.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from collections import defaultdict


@dataclass
class RootCauseCluster:
    """A cluster of findings with a shared root cause."""
    root_cause_id: str  # fingerprint of the root cause finding
    root_cause_message: str
    root_cause_file: str
    root_cause_line: int
    correlated_findings: List[str] = field(default_factory=list)  # fingerprints
    cluster_type: str = ""  # 'shared_source' | 'shared_sink' | 'shared_pattern' | 'cascade'
    description: str = ""


def find_root_causes(findings: List) -> List[RootCauseCluster]:
    """Correlate findings and identify root causes.

    Heuristics:
      1. Findings in the same function that are caused by missing input
         validation → the validation finding is the root cause
      2. Findings that share a source variable → earliest line is root cause
      3. Findings where one is a "missing check" and others are consequences
      4. Findings with the same CWE in the same file → likely related
    """
    clusters: List[RootCauseCluster] = []
    seen: set = set()

    # Group by file
    by_file: Dict[str, List] = defaultdict(list)
    for f in findings:
        by_file[f.file].append(f)

    for file, file_findings in by_file.items():
        if len(file_findings) < 2:
            continue

        # Sort by line number
        sorted_findings = sorted(file_findings, key=lambda f: f.start_line)

        # Heuristic 1: "missing validation" / "missing check" as root cause
        validation_findings = [
            f for f in sorted_findings
            if any(kw in f.rule_id.lower() or kw in f.message.lower()
                   for kw in ["missing", "validation", "unchecked", "no_check",
                              "nullness", "none", "guard", "precondition"])
        ]
        consequence_findings = [
            f for f in sorted_findings
            if f not in validation_findings
            and any(kw in f.rule_id.lower() or kw in f.message.lower()
                    for kw in ["injection", "eval", "exec", "traversal",
                               "xss", "ssrf", "redirect", "dereference"])
        ]

        for val_f in validation_findings:
            # find consequences after this validation finding
            consequences = [
                f for f in consequence_findings
                if f.start_line > val_f.start_line
                and f.start_line <= val_f.start_line + 30  # within 30 lines
                and f.fingerprint not in seen
            ]
            if consequences:
                cluster = RootCauseCluster(
                    root_cause_id=val_f.fingerprint,
                    root_cause_message=val_f.message,
                    root_cause_file=val_f.file,
                    root_cause_line=val_f.start_line,
                    correlated_findings=[f.fingerprint for f in consequences],
                    cluster_type="missing_validation",
                    description=f"Missing validation at line {val_f.start_line} likely causes {len(consequences)} downstream vulnerabilities",
                )
                clusters.append(cluster)
                seen.add(val_f.fingerprint)
                for c in consequences:
                    seen.add(c.fingerprint)

        # Heuristic 2: Same CWE in same file → cluster
        by_cwe: Dict[str, List] = defaultdict(list)
        for f in sorted_findings:
            if f.fingerprint not in seen and f.cwe:
                by_cwe[f.cwe].append(f)

        for cwe, cwe_findings in by_cwe.items():
            if len(cwe_findings) >= 2:
                # earliest finding is likely the root cause
                root = cwe_findings[0]
                cluster = RootCauseCluster(
                    root_cause_id=root.fingerprint,
                    root_cause_message=root.message,
                    root_cause_file=root.file,
                    root_cause_line=root.start_line,
                    correlated_findings=[f.fingerprint for f in cwe_findings[1:]],
                    cluster_type="shared_cwe",
                    description=f"{len(cwe_findings)} findings with {cwe} in {file} — likely share a root cause",
                )
                clusters.append(cluster)
                seen.update(f.fingerprint for f in cwe_findings)

        # Heuristic 3: Findings sharing a source variable (from taint tracking)
        taint_findings = [
            f for f in sorted_findings
            if "taint" in f.rule_id.lower() or "cpg_taint" in f.rule_id.lower()
        ]
        by_source: Dict[str, List] = defaultdict(list)
        for f in taint_findings:
            source = f.raw.get("source", "") if f.raw else ""
            if source:
                by_source[source].append(f)

        for source, source_findings in by_source.items():
            if len(source_findings) >= 2:
                root = min(source_findings, key=lambda f: f.start_line)
                if root.fingerprint not in seen:
                    cluster = RootCauseCluster(
                        root_cause_id=root.fingerprint,
                        root_cause_message=root.message,
                        root_cause_file=root.file,
                        root_cause_line=root.start_line,
                        correlated_findings=[f.fingerprint for f in source_findings if f != root],
                        cluster_type="shared_source",
                        description=f"Multiple taint flows from same source '{source}' — fixing the source fixes all downstream",
                    )
                    clusters.append(cluster)
                    seen.add(root.fingerprint)

    return clusters


def rca_stats(clusters: List[RootCauseCluster]) -> dict:
    """Return RCA statistics."""
    from collections import Counter
    by_type = Counter(c.cluster_type for c in clusters)
    total_correlated = sum(len(c.correlated_findings) for c in clusters)
    return {
        "total_clusters": len(clusters),
        "total_correlated_findings": total_correlated,
        "by_type": dict(by_type),
        "findings_explained": total_correlated + len(clusters),
    }
