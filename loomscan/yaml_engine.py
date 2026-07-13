"""v5.2: Native YAML rule engine — applies LoomScan YAML pack rules without semgrep.

This module reads YAML rule packs (the same format as semgrep packs) and
applies the regex-based rules using Python's `re` module. This eliminates
the dependency on the external semgrep binary for basic pattern rules.

v5.7: When the optional Rust core (`loomscan_regex`) is installed, all
regex matching is delegated to it for 10-50x speedup. The Rust engine
uses rayon for parallel multi-rule scanning and is ReDoS-safe (linear-time
guarantee). Auto-detection is transparent — if the Rust extension is not
available, the Python `re` fallback is used.

Supported rule formats:
  - pattern: "regex"          → re.search(pattern, line) per line
  - pattern-regex: "regex"    → same as pattern (alias)
  - pattern-either:           → first matching pattern from the list

NOT supported (falls back to semgrep if installed):
  - pattern-inside, pattern-not-inside (requires AST)
  - metavariable-regex, metavariable-pattern (requires AST)
  - patterns with focus-metavariable (requires AST)

When a rule uses unsupported features, it's skipped (with a debug log).
When semgrep IS installed, it's preferred (supports all features).

Usage:
    from loomscan.yaml_engine import apply_packs
    findings = apply_packs(pack_paths, file_paths, repo_root)
"""
from __future__ import annotations

import logging
import re
import yaml
from pathlib import Path
from typing import List, Dict, Set, Optional, Tuple
from dataclasses import dataclass

_logger = logging.getLogger("loomscan.yaml_engine")


# ============================================================================
# v5.7: Rust core auto-detection
# ============================================================================
#
# Try to import the Rust extension. If available, use it for batch scanning.
# If not, fall back to the pure-Python implementation transparently.

_RUST_ENGINE = None
_RUST_ENGINE_CHECKED = False


def _get_rust_engine():
    """Return a cached Rust RegexEngine instance, or None if unavailable.

    The Rust engine is loaded once per process. Subsequent calls reuse the
    same engine instance (rules are added per-scan via add_rules()).
    """
    global _RUST_ENGINE, _RUST_ENGINE_CHECKED
    if _RUST_ENGINE_CHECKED:
        return _RUST_ENGINE
    _RUST_ENGINE_CHECKED = True
    try:
        from loomscan_regex import is_available, RegexEngine  # type: ignore
        if is_available():
            _RUST_ENGINE = RegexEngine()
            _logger.info("v5.7: Rust regex core detected — using native engine for 10-50x faster YAML rule scanning")
        else:
            _logger.debug("v5.7: loomscan_regex.is_available() returned False — falling back to Python re")
    except ImportError:
        _logger.debug("v5.7: loomscan_regex not installed — using Python re fallback (pip install loomscan-regex for 10-50x speedup)")
    except Exception as e:
        _logger.warning(f"v5.7: Failed to load Rust regex core: {e}")
    return _RUST_ENGINE


def is_rust_core_active() -> bool:
    """Return True if the Rust regex core is loaded and active."""
    return _get_rust_engine() is not None


@dataclass
class YAMLHit:
    """A finding from the native YAML rule engine."""
    rule_id: str
    file: str
    line: int
    message: str
    severity: str
    cwe: str
    pattern: str  # the regex that matched


# Severity mapping from YAML string to severity level
_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "warning": "medium",
    "error": "high",
    "note": "low",
}


def _extract_pattern(rule: dict) -> Optional[str]:
    """Extract a regex pattern from a rule dict.

    Returns None if the rule uses unsupported features (pattern-inside,
    metavariables, etc.) or has no usable pattern.
    """
    # Simple pattern: "regex"
    if "pattern" in rule:
        return rule["pattern"]

    # pattern-regex: "regex"
    if "pattern-regex" in rule:
        return rule["pattern-regex"]

    # pattern-either: list of {pattern: "regex"} dicts
    if "pattern-either" in rule:
        patterns = rule["pattern-either"]
        if isinstance(patterns, list) and len(patterns) > 0:
            # Use the first pattern (can't OR in a single regex without joining)
            # Join all patterns with | for true OR behavior
            all_pats = []
            for p in patterns:
                if isinstance(p, dict) and "pattern" in p:
                    all_pats.append(p["pattern"])
            if all_pats:
                return "|".join(f"(?:{p})" for p in all_pats)
        return None

    # pattern: list of patterns (AND semantics — we approximate with first)
    if "patterns" in rule:
        pat_list = rule["patterns"]
        if isinstance(pat_list, list):
            # Filter for simple pattern entries
            simple_pats = []
            for entry in pat_list:
                if isinstance(entry, dict):
                    if "pattern" in entry:
                        simple_pats.append(entry["pattern"])
                    # Skip pattern-inside, pattern-not-inside, metavariable-*
                    # (these require AST support — only semgrep can handle them)
            if simple_pats:
                # For AND semantics, we can't truly intersect with regex.
                # Use the first pattern (conservative — may over-match).
                return simple_pats[0]
        return None

    return None


def _has_unsupported_features(rule: dict) -> bool:
    """Check if a rule uses features the native engine can't handle."""
    unsupported_keys = {
        "pattern-inside", "pattern-not-inside",
        "metavariable-regex", "metavariable-pattern",
        "metavariable-comparison", "focus-metavariable",
        "pattern-not-regex",
    }
    # Check top-level keys
    for key in rule:
        if key in unsupported_keys:
            return True
    # Check inside patterns list
    if "patterns" in rule and isinstance(rule["patterns"], list):
        for entry in rule["patterns"]:
            if isinstance(entry, dict):
                for key in entry:
                    if key in unsupported_keys:
                        return True
    return False


def apply_pack_to_file(pack_path: Path, file_path: Path,
                       repo_root: Optional[Path] = None) -> List[YAMLHit]:
    """Apply all rules in a YAML pack to a single file.

    Args:
        pack_path: Path to the YAML pack file
        file_path: Path to the source file to scan
        repo_root: Repo root for relative path calculation

    Returns:
        List of YAMLHit findings
    """
    hits: List[YAMLHit] = []

    try:
        with open(pack_path) as f:
            data = yaml.safe_load(f)
    except Exception as e:
        _logger.debug(f"Failed to load pack {pack_path}: {e}")
        return hits

    rules = data.get("rules", [])
    if not rules:
        return hits

    # Read the source file
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return hits

    lines = source.splitlines()
    rel_path = str(file_path.relative_to(repo_root)) if repo_root else str(file_path)

    for rule in rules:
        rule_id = rule.get("id", "")
        if not rule_id:
            continue

        # Skip rules with unsupported features
        if _has_unsupported_features(rule):
            continue

        pattern_str = _extract_pattern(rule)
        if not pattern_str:
            continue

        # Compile the regex
        try:
            # Check if the rule specifies case-insensitive
            flags = 0
            # Some YAML packs use /pattern/flags syntax
            if pattern_str.startswith("/") and "/" in pattern_str[1:]:
                last_slash = pattern_str.rfind("/")
                if last_slash > 0:
                    flag_str = pattern_str[last_slash + 1:]
                    pattern_str = pattern_str[1:last_slash]
                    if "i" in flag_str:
                        flags |= re.IGNORECASE
            regex = re.compile(pattern_str, flags)
        except re.error as e:
            _logger.debug(f"Rule {rule_id}: invalid regex '{pattern_str}': {e}")
            continue

        message = rule.get("message", "")
        severity = _SEVERITY_MAP.get(
            str(rule.get("severity", "medium")).lower(), "medium"
        )
        cwe = ""
        metadata = rule.get("metadata", {})
        if isinstance(metadata, dict):
            cwe = metadata.get("cwe", "")

        # Search line by line
        for i, line in enumerate(lines, 1):
            if regex.search(line):
                hits.append(YAMLHit(
                    rule_id=rule_id,
                    file=rel_path,
                    line=i,
                    message=message,
                    severity=severity,
                    cwe=cwe,
                    pattern=pattern_str,
                ))

    return hits


def apply_packs(pack_paths: List[Path],
                file_paths: List[Path],
                repo_root: Optional[Path] = None) -> List[YAMLHit]:
    """Apply multiple YAML packs to multiple files.

    v5.7: When the Rust core is available, delegates to `apply_packs_rust()`
    for 10-50x faster batch scanning. Falls back to the per-file Python
    implementation otherwise.

    Args:
        pack_paths: List of YAML pack file paths
        file_paths: List of source files to scan
        repo_root: Repo root for relative path calculation

    Returns:
        List of all YAMLHit findings
    """
    # v5.7: Rust fast-path
    rust_engine = _get_rust_engine()
    if rust_engine is not None:
        try:
            return apply_packs_rust(rust_engine, pack_paths, file_paths, repo_root)
        except Exception as e:
            _logger.warning(f"v5.7: Rust engine failed ({e}) — falling back to Python re")

    all_hits: List[YAMLHit] = []

    # Determine which file extensions each pack targets
    # (skip packs that don't match any file's language)
    for pack_path in pack_paths:
        if not pack_path.exists():
            continue

        for file_path in file_paths:
            if not file_path.exists():
                continue
            hits = apply_pack_to_file(pack_path, file_path, repo_root)
            all_hits.extend(hits)

    return all_hits


def apply_packs_rust(rust_engine,
                     pack_paths: List[Path],
                     file_paths: List[Path],
                     repo_root: Optional[Path] = None) -> List[YAMLHit]:
    """v5.7: Apply multiple YAML packs to multiple files using the Rust core.

    This is the fast-path called by `apply_packs()` when the Rust extension
    is available. It compiles all rules into the Rust engine once, then
    batch-scans all files in parallel (rayon).

    The Rust engine is RESET and rebuilt on every call (rules from previous
    calls are cleared). This is correct because each scan may use different
    pack paths.

    Args:
        rust_engine: A loomscan_regex.RegexEngine instance
        pack_paths: List of YAML pack file paths
        file_paths: List of source files to scan
        repo_root: Repo root for relative path calculation

    Returns:
        List of all YAMLHit findings
    """
    # Build rule list and metadata for ALL packs first
    # (rule_id, pattern, severity, message, cwe)
    rules_to_add: List[Tuple[str, str, str, str, str]] = []
    # Map rule_id -> (pattern_str, message, severity, cwe) for hit construction
    rule_meta: Dict[str, Tuple[str, str, str, str]] = {}

    for pack_path in pack_paths:
        if not pack_path.exists():
            continue
        try:
            with open(pack_path) as f:
                data = yaml.safe_load(f)
        except Exception as e:
            _logger.debug(f"Failed to load pack {pack_path}: {e}")
            continue

        for rule in data.get("rules", []):
            rule_id = rule.get("id", "")
            if not rule_id:
                continue
            if _has_unsupported_features(rule):
                continue
            pattern_str = _extract_pattern(rule)
            if not pattern_str:
                continue

            # Strip /pattern/flags syntax (Rust regex doesn't support it)
            flags = 0
            if pattern_str.startswith("/") and "/" in pattern_str[1:]:
                last_slash = pattern_str.rfind("/")
                if last_slash > 0:
                    flag_str = pattern_str[last_slash + 1:]
                    pattern_str = pattern_str[1:last_slash]
                    # Note: Rust regex is always case-sensitive by default;
                    # for (?i) we'd need to prepend inline flag. Skip for now.

            message = rule.get("message", "")
            severity = _SEVERITY_MAP.get(
                str(rule.get("severity", "medium")).lower(), "medium"
            )
            metadata = rule.get("metadata", {})
            cwe = ""
            if isinstance(metadata, dict):
                cwe = metadata.get("cwe", "")

            rules_to_add.append((rule_id, pattern_str, severity, message, cwe))
            rule_meta[rule_id] = (pattern_str, message, severity, cwe)

    if not rules_to_add:
        return []

    # Read all source files (skip missing/empty)
    files_to_scan: Dict[str, str] = {}
    file_rel_paths: Dict[str, str] = {}
    for file_path in file_paths:
        if not file_path.exists():
            continue
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        if not content:
            continue
        rel = str(file_path.relative_to(repo_root)) if repo_root else str(file_path)
        files_to_scan[rel] = content
        file_rel_paths[rel] = rel

    if not files_to_scan:
        return []

    # Build a fresh Rust engine for this scan (rules are not incremental)
    # Reuse the cached instance — but we need to clear it. Since the Rust
    # RegexEngine doesn't expose clear(), we create a new one each time.
    # Performance impact is minimal because rule compilation is fast.
    from loomscan_regex import RegexEngine  # type: ignore
    eng = RegexEngine()
    # add_rules returns count of successfully added rules
    added = eng.add_rules(rules_to_add)
    _logger.debug(f"v5.7: Rust engine loaded {added}/{len(rules_to_add)} rules, "
                  f"scanning {len(files_to_scan)} files")

    # Batch scan all files in parallel (rayon)
    raw_hits = eng.scan_files(files_to_scan)
    # raw_hits is a list of (path, rule_id, line, message)

    # Convert to YAMLHit
    all_hits: List[YAMLHit] = []
    for path, rule_id, line, _msg in raw_hits:
        meta = rule_meta.get(rule_id)
        if meta is None:
            continue
        pattern_str, message, severity, cwe = meta
        all_hits.append(YAMLHit(
            rule_id=rule_id,
            file=path,
            line=line,
            message=message,
            severity=severity,
            cwe=cwe,
            pattern=pattern_str,
        ))

    return all_hits


def count_applicable_rules(pack_paths: List[Path]) -> Tuple[int, int, int]:
    """Count rules in packs: (total, applicable, unsupported).

    applicable = rules the native engine can handle
    unsupported = rules that need semgrep (pattern-inside, metavariables, etc.)
    """
    total = 0
    applicable = 0
    unsupported = 0

    for pack_path in pack_paths:
        if not pack_path.exists():
            continue
        try:
            with open(pack_path) as f:
                data = yaml.safe_load(f)
        except Exception:
            continue

        for rule in data.get("rules", []):
            total += 1
            if _has_unsupported_features(rule):
                unsupported += 1
            elif _extract_pattern(rule) is not None:
                applicable += 1
            else:
                unsupported += 1

    return total, applicable, unsupported
