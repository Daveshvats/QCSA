"""v4.39: CLI wrapper for spec_mining — mine API patterns and check violations.

v4.38 had a critical bug: referenced non-existent attributes on SpecViolation
(v.rule_id, v.suggestion, v.pattern_name, v.expected). v4.39 fixes this by
using the actual fields (v.object_type, v.expected_pattern, v.actual_sequence).

v4.39 also fixes the --mine-only/--check-only flag inversion from v4.38.
"""
from __future__ import annotations

from pathlib import Path
from typing import List

import click


@click.command("spec")
@click.option("--repo", default=".", help="Repository root")
@click.option("--max-files", default=100, type=int, help="Max files to scan for patterns")
@click.option("--mine-only", is_flag=True, help="Only mine patterns (skip violation check)")
@click.option("--check-only", is_flag=True, help="Only check for violations (skip mining display)")
@click.option("--min-confidence", default=0.3, type=float,
              help="Minimum pattern confidence to flag violations (default: 0.3, lower = more findings)")
def spec_cmd(repo: str, max_files: int, mine_only: bool, check_only: bool, min_confidence: float):
    """Mine API usage patterns and check for spec violations.

    Spec mining analyzes how APIs are used across your codebase and derives
    implicit specifications (e.g., "open() is always followed by close()").
    Violations of these specs are reported as potential bugs.

    This is the next auto-derivation path after `stca mine`:
    - `stca mine` derives rules from bug-fix COMMITS
    - `stca spec` derives specs from correct USAGE patterns

    Examples:
      stca spec                              # mine + check (default)
      stca spec --mine-only                  # just mine patterns, show them
      stca spec --check-only                 # just check for violations
      stca spec --max-files 500              # scan more files
    """
    from .spec_mining import mine_api_patterns, check_spec_violations

    repo_root = Path(repo).resolve()
    if not repo_root.exists():
        click.echo(f"Error: {repo_root} does not exist", err=True)
        return

    # v4.39: Fixed flag logic — --mine-only means ONLY mine, --check-only means ONLY check
    # Default (no flags): mine + check
    do_mine = not check_only  # mine unless --check-only
    do_check = not mine_only  # check unless --mine-only

    patterns = {}
    if do_mine:
        click.echo(f"Mining API patterns in {repo_root} (max {max_files} files)...")
        patterns = mine_api_patterns(repo_root, max_files=max_files)
        total = sum(len(v) for v in patterns.values())
        click.echo(f"\nMined {total} patterns across {len(patterns)} APIs:")
        for api, api_patterns in sorted(patterns.items(), key=lambda x: -len(x[1]))[:15]:
            click.echo(f"  {api}: {len(api_patterns)} pattern(s)")
            for p in api_patterns[:3]:
                click.echo(f"    - {' -> '.join(p.sequence)} (confidence: {p.confidence:.0%})")
            if len(api_patterns) > 3:
                click.echo(f"    ... and {len(api_patterns) - 3} more")

    if do_check:
        if not patterns:
            # --check-only mode: still need to mine patterns first to check against
            click.echo(f"Mining patterns for violation check...")
            patterns = mine_api_patterns(repo_root, max_files=max_files)
        if patterns:
            click.echo(f"\nChecking for spec violations (min_confidence={min_confidence})...")
            violations = check_spec_violations(repo_root, patterns, min_confidence=min_confidence)
            click.echo(f"\nFound {len(violations)} spec violation(s):")
            for v in violations[:20]:
                # v4.39: Use actual SpecViolation fields (not the non-existent ones from v4.38)
                click.echo(f"  {v.file}:{v.line} — {v.description}")
                click.echo(f"    Object: {v.object_type}")
                click.echo(f"    Expected: {v.expected_pattern}")
                click.echo(f"    Actual: {' -> '.join(v.actual_sequence)}")
                click.echo(f"    Suggestion: Follow pattern: {v.expected_pattern}")
            if len(violations) > 20:
                click.echo(f"  ... and {len(violations) - 20} more")
        else:
            click.echo(f"\nNo patterns mined — cannot check for violations.")
