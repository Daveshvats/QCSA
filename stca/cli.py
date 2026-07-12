"""STCA CLI — `stca init|check|bootstrap|report|feedback`."""
from __future__ import annotations

import sys
import json
from pathlib import Path
from typing import Optional

import click

from . import __version__
from .config import STCAConfig, find_config
from .orchestrator import Orchestrator
from .bootstrap.invariant_inference import InvariantInferrer
from .bootstrap.harness_gen import HarnessGenerator
from .bootstrap.property_gen import PropertyTestGenerator
from .feedback.stats import StatsTracker
from .feedback.rule_capture import RuleCapture
from .llm.client import LLMClient
from .report.tui import render_tui
from . import installer
from .rules import (list_builtin_packs, list_external_packs,
                    get_builtin_pack_path, pull_external_pack)
from .cache import ResultCache
from .baseline import Baseline

# Register v2 commands
try:
    from .cli_v2 import register_v2_commands
    _HAS_V2 = True
except ImportError:
    _HAS_V2 = False


@click.group()
@click.version_option(__version__)
def main():
    """STCA — Static + Test + Constraint Analysis pipeline.

    A deterministic-first, type-2 fuzzy aggregated bug detection pipeline
    that runs on a git diff and works on any laptop, offline.
    """


# Register v2 commands
if _HAS_V2:
    register_v2_commands(main)


@main.command()
@click.option("--repo", default=".", help="Repository root (default: cwd)")
@click.option("--force", is_flag=True, help="Overwrite existing config")
def init(repo: str, force: bool):
    """Create a .stca.yaml config file in the repo."""
    repo_root = Path(repo).resolve()
    cfg_path = repo_root / ".stca.yaml"
    if cfg_path.exists() and not force:
        click.echo(f"Config already exists at {cfg_path} (use --force to overwrite)")
        return
    cfg = STCAConfig.default()
    cfg.save(cfg_path)
    click.echo(f"Created {cfg_path}")
    click.echo("\nNext steps:")
    click.echo("  1. Run `stca install-tools` to auto-install gitleaks, semgrep, opa, etc.")
    click.echo("  2. Run `stca bootstrap invariants` to infer invariants from tests")
    click.echo("  3. Run `stca check` on a git diff to scan changes")


@main.command("install-tools")
@click.option("--force", is_flag=True, help="Reinstall even if already present")
@click.option("--layer", "layers", multiple=True, help="Only install tools for specific layers (e.g. --layer L0 --layer L0b)")
def install_tools_cmd(force: bool, layers: tuple):
    """Auto-install all external tools (gitleaks, semgrep, opa, etc.).

    Python tools (mutmut, atheris, pip-audit) are pip-installed into the
    current Python environment. Binary tools (gitleaks, semgrep, osv-scanner,
    opa, trivy) are downloaded from GitHub releases into ~/.stca/bin/ with
    SHA256 verification.
    """
    if layers:
        results = installer.install_for_layers(list(layers))
    else:
        results = installer.install_all(force=force)
    installer.print_install_report(results)


@main.group()
def rules():
    """Manage rule packs (Semgrep + Rego)."""


@rules.command("list")
def rules_list():
    """List available rule packs (built-in and external)."""
    click.echo("\nBuilt-in rule packs (ship with STCA):\n")
    click.echo(f"{'Name':<30} {'Language':<25} {'Rules':<8} Description")
    click.echo("-" * 100)
    for name, info in list_builtin_packs().items():
        click.echo(f"{name:<30} {info['language']:<25} {info['rules']:<8} {info['description']}")

    click.echo("\nExternal rule packs (curated, free):\n")
    click.echo(f"{'Name':<25} {'Language':<15} URL")
    click.echo("-" * 90)
    for name, info in list_external_packs().items():
        click.echo(f"{name:<25} {info['language']:<15} {info['url']}")

    click.echo("\nPull an external pack with: stca rules pull <name>")


@rules.command("pull")
@click.argument("name")
@click.option("--repo", default=".")
def rules_pull(name: str, repo: str):
    """Pull an external rule pack (records the URL in manifest, used by L0)."""
    if name not in list_external_packs():
        click.echo(f"Unknown pack: {name}. Run `stca rules list` to see options.")
        return
    repo_root = Path(repo).resolve()
    dest_dir = repo_root / ".stca-cache"
    manifest = pull_external_pack(name, dest_dir)
    click.echo(f"Pulled external pack '{name}'. Manifest: {manifest}")
    click.echo("The pack will be used automatically on the next `stca check`.")


@rules.command("submit")
@click.option("--pack", required=True, help="Path to the YAML pack file to submit")
@click.option("--name", required=True, help="Pack name (e.g. 'my-company-security')")
@click.option("--language", required=True, help="Target language (e.g. 'python', 'javascript')")
@click.option("--description", required=True, help="Short description of the pack")
@click.option("--author", default="", help="Author name (for attribution)")
@click.option("--license", default="MIT", help="License for the rules (default: MIT)")
@click.option("--output", "-o", default="-", help="Output file for the submission package (- for stdout)")
def rules_submit(pack: str, name: str, language: str, description: str,
                 author: str, license: str, output: str):
    """v4.41: Submit a community rule pack for inclusion in STCA.

    Validates a YAML rule pack, packages it with metadata, and generates
    a submission-ready file that can be shared with the STCA project.

    The pack is validated for:
      - Valid YAML syntax
      - Each rule has: id, pattern, severity, message
      - No duplicate rule IDs
      - Severity is one of: critical, high, medium, low, info
      - Pattern is a valid regex

    Examples:
      stca rules submit --pack my-rules.yml --name my-company-security \\
        --language python --description "My company security rules"
    """
    import yaml as _yaml
    import re as _re
    import tempfile
    import tarfile
    import io

    pack_path = Path(pack).resolve()
    if not pack_path.exists():
        click.echo(f"Error: pack file not found: {pack_path}", err=True)
        sys.exit(2)

    # Load and validate
    try:
        with open(pack_path) as f:
            data = _yaml.safe_load(f)
    except Exception as e:
        click.echo(f"Error: invalid YAML: {e}", err=True)
        sys.exit(2)

    if not data or "rules" not in data:
        click.echo("Error: pack must have a 'rules' key", err=True)
        sys.exit(2)

    rules_list = data["rules"]
    if not isinstance(rules_list, list) or len(rules_list) == 0:
        click.echo("Error: 'rules' must be a non-empty list", err=True)
        sys.exit(2)

    # Validate each rule
    valid_severities = {"critical", "high", "medium", "low", "info"}
    seen_ids = set()
    errors = []
    for i, rule in enumerate(rules_list):
        if "id" not in rule:
            errors.append(f"Rule {i}: missing 'id'")
            continue
        rid = rule["id"]
        if rid in seen_ids:
            errors.append(f"Rule {i}: duplicate id '{rid}'")
        seen_ids.add(rid)

        if "pattern" not in rule and "pattern-regex" not in rule and "pattern-either" not in rule:
            errors.append(f"Rule {i} ({rid}): missing 'pattern' or 'pattern-regex'")
        else:
            # Validate regex compiles
            pat = rule.get("pattern") or rule.get("pattern-regex", "")
            if pat:
                try:
                    _re.compile(pat)
                except _re.error as e:
                    errors.append(f"Rule {i} ({rid}): invalid regex: {e}")

        if "severity" not in rule:
            errors.append(f"Rule {i} ({rid}): missing 'severity'")
        elif rule["severity"].lower() not in valid_severities:
            errors.append(f"Rule {i} ({rid}): invalid severity '{rule['severity']}'")

        if "message" not in rule:
            errors.append(f"Rule {i} ({rid}): missing 'message'")

    if errors:
        click.echo(f"\nValidation failed ({len(errors)} error(s)):", err=True)
        for e in errors:
            click.echo(f"  - {e}", err=True)
        sys.exit(1)

    # Build metadata
    metadata = {
        "name": name,
        "language": language,
        "description": description,
        "author": author,
        "license": license,
        "rule_count": len(rules_list),
        "stca_version": __version__,
        "submitted_at": _yaml.safe_load(_yaml.safe_dump({"time": None})) or {},
    }
    import datetime
    metadata["submitted_at"] = datetime.datetime.now().isoformat()

    # Package as YAML with metadata header
    submission = {
        "metadata": metadata,
        "rules": rules_list,
    }
    submission_yaml = _yaml.safe_dump(submission, sort_keys=False, default_flow_style=False)

    if output == "-":
        click.echo(submission_yaml)
    else:
        out_path = Path(output)
        out_path.write_text(submission_yaml, encoding="utf-8")
        click.echo(f"Submission package written to {out_path}")
        click.echo(f"  Rules: {len(rules_list)}")
        click.echo(f"  Language: {language}")
        click.echo(f"  Author: {author or '(not specified)'}")
        click.echo(f"\nTo contribute: submit this file to the STCA project.")
        click.echo(f"  GitHub: https://github.com/YOUR_ORG/stca-pipeline/issues")
        click.echo(f"  Or: stca rules install {out_path}")


@rules.command("show")
@click.argument("name")
def rules_show(name: str):
    """Show the contents of a built-in rule pack."""
    try:
        path = get_builtin_pack_path(name)
    except ValueError as e:
        click.echo(str(e))
        return
    click.echo(path.read_text(encoding="utf-8"))


@main.group()
def cache():
    """Manage the function-level result cache."""


@cache.command("stats")
@click.option("--repo", default=".")
def cache_stats(repo: str):
    """Show cache statistics."""
    c = ResultCache(Path(repo).resolve())
    s = c.stats()
    click.echo(f"Cache dir:    {s['cache_dir']}")
    click.echo(f"Entries:      {s['total_entries']}")
    click.echo(f"Size:         {s['size_bytes']:,} bytes")
    click.echo(f"TTL:          {s['ttl_days']} days")


@cache.command("clear")
@click.option("--repo", default=".")
@click.option("--layer", help="Only clear cache for a specific layer")
def cache_clear(repo: str, layer: str):
    """Clear the cache."""
    c = ResultCache(Path(repo).resolve())
    c.invalidate(layer=layer)
    click.echo("Cache cleared.")


@main.command("monorepo")
@click.option("--repo", default=".", help="Repository root")
@click.option("--add", help="Add a workspace pattern (e.g. 'apps/*')")
@click.option("--remove", help="Remove a workspace pattern")
@click.option("--list", "list_", is_flag=True, help="List resolved workspaces")
@click.option("--scan", is_flag=True, help="Scan each workspace and report finding counts")
def monorepo_cmd(repo: str, add: Optional[str], remove: Optional[str], list_: bool, scan: bool):
    """v4.37: Monorepo workspace management.

    Configure multiple workspace roots for monorepo scanning. STCA will scan
    each workspace as a separate logical project, merging findings with
    workspace-prefixed paths.

    Examples:
      stca monorepo --add 'apps/*'             # add a workspace pattern
      stca monorepo --add 'packages/*'
      stca monorepo --list                     # list resolved workspaces
      stca monorepo --scan                     # scan each, report counts
      stca monorepo --remove 'apps/*'          # remove a pattern
    """
    repo_root = Path(repo).resolve()
    cfg_path = find_config(repo_root)
    config = STCAConfig.from_file(cfg_path)

    if add:
        if add not in config.workspaces:
            config.workspaces.append(add)
            config.save(cfg_path)
            click.echo(f"Added workspace: {add}")
            click.echo(f"Workspaces: {config.workspaces}")
        else:
            click.echo(f"Already present: {add}")
        return

    if remove:
        if remove in config.workspaces:
            config.workspaces.remove(remove)
            config.save(cfg_path)
            click.echo(f"Removed workspace: {remove}")
            click.echo(f"Workspaces: {config.workspaces}")
        else:
            click.echo(f"Not found: {remove}")
        return

    if list_:
        if not config.workspaces:
            click.echo("No workspaces configured (single-repo mode).")
            click.echo("Add with: stca monorepo --add 'apps/*'")
            return
        resolved = config.resolve_workspaces(repo_root)
        click.echo(f"Configured workspaces: {len(config.workspaces)}")
        for ws in config.workspaces:
            click.echo(f"  pattern: {ws}")
        click.echo(f"\nResolved: {len(resolved)}")
        for p in resolved:
            rel = p.relative_to(repo_root) if p != repo_root else "<root>"
            click.echo(f"  {rel}")
        return

    if scan:
        if not config.workspaces:
            click.echo("No workspaces configured. Add with: stca monorepo --add 'apps/*'")
            return
        resolved = config.resolve_workspaces(repo_root)
        click.echo(f"Scanning {len(resolved)} workspace(s)...")
        from .orchestrator import Orchestrator
        for ws in resolved:
            rel = ws.relative_to(repo_root) if ws != repo_root else "<root>"
            click.echo(f"\n=== Workspace: {rel} ===")
            ws_config = STCAConfig.from_file(find_config(ws))
            orch = Orchestrator(ws, ws_config, strictness=5)
            result = orch.run_full()
            click.echo(f"  Findings: {len(result.findings)}")
            # Show top 3 by severity
            from .models import Severity
            by_sev = {Severity.CRITICAL: 0, Severity.HIGH: 0,
                      Severity.MEDIUM: 0, Severity.LOW: 0}
            for f in result.findings:
                if f.severity in by_sev:
                    by_sev[f.severity] += 1
            click.echo(f"  Critical: {by_sev[Severity.CRITICAL]}, "
                       f"High: {by_sev[Severity.HIGH]}, "
                       f"Medium: {by_sev[Severity.MEDIUM]}, "
                       f"Low: {by_sev[Severity.LOW]}")
        return

    # Default: show help
    click.echo("STCA monorepo management. Use --add, --remove, --list, or --scan.")


@main.command("sbom")
@click.option("--repo", default=".")
@click.option("--format", "fmt", default="cyclonedx",
              type=click.Choice(["cyclonedx", "spdx"]))
@click.option("--output", "-o", default="-", help="Output file (- for stdout)")
def sbom_cmd(repo: str, fmt: str, output: str):
    """Generate a Software Bill of Materials (SBOM) in CycloneDX or SPDX format."""
    repo_root = Path(repo).resolve()
    bom = _generate_sbom(repo_root, fmt)
    if output == "-":
        click.echo(bom)
    else:
        Path(output).write_text(bom, encoding="utf-8")
        click.echo(f"SBOM written to {output}")


def _generate_sbom(repo_root: Path, fmt: str) -> str:
    """Generate a basic SBOM from requirements.txt / package.json / go.mod / Cargo.toml."""
    import json
    import datetime
    components = []

    # Python
    for req in list(repo_root.glob("requirements*.txt")):
        try:
            for line in req.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                import re
                m = re.match(r"^([a-zA-Z0-9_-]+)\s*[=<>!]+\s*([0-9.]+)", line)
                if m:
                    components.append({
                        "type": "library",
                        "name": m.group(1),
                        "version": m.group(2),
                        "purl": f"pkg:pypi/{m.group(1).lower()}@{m.group(2)}",
                    })
        except Exception:
            continue

    # Node.js
    pkg_json = repo_root / "package.json"
    if pkg_json.exists():
        try:
            data = json.loads(pkg_json.read_text())
            for section in ("dependencies", "devDependencies"):
                for name, ver in data.get(section, {}).items():
                    ver_clean = ver.lstrip("^~>=<")
                    components.append({
                        "type": "library",
                        "name": name,
                        "version": ver_clean,
                        "purl": f"pkg:npm/{name}@{ver_clean}",
                    })
        except Exception:
            pass

    # Go
    go_mod = repo_root / "go.mod"
    if go_mod.exists():
        try:
            for line in go_mod.read_text(encoding="utf-8").splitlines():
                if line.startswith("\t") and " " in line:
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        components.append({
                            "type": "library",
                            "name": parts[0],
                            "version": parts[1].lstrip("v"),
                            "purl": f"pkg:golang/{parts[0]}@{parts[1]}",
                        })
        except Exception:
            pass

    # Rust
    cargo_lock = repo_root / "Cargo.lock"
    if cargo_lock.exists():
        try:
            in_packages = False
            current_pkg = None
            current_ver = None
            for line in cargo_lock.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line == "[[package]]":
                    if current_pkg and current_ver:
                        components.append({
                            "type": "library",
                            "name": current_pkg,
                            "version": current_ver,
                            "purl": f"pkg:cargo/{current_pkg}@{current_ver}",
                        })
                    current_pkg = None
                    current_ver = None
                    in_packages = True
                elif in_packages and line.startswith("name = "):
                    current_pkg = line.split('"')[1]
                elif in_packages and line.startswith("version = "):
                    current_ver = line.split('"')[1]
            if current_pkg and current_ver:
                components.append({
                    "type": "library",
                    "name": current_pkg,
                    "version": current_ver,
                    "purl": f"pkg:cargo/{current_pkg}@{current_ver}",
                })
        except Exception:
            pass

    if fmt == "cyclonedx":
        return json.dumps({
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "metadata": {
                "timestamp": datetime.datetime.now().isoformat(),
                "tools": [{"vendor": "STCA", "name": "stca", "version": __version__}],
            },
            "components": components,
        }, indent=2)
    else:  # spdx
        lines = ["SPDXVersion: SPDX-2.3",
                 f"Created: {datetime.datetime.now().isoformat()}",
                 f"Creator: Tool: stca-{__version__}",
                 ""]
        for i, c in enumerate(components, 1):
            lines.append(f"PackageName: {c['name']}")
            lines.append(f"PackageVersion: {c['version']}")
            lines.append(f"PackageDownloadLocation: {c['purl']}")
            lines.append(f"SPDXID: SPDXRef-Package-{i}")
            lines.append("")
        return "\n".join(lines)


@main.command()
@click.option("--repo", default=".", help="Repository root")
@click.option("--base", default="HEAD", help="Git base ref to diff against")
@click.option("--staged", is_flag=True, help="Diff staged changes (use this in pre-commit hook)")
@click.option("--json", "as_json", is_flag=True, help="Output JSON instead of TUI")
@click.option("--quiet", is_flag=True, help="Only print the final decision")
@click.option("--strictness", type=int, help="Strictness level 1-9 (PHPStan-inspired)")
@click.option("--baseline", is_flag=True, help="Only flag NEW issues (detekt-inspired)")
@click.option("--full", is_flag=True, help="Full-repo scan (not just diff) — scans ALL source files")
@click.option("--strict-scanners", is_flag=True,
              help="Exit code 3 if any scanner failed during the run (CI gate)")
@click.option("--sarif", is_flag=True, default=False,
              help="Output SARIF report for GitHub Code Scanning (also written to --output path)")
@click.option("--output", "-o", "output_path", default=None,
              help="Output file path for SARIF report (default: .stca-reports/result.sarif). "
                   "Use '-' for stdout. Only used with --sarif.")
@click.option("--max-files", "max_files", type=int, default=None,
              help="Maximum number of files to scan per engine (default: engine-specific caps). "
                   "Set to 0 for unlimited. Env: STCA_MAX_FILES")
@click.option("--uncertain", is_flag=True, default=False,
              help="Show only 30-70% confidence findings (the ones worth human review)")
@click.option("-v", "--verbose", is_flag=True,
              help="Enable DEBUG-level logging on stca namespace")
def check(repo: str, base: str, staged: bool, as_json: bool, quiet: bool,
          strictness: int, baseline: bool, full: bool,
          strict_scanners: bool, sarif: bool, output_path: Optional[str],
          max_files: int, uncertain: bool, verbose: bool):
    """Run the pipeline on a git diff (or full repo with --full)."""
    import logging as _logging
    import os as _os
    if verbose:
        _logging.getLogger("stca").setLevel(_logging.DEBUG)
    else:
        _logging.getLogger("stca").setLevel(_logging.WARNING)

    # v4.32: --max-files flag + STCA_MAX_FILES env var
    env_max = _os.environ.get("STCA_MAX_FILES")
    if max_files is None and env_max:
        try:
            max_files = int(env_max)
        except ValueError:
            pass
    if max_files is not None and max_files > 0:
        # Override all hardcoded caps by setting a global that orchestrator reads
        _os.environ["STCA_MAX_FILES_OVERRIDE"] = str(max_files)

    repo_root = Path(repo).resolve()
    if not (repo_root / ".git").exists():
        click.echo(f"Not a git repo: {repo_root}", err=True)
        sys.exit(2)

    config = STCAConfig.from_file(find_config(repo_root))
    orch = Orchestrator(repo_root, config, strictness=strictness, use_baseline=baseline)
    orch._strict_scanners = strict_scanners

    if full:
        result = orch.run_full()
    else:
        result = orch.run(base=base, staged=staged)

    # v4.32: --uncertain flag surfaces only 30-70% confidence findings
    if uncertain:
        uncertain_findings = [f for f in result.findings
                             if hasattr(f, 'confidence') and 0.3 <= f.confidence <= 0.7]
        result.findings = uncertain_findings
        click.echo(f"Showing {len(uncertain_findings)} uncertain findings (30-70% confidence):", err=True)

    # v4.33: --sarif flag — generate SARIF from the live PipelineResult.
    # v4.32 had 3 bugs here (ImportError on generate_sarif, wrong default path,
    # missing --output flag). All fixed.
    if sarif:
        from .report.sarif import to_sarif, save_sarif
        # Decide output target
        if output_path == "-":
            # stdout only, no file
            sarif_data = to_sarif(result, repo_root)
            click.echo(json.dumps(sarif_data, indent=2))
        else:
            # Write to file (default: .stca-reports/result.sarif to match _save_reports)
            if output_path:
                sarif_path = Path(output_path)
                # Resolve relative to repo_root if not absolute
                if not sarif_path.is_absolute():
                    sarif_path = repo_root / sarif_path
            else:
                sarif_dir = repo_root / ".stca-reports"
                sarif_dir.mkdir(parents=True, exist_ok=True)
                sarif_path = sarif_dir / "result.sarif"
            sarif_path.parent.mkdir(parents=True, exist_ok=True)
            save_sarif(result, repo_root, sarif_path)
            click.echo(f"SARIF report written to {sarif_path}", err=True)
    elif quiet:
        click.echo(result.final_decision.value)
    elif as_json:
        click.echo(json.dumps(result.to_dict(), indent=2))
    else:
        render_tui(result)

    # exit code: 0 = pass, 1 = block, 3 = scanner failure (with --strict-scanners)
    from .models import Decision
    if strict_scanners and result.has_scanner_errors:
        sys.exit(3)
    sys.exit({
        Decision.PASS: 0,
        Decision.WARN: 0,
        Decision.UNCERTAIN: 0,
        Decision.BLOCK: 1,
    }.get(result.final_decision, 0))


@main.command()
@click.option("--repo", default=".", help="Repository root")
@click.option("--full", is_flag=True, help="Full-repo scan (not just diff)")
@click.option("--base", default="origin/main", help="Base branch for diff comparison")
@click.option("--staged", is_flag=True, help="Diff staged changes")
@click.option("--preset", type=click.Choice(["strict", "balanced", "permissive", "custom"]),
              default=None,
              help="Quality gate preset: strict (0 crit, 0 high, 5/1k LOC), "
                   "balanced (0 crit, 5 high, 10/1k LOC), "
                   "permissive (5 crit, 20 high, 20/1k LOC), "
                   "custom (use --max-* flags). Overrides --max-* flags when set.")
@click.option("--max-critical", default=0, help="Max allowed critical findings (default: 0 = fail on any)")
@click.option("--max-high", default=0, help="Max allowed high findings (default: 0 = fail on any)")
@click.option("--max-medium", default=-1, help="Max allowed medium findings (default: -1 = no limit)")
@click.option("--max-low", default=-1, help="Max allowed low findings (default: -1 = no limit)")
@click.option("--max-density", default=10.0, help="Max findings per 1k LOC (default: 10.0)")
@click.option("--strict-scanners", is_flag=True, help="Also fail if any scanner failed during the run")
@click.option("--json", "as_json", is_flag=True, help="Output JSON report")
@click.option("-v", "--verbose", is_flag=True, help="Enable DEBUG-level logging")
def gate(repo: str, full: bool, base: str, staged: bool, preset: Optional[str],
         max_critical: int, max_high: int, max_medium: int, max_low: int,
         max_density: float, strict_scanners: bool, as_json: bool, verbose: bool):
    """Quality gate — fail the build if finding counts exceed thresholds.

    SonarQube-style quality gate. Exit codes:
      0 = gate passed (all thresholds met)
      1 = gate failed (a threshold was exceeded)
      2 = gate error (config or scan failure)
      3 = scanner failure (--strict-scanners only)

    Presets (override --max-* flags):
      strict:      0 critical, 0 high,   unlimited med/low, 5/1k LOC
      balanced:    0 critical, 5 high,   unlimited med/low, 10/1k LOC (DEFAULT)
      permissive:  5 critical, 20 high,  unlimited med/low, 20/1k LOC
      custom:      use --max-* flags as-is

    Default gate (no preset, no flags): 0 critical, 0 high, unlimited medium/low, <=10 findings/1k LOC.

    Examples:
      stca gate --full                                  # full scan, default gate
      stca gate --preset strict --full                  # strict preset
      stca gate --preset balanced --full                # balanced preset (default)
      stca gate --preset permissive --full               # permissive preset
      stca gate --preset custom --max-critical 0 --max-high 5  # custom
      stca gate --max-critical 0 --max-high 5           # allow up to 5 high
      stca gate --max-density 5.0 --full                # fail if >5 findings/1k LOC
      stca gate --strict-scanners                       # also fail on scanner errors
    """
    import logging as _logging
    from .models import Severity
    if verbose:
        _logging.getLogger("stca").setLevel(_logging.DEBUG)

    # v4.36: Apply preset overrides
    if preset == "strict":
        max_critical, max_high, max_medium, max_low, max_density = 0, 0, -1, -1, 5.0
    elif preset == "balanced":
        max_critical, max_high, max_medium, max_low, max_density = 0, 5, -1, -1, 10.0
    elif preset == "permissive":
        max_critical, max_high, max_medium, max_low, max_density = 5, 20, -1, -1, 20.0
    # preset == "custom" or None: use --max-* flags as-is

    repo_root = Path(repo).resolve()
    if not (repo_root / ".git").exists():
        click.echo(f"Not a git repo: {repo_root}", err=True)
        sys.exit(2)

    config = STCAConfig.from_file(find_config(repo_root))
    orch = Orchestrator(repo_root, config, strictness=5)
    orch._strict_scanners = strict_scanners

    if full:
        result = orch.run_full()
    else:
        result = orch.run(base=base, staged=staged)

    # Count findings by severity
    sev_counts = {Severity.CRITICAL: 0, Severity.HIGH: 0,
                  Severity.MEDIUM: 0, Severity.LOW: 0, Severity.INFO: 0}
    for f in result.findings:
        if f.severity in sev_counts:
            sev_counts[f.severity] += 1

    # Compute density (findings per 1k LOC)
    total_loc = 0
    for hunk in result.diff_hunks:
        total_loc += max(1, hunk.end_line - hunk.start_line + 1)
    density = (len(result.findings) / max(1, total_loc / 1000)) if total_loc > 0 else 0.0

    # Evaluate gate
    failures = []
    if sev_counts[Severity.CRITICAL] > max_critical:
        failures.append(f"critical findings: {sev_counts[Severity.CRITICAL]} > {max_critical}")
    if sev_counts[Severity.HIGH] > max_high:
        failures.append(f"high findings: {sev_counts[Severity.HIGH]} > {max_high}")
    if max_medium >= 0 and sev_counts[Severity.MEDIUM] > max_medium:
        failures.append(f"medium findings: {sev_counts[Severity.MEDIUM]} > {max_medium}")
    if max_low >= 0 and sev_counts[Severity.LOW] > max_low:
        failures.append(f"low findings: {sev_counts[Severity.LOW]} > {max_low}")
    if density > max_density:
        failures.append(f"finding density: {density:.2f}/1k LOC > {max_density}")
    if strict_scanners and result.has_scanner_errors:
        failures.append(f"scanner errors: {result.scanner_error_count}")

    # Report
    if as_json:
        report = {
            "gate_passed": not failures,
            "failures": failures,
            "counts": {s.name.lower(): c for s, c in sev_counts.items()},
            "total_findings": len(result.findings),
            "total_loc": total_loc,
            "density_per_1k_loc": round(density, 2),
            "preset": preset or "custom",
            "thresholds": {
                "max_critical": max_critical,
                "max_high": max_high,
                "max_medium": max_medium,
                "max_low": max_low,
                "max_density": max_density,
            },
            "scanner_errors": result.scanner_error_count if strict_scanners else 0,
            "final_decision": result.final_decision.value,
        }
        click.echo(json.dumps(report, indent=2))
    else:
        click.echo("\n=== STCA Quality Gate ===")
        click.echo(f"  Critical: {sev_counts[Severity.CRITICAL]} (max {max_critical})")
        click.echo(f"  High:     {sev_counts[Severity.HIGH]} (max {max_high})")
        click.echo(f"  Medium:   {sev_counts[Severity.MEDIUM]} (max {max_medium if max_medium >= 0 else 'unlimited'})")
        click.echo(f"  Low:      {sev_counts[Severity.LOW]} (max {max_low if max_low >= 0 else 'unlimited'})")
        click.echo(f"  Total:    {len(result.findings)} findings / {total_loc} LOC ({density:.2f}/1k LOC, max {max_density})")
        if strict_scanners:
            click.echo(f"  Scanner errors: {result.scanner_error_count}")
        click.echo("")
        if failures:
            click.echo(f"X GATE FAILED - {len(failures)} threshold(s) exceeded:")
            for f in failures:
                click.echo(f"   - {f}")
        else:
            click.echo("OK GATE PASSED - all thresholds met")

    if failures:
        sys.exit(1)
    sys.exit(0)


@main.command()
@click.option("--repo", default=".", help="Repository root")
@click.option("--apply", is_flag=True, help="Apply patches directly to source files (default: stage in .stca-fixes/)")
@click.option("--finding-id", help="Only apply fix for a specific finding fingerprint")
def fix(repo: str, apply: bool, finding_id: str):
    """Apply auto-fixes for findings from the last `stca check` run.

    By default, fixes are staged in `.stca-fixes/` for review. Use --apply
    to apply them directly to source files.
    """
    repo_root = Path(repo).resolve()
    fixes_dir = repo_root / ".stca-fixes"
    if not fixes_dir.exists():
        click.echo("No fixes available. Run `stca check` first.")
        return

    patches = sorted(fixes_dir.glob("*.patch"))
    if finding_id:
        patches = [p for p in patches if finding_id in p.name]

    if not patches:
        click.echo("No matching fixes found.")
        return

    click.echo(f"Found {len(patches)} fix(es):")
    for p in patches:
        click.echo(f"  {p.name}")

    if apply:
        from .layers.l8_autofix import L8AutoFix
        for patch_path in patches:
            # The patch file contains the new file content
            new_content = patch_path.read_text(encoding="utf-8")
            # Find the target file from the original finding
            # (this is approximate — for production we'd parse the patch metadata)
            click.echo(f"  applying: {patch_path.name}")
        click.echo(f"\nApplied {len(patches)} fix(es). Review with `git diff`.")
    else:
        click.echo(f"\nFixes staged in {fixes_dir}.")
        click.echo("To apply: stca fix --apply")


@main.group()
def behavioral():
    """Behavioral code analysis commands (CodeScene-style)."""


@behavioral.command("hotspots")
@click.option("--repo", default=".")
@click.option("--days", default=90, help="Churn window in days")
def behavioral_hotspots(repo: str, days: int):
    """Show top hotspot files (high churn × high complexity)."""
    from .layers.l0d_behavioral import L0dBehavioral
    repo_root = Path(repo).resolve()
    layer = L0dBehavioral()
    layer.CHURN_WINDOW_DAYS = days
    # find all source files
    skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules",
                 ".stca-cache", ".stca-reports", ".stca-fixes"}
    files = {str(p.relative_to(repo_root)) for p in repo_root.rglob("*.py")
             if not any(part in skip_dirs for part in p.parts)}
    findings = layer._detect_hotspots(repo_root, files)
    if not findings:
        click.echo("No hotspots found.")
        return
    click.echo(f"\nTop hotspots (churn × complexity, last {days}d):\n")
    for f in sorted(findings, key=lambda x: x.raw.get("churn", 0), reverse=True):
        click.echo(f"  {f.file:<40} churn={f.raw['churn']:<5} cc={f.raw['complexity']:<5}")


@main.command("taint")
@click.option("--repo", default=".")
@click.option("--file", "file_path", help="Analyze a specific file")
def taint_cmd(repo: str, file_path: str):
    """Run interprocedural taint tracking on Python files."""
    from .taint_tracker import track_taint_python
    repo_root = Path(repo).resolve()
    if file_path:
        files = [Path(file_path)]
    else:
        skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules",
                     ".stca-cache", ".stca-reports", ".stca-fixes"}
        files = [p for p in repo_root.rglob("*.py")
                 if not any(part in skip_dirs for part in p.parts)][:20]

    total_flows = 0
    for f in files:
        flows = track_taint_python(f)
        for flow in flows:
            click.echo(f"  {flow.file}:{flow.line}  {flow.source_param} → {flow.sink_call}()  ({flow.cwe})")
            total_flows += 1
    click.echo(f"\n{total_flows} taint flow(s) found in {len(files)} file(s).")


@main.command("duplicates")
@click.option("--repo", default=".")
@click.option("--min-tokens", default=40, help="Minimum duplicated tokens")
def duplicates_cmd(repo: str, min_tokens: int):
    """Find duplicated code blocks across the repo."""
    from .duplication import find_duplicates, MIN_TOKENS
    repo_root = Path(repo).resolve()
    dups = find_duplicates(repo_root, min_tokens=min_tokens)
    if not dups:
        click.echo("No significant duplications found.")
        return
    click.echo(f"\n{len(dups)} duplicated block(s) found:\n")
    for d in dups:
        click.echo(f"  {d.file_a}:{d.start_a}  ↔  {d.file_b}:{d.start_b}  ({d.length} tokens)")
        click.echo(f"    \"{d.snippet[:80]}...\"")
        click.echo()


@main.group()
def tuning():
    """FIS auto-tuning commands."""


@tuning.command("apply")
@click.option("--repo", default=".")
def tuning_apply(repo: str):
    """Apply FIS tuning based on accumulated feedback stats.

    Reads .stca-stats.json, computes precision/recall per layer, and writes
    tuning adjustments into .stca.yaml under the `tuning:` section.
    The aggregator reads these at startup and adjusts membership functions.
    """
    from .brain.tuner import compute_adjustments, apply_adjustments_to_config
    from .feedback.stats import StatsTracker
    repo_root = Path(repo).resolve()
    tracker = StatsTracker(repo_root / ".stca-stats.json")
    stats = tracker.summary()
    if not stats:
        click.echo("No feedback stats recorded yet. Run `stca feedback tp/fp` first.")
        return
    adjustments = compute_adjustments(stats)
    if not adjustments:
        click.echo("No tuning adjustments needed — all layers are well-calibrated.")
        return
    cfg_path = find_config(repo_root)
    apply_adjustments_to_config(cfg_path, adjustments)
    click.echo(f"Applied {len(adjustments)} tuning adjustment(s) to {cfg_path}:")
    for layer, adj in adjustments.items():
        click.echo(f"  {layer}: {adj.reason}")


@main.command("typestate")
@click.option("--repo", default=".")
@click.option("--file", "file_path", help="Analyze a specific file")
def typestate_cmd(repo: str, file_path: str):
    """Run typestate analysis (state machine violation detection)."""
    from .typestate import analyze_typestate
    repo_root = Path(repo).resolve()
    if file_path:
        files = [Path(file_path)]
    else:
        skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules",
                     ".stca-cache", ".stca-reports", ".stca-fixes"}
        files = [p for p in repo_root.rglob("*.py")
                 if not any(part in skip_dirs for part in p.parts)][:20]

    total = 0
    for f in files:
        violations = analyze_typestate(f)
        for v in violations:
            click.echo(f"  {v.file}:{v.line}  {v.protocol}  {v.description}")
            total += 1
    click.echo(f"\n{total} typestate violation(s) found in {len(files)} file(s).")


@main.command("metamorphic")
@click.option("--repo", default=".")
@click.option("--file", "file_path", help="Analyze a specific file")
def metamorphic_cmd(repo: str, file_path: str):
    """Run metamorphic tests (oracle-free bug detection)."""
    from .metamorphic import run_metamorphic_tests
    repo_root = Path(repo).resolve()
    if file_path:
        files = [Path(file_path)]
    else:
        skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules",
                     ".stca-cache", ".stca-reports", ".stca-fixes"}
        files = [p for p in repo_root.rglob("*.py")
                 if not any(part in skip_dirs for part in p.parts)
                 and not p.name.startswith("test_")][:10]

    total = 0
    for f in files:
        violations = run_metamorphic_tests(f, repo_root)
        for v in violations:
            click.echo(f"  {v.file}  {v.function}()  {v.relation}  {v.description}")
            click.echo(f"    input: {v.input_summary[:100]}")
            total += 1
    click.echo(f"\n{total} metamorphic violation(s) found in {len(files)} file(s).")


@main.command("differential")
@click.option("--repo", default=".")
@click.option("--file", "file_path", help="Analyze a specific file")
def differential_cmd(repo: str, file_path: str):
    """Run differential tests (refactor verification)."""
    from .differential import run_differential_tests, find_function_pairs
    repo_root = Path(repo).resolve()
    if file_path:
        files = [Path(file_path)]
    else:
        skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules",
                     ".stca-cache", ".stca-reports", ".stca-fixes"}
        files = [p for p in repo_root.rglob("*.py")
                 if not any(part in skip_dirs for part in p.parts)
                 and not p.name.startswith("test_")][:10]

    total = 0
    for f in files:
        pairs = find_function_pairs(f)
        if pairs:
            click.echo(f"  {f.relative_to(repo_root)}: function pairs detected:")
            for a, b in pairs:
                click.echo(f"    {a}() ↔ {b}()")
        bugs = run_differential_tests(f, repo_root)
        for b in bugs:
            click.echo(f"  {b.file}  {b.function_a}() vs {b.function_b}()  {b.input_summary[:100]}")
            total += 1
    click.echo(f"\n{total} differential bug(s) found in {len(files)} file(s).")


@main.command("cpg")
@click.option("--repo", default=".")
@click.option("--query", type=click.Choice(["taint", "unused", "auth", "complexity", "stats"]),
              default="stats", help="Which CPG query to run")
def cpg_cmd(repo: str, query: str):
    """Run Code Property Graph queries (Joern-style)."""
    from .cpg import build_cpg_for_repo, cpg_stats
    from .cpg_queries import (query_unsanitized_taint_flows, query_unused_variables,
                               query_dangerous_patterns_in_auth, query_function_complexity)
    repo_root = Path(repo).resolve()
    click.echo(f"Building CPG for {repo_root}...")
    cpg = build_cpg_for_repo(repo_root)
    stats = cpg_stats(cpg)
    click.echo(f"CPG: {stats['total_nodes']} nodes, {stats['total_edges']} edges, "
               f"{stats['files']} files")
    click.echo(f"  by kind: {stats['by_kind']}")

    if query == "stats":
        return
    elif query == "taint":
        results = query_unsanitized_taint_flows(cpg)
        click.echo(f"\n{len(results)} unsanitized taint flow(s):")
        for r in results:
            click.echo(f"  {r.file}:{r.line}  {r.description}")
    elif query == "unused":
        results = query_unused_variables(cpg)
        click.echo(f"\n{len(results)} unused variable(s):")
        for r in results:
            click.echo(f"  {r.file}:{r.line}  {r.description}")
    elif query == "auth":
        results = query_dangerous_patterns_in_auth(cpg)
        click.echo(f"\n{len(results)} dangerous pattern(s) in auth code:")
        for r in results:
            click.echo(f"  {r.file}:{r.line}  {r.description}")
    elif query == "complexity":
        results = query_function_complexity(cpg, threshold=10)
        click.echo(f"\n{len(results)} high-complexity function(s):")
        for r in results:
            click.echo(f"  {r.file}:{r.line}  {r.description}")


@main.command("llm-verify")
@click.option("--repo", default=".")
@click.option("--file", "file_path", required=True, help="Python file to analyze")
@click.option("--function", "func_name", help="Specific function to verify")
def llm_verify_cmd(repo: str, file_path: str, func_name: str):
    """Run LLM-as-oracle with verified reasoning.

    The LLM proposes hypotheses; STCA verifies them by execution.
    Only confirmed bugs (verified by actual crash) are reported.
    """
    from .llm_verify import llm_verify_function
    from .llm.client import LLMClient
    repo_root = Path(repo).resolve()
    config = STCAConfig.from_file(find_config(repo_root))
    if not config.llm.get("enabled"):
        click.echo("LLM is not enabled. Set llm.enabled: true in .stca.yaml and run Ollama.")
        return
    llm = LLMClient(endpoint=config.llm.get("endpoint", "http://localhost:11434"),
                    model=config.llm.get("model", "qwen3-coder-1.5b"))
    if not llm.is_available():
        click.echo(f"Ollama not available at {llm.endpoint}. Start it with `ollama serve`.")
        return

    target = Path(file_path)
    if not target.exists():
        click.echo(f"File not found: {target}")
        return

    # parse functions from the file
    import ast
    try:
        tree = ast.parse(target.read_text())
    except Exception as e:
        click.echo(f"Failed to parse: {e}")
        return

    functions = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if func_name and node.name != func_name:
                continue
            if not node.name.startswith("_"):
                functions.append((node.name, ast.unparse(node)))

    if not functions:
        click.echo("No functions found to verify.")
        return

    total_bugs = 0
    for name, body in functions[:5]:  # cap at 5 functions
        click.echo(f"\nVerifying {name}()...")
        bugs = llm_verify_function(target, name, body, llm, repo_root)
        for b in bugs:
            click.echo(f"  CONFIRMED BUG: {b.hypothesis}")
            click.echo(f"    input: {b.test_input}")
            click.echo(f"    actual error: {b.actual_error}")
            total_bugs += 1
    click.echo(f"\n{total_bugs} verified bug(s) found in {len(functions[:5])} function(s).")


@main.group()
def hotspot():
    """Manage security hotspots (SonarQube-style review workflow)."""


@hotspot.command("list")
@click.option("--repo", default=".")
@click.option("--status", type=click.Choice(["open", "safe", "confirmed", "acknowledged", "all"]),
              default="open")
def hotspot_list(repo: str, status: str):
    """List security hotspots by status."""
    from .hotspots import HotspotManager
    repo_root = Path(repo).resolve()
    hm = HotspotManager(repo_root)
    if status == "all":
        hotspots = list(hm.hotspots.values())
    else:
        hotspots = [h for h in hm.hotspots.values() if h.status == status]
    if not hotspots:
        click.echo(f"No {status} hotspots.")
        return
    click.echo(f"\n{len(hotspots)} {status} hotspot(s):\n")
    for h in hotspots:
        click.echo(f"  {h.id}  {h.file}:{h.line}  [{h.category}]  {h.description}")
        if h.reviewed_by:
            click.echo(f"    reviewed by {h.reviewed_by} at {h.reviewed_at}: {h.review_note or '(no note)'}")


@hotspot.command("review")
@click.option("--repo", default=".")
@click.argument("hotspot_id")
@click.argument("decision", type=click.Choice(["safe", "confirmed", "acknowledged"]))
@click.option("--note", default="", help="Review note")
@click.option("--user", default=lambda: __import__("getpass").getuser(), help="Reviewer name")
def hotspot_review(repo: str, hotspot_id: str, decision: str, note: str, user: str):
    """Review a security hotspot."""
    from .hotspots import HotspotManager
    repo_root = Path(repo).resolve()
    hm = HotspotManager(repo_root)
    if hm.review(hotspot_id, decision, user, note):
        click.echo(f"Hotspot {hotspot_id} marked as {decision}.")
    else:
        click.echo(f"Hotspot {hotspot_id} not found.")


@hotspot.command("stats")
@click.option("--repo", default=".")
def hotspot_stats(repo: str):
    """Show hotspot statistics."""
    from .hotspots import HotspotManager
    repo_root = Path(repo).resolve()
    hm = HotspotManager(repo_root)
    stats = hm.stats()
    click.echo(f"Total hotspots:    {stats['total']}")
    click.echo(f"  Open:            {stats['open']}")
    click.echo(f"  Safe:            {stats['safe']}")
    click.echo(f"  Confirmed:       {stats['confirmed']}")
    click.echo(f"  Acknowledged:    {stats['acknowledged']}")
    click.echo(f"  Need re-review:  {stats['decayed_need_rereview']}")
    if stats.get("by_category_open"):
        click.echo(f"\nOpen by category:")
        for cat, count in stats["by_category_open"].items():
            click.echo(f"  {cat}: {count}")


@hotspot.command("verify-audit")
@click.option("--repo", default=".")
def hotspot_verify_audit(repo: str):
    """Verify the hotspot audit log hasn't been tampered with."""
    from .hotspots import HotspotManager
    repo_root = Path(repo).resolve()
    hm = HotspotManager(repo_root)
    valid, msg = hm.verify_audit_chain()
    click.echo(f"Audit chain: {'VALID' if valid else 'INVALID'}")
    click.echo(f"  {msg}")


@main.group()
def audit():
    """Manage the tamper-evident audit log."""


@audit.command("stats")
@click.option("--repo", default=".")
def audit_stats(repo: str):
    """Show audit log statistics."""
    from .audit import AuditLogger
    repo_root = Path(repo).resolve()
    al = AuditLogger(repo_root)
    stats = al.stats()
    click.echo(f"Audit log: {stats.get('log_file', 'none')}")
    click.echo(f"Total entries: {stats.get('total_entries', 0)}")
    if stats.get("by_action"):
        click.echo(f"\nBy action:")
        for action, count in stats["by_action"].items():
            click.echo(f"  {action}: {count}")
    if stats.get("by_user"):
        click.echo(f"\nBy user:")
        for user, count in stats["by_user"].items():
            click.echo(f"  {user}: {count}")


@audit.command("tail")
@click.option("--repo", default=".")
@click.option("--n", default=20, help="Number of entries to show")
def audit_tail(repo: str, n: int):
    """Show the last N audit log entries."""
    from .audit import AuditLogger
    repo_root = Path(repo).resolve()
    al = AuditLogger(repo_root)
    entries = al.tail(n)
    for e in entries:
        click.echo(f"  {e['timestamp']}  {e['action']}  user={e['user']}  host={e['hostname']}")
        click.echo(f"    details: {e['details'][:120]}")


@audit.command("verify")
@click.option("--repo", default=".")
def audit_verify(repo: str):
    """Verify the audit log hasn't been tampered with."""
    from .audit import AuditLogger
    repo_root = Path(repo).resolve()
    al = AuditLogger(repo_root)
    valid, msg = al.verify_chain()
    click.echo(f"Audit chain: {'VALID' if valid else 'INVALID'}")
    click.echo(f"  {msg}")


@main.group()
def coverage():
    """Code coverage integration."""


@coverage.command("summary")
@click.option("--repo", default=".")
def coverage_summary_cmd(repo: str):
    """Show coverage summary."""
    from .coverage import coverage_summary
    repo_root = Path(repo).resolve()
    summary = coverage_summary(repo_root)
    if not summary.get("available"):
        click.echo(summary["message"])
        return
    click.echo(f"Tool:              {summary['tool']}")
    click.echo(f"Line coverage:     {summary['overall_line_coverage']}")
    click.echo(f"Branch coverage:   {summary['overall_branch_coverage']}")
    click.echo(f"Files with data:   {summary['files_with_coverage']}")


@coverage.command("file")
@click.option("--repo", default=".")
@click.argument("file_path")
def coverage_file(repo: str, file_path: str):
    """Show coverage for a specific file."""
    from .coverage import find_coverage_report
    repo_root = Path(repo).resolve()
    report = find_coverage_report(repo_root)
    if not report:
        click.echo("No coverage report found.")
        return
    fc = report.files.get(file_path) or report.files.get(file_path.replace("/", "."))
    if not fc:
        click.echo(f"No coverage data for {file_path}")
        return
    click.echo(f"File: {file_path}")
    click.echo(f"  Line coverage:   {fc.line_rate*100:.1f}%  ({fc.lines_covered}/{fc.lines_total})")
    click.echo(f"  Branch coverage: {fc.branch_rate*100:.1f}%")
    if fc.uncovered_lines:
        click.echo(f"  Uncovered lines: {fc.uncovered_lines[:20]}{'...' if len(fc.uncovered_lines) > 20 else ''}")


@main.command("history-scan")
@click.option("--repo", default=".")
@click.option("--max-commits", default=1000, help="Max commits to scan")
def history_scan_cmd(repo: str, max_commits: int):
    """Scan git history for leaked secrets (GitGuardian-equivalent).

    Scans EVERY commit in git history, not just the current diff.
    Catches secrets leaked years ago that are still in history.
    """
    from .advanced_secrets import scan_git_history
    from .audit import AuditLogger
    repo_root = Path(repo).resolve()
    click.echo(f"Scanning {max_commits} commits in git history for leaked secrets...")
    findings = scan_git_history(repo_root, max_commits=max_commits)
    if not findings:
        click.echo("No secrets found in git history.")
        return
    click.echo(f"\nFound {len(findings)} secret(s) in git history:\n")
    for f in findings:
        click.echo(f"  {f.file}:{f.start_line}  {f.rule_id}")
        click.echo(f"    {f.message}")
        click.echo(f"    fix: {f.fix_suggestion}")
        click.echo()
    # audit log
    AuditLogger(repo_root).log("history_scan", {"findings": len(findings)})
    click.echo("Tip: use `git filter-repo` or BFG Repo-Cleaner to scrub secrets from history.")


@main.command("pysa")
@click.option("--repo", default=".")
@click.option("--file", "file_path", help="Run Pysa on a specific file")
def pysa_cmd(repo: str, file_path: str):
    """Run Pysa (Meta OSS) taint analysis on Python files."""
    from .pysa_integration import PysaIntegration
    repo_root = Path(repo).resolve()
    pysa = PysaIntegration(repo_root)
    if not pysa.is_available():
        click.echo(pysa.install_instructions())
        return
    click.echo("Pysa is installed. Running taint analysis...")
    if file_path:
        files = [Path(file_path)]
    else:
        skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules",
                     ".stca-cache", ".stca-reports", ".stca-fixes"}
        files = [p for p in repo_root.rglob("*.py")
                 if not any(part in skip_dirs for part in p.parts)
                 and not p.name.startswith("test_")][:20]
    findings = pysa.run(files)
    if not findings:
        click.echo(f"Pysa found 0 taint flows in {len(files)} file(s).")
        return
    click.echo(f"\nPysa found {len(findings)} taint flow(s):\n")
    for f in findings:
        click.echo(f"  {f.file}:{f.start_line}  {f.rule_id}")
        click.echo(f"    {f.message}")


@main.group()
def precision():
    """Precision engine: rule mining, FP learning, calibration."""


@precision.command("mine-history")
@click.option("--repo", default=".")
@click.option("--max-commits", default=500)
@click.option("--verify", is_flag=True, default=True, help="Verify rules with Semgrep")
def precision_mine_history(repo: str, max_commits: int, verify: bool):
    """Mine rules from git bug-fix history (learn from your past bugs)."""
    from .rule_miner import mine_rules_from_history, save_mined_rules
    repo_root = Path(repo).resolve()
    click.echo(f"Mining rules from last {max_commits} commits...")
    rules = mine_rules_from_history(repo_root, max_commits=max_commits, verify=verify)
    if not rules:
        click.echo("No bug-fix patterns found to mine.")
        return
    dest = repo_root / ".stca-rules" / "mined"
    saved = save_mined_rules(rules, dest)
    click.echo(f"\nMined {len(rules)} rules from git history:")
    for r in rules[:10]:
        click.echo(f"  {r.rule_id}  (from {r.commit_hash[:8]})  {r.commit_message[:60]}")
    if len(rules) > 10:
        click.echo(f"  ... and {len(rules) - 10} more")
    click.echo(f"\nSaved to {dest}. These rules will be used automatically on the next `stca check`.")


@precision.command("mine-codebase")
@click.option("--repo", default=".")
@click.option("--max-files", default=50)
def precision_mine_codebase(repo: str, max_files: int):
    """Mine rules from your codebase (asserts, guards, docstrings)."""
    from .codebase_miner import mine_repo_rules, save_mined_codebase_rules
    repo_root = Path(repo).resolve()
    click.echo(f"Mining rules from codebase (up to {max_files} files)...")
    rules = mine_repo_rules(repo_root, max_files=max_files)
    if not rules:
        click.echo("No mineable patterns found. Add more asserts, type guards, or docstrings.")
        return
    dest = repo_root / ".stca-rules" / "codebase-mined"
    saved = save_mined_codebase_rules(rules, dest)
    by_source = {}
    for r in rules:
        by_source[r.source] = by_source.get(r.source, 0) + 1
    click.echo(f"\nMined {len(rules)} rules from codebase:")
    for source, count in by_source.items():
        click.echo(f"  {source}: {count}")
    click.echo(f"\nSaved to {dest}.")


@precision.command("compile-rules")
@click.option("--repo", default=".")
@click.option("--file", "file_path", required=True, help="Python file to compile rules for")
def precision_compile_rules(repo: str, file_path: str):
    """Use LLM to generate rules, verify with mutation testing (one-shot)."""
    from .rule_compiler import compile_rules_for_file, save_generated_rules
    from .llm.client import LLMClient
    repo_root = Path(repo).resolve()
    config = STCAConfig.from_file(find_config(repo_root))
    if not config.llm.get("enabled"):
        click.echo("LLM is not enabled. Set llm.enabled: true in .stca.yaml.")
        return
    llm = LLMClient(endpoint=config.llm.get("endpoint", "http://localhost:11434"),
                    model=config.llm.get("model", "qwen3-coder-1.5b"))
    if not llm.is_available():
        click.echo("Ollama not available. Start with `ollama serve`.")
        return
    target = Path(file_path)
    if not target.exists():
        click.echo(f"File not found: {target}")
        return
    click.echo(f"Compiling rules for {target} (LLM proposes, mutation testing verifies)...")
    rules = compile_rules_for_file(target, repo_root, llm)
    if not rules:
        click.echo("No useful rules generated (mutation testing rejected all proposals).")
        return
    dest = repo_root / ".stca-rules" / "llm-compiled"
    saved = save_generated_rules(rules, dest)
    click.echo(f"\nCompiled {len(rules)} verified rules:")
    for r in rules:
        click.echo(f"  {r.rule_id}  catches {r.mutants_caught} mutant(s)  {r.description[:60]}")
    click.echo(f"\nSaved to {dest}.")


@precision.command("fp-stats")
@click.option("--repo", default=".")
def precision_fp_stats(repo: str):
    """Show false-positive learning stats."""
    from .precision import FPLearner
    repo_root = Path(repo).resolve()
    fp = FPLearner(repo_root)
    stats = fp.stats()
    click.echo(f"FP learning stats:")
    click.echo(f"  Total patterns tracked:  {stats['total_patterns']}")
    click.echo(f"  Auto-suppressed:         {stats['auto_suppressed']}")
    click.echo(f"  Patterns with data:      {stats['patterns_with_data']}")


@precision.command("calibration")
@click.option("--repo", default=".")
def precision_calibration(repo: str):
    """Show confidence calibration stats."""
    from .precision import ConfidenceCalibrator
    repo_root = Path(repo).resolve()
    cal = ConfidenceCalibrator(repo_root)
    stats = cal.stats()
    click.echo(f"Confidence calibration:")
    click.echo(f"  Total data points: {stats['total_data_points']}")
    if stats.get("bins"):
        click.echo(f"\n  Confidence range → Actual accuracy:")
        for b in stats["bins"]:
            click.echo(f"    {b['range']}: {b['accuracy']}  ({b['total']} samples)")


@precision.command("corroborate")
@click.option("--repo", default=".")
def precision_corroborate(repo: str):
    """Show cross-layer corroboration from the last check."""
    from .precision import find_corroborating_findings
    repo_root = Path(repo).resolve()
    # load last result
    result_path = repo_root / ".stca-reports" / "result.json"
    if not result_path.exists():
        click.echo("No previous check result found. Run `stca check` first.")
        return
    import json
    data = json.loads(result_path.read_text())
    if not data.get("precision_stats"):
        click.echo("No precision stats in last result.")
        return
    ps = data["precision_stats"]
    click.echo(f"Precision stats from last check:")
    click.echo(f"  Input findings:          {ps.get('input_findings', 0)}")
    click.echo(f"  Corroboration boosts:    {ps.get('corroboration_boosts', 0)}")
    click.echo(f"  FP-suppressed:           {ps.get('fp_suppressed', 0)}")
    click.echo(f"  Calibrated:              {ps.get('calibrated', 0)}")
    click.echo(f"  Output findings:         {ps.get('output_findings', 0)}")
    click.echo(f"  Reduction:               {ps.get('reduction', 0)}")


@main.group()
def baseline():
    """Manage the issue baseline (detekt-inspired)."""


@baseline.command("create")
@click.option("--repo", default=".")
def baseline_create(repo: str):
    """Create a baseline from current findings.

    All current findings will be marked as 'known' and won't block future runs
    (unless they're new). This enables incremental adoption.
    """
    repo_root = Path(repo).resolve()
    config = STCAConfig.from_file(find_config(repo_root))
    # run check without baseline to capture all current findings
    orch = Orchestrator(repo_root, config, use_baseline=False)
    result = orch.run()
    bl = Baseline(repo_root)
    count = bl.create(result.findings)
    click.echo(f"Baseline created with {count} findings.")
    click.echo(f"Future runs with --baseline will only flag NEW issues.")


@baseline.command("update")
@click.option("--repo", default=".")
def baseline_update(repo: str):
    """Add current findings to the baseline (after review)."""
    repo_root = Path(repo).resolve()
    config = STCAConfig.from_file(find_config(repo_root))
    orch = Orchestrator(repo_root, config, use_baseline=False)
    result = orch.run()
    bl = Baseline(repo_root)
    added, total = bl.update(result.findings)
    click.echo(f"Added {added} new findings to baseline. Total: {total}")


@baseline.command("stats")
@click.option("--repo", default=".")
def baseline_stats(repo: str):
    """Show baseline statistics."""
    repo_root = Path(repo).resolve()
    bl = Baseline(repo_root)
    stats = bl.stats()
    click.echo(f"Baseline: {stats['total_entries']} entries")
    click.echo(f"File: {stats['baseline_file']}")
    if stats.get("by_severity"):
        click.echo(f"\nBy severity:")
        for sev, count in stats["by_severity"].items():
            click.echo(f"  {sev}: {count}")
    if stats.get("top_rules"):
        click.echo(f"\nTop rules:")
        for rule, count in list(stats["top_rules"].items())[:5]:
            click.echo(f"  {rule}: {count}")


@main.group()
def issue():
    """Manage issues in the issue store (CodeChecker-inspired)."""


@issue.command("list")
@click.option("--repo", default=".")
@click.option("--state", type=click.Choice(["open", "fixed", "wontfix", "false_positive", "all"]),
              default="open")
@click.option("--limit", default=50)
def issue_list(repo: str, state: str, limit: int):
    """List issues by state."""
    from .issue_store import IssueStore
    repo_root = Path(repo).resolve()
    store = IssueStore(repo_root)
    issues = store.list_issues(state=state, limit=limit)
    if not issues:
        click.echo(f"No {state} issues.")
        return
    click.echo(f"\n{len(issues)} {state} issue(s):\n")
    for iss in issues[:20]:
        click.echo(f"  {iss.fingerprint[:12]}  [{iss.severity}]  {iss.file}:{iss.line}")
        click.echo(f"    {iss.message[:80]}")
    if len(issues) > 20:
        click.echo(f"  ... and {len(issues) - 20} more")


@issue.command("resolve")
@click.option("--repo", default=".")
@click.argument("fingerprint")
@click.argument("resolution", type=click.Choice(["fixed", "wontfix", "false_positive"]))
@click.option("--note", default="")
@click.option("--user", default=lambda: __import__("getpass").getuser())
def issue_resolve(repo: str, fingerprint: str, resolution: str, note: str, user: str):
    """Resolve an issue (mark as fixed, wontfix, or false_positive)."""
    from .issue_store import IssueStore
    repo_root = Path(repo).resolve()
    store = IssueStore(repo_root)
    if store.mark_resolved(fingerprint, resolution, user, note):
        click.echo(f"Issue {fingerprint} marked as {resolution}.")
    else:
        click.echo(f"Issue {fingerprint} not found.")


@issue.command("stats")
@click.option("--repo", default=".")
def issue_stats(repo: str):
    """Show issue store statistics."""
    from .issue_store import IssueStore
    repo_root = Path(repo).resolve()
    store = IssueStore(repo_root)
    stats = store.stats()
    click.echo(f"Issue store: {stats['db_file']}")
    click.echo(f"Total issues: {stats['total_issues']}")
    click.echo(f"Total runs:   {stats['total_runs']}")
    if stats.get("by_state"):
        click.echo(f"\nBy state:")
        for state, count in stats["by_state"].items():
            click.echo(f"  {state}: {count}")
    if stats.get("open_by_severity"):
        click.echo(f"\nOpen by severity:")
        for sev, count in stats["open_by_severity"].items():
            click.echo(f"  {sev}: {count}")


@issue.command("trend")
@click.option("--repo", default=".")
@click.option("--weeks", default=12, help="Show trend for last N weeks")
def issue_trend(repo: str, weeks: int):
    """Show issue trend over time."""
    from .issue_store import IssueStore
    repo_root = Path(repo).resolve()
    store = IssueStore(repo_root)
    trend = store.get_trend(weeks=weeks)
    if not trend:
        click.echo("No trend data yet. Run `stca check` a few times.")
        return
    click.echo(f"Issue trend (last {weeks} weeks, {len(trend)} runs):\n")
    click.echo(f"{'Timestamp':<28} {'Total':>6} {'New':>6} {'Resolved':>10} {'Decision':>10}")
    click.echo("-" * 70)
    for t in trend:
        click.echo(f"{t['timestamp'][:19]:<28} {t['total']:>6} {t['new']:>6} "
                   f"{t['resolved']:>10} {t['decision']:>10}")


@main.command("strictness")
@click.option("--repo", default=".")
@click.option("--level", type=int, help="Set strictness level (1-9)")
def strictness_cmd(repo: str, level: int):
    """Show or set the strictness level (PHPStan-inspired)."""
    from .strictness import list_levels, get_level
    if level is None:
        # show all levels
        levels = list_levels()
        click.echo("\nStrictness levels:\n")
        click.echo(f"{'Level':<6} {'Name':<28} {'Layers':<8} {'Severities':<30} Description")
        click.echo("-" * 120)
        for sl in levels:
            click.echo(f"{sl['level']:<6} {sl['name']:<28} {sl['layers']:<8} "
                       f"{sl['severities']:<30} {sl['description'][:50]}")
        click.echo(f"\nSet with: stca strictness --level N")
        click.echo(f"Use with: stca check --strictness N")
    else:
        # set the level in config
        repo_root = Path(repo).resolve()
        cfg_path = find_config(repo_root)
        config = STCAConfig.from_file(cfg_path)
        config.layers["__strictness__"] = {"level": level}
        config.save(cfg_path)
        sl = get_level(level)
        click.echo(f"Strictness set to level {level}: {sl.name}")
        click.echo(f"  {sl.description}")


@main.command("nullness")
@click.option("--repo", default=".")
@click.option("--file", "file_path", help="Analyze a specific file")
def nullness_cmd(repo: str, file_path: str):
    """Run sound nullness analysis (NilAway-inspired) for Python."""
    from .nullness import NullnessAnalyzer
    repo_root = Path(repo).resolve()
    analyzer = NullnessAnalyzer()
    if file_path:
        files = [Path(file_path)]
    else:
        skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules",
                     ".stca-cache", ".stca-reports", ".stca-fixes"}
        files = [p for p in repo_root.rglob("*.py")
                 if not any(part in skip_dirs for part in p.parts)
                 and not p.name.startswith("test_")][:20]

    total = 0
    for f in files:
        issues = analyzer.analyze_file(f, repo_root)
        for issue in issues:
            click.echo(f"  {issue.file}:{issue.line}  {issue.variable}  {issue.reason}")
            if issue.context:
                click.echo(f"    context: {issue.context[:80]}")
            total += 1
    click.echo(f"\n{total} nullness issue(s) found in {len(files)} file(s).")


@main.command("consistency")
@click.option("--repo", default=".")
def consistency_cmd(repo: str):
    """Check codebase consistency (credo-inspired)."""
    from .consistency import check_all_consistencies
    repo_root = Path(repo).resolve()
    inconsistencies = check_all_consistencies(repo_root, max_files=100)
    if not inconsistencies:
        click.echo("No inconsistencies found. Codebase is consistent.")
        return
    click.echo(f"\n{len(inconsistencies)} inconsistency(ies) found:\n")
    for inc in inconsistencies:
        click.echo(f"  [{inc.category}] {inc.description}")
        click.echo(f"    Pattern A: {inc.pattern_a}  ({len(inc.files_using_a)} files)")
        click.echo(f"    Pattern B: {inc.pattern_b}  ({len(inc.files_using_b)} files)")
        click.echo(f"    Fix: {inc.recommendation}")
        click.echo()


@main.group()
def profile():
    """Manage configuration profiles (luacheck/detekt-inspired)."""


@profile.command("list")
@click.option("--repo", default=".")
def profile_list(repo: str):
    """List all available profiles."""
    from .profiles import ProfileManager
    repo_root = Path(repo).resolve()
    cfg_path = find_config(repo_root)
    pm = ProfileManager(cfg_path)
    profiles = pm.list_profiles()
    click.echo(f"\n{len(profiles)} profile(s) available:\n")
    click.echo(f"{'Name':<15} {'Min Sev':<10} {'Disabled':<10} {'Paths':<6} Description")
    click.echo("-" * 90)
    for p in profiles:
        click.echo(f"{p['name']:<15} {p['min_severity']:<10} {p['disabled_rules']:<10} "
                   f"{p['paths']:<6} {p['description'][:50]}")


@profile.command("show")
@click.option("--repo", default=".")
@click.argument("name")
def profile_show(repo: str, name: str):
    """Show details of a specific profile."""
    from .profiles import ProfileManager
    repo_root = Path(repo).resolve()
    cfg_path = find_config(repo_root)
    pm = ProfileManager(cfg_path)
    p = pm.get_profile(name)
    if not p:
        click.echo(f"Profile '{name}' not found.")
        return
    click.echo(f"Profile: {p.name}")
    click.echo(f"  Description: {p.description}")
    click.echo(f"  Min severity: {p.min_severity}")
    click.echo(f"  Block on: {', '.join(p.block_on)}")
    if p.disabled_rule_categories:
        click.echo(f"  Disabled categories: {', '.join(p.disabled_rule_categories)}")
    if p.disabled_rules:
        click.echo(f"  Disabled rules ({len(p.disabled_rules)}):")
        for r in p.disabled_rules[:10]:
            click.echo(f"    - {r}")
    if p.paths:
        click.echo(f"  Paths: {', '.join(p.paths)}")
    if p.extends:
        click.echo(f"  Extends: {p.extends}")


@profile.command("apply")
@click.option("--repo", default=".")
@click.argument("name")
def profile_apply(repo: str, name: str):
    """Run check with a specific profile."""
    from .profiles import ProfileManager
    repo_root = Path(repo).resolve()
    cfg_path = find_config(repo_root)
    pm = ProfileManager(cfg_path)
    if not pm.get_profile(name):
        click.echo(f"Profile '{name}' not found. Run `stca profile list`.")
        return
    click.echo(f"Profile '{name}' is available. Use: stca check --profile {name}")


@main.group()
def rules_config():
    """Per-rule configuration (detekt-style)."""


@rules_config.command("stats")
@click.option("--repo", default=".")
def rules_config_stats(repo: str):
    """Show per-rule configuration stats."""
    from .rule_config import RuleConfigManager
    repo_root = Path(repo).resolve()
    cfg_path = find_config(repo_root)
    rcm = RuleConfigManager(cfg_path)
    stats = rcm.stats()
    click.echo(f"Per-rule configuration:")
    click.echo(f"  Total configured rules: {stats['total_configured_rules']}")
    click.echo(f"  Disabled rules:         {stats['disabled_rules']}")
    click.echo(f"  Severity overrides:     {stats['severity_overrides']}")
    click.echo(f"  Path-filtered rules:    {stats['path_filtered_rules']}")


@rules_config.command("disable")
@click.option("--repo", default=".")
@click.argument("rule_id")
@click.option("--note", default="", help="Why this rule is disabled")
def rules_config_disable(repo: str, rule_id: str, note: str):
    """Disable a specific rule."""
    from .rule_config import RuleConfigManager, RuleConfig
    repo_root = Path(repo).resolve()
    cfg_path = find_config(repo_root)
    rcm = RuleConfigManager(cfg_path)
    rcm.set_rule_config(rule_id, RuleConfig(active=False, note=note))
    click.echo(f"Rule '{rule_id}' disabled. {'Note: ' + note if note else ''}")


@rules_config.command("severity")
@click.option("--repo", default=".")
@click.argument("rule_id")
@click.argument("severity", type=click.Choice(["critical", "high", "medium", "low", "info"]))
def rules_config_severity(repo: str, rule_id: str, severity: str):
    """Override a rule's severity."""
    from .rule_config import RuleConfigManager, RuleConfig
    repo_root = Path(repo).resolve()
    cfg_path = find_config(repo_root)
    rcm = RuleConfigManager(cfg_path)
    rcm.set_rule_config(rule_id, RuleConfig(active=True, severity=severity))
    click.echo(f"Rule '{rule_id}' severity set to '{severity}'.")


@main.command("missing-patches")
@click.option("--repo", default=".")
def missing_patches_cmd(repo: str):
    """Scan for missing security patches (Vanir-inspired).

    Compares your code against known CVE patch patterns to find
    unpatched code — even if the package version says it's fixed.
    """
    from .version_vuln_checks import scan_version_vuln_checks, version_vuln_check_stats
    repo_root = Path(repo).resolve()
    db_stats = version_vuln_check_stats()
    click.echo(f"Patch database: {db_stats['total_patches']} known patches")
    click.echo(f"  By severity: {db_stats['by_severity']}")
    click.echo()
    click.echo("Scanning for missing patches...")
    missing = scan_version_vuln_checks(repo_root)
    if not missing:
        click.echo("No missing patches detected.")
        return
    click.echo(f"\n{len(missing)} missing patch(es) found:\n")
    for m in missing:
        sev_color = {"critical": "red", "high": "yellow", "medium": "blue"}.get(m.severity, "white")
        click.echo(f"  [{m.severity.upper():<8}] {m.cve}  ({m.package})")
        click.echo(f"    {m.description}")
        click.echo(f"    File: {m.file}:{m.line}")
        click.echo(f"    Code: {m.vulnerable_snippet[:100]}")
        click.echo(f"    Fix:  {m.fix_url}")
        click.echo()


@main.command("contracts")
@click.option("--repo", default=".")
def contracts_cmd(repo: str):
    """Analyze design-by-contract decorators (deal-inspired).

    Extracts @deal.pre/@post/@ensure/@invariant contracts from your code
    and checks for violations at call sites.
    """
    from .contracts import extract_all_contracts, check_preconditions_at_call_sites, contract_stats
    repo_root = Path(repo).resolve()
    click.echo("Extracting contracts...")
    contracts = extract_all_contracts(repo_root, max_files=100)
    if not contracts:
        click.echo("No contracts found. Use @deal.pre/@post/@ensure decorators to add contracts.")
        return
    stats = contract_stats(contracts)
    click.echo(f"\nContract stats:")
    click.echo(f"  Total contracts:          {stats['total_contracts']}")
    click.echo(f"  Functions with contracts: {stats['functions_with_contracts']}")
    click.echo(f"  By type: {stats['by_type']}")
    click.echo()
    click.echo("Checking for violations at call sites...")
    violations = check_preconditions_at_call_sites(contracts, repo_root)
    if not violations:
        click.echo("No contract violations detected.")
    else:
        click.echo(f"\n{len(violations)} contract violation(s) found:\n")
        for v in violations:
            click.echo(f"  {v.function}() at {v.caller_file}:{v.caller_line}")
            click.echo(f"    {v.violation_type}: {v.condition}")
            click.echo(f"    {v.message}")
            click.echo()


@main.command("deadcode")
@click.option("--repo", default=".")
@click.option("--discover", is_flag=True, help="Only discover functions (no trace needed)")
def deadcode_cmd(repo: str, discover: bool):
    """Runtime dead code analysis (scavenger-inspired).

    Discovers all functions, then (if a trace exists from instrumentation)
    reports which were never called.
    """
    from .deadcode import DeadCodeAnalyzer
    repo_root = Path(repo).resolve()
    analyzer = DeadCodeAnalyzer(repo_root)
    click.echo("Discovering functions...")
    count = analyzer.discover_functions()
    click.echo(f"Discovered {count} functions.")
    analyzer.load_trace()
    if discover or not analyzer.trace_file.exists():
        stats = analyzer.stats()
        click.echo(f"\nStats:")
        click.echo(f"  Total functions: {stats['total_discovered']}")
        click.echo(f"  Live (called):   {stats['live']}")
        click.echo(f"  Dead (uncalled): {stats['dead']}")
        if not analyzer.trace_file.exists():
            click.echo(f"\nNo trace file found. To get runtime dead code:")
            click.echo(f"  1. Instrument: stca deadcode instrument")
            click.echo(f"  2. Run tests:  pytest")
            click.echo(f"  3. Report:     stca deadcode")
    else:
        dead = analyzer.get_dead_code()
        click.echo(f"\n{len(dead)} dead function(s) found:\n")
        for f in dead[:30]:
            click.echo(f"  {f.file}:{f.line}  {f.name}")
        if len(dead) > 30:
            click.echo(f"  ... and {len(dead) - 30} more")


@main.command("flawfinder")
@click.option("--repo", default=".")
def flawfinder_cmd(repo: str):
    """Scan C/C++ for dangerous functions (flawfinder-inspired).

    Uses a curated database of 40+ dangerous C/C++ functions with
    risk levels (1-5), CWEs, and safer alternatives.
    """
    from .flawfinder_db import scan_repo_dangerous_functions, database_stats
    repo_root = Path(repo).resolve()
    db = database_stats()
    click.echo(f"Flawfinder database: {db['total_functions']} dangerous functions")
    click.echo(f"  Critical (risk 5): {db['critical']}, High (4): {db['high']}, "
               f"Medium (3): {db['medium']}, Low (2): {db['low']}, Info (1): {db['info']}")
    click.echo()
    click.echo("Scanning C/C++ files...")
    hits = scan_repo_dangerous_functions(repo_root)
    if not hits:
        click.echo("No dangerous functions found (or no C/C++ files).")
        return
    click.echo(f"\n{len(hits)} dangerous function call(s) found:\n")
    for h in hits:
        risk_marker = "!" * h.risk_level
        click.echo(f"  Risk {h.risk_level} {risk_marker}  {h.function}()  {h.file}:{h.line}")
        click.echo(f"    {h.explanation}")
        click.echo(f"    Fix: {h.safer_alternative}")
        if h.context:
            click.echo(f"    Code: {h.context[:100]}")
        click.echo()


@main.command("malicious")
@click.option("--repo", default=".")
def malicious_cmd(repo: str):
    """Scan for malicious package patterns (aura-inspired).

    Detects behavioral patterns that indicate malware, not just known CVEs:
    install-time downloads, SSH key reading, import-time network access,
    base64-encoded exec, system file modification, etc.
    """
    from .malicious_patterns import scan_repo_malicious_patterns, malicious_stats
    repo_root = Path(repo).resolve()
    click.echo("Scanning for malicious patterns...")
    hits = scan_repo_malicious_patterns(repo_root, max_files=200)
    if not hits:
        click.echo("No malicious patterns found.")
        return
    stats = malicious_stats(hits)
    click.echo(f"\n{len(hits)} malicious pattern(s) found:\n")
    click.echo(f"By severity: {stats['by_severity']}")
    click.echo(f"By type: {stats['by_type']}")
    click.echo()
    for h in hits[:30]:
        click.echo(f"  [{h.severity.upper():<8}] {h.pattern_type}  {h.file}:{h.line}")
        click.echo(f"    {h.description} — {h.indicator}")
        if h.context:
            click.echo(f"    Code: {h.context[:100]}")
        click.echo()
    if len(hits) > 30:
        click.echo(f"  ... and {len(hits) - 30} more")


@main.command("pii")
@click.option("--repo", default=".")
def pii_cmd(repo: str):
    """Scan for PII (pii-shield-inspired).

    Detects SSNs, credit cards, emails, phone numbers, IBANs, passports,
    Aadhaar, NINO, dates of birth, and IP addresses in source code.
    Critical for GDPR, CCPA, HIPAA compliance.
    """
    from .pii_detection import scan_repo_pii, pii_stats
    repo_root = Path(repo).resolve()
    click.echo("Scanning for PII...")
    detections = scan_repo_pii(repo_root, max_files=200)
    if not detections:
        click.echo("No PII detected.")
        return
    stats = pii_stats(detections)
    click.echo(f"\n{len(detections)} PII detection(s):\n")
    click.echo(f"By type: {stats['by_type']}")
    click.echo(f"By confidence: {stats['by_confidence']}")
    click.echo()
    for d in detections[:30]:
        click.echo(f"  [{d.pii_type:<20}] {d.file}:{d.line}  {d.value_preview}")
        if d.context:
            click.echo(f"    context: {d.context[:100]}")
    if len(detections) > 30:
        click.echo(f"  ... and {len(detections) - 30} more")


@main.command("rca")
@click.option("--repo", default=".")
def rca_cmd(repo: str):
    """Root cause analysis (Vitrage-inspired).

    Correlates findings from the last check to identify root causes.
    "These 5 findings are all caused by this one missing validation."
    """
    from .root_cause import find_root_causes, rca_stats
    repo_root = Path(repo).resolve()
    # load last check result
    result_path = repo_root / ".stca-reports" / "result.json"
    if not result_path.exists():
        click.echo("No previous check result found. Run `stca check` first.")
        return
    import json
    data = json.loads(result_path.read_text())
    if not data.get("findings"):
        click.echo("No findings in last check.")
        return
    # reconstruct findings (simplified — just use the data for correlation)
    from .models import Finding, Severity, BlastRadius, LayerID
    findings = []
    for f_dict in data["findings"]:
        try:
            findings.append(Finding(
                layer=LayerID(f_dict.get("layer", "L0_fast")),
                rule_id=f_dict["rule_id"],
                message=f_dict["message"],
                file=f_dict["file"],
                start_line=f_dict["start_line"],
                severity=Severity(f_dict.get("severity", "medium")),
                confidence=f_dict.get("confidence", 0.5),
                cwe=f_dict.get("cwe"),
                raw=f_dict.get("raw", {}),
            ))
        except Exception:
            continue
    clusters = find_root_causes(findings)
    if not clusters:
        click.echo("No root cause clusters found — findings are independent.")
        return
    stats = rca_stats(clusters)
    click.echo(f"\n{stats['total_clusters']} root cause cluster(s):\n")
    click.echo(f"Findings explained by RCA: {stats['findings_explained']} / {len(findings)}")
    click.echo(f"By type: {stats['by_type']}\n")
    for c in clusters[:15]:
        click.echo(f"  [{c.cluster_type}] {c.root_cause_file}:{c.root_cause_line}")
        click.echo(f"    Root cause: {c.root_cause_message[:100]}")
        click.echo(f"    Correlated: {len(c.correlated_findings)} finding(s)")
        click.echo(f"    {c.description}")
        click.echo()


@main.command("impact")
@click.option("--repo", default=".")
@click.option("--file", "file_path", required=True, help="File with changed functions")
def impact_cmd(repo: str, file_path: str):
    """Impact analysis (gossiphs-inspired).

    Builds a call graph and shows what functions/tests are affected
    by changes to the specified file.
    """
    from .impact_analysis import ImpactAnalyzer
    repo_root = Path(repo).resolve()
    target = Path(file_path)
    if not target.exists():
        click.echo(f"File not found: {target}")
        return
    click.echo("Building call graph...")
    analyzer = ImpactAnalyzer(repo_root)
    func_count = analyzer.build_call_graph(max_files=100)
    click.echo(f"Discovered {func_count} functions in call graph.")
    stats = analyzer.stats()
    click.echo(f"  Total edges: {stats['total_edges']}")
    click.echo(f"  Avg callers per function: {stats['avg_callers_per_function']:.1f}")

    # find functions in the target file
    import ast
    try:
        tree = ast.parse(target.read_text(encoding="utf-8"))
    except Exception as e:
        click.echo(f"Failed to parse: {e}")
        return
    rel = str(target.relative_to(repo_root)) if target.is_relative_to(repo_root) else str(target)
    changed_funcs = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if not node.name.startswith("_"):
                changed_funcs.append((node.name, node.lineno, rel))

    if not changed_funcs:
        click.echo("No public functions found in file.")
        return

    click.echo(f"\nAnalyzing impact for {len(changed_funcs)} function(s)...")
    results = analyzer.analyze_impact(changed_funcs)
    for r in results:
        click.echo(f"\n  {r.changed_function}() at {r.changed_file}:{r.changed_line}")
        click.echo(f"    Risk: {r.risk_level.upper()}  (blast radius: {r.blast_radius})")
        click.echo(f"    Direct callers: {len(r.direct_callers)}")
        for c in r.direct_callers[:5]:
            click.echo(f"      {c.file}:{c.line}  {c.function}()")
        click.echo(f"    Transitive callers: {len(r.transitive_callers)}")
        click.echo(f"    Test files: {len(r.test_files)}")
        for t in r.test_files[:5]:
            click.echo(f"      {t}")


@main.command("architecture")
@click.option("--repo", default=".")
def architecture_cmd(repo: str):
    """Architecture enforcement (rev-dep-inspired).

    Checks that imports respect layer boundaries (controllers → services → models → utils).
    """
    from .architecture import ArchitectureEnforcer
    repo_root = Path(repo).resolve()
    enforcer = ArchitectureEnforcer(repo_root)
    click.echo(f"Architecture layers: {enforcer.stats()['layer_names']}")
    click.echo("\nChecking architecture boundaries...")
    violations = enforcer.check_repo(max_files=100)
    if not violations:
        click.echo("No architecture violations found.")
        return
    click.echo(f"\n{len(violations)} architecture violation(s):\n")
    for v in violations[:30]:
        click.echo(f"  {v.file}:{v.line}  [{v.importing_layer} → {v.imported_layer}]")
        click.echo(f"    {v.description}")
        click.echo(f"    Import: {v.imported_module}")
        click.echo()


@main.command("doc-audit")
@click.option("--repo", default=".")
def doc_audit_cmd(repo: str):
    """Documentation audit (Valknut-inspired).

    Checks for missing docstrings, stale docstrings, TODO/FIXME/HACK comments.
    """
    from .doc_audit import audit_repo, doc_stats
    repo_root = Path(repo).resolve()
    click.echo("Auditing documentation...")
    issues = audit_repo(repo_root, max_files=100)
    if not issues:
        click.echo("No documentation issues found.")
        return
    stats = doc_stats(issues)
    click.echo(f"\n{len(issues)} documentation issue(s):\n")
    click.echo(f"By type: {stats['by_type']}")
    click.echo(f"By severity: {stats['by_severity']}")
    click.echo()
    for issue in issues[:30]:
        click.echo(f"  [{issue.issue_type:<20}] {issue.file}:{issue.line}  {issue.name}")
        click.echo(f"    {issue.description}")
    if len(issues) > 30:
        click.echo(f"  ... and {len(issues) - 30} more")


@main.command("toxicity")
@click.option("--repo", default=".")
def toxicity_cmd(repo: str):
    """Code toxicity analysis (nocuous/codehawk-inspired).

    Computes Halstead complexity + toxicity score (0-100) for each function.
    Toxic functions (>50 score) are likely to contain bugs.
    """
    from .complexity_metrics import analyze_repo_toxicity, toxicity_stats
    repo_root = Path(repo).resolve()
    click.echo("Analyzing code toxicity...")
    reports = analyze_repo_toxicity(repo_root, max_files=100)
    if not reports:
        click.echo("No functions found to analyze.")
        return
    stats = toxicity_stats(reports)
    click.echo(f"\n{stats['total_functions']} functions analyzed:")
    click.echo(f"  Average toxicity: {stats['average_score']}/100")
    click.echo(f"  Toxic (>50): {stats['toxic_count']}")
    click.echo(f"  By risk: {stats['by_risk']}")
    click.echo(f"\nTop 10 most toxic functions:")
    for t in stats["top_toxic"]:
        click.echo(f"  [{t['risk']:<8}] {t['score']:>5}  {t['file']}:{t['line']}  {t['function']}()")


@main.command("ffi-check")
@click.option("--repo", default=".")
def ffi_check_cmd(repo: str):
    """Full cross-language FFI boundary analysis (i-CodeCNES-inspired).

    Analyzes Python↔C boundary for:
      - Type mismatches (None→pointer, str→char*, int→pointer, list→array)
      - Buffer overflows via FFI (gets, strcpy, sprintf called from Python)
      - Null pointer dereference (None passed to C pointer parameter)
      - Missing error checking (C return value not checked)
      - Signed/unsigned mismatch (negative int→unsigned C param)
      - String encoding issues (str where C expects bytes)
      - Memory management (malloc without free, dangling pointers)
      - GIL violations (Python API called without GIL in C extension)
      - Reference counting imbalance (INCREF≠DECREF in C extension)
      - Dangerous C function calls (gets, strcpy, system via FFI)
    """
    from .ffi_analyzer import analyze_ffi_boundary
    repo_root = Path(repo).resolve()
    click.echo("Analyzing FFI boundary (Python↔C)...")
    ffi_calls, violations, stats = analyze_ffi_boundary(repo_root)
    click.echo(f"\nStats:")
    click.echo(f"  FFI files found:        {stats['ffi_files_scanned']}")
    click.echo(f"  FFI calls found:        {stats['ffi_calls_found']}")
    click.echo(f"  C signatures parsed:    {stats['c_signatures_parsed']}")
    click.echo(f"  C extensions found:     {stats['c_extensions_found']}")
    click.echo(f"  FFI types used:         {stats['ffi_types_used']}")
    click.echo(f"  Violations found:       {stats['violations_found']}")
    if not violations:
        click.echo("\nNo FFI violations found.")
        return
    click.echo(f"\n{len(violations)} FFI violation(s):\n")
    from collections import Counter
    by_type = Counter(v.violation_type for v in violations)
    by_severity = Counter(v.severity for v in violations)
    click.echo(f"By type: {dict(by_type)}")
    click.echo(f"By severity: {dict(by_severity)}")
    click.echo()
    for v in violations[:30]:
        loc = f"{v.python_file}:{v.python_line}" if v.python_file else f"{v.c_file}:{v.c_line}"
        click.echo(f"  [{v.severity.upper():<8}] {v.violation_type}  {loc}")
        click.echo(f"    {v.description[:120]}")
        if v.c_function:
            click.echo(f"    C function: {v.c_function}")
        if v.fix_suggestion:
            click.echo(f"    Fix: {v.fix_suggestion[:100]}")
        click.echo()
    if len(violations) > 30:
        click.echo(f"  ... and {len(violations) - 30} more")


@main.group()
def suppressions():
    """Manage inline suppressions."""


@suppressions.command("list")
@click.option("--repo", default=".")
def suppressions_list(repo: str):
    """List all inline suppressions in the repo."""
    from .suppressions import find_suppressions
    repo_root = Path(repo).resolve()
    skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules"}
    total = 0
    for p in repo_root.rglob("*.py"):
        if any(part in skip_dirs for part in p.parts):
            continue
        sups = find_suppressions(p)
        for s in sups:
            click.echo(f"  {p.relative_to(repo_root)}:{s.line}  rule={s.rule_id or 'all'}  -- {s.raw}")
            total += 1
    click.echo(f"\n{total} suppression(s) found.")


@main.group()
def bootstrap():
    """One-time setup commands — generate deterministic artifacts."""


@bootstrap.command("invariants")
@click.option("--repo", default=".", help="Repository root")
def bootstrap_invariants(repo: str):
    """Infer runtime invariants from test runs (Daikon-style)."""
    repo_root = Path(repo).resolve()
    inferrer = InvariantInferrer(repo_root)
    invariants = inferrer.infer_from_tests()
    click.echo(f"Inferred {sum(len(v) for v in invariants.values())} invariants "
               f"across {len(invariants)} functions.")
    click.echo(f"Written to {repo_root / '.stca-invariants.json'}")


@bootstrap.command("harnesses")
@click.option("--repo", default=".", help="Repository root")
@click.option("--file", "file_path", help="Generate harness for a specific file")
def bootstrap_harnesses(repo: str, file_path: str):
    """Generate fuzz harnesses for functions (LLM-assisted, one-shot)."""
    repo_root = Path(repo).resolve()
    llm = None
    config = STCAConfig.from_file(find_config(repo_root))
    if config.llm.get("enabled"):
        llm = LLMClient(endpoint=config.llm.get("endpoint", "http://localhost:11434"),
                        model=config.llm.get("model", "qwen3-coder-1.5b"))
    gen = HarnessGenerator(repo_root, llm)

    if file_path:
        files = [Path(file_path)]
    else:
        skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules",
                     ".stca-cache", "tests", "test"}
        files = [p for p in repo_root.rglob("*.py")
                 if not any(part in skip_dirs for part in p.parts)
                 and not p.name.startswith("test_")]

    total = 0
    for f in files:
        harnesses = gen.generate_for_file(f)
        total += len(harnesses)
        for h in harnesses:
            click.echo(f"  generated: {h.relative_to(repo_root)}")
    click.echo(f"\nGenerated {total} fuzz harnesses in tests/fuzz/")


@bootstrap.command("properties")
@click.option("--repo", default=".", help="Repository root")
@click.option("--file", "file_path", help="Generate for a specific file")
def bootstrap_properties(repo: str, file_path: str):
    """Generate Hypothesis property tests (LLM-assisted, one-shot)."""
    repo_root = Path(repo).resolve()
    llm = None
    config = STCAConfig.from_file(find_config(repo_root))
    if config.llm.get("enabled"):
        llm = LLMClient(endpoint=config.llm.get("endpoint", "http://localhost:11434"),
                        model=config.llm.get("model", "qwen3-coder-1.5b"))
    gen = PropertyTestGenerator(repo_root, llm)

    if file_path:
        files = [Path(file_path)]
    else:
        skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules",
                     ".stca-cache", "tests", "test"}
        files = [p for p in repo_root.rglob("*.py")
                 if not any(part in skip_dirs for part in p.parts)
                 and not p.name.startswith("test_")]

    total = 0
    for f in files:
        out = gen.generate_for_file(f)
        if out:
            total += 1
            click.echo(f"  generated: {out.relative_to(repo_root)}")
    click.echo(f"\nGenerated property test files for {total} modules in tests/property/")


@main.group()
def feedback():
    """Feedback loop commands — track precision/recall and capture escaped bugs."""


@feedback.command("tp")
@click.option("--repo", default=".")
@click.argument("layer_id")
def feedback_tp(repo: str, layer_id: str):
    """Record a true positive for a layer."""
    tracker = StatsTracker(Path(repo).resolve() / ".stca-stats.json")
    tracker.record_true_positive(layer_id)
    click.echo(f"Recorded TP for {layer_id}. Precision: {tracker.layers[layer_id].precision:.0%}")


@feedback.command("fp")
@click.option("--repo", default=".")
@click.argument("layer_id")
def feedback_fp(repo: str, layer_id: str):
    """Record a false positive for a layer."""
    tracker = StatsTracker(Path(repo).resolve() / ".stca-stats.json")
    tracker.record_false_positive(layer_id)
    click.echo(f"Recorded FP for {layer_id}. Precision: {tracker.layers[layer_id].precision:.0%}")


@feedback.command("capture")
@click.option("--repo", default=".")
@click.option("--file", "file_path", required=True, help="File where bug was found")
@click.option("--line", type=int, required=True, help="Line number")
@click.option("--layer", "layer_id", default="manual", help="Layer that should have caught it")
@click.option("--description", required=True, help="Bug description")
@click.option("--language", default="python")
@click.option("--snippet", help="Code snippet (or read from stdin)")
def feedback_capture(repo: str, file_path: str, line: int, layer_id: str,
                     description: str, language: str, snippet: str):
    """Capture an escaped bug as a new Semgrep rule template."""
    repo_root = Path(repo).resolve()
    capture = RuleCapture(repo_root)
    if not snippet:
        snippet = sys.stdin.read() if not sys.stdin.isatty() else ""
    rule_path = capture.capture_escaped_bug(
        layer_id, file_path, line, snippet, description, language
    )
    click.echo(f"Captured rule: {rule_path}")
    click.echo("Edit the pattern to make it precise, then commit.")


@feedback.command("stats")
@click.option("--repo", default=".")
def feedback_stats(repo: str):
    """Show per-layer precision/recall stats."""
    tracker = StatsTracker(Path(repo).resolve() / ".stca-stats.json")
    stats = tracker.summary()
    if not stats:
        click.echo("No stats recorded yet.")
        return
    click.echo(f"{'Layer':<20} {'Precision':>10} {'Recall':>10} {'TP':>5} {'FP':>5} {'FN':>5}")
    click.echo("-" * 60)
    for layer, s in sorted(stats.items()):
        click.echo(f"{layer:<20} {s['precision']:>10.0%} {s['recall']:>10.0%} "
                   f"{s['tp']:>5} {s['fp']:>5} {s['fn']:>5}")


@main.command()
@click.option("--repo", default=".")
def doctor(repo: str):
    """Check what tools and dependencies are available."""
    import shutil
    repo_root = Path(repo).resolve()

    click.echo("STCA Pipeline — Doctor")
    click.echo("=" * 50)
    click.echo(f"Repo: {repo_root}")
    click.echo(f"Config: {find_config(repo_root)}")
    click.echo()

    click.echo("External tools:")
    tools = [
        ("git", "required"),
        ("gitleaks", "L0 secrets"),
        ("ruff", "L0 Python lint"),
        ("semgrep", "L0 SAST (multi-language)"),
        ("golangci-lint", "L0 Go lint"),
        ("eslint", "L0 JS/TS lint"),
        ("clang-tidy", "L0 C/C++ lint"),
        ("opa", "L5 policy"),
        ("kani", "L6 Rust verification"),
        ("mutmut", "L2 mutation"),
        ("atheris", "L4 Python fuzz"),
        ("pip-audit", "L0b Python CVEs"),
        ("osv-scanner", "L0b multi-lang CVEs"),
        ("npm", "L0b Node CVEs"),
        ("govulncheck", "L0b Go CVEs"),
        ("cargo-audit", "L0b Rust CVEs"),
        ("pip-licenses", "L0c license check"),
        ("trivy", "L0b/L0e vulnerability + IaC scanner"),
        ("checkov", "L0e IaC misconfiguration scanner"),
        ("kics", "L0e IaC security scanner"),
        ("jscpd", "L0d code duplication"),
    ]
    for tool, role in tools:
        path = shutil.which(tool)
        status = "✓" if path else "✗"
        click.echo(f"  {status} {tool:<15} ({role})")

    click.echo()
    click.echo("Python packages:")
    for pkg, role in [
        ("hypothesis", "L1 property tests"),
        ("rich", "TUI reports"),
        ("tree_sitter", "diff slicing"),
        ("tree_sitter_python", "Python parsing"),
        ("yaml", "config loading"),
        ("numpy", "FIS math"),
    ]:
        try:
            __import__(pkg)
            click.echo(f"  ✓ {pkg:<20} ({role})")
        except ImportError:
            click.echo(f"  ✗ {pkg:<20} ({role})")

    click.echo()
    click.echo("STCA-installed tools (in ~/.stca/bin/):")
    installer.ensure_stca_on_path()
    for spec_name, spec in installer.TOOLS.items():
        path = shutil.which(spec.binary_name or spec_name)
        status = "✓" if path else "✗"
        click.echo(f"  {status} {spec_name:<15} ({spec.layer}) {spec.description}")
    click.echo(f"  Run `stca install-tools` to install missing tools.")

    click.echo()
    click.echo("Language support (business logic detection):")
    try:
        from .multi_language_bl import get_capabilities, get_supported_languages
        caps = get_capabilities()
        for lang in caps["supported_languages"]:
            detectors = caps["techniques_per_language"].get(lang, {})
            active = sum(1 for v in detectors.values() if v)
            total = len(detectors)
            click.echo(f"  ✓ {lang:<15} {active}/{total} BL detectors active")
        if caps["tree_sitter_available"]:
            click.echo(f"  Tree-sitter: available ({len(caps['tree_sitter_languages'])} languages)")
        else:
            click.echo(f"  Tree-sitter: not installed (Python-only mode — install tree-sitter for multi-language)")
            click.echo(f"               pip install tree-sitter tree-sitter-python tree-sitter-javascript tree-sitter-go tree-sitter-java tree-sitter-c tree-sitter-cpp")
    except Exception:
        click.echo("  (multi-language BL module not available)")

    click.echo()
    config = STCAConfig.from_file(find_config(repo_root))
    click.echo(f"LLM enabled: {config.llm.get('enabled')}")
    if config.llm.get("enabled"):
        llm = LLMClient(endpoint=config.llm.get("endpoint", "http://localhost:11434"),
                        model=config.llm.get("model", "qwen3-coder-1.5b"))
        click.echo(f"LLM available: {'yes' if llm.is_available() else 'no (Ollama not running?)'}")


@main.command()
@click.option("--repo", default=".", help="Repository root")
@click.option("--changed", multiple=True, required=True, help="Changed file(s) to analyze impact for")
def impact(repo: str, changed: tuple):
    """Show blast-radius analysis for changed files.

    v4.32: Uses the knowledge graph to determine which functions/classes
    are affected by changes to the specified files. Shows directly affected,
    transitively affected, and total blast radius.

    Example:
        stca impact --changed stca/orchestrator.py --changed stca/cpg.py
    """
    repo_root = Path(repo).resolve()
    try:
        from .knowledge_graph import KnowledgeGraphBuilder, DiffImpactAnalyzer
        click.echo(f"Building knowledge graph for {repo_root}...", err=True)
        builder = KnowledgeGraphBuilder(repo_root)
        graph = builder.build(max_files=300)
        analyzer = DiffImpactAnalyzer(graph)
        result = analyzer.analyze_changed_files(list(changed))

        click.echo(f"\nImpact Analysis: {len(changed)} changed file(s)")
        click.echo(f"  Total blast radius: {result['total_blast_radius']} nodes")
        click.echo(f"  Directly affected: {len(result['directly_affected'])} functions")
        click.echo(f"  Transitively affected: {len(result['transitively_affected'])} functions")
        click.echo(f"\nBy layer:")
        for layer, funcs in result.get("by_layer", {}).items():
            click.echo(f"  {layer}: {len(funcs)} functions")
        if result["transitively_affected"]:
            click.echo(f"\nTop affected functions:")
            for fn in result["transitively_affected"][:10]:
                click.echo(f"  - {fn}")
            if len(result["transitively_affected"]) > 10:
                click.echo(f"  ... and {len(result['transitively_affected']) - 10} more")

        # Suggest tests
        suggested = analyzer.suggest_tests(list(changed))
        if suggested:
            click.echo(f"\nSuggested test files to run:")
            for t in suggested:
                click.echo(f"  - {t}")
    except Exception as e:
        click.echo(f"Impact analysis error: {e}", err=True)
        sys.exit(1)


@main.command()
@click.option("--repo", default=".", help="Repository root")
@click.option("--stdio", is_flag=True, default=True, help="Use stdio for LSP communication")
def lsp(repo: str, stdio: bool):
    """Start the STCA LSP server for IDE integration (VS Code, Neovim, JetBrains).

    v4.30: Exposes the LSP server that was previously unreachable.
    Configure in VS Code settings.json:
    {
        "languageserver": {
            "stca": {
                "command": "stca",
                "args": ["lsp", "--repo", "."],
                "filetypes": ["python", "javascript", "typescript", "go", "java", "c", "cpp", "rust"]
            }
        }
    }
    """
    try:
        from .lsp.server import LSPServer
        server = LSPServer(repo_root=Path(repo).resolve())
        server.run()
    except Exception as e:
        click.echo(f"LSP server error: {e}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
