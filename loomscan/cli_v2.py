"""v2 CLI commands — registers additional `loomscan <cmd>` subcommands.

Use `register_v2_commands(main_group)` to attach all v2 commands to the
existing click.Group. Each command lazily imports its module so that
importing cli_v2 stays cheap and so an optional dependency missing doesn't
break unrelated commands.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, List

import click


def _iter_source_files(repo: Path, exts: set) -> List[Path]:
    skip = {"node_modules", ".git", "vendor", "__pycache__", "dist", "build", ".venv", ".next"}
    out: List[Path] = []
    for p in repo.rglob("*"):
        if not p.is_file() or p.suffix.lower() not in exts:
            continue
        if any(s in str(p) for s in skip):
            continue
        out.append(p)
    return out


def _print_findings(findings: List[Any], title: str = "Findings") -> None:
    click.echo(f"\n{title}: {len(findings)}")
    for f in findings[:50]:
        line = getattr(f, "line", 0)
        rule_id = getattr(f, "rule_id", "")
        sev = getattr(f, "severity", "")
        desc = getattr(f, "description", "") or getattr(f, "message", "")
        file_str = getattr(f, "file", "")
        click.echo(f"  [{sev.upper():<8}] {rule_id:<35} {file_str}:{line} — {desc[:80]}")
    if len(findings) > 50:
        click.echo(f"  ... and {len(findings) - 50} more")


# =============================================================================
# 1. symbolic
# =============================================================================

@click.command("symbolic")
@click.option("--repo", default=".", help="Repository root")
@click.option("--file", "file_path", default=None, help="Single file to analyze")
def symbolic_cmd(repo: str, file_path: str):
    """Run Z3 symbolic execution + abstract interpretation + type narrowing."""
    from . import symbolic
    repo_root = Path(repo).resolve()
    if file_path:
        files = [Path(file_path)]
    else:
        files = _iter_source_files(repo_root, {".py"})
    total = []
    for fp in files:
        total.extend(symbolic.analyze_file(fp))
    _print_findings(total, "Symbolic / abstract / narrowing findings")


# =============================================================================
# 2. concurrency
# =============================================================================

@click.command("concurrency")
@click.option("--repo", default=".", help="Repository root")
def concurrency_cmd(repo: str):
    """Detect async/concurrency bugs (Python asyncio, JS Promises, Go channels)."""
    from . import concurrency
    findings = concurrency.analyze_repo_concurrency(Path(repo).resolve())
    _print_findings(findings, "Concurrency findings")


# =============================================================================
# 3. business-logic
# =============================================================================

@click.command("business-logic")
@click.option("--repo", default=".", help="Repository root")
def business_logic_cmd(repo: str):
    """Extract auth matrix, business state machines, invariants, doc drift."""
    from . import business_logic as bl
    repo_root = Path(repo).resolve()
    extractor = bl.AuthMatrixExtractor()
    detector = bl.AuthViolationDetector()
    sm = bl.BusinessStateMachineAnalyzer()
    inv = bl.InvariantMiner()
    drift = bl.DocDriftAnalyzer()
    all_rules = []
    all_violations = []
    all_sm = []
    all_invariants = []
    all_drift = []
    for path in _iter_source_files(repo_root, {".py", ".js", ".jsx", ".ts", ".tsx"}):
        rules = extractor.extract_from_file(path)
        all_rules.extend(rules)
        all_violations.extend(detector.analyze_file(path))
        all_sm.extend(sm.analyze_file(path))
        all_invariants.extend(inv.mine_file(path))
        all_drift.extend(drift.analyze_file(path))
    click.echo(f"\nAuth rules extracted:  {len(all_rules)}")
    click.echo(f"Auth violations:       {len(all_violations)}")
    click.echo(f"State machine issues:  {len(all_sm)}")
    click.echo(f"Invariants mined:      {len(all_invariants)}")
    click.echo(f"Doc drift findings:    {len(all_drift)}")
    _print_findings(all_violations, "Auth violations")
    _print_findings(all_sm, "State machine violations")


# =============================================================================
# 4. crypto
# =============================================================================

@click.command("crypto")
@click.option("--repo", default=".", help="Repository root")
def crypto_cmd(repo: str):
    """Audit cryptographic correctness (MD5/SHA1/AES-ECB/static IV/etc.)."""
    from . import crypto_audit
    findings = crypto_audit.analyze_repo_crypto(Path(repo).resolve())
    _print_findings(findings, "Crypto findings")


# =============================================================================
# 5. iac
# =============================================================================

@click.command("iac")
@click.option("--repo", default=".", help="Repository root")
def iac_cmd(repo: str):
    """Scan IaC files (Terraform, Dockerfile, K8s, CloudFormation)."""
    from . import iac_scanner
    findings = iac_scanner.scan_iac(Path(repo).resolve())
    _print_findings(findings, "IaC findings")


# =============================================================================
# 6. modern
# =============================================================================

@click.command("modern")
@click.option("--repo", default=".", help="Repository root")
def modern_cmd(repo: str):
    """Scan for modern attack surfaces (LLM, GraphQL, WebSocket, SSE, gRPC, WebRTC)."""
    from . import modern_attacks
    findings = modern_attacks.scan_repo_modern_attacks(Path(repo).resolve())
    _print_findings(findings, "Modern attack surface findings")


# =============================================================================
# 7. supply-chain
# =============================================================================

@click.command("supply-chain")
@click.option("--repo", default=".", help="Repository root")
@click.option("--license", "project_license", default="MIT", help="Project license")
def supply_chain_cmd(repo: str, project_license: str):
    """Analyze dependencies for CVEs, typosquats, abandoned deps, license issues."""
    from . import supply_chain
    issues = supply_chain.analyze_supply_chain(Path(repo).resolve(), project_license)
    _print_findings(issues, "Supply chain issues")


# =============================================================================
# 8. dashboard
# =============================================================================

@click.command("dashboard")
@click.option("--repo", default=".", help="Repository root")
@click.option("--input", "input_path", default=None, help="PipelineResult JSON to render (default: run full scan)")
@click.option("--output", "-o", default=None, help="Output HTML path (default: <repo>/loomscan-dashboard.html)")
@click.option("--open", "open_browser", is_flag=True, help="Open dashboard in browser after generating")
def dashboard_cmd(repo: str, input_path: str, output: str, open_browser: bool):
    """Generate a self-contained HTML dashboard with charts and filterable table.

    v4.44: Fixed 2 bugs:
    - When no --input, runs a FULL scan (was only running demo crypto+modern scan)
    - Output defaults to <repo>/loomscan-dashboard.html (was CWD)
    """
    from .report.dashboard import generate_dashboard
    repo_root = Path(repo).resolve()
    # v4.44: Default output to repo dir, not CWD
    if output:
        out_path = Path(output)
        if not out_path.is_absolute():
            out_path = repo_root / out_path
    else:
        out_path = repo_root / "loomscan-dashboard.html"

    findings_json = None
    if input_path:
        try:
            import json
            findings_json = json.loads(Path(input_path).read_text(encoding="utf-8"))
        except Exception as e:
            click.echo(f"Could not load input JSON: {e}", err=True)
            return
    else:
        # v4.44: Run a FULL scan instead of the demo crypto+modern scan
        click.echo(f"Running full LoomScan scan on {repo_root}...")
        try:
            from .config import STCAConfig, find_config
            from .orchestrator import Orchestrator
            config = STCAConfig.from_file(find_config(repo_root))
            orch = Orchestrator(repo_root, config)
            result = orch.run_full()
            findings_json = result.to_dict()
            click.echo(f"Scan complete: {len(result.findings)} findings")
        except Exception as e:
            click.echo(f"Scan failed: {e}", err=True)
            return

    generate_dashboard(repo_root, out_path, findings_json=findings_json)
    click.echo(f"Dashboard written to {out_path}")
    if open_browser:
        import webbrowser
        webbrowser.open(f"file://{out_path.resolve()}")


# =============================================================================
# 9. watch
# =============================================================================

@click.command("watch")
@click.option("--repo", default=".", help="Repository root")
@click.option("--debounce", default=0.5, help="Debounce seconds (default: 0.5 for sub-second feedback)")
@click.option("--strictness", default=5, type=int, help="Strictness level 1-9")
@click.option("--quiet", is_flag=True, help="Only show counts, not individual findings")
@click.option("--json", "as_json", is_flag=True, help="Output JSON per scan (for IDE integration)")
def watch_cmd(repo: str, debounce: float, strictness: int, quiet: bool, as_json: bool):
    """Watch the repo for changes and re-scan on save (sub-second feedback).

    v4.36: Upgraded from just printing changed files to actually re-running
    LoomScan on changed files and reporting new findings. Designed for IDE-like
    feedback loops — keep this running in a terminal while you code.

    Examples:
      loomscan watch                              # default: 0.5s debounce
      loomscan watch --debounce 0.2               # faster feedback
      loomscan watch --strictness 7               # more findings
      loomscan watch --json                       # machine-readable (for editor integration)
      loomscan watch --quiet                      # only show counts
    """
    from . import incremental
    from .config import STCAConfig, find_config
    from .orchestrator import Orchestrator
    import time

    repo_root = Path(repo).resolve()
    config = STCAConfig.from_file(find_config(repo_root))
    orch = Orchestrator(repo_root, config, strictness=strictness)

    # Cache the last scan's findings to compute deltas
    last_findings: dict = {}  # file -> set of rule_ids

    def on_change(changed: List[Path]) -> None:
        t0 = time.time()
        # Filter to source files only
        source_exts = {".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".java",
                       ".rs", ".c", ".cpp", ".cc", ".h", ".hpp", ".php",
                       ".rb", ".cs", ".swift", ".scala", ".kt", ".sql",
                       ".sh", ".bash", ".dart", ".lua", ".r", ".hs", ".ex", ".exs"}
        source_files = [p for p in changed if p.suffix.lower() in source_exts]
        if not source_files:
            return

        if not quiet and not as_json:
            click.echo(f"\n[watch] {len(source_files)} source file(s) changed — scanning...")

        # Run LoomScan on the changed files (treating them as a synthetic diff)
        try:
            result = orch.run_full()
            elapsed = time.time() - t0

            # Compute delta (new findings vs last scan)
            current_by_file: dict = {}
            for f in result.findings:
                if f.file not in current_by_file:
                    current_by_file[f.file] = set()
                current_by_file[f.file].add(f.rule_id)

            new_findings = []
            for f in result.findings:
                prev = last_findings.get(f.file, set())
                if f.rule_id not in prev:
                    new_findings.append(f)

            # Update cache
            last_findings.clear()
            last_findings.update(current_by_file)

            if as_json:
                import json
                report = {
                    "timestamp": time.time(),
                    "elapsed_seconds": round(elapsed, 3),
                    "files_changed": len(source_files),
                    "total_findings": len(result.findings),
                    "new_findings": len(new_findings),
                    "findings": [
                        {"rule_id": f.rule_id, "file": f.file,
                         "line": f.start_line, "severity": f.severity.value,
                         "message": f.message, "confidence": f.confidence}
                        for f in new_findings[:20]  # cap at 20 for performance
                    ],
                }
                click.echo(json.dumps(report))
            elif quiet:
                click.echo(f"[watch] {len(result.findings)} findings ({len(new_findings)} new) in {elapsed:.2f}s")
            else:
                click.echo(f"[watch] {len(result.findings)} total findings, {len(new_findings)} new (in {elapsed:.2f}s)")
                for f in new_findings[:10]:
                    sev_marker = {"critical": "!!", "high": "!", "medium": "?", "low": "-", "info": " "}.get(f.severity.value, " ")
                    click.echo(f"  {sev_marker} {f.rule_id} @ {f.file}:{f.start_line} — {f.message[:80]}")
                if len(new_findings) > 10:
                    click.echo(f"  ... and {len(new_findings) - 10} more")

        except Exception as e:
            click.echo(f"[watch] scan error: {e}", err=True)

    watcher = incremental.WatchMode(repo_root, on_change, debounce_seconds=debounce)
    click.echo(f"LoomScan watch mode — watching {repo_root}")
    click.echo(f"  debounce: {debounce}s, strictness: {strictness}")
    click.echo(f"  Press Ctrl-C to stop.\n")
    try:
        watcher.start()
    except KeyboardInterrupt:
        click.echo("\nStopped.")


# =============================================================================
# 10. lsp
# =============================================================================

@click.command("lsp")
@click.option("--repo", default=".", help="Repository root")
def lsp_cmd(repo: str):
    """Run the LoomScan language-server (diagnostics in your editor)."""
    # v4.33: Use the real LSPServer entry point (v4.32 imported a non-existent symbol).
    try:
        from .lsp.server import LSPServer
    except ImportError as e:
        click.echo(f"LSP server module not available: {e}", err=True)
        return
    server = LSPServer(Path(repo).resolve())
    click.echo(f"LoomScan LSP server running on {server.repo_root} (stdin/stdout) — Ctrl-C to stop.", err=True)
    server.run()


# =============================================================================
# 11. pre-commit
# =============================================================================

@click.command("pre-commit")
@click.option("--repo", default=".", help="Repository root")
@click.option("--files", "files_arg", default=None, help="Comma-separated file list (as passed by pre-commit)")
def pre_commit_cmd(repo: str, files_arg: str):
    """Run as a pre-commit hook — analyze the staged files."""
    from . import crypto_audit, modern_attacks, js_multiline
    repo_root = Path(repo).resolve()
    files = [Path(f) for f in files_arg.split(",")] if files_arg else _iter_source_files(repo_root, {".py", ".js", ".jsx", ".ts", ".tsx"})
    findings = []
    for fp in files:
        if not fp.exists(): continue
        findings.extend(crypto_audit.analyze_crypto(fp))
        findings.extend(modern_attacks.scan_modern_attacks(fp))
        findings.extend(js_multiline.scan_file_multiline(fp))
    _print_findings(findings, "Pre-commit findings")
    # exit code 1 if any high/critical
    if any(getattr(f, "severity", "").lower() in {"high", "critical"} for f in findings):
        raise click.ClickException("Pre-commit check failed — see findings above.")


# =============================================================================
# 12. rule-lint
# =============================================================================

@click.command("rule-lint")
@click.option("--rules-dir", default=".loomscan/rules", help="Directory of custom rule files")
def rule_lint_cmd(rules_dir: str):
    """Lint custom rule files for overly-broad patterns."""
    from . import rule_dsl
    rules = rule_dsl.load_rules_dir(Path(rules_dir))
    if not rules:
        click.echo(f"No rules found in {rules_dir}")
        return
    click.echo(f"Loaded {len(rules)} rules from {rules_dir}")
    linter = rule_dsl.RuleLinter()
    issues = linter.lint(rules)
    if not issues:
        click.echo("All rules OK.")
        return
    for rid, reason in issues:
        click.echo(f"  [LINT] {rid}: {reason}")


# =============================================================================
# 13. gnn
# =============================================================================

@click.command("update-cves")
@click.option("--repo", default=".", help="Repo to scan for dependencies")
@click.option("--prune", is_flag=True, help="Prune stale cache entries")
@click.option("--stats", "show_stats", is_flag=True, help="Show cache stats only")
def update_cves_cmd(repo: str, prune: bool, show_stats: bool):
    """Update CVE database from OSV.dev (all ecosystems).

    Queries OSV.dev API for Maven, npm, PyPI, Go, Cargo, Gem, Composer.
    Results cached in SQLite with 7-day TTL.
    """
    from .unified_cve_db import UnifiedCVEDatabase
    cve_db = UnifiedCVEDatabase()
    if show_stats:
        click.echo(f"CVE cache stats: {cve_db.stats()}")
        return
    if prune:
        cve_db.prune()
        click.echo("Pruned stale cache entries.")
        click.echo(f"Stats after prune: {cve_db.stats()}")
        return
    repo_root = Path(repo).resolve()
    click.echo(f"Scanning dependencies in {repo_root}...")
    from .supply_chain import (_scan_pip_requirements, _scan_pyproject, _scan_package_json,
        _scan_go_mod, _scan_pom_xml, _scan_cargo_toml, _scan_gemfile, _scan_gradle, _scan_composer_json)
    deps = []
    deps += _scan_pip_requirements(repo_root)
    deps += _scan_pyproject(repo_root)
    deps += _scan_package_json(repo_root)
    deps += _scan_go_mod(repo_root)
    deps += _scan_pom_xml(repo_root)
    deps += _scan_cargo_toml(repo_root)
    deps += _scan_gemfile(repo_root)
    deps += _scan_gradle(repo_root)
    deps += _scan_composer_json(repo_root)
    eco_map = {"pypi":"PyPI","npm":"npm","go":"Go","maven":"Maven","cargo":"Cargo","gem":"Gem","composer":"Composer"}
    packages = [(eco_map.get(d.ecosystem, d.ecosystem), d.name, d.version) for d in deps if d.version != "latest"]
    click.echo(f"Found {len(packages)} packages across {len(set(e for e,_,_ in packages))} ecosystems")
    click.echo("Querying OSV.dev (this may take 30-60s)...")
    cves = cve_db.update_all(packages)
    click.echo(f"\nFound {len(cves)} CVEs across all packages")
    click.echo(f"Cache stats: {cve_db.stats()}")
    from collections import Counter
    sev_counts = Counter(c.severity for c in cves)
    click.echo(f"By severity: {dict(sev_counts)}")
    for cve in cves[:20]:
        click.echo(f"  [{cve.severity.upper()}] {cve.cve_id}: {cve.package}@{cve.version} -> fix: {cve.fixed_version}")

@click.command("gnn")
@click.option("--repo", default=".", help="Repository root")
@click.option("--threshold", default=0.5, help="Risk-score threshold (0..1)")
def gnn_cmd(repo: str, threshold: float):
    """Score every function with the GNN-on-CPG model."""
    from . import learning
    results = learning.scan_repo_with_gnn(Path(repo).resolve())
    flagged = [r for r in results if r.score >= threshold]
    click.echo(f"\nGNN scored {len(results)} functions, {len(flagged)} above threshold {threshold}")
    flagged.sort(key=lambda r: r.score, reverse=True)
    for r in flagged[:30]:
        click.echo(f"  score={r.score:.2f} {r.file}:{r.line} {r.function}()")


# =============================================================================
# 14. similar
# =============================================================================

@click.command("similar")
@click.option("--repo", default=".", help="Repository root")
@click.option("--file", "file_path", required=True, help="File to find similar code for")
@click.option("--top-k", default=5, help="Top-K matches")
def similar_cmd(repo: str, file_path: str, top_k: int):
    """Find similar code snippets using character 3-gram embeddings."""
    from . import learning
    repo_root = Path(repo).resolve()
    emb = learning.CodeEmbeddings()
    target = Path(file_path)
    if not target.exists():
        click.echo(f"File not found: {target}", err=True); return
    target_code = target.read_text(encoding="utf-8", errors="replace")
    for path in _iter_source_files(repo_root, {".py", ".js", ".jsx", ".ts", ".tsx", ".go"}):
        try:
            code = path.read_text(encoding="utf-8", errors="replace")
            emb.add(str(path), code)
        except Exception:
            continue
    matches = emb.find_similar(target_code, top_k=top_k)
    click.echo(f"\nTop-{top_k} similar files to {target}:")
    for path_str, score in matches:
        if Path(path_str) == target: continue
        click.echo(f"  {score:.3f}  {path_str}")


# =============================================================================
# 15. trace
# =============================================================================

@click.command("trace")
@click.option("--repo", default=".", help="Repository root")
@click.option("--rule-id", default=None, help="Filter to a specific rule_id")
def trace_cmd(repo: str, rule_id: str):
    """Trace a finding's lifecycle: FIS evaluation + counterfactual + BBN trace."""
    from .brain.aggregator import Aggregator
    from .models import Finding, Severity, LayerID, BlastRadius, Category
    repo_root = Path(repo).resolve()
    click.echo(f"Tracing findings in {repo_root}...")
    agg = Aggregator()
    # demo: synthesize one finding per source file
    from . import crypto_audit
    findings = crypto_audit.analyze_repo_crypto(repo_root)
    if rule_id:
        findings = [f for f in findings if f.rule_id == rule_id]
    click.echo(f"Found {len(findings)} crypto findings to trace.")
    for cf in findings[:5]:
        finding = Finding(
            layer=LayerID.L6_SYMBOLIC, rule_id=cf.rule_id,
            message=cf.description, file=cf.file, start_line=cf.line,
            severity=Severity(cf.severity) if cf.severity in Severity._value2member_map_ else Severity.MEDIUM,
            confidence=cf.confidence, exploitability=0.5,
            blast_radius=BlastRadius.FUNCTION, category=Category.SECURITY, cwe=cf.cwe)
        decision = agg.aggregate_finding(finding)
        click.echo(f"\n  {cf.rule_id} @ {cf.file}:{cf.line}")
        click.echo(f"    decision: {decision.decision.value}")
        click.echo(f"    interval: [{decision.confidence_interval[0]:.2f}, {decision.confidence_interval[1]:.2f}]")
        click.echo(f"    reasoning: {decision.reasoning[:120]}")


# =============================================================================
# 16. code-quality
# =============================================================================

@click.command("code-quality")
@click.option("--repo", default=".", help="Repository root")
def code_quality_cmd(repo: str):
    """Multi-language code quality analysis (111+ rules across 5 languages)."""
    from . import code_quality
    issues = code_quality.analyze_repo_code_quality(Path(repo).resolve())
    _print_findings(issues, "Code quality issues")


# =============================================================================
# 17. config-scan
# =============================================================================

@click.command("config-scan")
@click.option("--repo", default=".", help="Repository root")
def config_scan_cmd(repo: str):
    """Scan config files for hardcoded secrets and insecure defaults."""
    from . import config_scanner
    issues = config_scanner.scan_repo_configs(Path(repo).resolve())
    _print_findings(issues, "Config issues")


# =============================================================================
# 18. maven-cve
# =============================================================================

@click.command("maven-cve")
@click.option("--repo", default=".", help="Repository root")
def maven_cve_cmd(repo: str):
    """Scan pom.xml files against the Maven CVE database."""
    from . import maven_cve_db
    repo_root = Path(repo).resolve()
    cve_db = maven_cve_db.MavenCVEDatabase()
    pom_files = list(repo_root.rglob("pom.xml"))
    findings = []
    for pom in pom_files:
        findings.extend(maven_cve_db.scan_pom_xml_for_cves(pom, cve_db))
    click.echo(f"\nScanned {len(pom_files)} pom.xml files, found {len(findings)} CVE matches")
    for cve in findings:
        click.echo(f"  {getattr(cve, 'cve_id', cve)} — {getattr(cve, 'description', cve)}")


# =============================================================================
# 19. ast-analysis
# =============================================================================

@click.command("ast-analysis")
@click.option("--repo", default=".", help="Repository root")
def ast_analysis_cmd(repo: str):
    """Run tree-sitter AST analysis across the repo."""
    from . import tree_sitter_analyzer
    findings = tree_sitter_analyzer.analyze_repo_with_ast(Path(repo).resolve())
    _print_findings(findings, "AST findings")


# =============================================================================
# 20. taint-analysis
# =============================================================================

@click.command("taint-analysis")
@click.option("--repo", default=".", help="Repository root")
@click.option("--file", "file_path", default=None, help="Single file to analyze")
def taint_analysis_cmd(repo: str, file_path: str):
    """Track taint flows from sources to sinks (Python only)."""
    from . import taint_tracker
    repo_root = Path(repo).resolve()
    files = [Path(file_path)] if file_path else _iter_source_files(repo_root, {".py"})
    flows = []
    for fp in files:
        flows.extend(taint_tracker.track_taint_python(fp))
    click.echo(f"\nTaint flows: {len(flows)}")
    for fl in flows[:30]:
        click.echo(f"  {fl}")


# =============================================================================
# 21. source-discovery
# =============================================================================

@click.command("source-discovery")
@click.option("--repo", default=".", help="Repository root")
def source_discovery_cmd(repo: str):
    """Discover taint sources (user input, env, network, file) across the repo."""
    from . import source_discovery
    sources = source_discovery.discover_sources_in_repo(Path(repo).resolve())
    click.echo(f"\nDiscovered {len(sources)} sources")
    summary = source_discovery.source_summary(sources)
    for kind, count in summary.items():
        click.echo(f"  {kind}: {count}")


# =============================================================================
# 21b. mine (v4.36)
# =============================================================================

@click.command("mine")
@click.option("--repo", default=".", help="Repository root")
@click.option("--max-commits", default=500, help="Max commits to scan")
@click.option("--no-verify", is_flag=True, help="Skip Semgrep verification (faster, more false positives)")
@click.option("--dest", default=".loomscan-rules/mined", help="Destination dir for mined rules")
def mine_cmd(repo: str, max_commits: int, no_verify: bool, dest: str):
    """Mine rules from git history — auto-derive rules from bug-fix commits.

    v4.36: Wires rule_miner.py into the CLI. Scans git log for commits with
    "fix", "bug", "patch", "CVE", "security" in the message, diffs the
    before/after code, and generates Semgrep rules that match the buggy
    pattern. Rules are saved to .loomscan-rules/mined/ and auto-loaded on
    the next `loomscan check`.

    This is "learning from your own mistakes" — every bug you've ever
    fixed becomes a permanent rule that prevents the same bug from
    recurring.

    Examples:
      loomscan mine                              # default: 500 commits, verify
      loomscan mine --max-commits 1000           # scan more history
      loomscan mine --no-verify                  # skip Semgrep verification
      loomscan mine --dest ~/.loomscan/rules/mined   # custom destination
    """
    from .rule_miner import mine_rules_from_history, save_mined_rules
    repo_root = Path(repo).resolve()
    dest_dir = Path(dest).resolve()
    if not dest_dir.is_absolute():
        dest_dir = repo_root / dest

    click.echo(f"Mining rules from {repo_root} (max {max_commits} commits)...")
    rules = mine_rules_from_history(repo_root, max_commits=max_commits,
                                     verify=not no_verify)
    if not rules:
        click.echo("No bug-fix patterns found. Try --max-commits 1000 for more history.")
        return

    click.echo(f"Mined {len(rules)} candidate rules.")
    saved = save_mined_rules(rules, dest_dir)
    click.echo(f"Saved {len(saved)} verified rules to {dest_dir}")
    for path in saved[:5]:
        click.echo(f"  - {path}")
    if len(saved) > 5:
        click.echo(f"  ... and {len(saved) - 5} more")
    click.echo(f"\nNext: run `loomscan check` — mined rules will be auto-loaded.")


# =============================================================================
# 22. js-quality
# =============================================================================

@click.command("js-quality")
@click.option("--repo", default=".", help="Repository root")
def js_quality_cmd(repo: str):
    """JS code quality: cyclomatic complexity, toxicity, Halstead, grades."""
    from . import js_quality
    reports = js_quality.analyze_repo_js_quality(Path(repo).resolve())
    click.echo(js_quality.print_js_quality_report(reports))


# =============================================================================
# 23. optimize
# =============================================================================

@click.command("optimize")
@click.option("--repo", default=".", help="Repository root")
@click.option("--clear-cache", is_flag=True, help="Clear the file-level cache first")
def optimize_cmd(repo: str, clear_cache: bool):
    """Run an optimized parallel scan using the file-level cache + dep graph."""
    from . import incremental
    repo_root = Path(repo).resolve()
    cache_dir = repo_root / ".loomscan-cache"
    cache = incremental.FileLevelCache(cache_dir)
    if clear_cache:
        cache.clear()
        click.echo("Cache cleared.")
    tracker = incremental.DependencyTracker(repo_root)
    tracker.build()
    click.echo(f"Built dep graph: {len(tracker.graph)} modules, "
               f"{sum(len(v) for v in tracker.graph.values())} edges")
    # demo analyzer: count lines per file
    def analyzer(fp: Path) -> list:
        try:
            return [{"file": str(fp), "line": 0, "rule_id": "LOC", "severity": "info",
                      "description": f"{len(fp.read_text(encoding='utf-8', errors='replace').splitlines())} lines"}]
        except Exception:
            return []
    files = _iter_source_files(repo_root, {".py"})
    click.echo(f"Scanning {len(files)} Python files in parallel...")
    results = incremental.parallel_scan(files, analyzer, use_processes=False)
    total_findings = sum(len(v) for v in results.values())
    click.echo(f"Done. {total_findings} findings.")


# =============================================================================
# 24. js-multiline
# =============================================================================

@click.command("js-multiline")
@click.option("--repo", default=".", help="Repository root")
def js_multiline_cmd(repo: str):
    """Run the 12 multi-line JS pattern matchers."""
    from . import js_multiline
    findings = js_multiline.scan_repo_multiline(Path(repo).resolve())
    _print_findings(findings, "Multi-line JS findings")


# =============================================================================
# Registration
# =============================================================================

# v4.37: Import bot_cmd from loomscan.bot (must be before _V2_COMMANDS list)
try:
    from .bot import bot_cmd
except ImportError:
    bot_cmd = None  # type: ignore

# v4.37: Import playground_cmd from loomscan.playground
try:
    from .playground import playground_cmd
except ImportError:
    playground_cmd = None  # type: ignore

# v4.38: Import spec_cmd from loomscan.spec_mining
try:
    from .spec_mining_cmd import spec_cmd
except ImportError:
    spec_cmd = None  # type: ignore


_V2_COMMANDS = [
    symbolic_cmd, concurrency_cmd, business_logic_cmd, crypto_cmd,
    iac_cmd, modern_cmd, supply_chain_cmd, dashboard_cmd, watch_cmd,
    lsp_cmd, pre_commit_cmd, rule_lint_cmd, gnn_cmd, similar_cmd,
    trace_cmd, code_quality_cmd, config_scan_cmd, maven_cve_cmd,
    ast_analysis_cmd, taint_analysis_cmd, source_discovery_cmd,
    js_quality_cmd, optimize_cmd, js_multiline_cmd, update_cves_cmd,
    mine_cmd,        # v4.36: auto-rule mining from git history
    bot_cmd,         # v4.37: PR comment bot
    playground_cmd,  # v4.37: online rule playground
    spec_cmd,        # v4.38: spec mining
]


def register_v2_commands(main_group: click.Group) -> None:
    """Register all v2 subcommands on an existing click.Group."""
    for cmd in _V2_COMMANDS:
        main_group.add_command(cmd)
