"""Rich TUI rendering of pipeline results."""
from __future__ import annotations

from typing import List

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.tree import Tree
    from rich import box
    _HAS_RICH = True
except ImportError:
    _HAS_RICH = False

from ..models import PipelineResult, Finding, Severity, Decision


_SEV_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}

_DECISION_STYLE = {
    Decision.BLOCK: "bold red on white",
    Decision.WARN: "yellow",
    Decision.PASS: "green",
    Decision.UNCERTAIN: "magenta",
}


def render_tui(result: PipelineResult, console=None) -> None:
    """Print a TUI summary of the pipeline result."""
    if not _HAS_RICH:
        print("Install `rich` for TUI output. Falling back to plain text.")
        _render_plain(result)
        return

    console = console or Console()

    # header
    title_style = _DECISION_STYLE.get(result.final_decision, "white")
    console.print(Panel(
        Text(f"STCA Pipeline — Final Decision: {result.final_decision.value.upper()}",
             style=title_style, justify="center"),
        box=box.DOUBLE,
    ))

    # summary stats
    summary = Table.grid(expand=True)
    summary.add_column(justify="left")
    summary.add_column(justify="right")
    summary.add_column(justify="left")
    summary.add_column(justify="right")
    summary.add_row(
        "Findings:", str(len(result.findings)),
        "LLM invoked:", "yes" if result.llm_invoked else "no",
    )
    by_sev = {}
    for f in result.findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    summary.add_row(
        "By severity:", ", ".join(f"{s.value}={c}" for s, c in by_sev.items()) or "none",
        "Diff hunks:", str(len(result.diff_hunks)),
    )
    console.print(summary)
    console.print()

    # layer timings
    if result.layer_timings:
        timing_table = Table(title="Layer Timings", box=box.SIMPLE)
        timing_table.add_column("Layer", style="cyan")
        timing_table.add_column("Time (s)", justify="right", style="green")
        for layer, t in sorted(result.layer_timings.items(), key=lambda x: x[0]):
            timing_table.add_row(layer, f"{t:.2f}")
        console.print(timing_table)
        console.print()

    # findings table
    if result.findings:
        findings_table = Table(title="Findings", box=box.ROUNDED, show_lines=True)
        findings_table.add_column("#", style="dim", width=3)
        findings_table.add_column("Sev", width=8)
        findings_table.add_column("Layer", style="cyan", width=12)
        findings_table.add_column("Decision", width=10)
        findings_table.add_column("File:Line", style="cyan")
        findings_table.add_column("Message")

        for i, (finding, decision) in enumerate(zip(result.findings, result.decisions), 1):
            sev_text = Text(finding.severity.value.upper(), style=_SEV_STYLE.get(finding.severity, "white"))
            dec_text = Text(decision.decision.value.upper(),
                            style=_DECISION_STYLE.get(decision.decision, "white"))
            loc = f"{finding.file}:{finding.start_line}"
            findings_table.add_row(str(i), sev_text, finding.layer.value, dec_text, loc, finding.message[:80])
        console.print(findings_table)
        console.print()

        # detailed view of blocked/warned findings
        critical = [(f, d) for f, d in zip(result.findings, result.decisions)
                    if d.decision in (Decision.BLOCK, Decision.WARN)]
        if critical:
            details_tree = Tree("Critical Findings (BLOCK/WARN)", style="bold")
            for f, d in critical:
                node = details_tree.add(
                    Text(f"{f.rule_id} → {d.decision.value}", style=_DECISION_STYLE.get(d.decision))
                )
                node.add(Text(f"File: {f.file}:{f.start_line}-{f.end_line}", style="cyan"))
                node.add(Text(f"Message: {f.message}", style="white"))
                node.add(Text(f"Confidence: {f.confidence:.0%} | "
                              f"Exploitability: {f.exploitability:.0%} | "
                              f"Blast: {f.blast_radius.value}", style="dim"))
                node.add(Text(f"FIS: {d.reasoning}", style="dim italic"))
                if f.fix_suggestion:
                    node.add(Text(f"Fix: {f.fix_suggestion}", style="green"))
            console.print(details_tree)
    else:
        console.print(Panel(Text("No findings — clean diff!", style="green bold"),
                            box=box.ROUNDED))


def _render_plain(result: PipelineResult) -> None:
    print(f"\n=== STCA Pipeline — Final Decision: {result.final_decision.value.upper()} ===")
    print(f"Findings: {len(result.findings)} | LLM invoked: {result.llm_invoked}")
    for i, f in enumerate(result.findings, 1):
        print(f"  [{f.severity.value}] {f.layer.value}: {f.message[:80]} ({f.file}:{f.start_line})")
