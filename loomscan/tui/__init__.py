"""LoomScan TUI — progress bars, animated mascot, and stage indicators.

v5.7 introduces an animated ASCII spider mascot ("Loomy") plus Rich-powered
progress bars so users can see exactly which layer is running and how far
along the pipeline is. This eliminates the "is it stuck?" problem.

Public API:
    from loomscan.tui import ScanProgress, Mascot

    with ScanProgress(total_stages=12, show_mascot=True) as sp:
        sp.stage("L0 Fast", "Scanning 1,245 files...")
        ...do work...
        sp.complete_stage(findings_count=3)

    mascot = Mascot()
    mascot.say("Starting scan...")
"""
from .progress import ScanProgress, Stage  # noqa: F401
from .mascot import Mascot, get_global_mascot  # noqa: F401

__all__ = ["ScanProgress", "Stage", "Mascot", "get_global_mascot"]
