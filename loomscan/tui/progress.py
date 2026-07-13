"""ScanProgress — Rich-powered progress bar for the LoomScan pipeline.

v5.7: The original CLI had no progress indicator. A full-repo scan on a
large codebase can take 30+ seconds, during which the terminal showed
nothing — users thought it was stuck.

ScanProgress shows:
  1. A two-line animated mascot (Loomy) on the left
  2. A spinner + current stage name on the right
  3. A progress bar [████░░░░░░] N/12 stages
  4. A live findings counter

Usage (from orchestrator):

    from loomscan.tui import ScanProgress

    with ScanProgress(total_stages=12, show_mascot=True) as sp:
        sp.start_stage("L0 Fast", "Scanning 1,245 files...")
        findings += layer.run(...)
        sp.complete_stage(findings_count=len(findings))

        sp.start_stage("L1 Property", "Metamorphic testing...")
        ...

The progress bar is disabled when:
  - stdout is not a TTY (piped to file / CI log)
  - --quiet or --json is set on the CLI
  - $LOOMSCAN_NO_TUI=1 is set in the environment
  - --no-tui flag is passed
"""
from __future__ import annotations

import os
import sys
import time
import threading
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
    from rich.progress import MofNCompleteColumn, TimeElapsedColumn
    _HAS_RICH = True
except ImportError:
    _HAS_RICH = False


def _tui_disabled() -> bool:
    """Check if TUI is explicitly disabled."""
    if os.environ.get("LOOMSCAN_NO_TUI", "").lower() in ("1", "true", "yes"):
        return True
    if not sys.stdout.isatty():
        return True
    return False


@dataclass
class Stage:
    """One pipeline stage."""
    name: str
    description: str = ""
    started_at: float = 0.0
    finished_at: float = 0.0
    findings_count: int = 0
    status: str = "pending"  # pending | running | done | error

    @property
    def elapsed(self) -> float:
        if self.finished_at and self.started_at:
            return self.finished_at - self.started_at
        if self.started_at:
            return time.perf_counter() - self.started_at
        return 0.0


class ScanProgress:
    """Wraps Rich Progress + Loomy mascot for the pipeline."""

    def __init__(self, total_stages: int = 12, show_mascot: bool = True,
                 console: Optional["Console"] = None,
                 enabled: Optional[bool] = None):
        self.total_stages = total_stages
        self.completed_stages = 0
        self.stages: List[Stage] = []
        self._current_stage: Optional[Stage] = None
        self._lock = threading.Lock()

        # Decide if TUI is enabled
        if enabled is None:
            enabled = _HAS_RICH and not _tui_disabled()
        self.enabled = enabled

        # v5.10: Force legacy_windows=False and force_terminal=True
        # This fixes progress bar freezing on Windows Terminal
        self.console = console or (Console(legacy_windows=False, force_terminal=True) if _HAS_RICH else None)
        self.show_mascot = show_mascot and self.enabled
        
        # Try to use image mascot first, fall back to ASCII
        from .mascot import get_global_mascot
        self.mascot = get_global_mascot(enabled=self.show_mascot)
        
        self._progress: Optional[Progress] = None
        self._task_id = None
        self._findings_count = 0

    # ---------- context manager ----------

    def __enter__(self) -> "ScanProgress":
        if not self.enabled:
            return self
        # Initialize Rich progress with v5.10 refresh rate fix
        self._progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(complete_style="green", finished_style="green"),
            MofNCompleteColumn(),
            TextColumn("•"),
            TimeElapsedColumn(),
            TextColumn("•"),
            TextColumn("[yellow]{task.fields[findings]} findings"),
            console=self.console,
            transient=False,
            refresh_per_second=10,  # v5.10: Force 10fps refresh to prevent freezing
        )
        self._progress.__enter__()
        self._task_id = self._progress.add_task(
            description="LoomScan pipeline",
            total=self.total_stages,
            findings=0,
        )
        # Mascot intro
        if self.show_mascot:
            self.mascot.say("init")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if not self.enabled:
            return False
        # Stop any mascot animation
        if self.show_mascot:
            self.mascot.stop_animation()
            # Pick the right outro line
            if exc_type is not None:
                self.mascot.say("warn", "Loomy hit a snag — but partial results are below.")
            elif self._findings_count == 0:
                self.mascot.say("pass")
            elif self._findings_count > 0:
                self.mascot.say("done", f"Loomy wove a web of {self._findings_count} findings.")
        if self._progress is not None:
            # Mark any in-flight stage as complete
            if self._current_stage and self._current_stage.status == "running":
                self._current_stage.status = "done" if exc_type is None else "error"
                self._current_stage.finished_at = time.perf_counter()
                self.completed_stages = min(self.completed_stages + 1, self.total_stages)
                if self._task_id is not None and self._progress is not None:
                    self._progress.update(
                        self._task_id,
                        completed=self.completed_stages,
                        description=self._current_stage.name,
                    )
            self._progress.__exit__(exc_type, exc_val, exc_tb)
        return False

    # ---------- stage lifecycle ----------

    def start_stage(self, name: str, description: str = "",
                    animate_mascot: bool = True) -> None:
        """Begin a new stage. Completes the previous stage if any."""
        with self._lock:
            if self._current_stage and self._current_stage.status == "running":
                self._complete_stage_locked(0)

            stage = Stage(
                name=name,
                description=description,
                started_at=time.perf_counter(),
                status="running",
            )
            self.stages.append(stage)
            self._current_stage = stage

        if not self.enabled:
            if description:
                print(f"[loomscan] {name}: {description}", file=sys.stderr)
            return

        # Update progress bar description
        if self._progress is not None and self._task_id is not None:
            label = f"{name}"
            if description:
                label += f" — {description}"
            self._progress.update(self._task_id, description=label)

        # Mascot animation
        if self.show_mascot and animate_mascot:
            self.mascot.update_phase("layers", description or name)
            self.mascot.start_animation(phase="layers", message=description or name)

    def complete_stage(self, findings_count: int = 0) -> None:
        """Mark the current stage as complete."""
        with self._lock:
            self._complete_stage_locked(findings_count)

    def _complete_stage_locked(self, findings_count: int) -> None:
        if not self._current_stage:
            return
        self._current_stage.status = "done"
        self._current_stage.finished_at = time.perf_counter()
        self._current_stage.findings_count = findings_count
        self.completed_stages += 1
        self._findings_count += findings_count

        if not self.enabled:
            return

        if self._progress is not None and self._task_id is not None:
            self._progress.update(
                self._task_id,
                completed=self.completed_stages,
                findings=self._findings_count,
                description=self._current_stage.name,
            )

    # ---------- introspection ----------

    def total_elapsed(self) -> float:
        """Total elapsed time across all completed stages."""
        return sum(s.elapsed for s in self.stages if s.status == "done")

    def stage_summary(self) -> List[Dict[str, Any]]:
        """Return a summary of all stages."""
        return [
            {
                "name": s.name,
                "description": s.description,
                "elapsed": s.elapsed,
                "findings": s.findings_count,
                "status": s.status,
            }
            for s in self.stages
        ]