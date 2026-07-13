"""Loomy — the LoomScan mascot.

An ASCII spider that weaves a web of analysis. Like the mascots in claude-code
and opencode, Loomy shows different frames while the pipeline runs and prints
a final verdict when the scan completes. Loomy is non-blocking — animation
runs only when stdout is a TTY and `--no-tui` is not set.

Frames (8-step walk cycle):
       _           _           _           _
      / \\         / \\         / \\         / \\
     (o o)       (o o)       (- -)       (o o)
     /)__(       \\__(       /)__(       \\__(     ...etc.

The mascot is small (5 lines tall, 18 chars wide) so it fits in any terminal.
"""
from __future__ import annotations

import sys
import threading
import time
from typing import Optional

try:
    from rich.console import Console
    from rich.text import Text
    from rich.panel import Panel
    from rich.align import Align
    _HAS_RICH = True
except ImportError:
    _HAS_RICH = False


# 6-frame walk cycle for Loomy. Each frame is a 5-line string.
# Designed to look like a small spider/weaver creature.
_MASCOT_FRAMES = [
    # Frame 0: idle, eyes forward
    r"""
     ___
    /o o\
    \_-_/
    /| |\
   d b d b
""",
    # Frame 1: looking left, weaving
    r"""
     ___
    /o o\
    \-_-/
    /| |\   _
   d b d b-'
""",
    # Frame 2: pulling thread
    r"""
     ___
    /o o\
    \-_-/
    /| |\__
   d b d b \__
""",
    # Frame 3: looking right
    r"""
     ___
    /o o\
    \-_-/
   _/| |\
   '.d b d b
""",
    # Frame 4: tied knot
    r"""
     ___
    /o o\
    \-o-/
    /| |\
   d b d b
""",
    # Frame 5: celebrating (eyes happy)
    r"""
     ___
    /^^^\
    \_-_/
    /| |\
   d b d b
""",
]

# What Loomy says in each phase of the pipeline
_PHASE_LINES = {
    "init":      "Loomy is weaving the analysis web...",
    "discover":  "Counting threads (source files)...",
    "layers":    "Spinning layer-by-layer...",
    "taint":     "Tracing tainted threads across files...",
    "cpg":       "Building code property graph...",
    "metamorphic":"Knitting metamorphic relations...",
    "aggregate": "Weaving confidence intervals...",
    "llm":       "Asking the LLM oracle...",
    "autofix":   "Stitching fixes...",
    "done":      "Web complete!",
    "warn":      "Loomy sniffed something fishy.",
    "block":     "Loomy found a tear in the weave!",
    "pass":      "Web is clean and tight.",
}


class Mascot:
    """Animated Loomy mascot.

    Usage:
        mascot = Mascot()
        mascot.say("init")
        mascot.start_animation()  # background thread
        ... do work ...
        mascot.stop_animation()
        mascot.say("done")

    The animation runs in a daemon thread so it never blocks shutdown.
    """

    def __init__(self, console: Optional["Console"] = None,
                 enabled: bool = True, anim_interval: float = 0.4):
        self.console = console or (Console() if _HAS_RICH else None)
        self.enabled = enabled and _HAS_RICH and sys.stdout.isatty()
        self.anim_interval = anim_interval
        self._anim_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._current_phase = "init"
        self._current_message: Optional[str] = None
        self._frame_idx = 0

    # ---------- one-shot rendering ----------

    def say(self, phase: str, message: Optional[str] = None) -> None:
        """Render Loomy in a single frame with a speech bubble.

        Non-animated — for use at stage boundaries.
        """
        self._current_phase = phase
        self._current_message = message or _PHASE_LINES.get(phase, "")
        if not self.enabled:
            # Plain-text fallback
            print(f"[loomy] {self._current_message}")
            return
        self._render_frame(0, with_bubble=True)

    # ---------- background animation ----------

    def start_animation(self, phase: str = "layers",
                        message: Optional[str] = None) -> None:
        """Start the background walk-cycle animation.

        Safe to call multiple times — only one thread runs at a time.
        """
        if not self.enabled:
            return
        self._current_phase = phase
        self._current_message = message or _PHASE_LINES.get(phase, "")
        if self._anim_thread and self._anim_thread.is_alive():
            return
        self._stop_event.clear()
        self._anim_thread = threading.Thread(
            target=self._animate_loop, daemon=True
        )
        self._anim_thread.start()

    def stop_animation(self) -> None:
        """Stop the background animation and clear the frame."""
        if not self.enabled:
            return
        self._stop_event.set()
        if self._anim_thread:
            self._anim_thread.join(timeout=1.0)
        self._anim_thread = None
        # Clear the line where Loomy was animating
        try:
            sys.stdout.write("\r\033[K")
            sys.stdout.flush()
        except Exception:
            pass

    def update_phase(self, phase: str, message: Optional[str] = None) -> None:
        """Update the speech bubble without restarting the animation."""
        self._current_phase = phase
        self._current_message = message or _PHASE_LINES.get(phase, "")

    # ---------- internals ----------

    def _animate_loop(self) -> None:
        """Background loop that cycles through mascot frames."""
        n = len(_MASCOT_FRAMES)
        while not self._stop_event.is_set():
            self._render_frame(self._frame_idx % n, with_bubble=True, clear=True)
            self._frame_idx += 1
            self._stop_event.wait(self.anim_interval)

    def _render_frame(self, idx: int, with_bubble: bool = True,
                      clear: bool = False) -> None:
        """Render one mascot frame."""
        if not self.console:
            return
        frame = _MASCOT_FRAMES[idx % len(_MASCOT_FRAMES)]
        msg = self._current_message or ""

        # Use a small panel with the mascot + speech bubble side-by-side
        # Layout:  mascot (left) | speech (right)
        mascot_lines = frame.strip("\n").split("\n")
        # Pad all lines to the same width
        max_w = max(len(l) for l in mascot_lines)
        mascot_lines = [l.ljust(max_w) for l in mascot_lines]

        if with_bubble and msg:
            # Speech bubble: " ( msg ) "
            bubble_top = "  _" + "_" * max(0, len(msg)) + "_  "
            bubble_mid = f" ( {msg} ) "
            bubble_bot = "  ‾" + "‾" * max(0, len(msg)) + "‾  "
            lines = [
                f"{mascot_lines[i] if i < len(mascot_lines) else ' ' * max_w}    "
                f"{[bubble_top, bubble_mid, bubble_bot][i] if i < 3 else ''}"
                for i in range(max(len(mascot_lines), 3))
            ]
            content = "\n".join(lines)
        else:
            content = "\n".join(mascot_lines)

        if clear:
            # Move cursor up to overwrite the previous frame
            # (frame is ~5-8 lines tall; we move up 8 to be safe)
            sys.stdout.write("\033[8A\r\033[J")
            sys.stdout.flush()

        # Style: cyan mascot, yellow speech
        text = Text(content, style="cyan")
        # Print without trailing newline issues
        self.console.print(text, end="\r")


# ---------- global singleton ----------

_GLOBAL_MASCOT: Optional[Mascot] = None


def get_global_mascot(enabled: bool = True) -> Mascot:
    """Return the process-wide Mascot singleton.

    This lets the orchestrator and CLI share one mascot instance.
    """
    global _GLOBAL_MASCOT
    if _GLOBAL_MASCOT is None:
        _GLOBAL_MASCOT = Mascot(enabled=enabled)
    return _GLOBAL_MASCOT


def disable_mascot() -> None:
    """Disable the global mascot (e.g. when --no-tui or --quiet is set)."""
    global _GLOBAL_MASCOT
    if _GLOBAL_MASCOT is not None:
        _GLOBAL_MASCOT.stop_animation()
    _GLOBAL_MASCOT = Mascot(enabled=False)
