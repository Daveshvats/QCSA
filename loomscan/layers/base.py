"""Layer base class and interface.

Every layer follows the same contract: given the repo root, hunks, and config,
return a list of Findings. Layers are independent and idempotent — they can
run in parallel and in any order.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import List
import time
import shutil

from ..models import Finding, DiffHunk, LayerID
from ..config import STCAConfig


class LayerBase(ABC):
    """Base class for all pipeline layers."""
    id: LayerID
    name: str
    description: str

    @abstractmethod
    def run(self, repo_root: Path, hunks: List[DiffHunk],
            config: STCAConfig) -> List[Finding]:
        """Run the layer on the diff hunks. Must be safe to call in parallel."""
        ...

    def is_tool_available(self, tool: str) -> bool:
        """Check whether a CLI tool is on PATH."""
        return shutil.which(tool) is not None

    def time_run(self, repo_root: Path, hunks: List[DiffHunk],
                 config: STCAConfig) -> tuple[List[Finding], float]:
        """Wrap run() with timing."""
        t0 = time.perf_counter()
        try:
            findings = self.run(repo_root, hunks, config)
        except Exception as e:
            # a layer failure should never break the whole pipeline
            findings = [Finding(
                layer=self.id, rule_id=f"{self.id.value}.internal_error",
                message=f"Layer {self.name} crashed: {type(e).__name__}: {e}",
                file="<pipeline>", start_line=0,
                severity=__import__("loomscan.models", fromlist=["Severity"]).Severity.INFO,
                confidence=1.0,
            )]
        elapsed = time.perf_counter() - t0
        return findings, elapsed
