"""Incremental scanning: file-level caching, dependency tracking,
differential analysis, watch mode, and parallel scanning.

Designed so that re-scanning a repo after a small change is O(changed files)
instead of O(all files).
"""
from __future__ import annotations

import logging
_logger = logging.getLogger(__name__.replace('stca.', ''))

import ast
import hashlib
import json
import os
import threading
import time
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple


# =============================================================================
# File-level cache (content-hash keyed)
# =============================================================================

@dataclass
class CacheEntry:
    file: str
    hash: str
    mtime: float
    findings: List[dict] = field(default_factory=list)


class FileLevelCache:
    """Persistent file-hash cache.

    Keyed by content hash. If a file's hash hasn't changed, return the cached
    findings. Otherwise re-run the analyzer and cache the new result.
    """

    def __init__(self, cache_dir: Path) -> None:
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.index_file = self.cache_dir / "file_index.json"
        self.index: Dict[str, dict] = {}
        self._load()

    def _load(self) -> None:
        if not self.index_file.exists():
            self.index = {}
            return
        try:
            self.index = json.loads(self.index_file.read_text(encoding="utf-8"))
        except Exception:
            self.index = {}

    def _save(self) -> None:
        try:
            self.index_file.write_text(json.dumps(self.index, indent=2), encoding="utf-8")
        except Exception:
            pass

    @staticmethod
    def _hash_file(path: Path) -> str:
        h = hashlib.sha256()
        try:
            h.update(path.read_bytes())
        except Exception:
            return ""
        return h.hexdigest()

    def get_or_compute(self, file_path: Path,
                        analyzer: Callable[[Path], List[dict]]) -> List[dict]:
        """Return cached findings if hash matches; else run analyzer and cache."""
        if not file_path.exists():
            return []
        try:
            mtime = file_path.stat().st_mtime
        except Exception:
            mtime = 0.0
        key = str(file_path)
        cached = self.index.get(key)
        new_hash = self._hash_file(file_path)
        if cached and cached.get("hash") == new_hash:
            return cached.get("findings", [])
        findings = analyzer(file_path) or []
        self.index[key] = {"hash": new_hash, "mtime": mtime, "findings": findings}
        self._save()
        return findings

    def invalidate(self, file_path: Path) -> None:
        self.index.pop(str(file_path), None)
        self._save()

    def clear(self) -> None:
        self.index = {}
        try: self.index_file.unlink()
        except Exception: pass  # v4.5: suppressed — add logging


# =============================================================================
# Dependency tracker (Python import graph)
# =============================================================================

class DependencyTracker:
    """Build a Python import graph and answer "what needs re-scan if X changes?".

    Nodes are module names. Edges are `import` / `from X import Y`.
    """

    def __init__(self, repo_root: Path) -> None:
        self.repo_root = repo_root
        self.graph: Dict[str, Set[str]] = {}      # module -> set of modules it imports
        self.reverse: Dict[str, Set[str]] = {}    # module -> set of modules that import it
        self.file_to_module: Dict[str, str] = {}
        self.module_to_file: Dict[str, Path] = {}

    def build(self) -> None:
        self.graph.clear()
        self.reverse.clear()
        self.file_to_module.clear()
        self.module_to_file.clear()
        for path in self.repo_root.rglob("*.py"):
            if any(s in str(path) for s in ("__pycache__", ".venv", "site-packages")):
                continue
            module = self._path_to_module(path)
            self.file_to_module[str(path)] = module
            self.module_to_file[module] = path
            self.graph.setdefault(module, set())
            try:
                source = path.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(source)
            except Exception:
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        self._add_edge(module, alias.name)
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        self._add_edge(module, node.module)
        # build reverse
        for src, deps in self.graph.items():
            for d in deps:
                self.reverse.setdefault(d, set()).add(src)

    def _path_to_module(self, path: Path) -> str:
        try:
            rel = path.relative_to(self.repo_root)
        except ValueError:
            rel = path
        parts = list(rel.with_suffix("").parts)
        if parts and parts[-1] == "__init__":
            parts = parts[:-1]
        return ".".join(parts)

    def _add_edge(self, src: str, dep: str) -> None:
        self.graph.setdefault(src, set()).add(dep)
        self.reverse.setdefault(dep, set()).add(src)

    def dependents_of(self, file_path: Path) -> List[Path]:
        """All files that transitively import `file_path`."""
        module = self.file_to_module.get(str(file_path))
        if not module:
            return []
        seen: Set[str] = set()
        stack = [module]
        while stack:
            cur = stack.pop()
            for dep in self.reverse.get(cur, set()):
                if dep not in seen:
                    seen.add(dep)
                    stack.append(dep)
        return [self.module_to_file[m] for m in seen if m in self.module_to_file]


# =============================================================================
# Differential analyzer
# =============================================================================

@dataclass
class DiffResult:
    added: List[dict] = field(default_factory=list)
    removed: List[dict] = field(default_factory=list)
    unchanged_count: int = 0


class DifferentialAnalyzer:
    """Compare two runs' findings and report added/removed issues."""

    def __init__(self) -> None:
        pass

    def diff(self, previous: List[dict], current: List[dict]) -> DiffResult:
        prev_keys = {self._key(f) for f in previous}
        curr_keys = {self._key(f) for f in current}
        added = [f for f in current if self._key(f) not in prev_keys]
        removed = [f for f in previous if self._key(f) not in curr_keys]
        unchanged = len(prev_keys & curr_keys)
        return DiffResult(added=added, removed=removed, unchanged_count=unchanged)

    @staticmethod
    def _key(finding: dict) -> str:
        return f"{finding.get('file','')}:{finding.get('line',0)}:{finding.get('rule_id','')}"


# =============================================================================
# Watch mode (filesystem watcher with debounce)
# =============================================================================

class WatchMode:
    """Polling-based filesystem watcher with a debounce window.

    Calls `on_change(changed_files)` after `debounce_seconds` of inactivity.
    Uses polling so it works on any platform without optional deps.
    """

    def __init__(self, repo_root: Path, on_change: Callable[[List[Path]], None],
                 debounce_seconds: float = 1.0,
                 extensions: Optional[Set[str]] = None) -> None:
        self.repo_root = repo_root
        self.on_change = on_change
        self.debounce = debounce_seconds
        self.extensions = extensions or {".py", ".js", ".jsx", ".ts", ".tsx", ".go"}
        self._mtimes: Dict[str, float] = {}
        self._pending: Set[Path] = set()
        self._last_event_time: float = 0.0
        self._running = False
        self._lock = threading.Lock()

    def _scan_mtimes(self) -> Dict[str, float]:
        out: Dict[str, float] = {}
        for path in self.repo_root.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in self.extensions:
                continue
            if any(s in str(path) for s in (".git", "node_modules", "__pycache__", ".venv")):
                continue
            try:
                out[str(path)] = path.stat().st_mtime
            except Exception:
                continue
        return out

    def start(self, poll_interval: float = 1.0) -> None:
        """Block and poll for changes. Cancel with .stop()."""
        self._running = True
        self._mtimes = self._scan_mtimes()
        while self._running:
            time.sleep(poll_interval)
            current = self._scan_mtimes()
            changed: List[Path] = []
            for path_str, mtime in current.items():
                if self._mtimes.get(path_str) != mtime:
                    changed.append(Path(path_str))
            # deleted files
            for path_str in list(self._mtimes.keys()):
                if path_str not in current:
                    changed.append(Path(path_str))
            self._mtimes = current
            if not changed:
                # maybe flush pending
                if self._pending and (time.time() - self._last_event_time) > self.debounce:
                    with self._lock:
                        to_fire = list(self._pending)
                        self._pending.clear()
                    if to_fire:
                        self.on_change(to_fire)
                continue
            with self._lock:
                self._pending.update(changed)
                self._last_event_time = time.time()
            # if debounce window has elapsed since last event, fire
            if (time.time() - self._last_event_time) > self.debounce:
                with self._lock:
                    to_fire = list(self._pending)
                    self._pending.clear()
                if to_fire:
                    self.on_change(to_fire)

    def stop(self) -> None:
        self._running = False


# =============================================================================
# Parallel scanner
# =============================================================================

def parallel_scan(files: List[Path],
                   analyzer: Callable[[Path], List[dict]],
                   max_workers: Optional[int] = None,
                   use_processes: bool = False) -> Dict[str, List[dict]]:
    """Run an analyzer over many files in parallel.

    Returns {file_path_str: findings}. Defaults to threads (lower memory,
    works with analyzers that share state). Set use_processes=True for CPU-bound
    analyzers — note the analyzer must be picklable in that case.
    """
    if not files:
        return {}
    workers = max_workers or min(32, (os.cpu_count() or 4) * 4)
    out: Dict[str, List[dict]] = {}
    Executor = ProcessPoolExecutor if use_processes else ThreadPoolExecutor
    with Executor(max_workers=workers) as pool:
        future_to_path = {pool.submit(analyzer, p): p for p in files}
        for fut in as_completed(future_to_path):
            p = future_to_path[fut]
            try:
                out[str(p)] = fut.result() or []
            except Exception as e:
                out[str(p)] = [{"error": str(e), "file": str(p), "line": 0,
                                 "rule_id": "INTERNAL-ERROR", "severity": "info"}]
    return out
