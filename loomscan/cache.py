"""Function-level result caching.

Caches layer results keyed on the function body hash. If the same function
is reviewed again (e.g. in a follow-up commit), the cached findings are
returned instantly — no re-analysis needed.

Cache is stored in .loomscan-cache/ and can be safely deleted (just slow on next run).
"""
from __future__ import annotations

import json
import hashlib
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime, timedelta


CACHE_DIR_NAME = ".loomscan-cache"
CACHE_TTL_DAYS = 7  # cached findings expire after 7 days


class ResultCache:
    """Persistent function-level result cache."""

    def __init__(self, repo_root: Path):
        self.cache_dir = repo_root / CACHE_DIR_NAME
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.index_file = self.cache_dir / "index.json"
        self.index: Dict[str, dict] = {}
        self._load_index()

    def _load_index(self) -> None:
        if not self.index_file.exists():
            self.index = {"entries": {}}
            return
        try:
            self.index = json.loads(self.index_file.read_text(encoding="utf-8"))
        except Exception:
            self.index = {"entries": {}}

    def _save_index(self) -> None:
        self.index_file.write_text(json.dumps(self.index, indent=2), encoding="utf-8")

    @staticmethod
    def _hash_key(layer: str, function_body: str) -> str:
        h = hashlib.sha256(f"{layer}|{function_body}".encode("utf-8")).hexdigest()
        return h[:32]

    def get(self, layer: str, function_body: str) -> Optional[List[dict]]:
        """Return cached findings for a layer+function, or None if not cached."""
        key = self._hash_key(layer, function_body)
        entry = self.index.get("entries", {}).get(key)
        if not entry:
            return None
        # check TTL
        cached_at = datetime.fromisoformat(entry["cached_at"])
        if datetime.now() - cached_at > timedelta(days=CACHE_TTL_DAYS):
            return None
        # load findings from file
        cache_file = self.cache_dir / f"{key}.json"
        if not cache_file.exists():
            return None
        try:
            return json.loads(cache_file.read_text(encoding="utf-8"))
        except Exception:
            return None

    def put(self, layer: str, function_body: str, findings: List[dict]) -> None:
        """Cache findings for a layer+function."""
        key = self._hash_key(layer, function_body)
        cache_file = self.cache_dir / f"{key}.json"
        cache_file.write_text(json.dumps(findings, indent=2), encoding="utf-8")
        self.index.setdefault("entries", {})[key] = {
            "layer": layer,
            "cached_at": datetime.now().isoformat(),
            "finding_count": len(findings),
        }
        self._save_index()

    def invalidate(self, layer: Optional[str] = None) -> None:
        """Invalidate cache entries. If layer is None, invalidate everything."""
        if layer is None:
            for cache_file in self.cache_dir.glob("*.json"):
                if cache_file.name != "index.json":
                    cache_file.unlink()
            self.index = {"entries": {}}
        else:
            keys_to_remove = [k for k, v in self.index.get("entries", {}).items()
                              if v.get("layer") == layer]
            for k in keys_to_remove:
                (self.cache_dir / f"{k}.json").unlink(missing_ok=True)
                self.index["entries"].pop(k, None)
        self._save_index()

    def stats(self) -> dict:
        entries = self.index.get("entries", {})
        return {
            "total_entries": len(entries),
            "cache_dir": str(self.cache_dir),
            "size_bytes": sum(f.stat().st_size for f in self.cache_dir.glob("*.json")),
            "ttl_days": CACHE_TTL_DAYS,
        }
