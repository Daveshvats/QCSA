"""Audit log system — tamper-evident logging of all LoomScan actions.

Enterprise feature: every LoomScan action (check, fix, review, config change)
is logged with a tamper-evident hash chain. Compliance auditors can verify
the log hasn't been altered.

The hash chain works like a blockchain:
  entry_n.this_hash = SHA256(entry_{n-1}.this_hash + entry_n.fields)

If any entry is modified, every subsequent hash will mismatch.

This is what enterprises need for SOC 2 / ISO 27001 / PCI-DSS compliance.
"""
from __future__ import annotations

import hashlib
import json
import os
import socket
import getpass
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional


AUDIT_LOG_FILE = ".loomscan-audit.log"


@dataclass
class AuditEntry:
    """A single tamper-evident audit log entry."""
    timestamp: str
    action: str  # check_run | fix_applied | hotspot_reviewed | config_changed | tool_installed | feedback_recorded
    user: str
    hostname: str
    details: str  # JSON string of action-specific details
    prev_hash: str
    this_hash: str


class AuditLogger:
    """Tamper-evident audit logger for LoomScan."""

    def __init__(self, repo_root: Path):
        self.repo_root = repo_root
        self.log_file = repo_root / AUDIT_LOG_FILE

    def _get_last_hash(self) -> str:
        if not self.log_file.exists():
            return "0" * 64  # genesis
        try:
            lines = self.log_file.read_text(encoding="utf-8").strip().splitlines()
            if not lines:
                return "0" * 64
            last = json.loads(lines[-1])
            return last.get("this_hash", "0" * 64)
        except Exception:
            return "0" * 64

    def _compute_hash(self, prev_hash: str, timestamp: str, action: str,
                       user: str, hostname: str, details: str) -> str:
        content = f"{prev_hash}|{timestamp}|{action}|{user}|{hostname}|{details}"
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def log(self, action: str, details: dict) -> None:
        """Append an audit entry."""
        timestamp = datetime.now().isoformat()
        try:
            user = getpass.getuser()
        except Exception:
            user = os.environ.get("USER", "unknown")
        try:
            hostname = socket.gethostname()
        except Exception:
            hostname = "unknown"

        details_str = json.dumps(details, sort_keys=True, default=str)
        prev_hash = self._get_last_hash()
        this_hash = self._compute_hash(prev_hash, timestamp, action, user, hostname, details_str)

        entry = AuditEntry(
            timestamp=timestamp, action=action, user=user,
            hostname=hostname, details=details_str,
            prev_hash=prev_hash, this_hash=this_hash,
        )
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(entry)) + "\n")

    def verify_chain(self) -> tuple:
        """Verify the audit log hasn't been tampered with.

        Returns (is_valid: bool, message: str).
        """
        if not self.log_file.exists():
            return True, "no audit log"
        try:
            lines = self.log_file.read_text(encoding="utf-8").strip().splitlines()
            prev_hash = "0" * 64
            for i, line in enumerate(lines, 1):
                entry = json.loads(line)
                if entry["prev_hash"] != prev_hash:
                    return False, f"chain broken at line {i}: prev_hash mismatch"
                expected = self._compute_hash(
                    entry["prev_hash"], entry["timestamp"], entry["action"],
                    entry["user"], entry["hostname"], entry["details"],
                )
                if entry["this_hash"] != expected:
                    return False, f"hash mismatch at line {i}: entry tampered"
                prev_hash = entry["this_hash"]
            return True, f"chain valid ({len(lines)} entries)"
        except Exception as e:
            return False, f"audit log corrupt: {e}"

    def tail(self, n: int = 20) -> list:
        """Get the last n entries."""
        if not self.log_file.exists():
            return []
        try:
            lines = self.log_file.read_text(encoding="utf-8").strip().splitlines()
            return [json.loads(line) for line in lines[-n:]]
        except Exception:
            return []

    def stats(self) -> dict:
        """Get audit log statistics."""
        if not self.log_file.exists():
            return {"total_entries": 0}
        try:
            lines = self.log_file.read_text(encoding="utf-8").strip().splitlines()
            from collections import Counter
            actions = Counter(json.loads(line)["action"] for line in lines)
            users = Counter(json.loads(line)["user"] for line in lines)
            return {
                "total_entries": len(lines),
                "by_action": dict(actions),
                "by_user": dict(users),
                "log_file": str(self.log_file),
                "size_bytes": self.log_file.stat().st_size,
            }
        except Exception:
            return {"total_entries": 0}
