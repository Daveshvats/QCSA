"""Issue store with SQLite — finding lifecycle and trend tracking.

Inspired by CodeChecker's defect database. Every finding is stored with:
  - Stable ID (fingerprint)
  - State: open | confirmed | fixed | wontfix | baselined
  - History: when first seen, when last seen, when resolved
  - Trend data: issues found vs fixed per week

This enables:
  - `loomscan trend` — show issues found/fixed over time
  - `loomscan issue list --state open` — list open issues
  - `loomscan issue resolve <id>` — mark as fixed/wontfix
  - Trend charts in the HTML report

Uses SQLite (stdlib) — no external database needed.
"""
from __future__ import annotations

import sqlite3
import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from collections import defaultdict


ISSUES_DB_FILE = ".loomscan-issues.db"


def _get_db(repo_root: Path) -> sqlite3.Connection:
    """Get a SQLite connection, creating the schema if needed."""
    db_path = repo_root / ISSUES_DB_FILE
    conn = sqlite3.connect(str(db_path))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS issues (
            fingerprint TEXT PRIMARY KEY,
            rule_id TEXT NOT NULL,
            file TEXT NOT NULL,
            line INTEGER NOT NULL,
            severity TEXT NOT NULL,
            message TEXT NOT NULL,
            layer TEXT NOT NULL,
            cwe TEXT,
            state TEXT DEFAULT 'open',
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            resolved_at TEXT,
            resolved_by TEXT,
            resolution_note TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS issue_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fingerprint TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            action TEXT NOT NULL,
            old_state TEXT,
            new_state TEXT,
            user TEXT,
            note TEXT,
            FOREIGN KEY (fingerprint) REFERENCES issues(fingerprint)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            total_findings INTEGER,
            new_findings INTEGER,
            resolved_findings INTEGER,
            final_decision TEXT
        )
    """)
    conn.commit()
    return conn


@dataclass
class Issue:
    """A stored issue."""
    fingerprint: str
    rule_id: str
    file: str
    line: int
    severity: str
    message: str
    layer: str
    cwe: str = ""
    state: str = "open"
    first_seen: str = ""
    last_seen: str = ""
    resolved_at: str = ""
    resolved_by: str = ""
    resolution_note: str = ""


class IssueStore:
    """SQLite-backed issue store with trend tracking."""

    def __init__(self, repo_root: Path):
        self.repo_root = repo_root
        self.conn = _get_db(repo_root)

    def upsert_findings(self, findings: List) -> Tuple[int, int]:
        """Upsert findings from a check run. Returns (new_count, recurring_count)."""
        now = datetime.now().isoformat()
        new_count = 0
        recurring_count = 0
        for f in findings:
            # check if exists
            cur = self.conn.execute(
                "SELECT fingerprint FROM issues WHERE fingerprint = ?",
                (f.fingerprint,)
            )
            exists = cur.fetchone()
            if exists:
                # update last_seen
                self.conn.execute(
                    "UPDATE issues SET last_seen = ? WHERE fingerprint = ?",
                    (now, f.fingerprint)
                )
                recurring_count += 1
            else:
                # insert new
                self.conn.execute(
                    """INSERT INTO issues
                    (fingerprint, rule_id, file, line, severity, message, layer, cwe,
                     state, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)""",
                    (f.fingerprint, f.rule_id, f.file, f.start_line,
                     f.severity.value, f.message, f.layer.value,
                     f.cwe or "", now, now)
                )
                new_count += 1
        self.conn.commit()
        return new_count, recurring_count

    def mark_resolved(self, fingerprint: str, resolution: str,
                       user: str, note: str = "") -> bool:
        """Mark an issue as resolved (fixed, wontfix, false_positive)."""
        now = datetime.now().isoformat()
        cur = self.conn.execute(
            "SELECT state FROM issues WHERE fingerprint = ?", (fingerprint,)
        )
        row = cur.fetchone()
        if not row:
            return False
        old_state = row[0]
        self.conn.execute(
            """UPDATE issues SET state = ?, resolved_at = ?, resolved_by = ?,
               resolution_note = ? WHERE fingerprint = ?""",
            (resolution, now, user, note, fingerprint)
        )
        self.conn.execute(
            """INSERT INTO issue_history
            (fingerprint, timestamp, action, old_state, new_state, user, note)
            VALUES (?, ?, 'resolve', ?, ?, ?, ?)""",
            (fingerprint, now, old_state, resolution, user, note)
        )
        self.conn.commit()
        return True

    def reopen(self, fingerprint: str, user: str, note: str = "") -> bool:
        """Reopen a resolved issue (it reappeared)."""
        now = datetime.now().isoformat()
        cur = self.conn.execute(
            "SELECT state FROM issues WHERE fingerprint = ?", (fingerprint,)
        )
        row = cur.fetchone()
        if not row:
            return False
        old_state = row[0]
        self.conn.execute(
            "UPDATE issues SET state = 'open', resolved_at = NULL WHERE fingerprint = ?",
            (fingerprint,)
        )
        self.conn.execute(
            """INSERT INTO issue_history
            (fingerprint, timestamp, action, old_state, new_state, user, note)
            VALUES (?, ?, 'reopen', ?, 'open', ?, ?)""",
            (fingerprint, now, old_state, user, note)
        )
        self.conn.commit()
        return True

    def record_run(self, total: int, new: int, resolved: int, decision: str) -> None:
        """Record a check run for trend tracking."""
        now = datetime.now().isoformat()
        self.conn.execute(
            """INSERT INTO runs (timestamp, total_findings, new_findings,
               resolved_findings, final_decision) VALUES (?, ?, ?, ?, ?)""",
            (now, total, new, resolved, decision)
        )
        self.conn.commit()

    def get_trend(self, weeks: int = 12) -> List[dict]:
        """Get issue trend over the last N weeks."""
        cutoff = (datetime.now() - timedelta(weeks=weeks)).isoformat()
        cur = self.conn.execute(
            """SELECT timestamp, total_findings, new_findings, resolved_findings,
               final_decision FROM runs WHERE timestamp > ? ORDER BY timestamp""",
            (cutoff,)
        )
        return [
            {
                "timestamp": row[0],
                "total": row[1],
                "new": row[2],
                "resolved": row[3],
                "decision": row[4],
            }
            for row in cur.fetchall()
        ]

    def list_issues(self, state: str = "open", limit: int = 100) -> List[Issue]:
        """List issues, optionally filtered by state."""
        if state == "all":
            cur = self.conn.execute(
                "SELECT * FROM issues ORDER BY last_seen DESC LIMIT ?", (limit,)
            )
        else:
            cur = self.conn.execute(
                "SELECT * FROM issues WHERE state = ? ORDER BY last_seen DESC LIMIT ?",
                (state, limit)
            )
        return [Issue(*row) for row in cur.fetchall()]

    def stats(self) -> dict:
        """Return issue store statistics."""
        cur = self.conn.execute(
            "SELECT state, COUNT(*) FROM issues GROUP BY state"
        )
        by_state = dict(cur.fetchall())
        cur = self.conn.execute("SELECT COUNT(*) FROM runs")
        run_count = cur.fetchone()[0]
        cur = self.conn.execute(
            "SELECT severity, COUNT(*) FROM issues WHERE state = 'open' GROUP BY severity"
        )
        open_by_severity = dict(cur.fetchall())
        return {
            "total_issues": sum(by_state.values()),
            "by_state": by_state,
            "open_by_severity": open_by_severity,
            "total_runs": run_count,
            "db_file": str(self.repo_root / ISSUES_DB_FILE),
        }

    def close(self):
        self.conn.close()
