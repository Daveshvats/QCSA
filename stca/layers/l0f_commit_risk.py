"""L0f — Commit Risk Analysis (git metadata).

Research-backed predictors of bug risk:
  - Large commits (>300 lines changed) — 3-4x bug risk (Civis Analytics, MSR studies)
  - Late-night commits (10pm-6am local) — 2x bug risk
  - Weekend commits — 1.5x bug risk
  - Tangled commits (multiple unrelated changes) — 2x bug risk
  - Risky commit messages ("hotfix", "wip", "hack", "temp") — 2x bug risk
  - Friday afternoon commits — 2x bug risk (deploy before weekend)
  - Commits by new contributors — 1.5x bug risk
  - Reverts in the last 7 days — high risk of regression

These are *probabilistic* signals — none is a bug, but combined they raise
the prior probability that the diff contains a bug. The FIS treats these
as low-confidence signals that nudge the decision.
"""
from __future__ import annotations

import subprocess
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from .base import LayerBase
from ..models import Finding, DiffHunk, LayerID, Severity, BlastRadius


RISKY_MESSAGE_PATTERNS = [
    (r"\b(wip|work in progress|temp|temporary|hack|hacky|hacked)\b", "WIP/hack message", 0.6),
    (r"\bhotfix\b", "hotfix in message", 0.7),
    (r"\b(revert|rollback)\b", "revert in message", 0.5),
    (r"\b(please|plz|asap|urgent)\b", "urgent language", 0.5),
    (r"\b(testing|just testing)\b", "testing message", 0.4),
    (r"\bTODO\b", "TODO in commit message", 0.4),
    (r"^\s*\.\.\.\s*$", "placeholder message", 0.6),
    (r"^\s*\w+\s*$", "single-word message", 0.3),
]


class L0fCommitRisk(LayerBase):
    id = LayerID.L0F_COMMIT_RISK  # v4.11: use own LayerID
    name = "Commit Risk"
    description = "Git metadata risk analysis (size, time, message, author)"
    LAYER_TAG = "L0f_commit"

    LARGE_COMMIT_LINES = 300
    LARGE_COMMIT_FILES = 10
    LATE_NIGHT_START = 22  # 10 PM
    LATE_NIGHT_END = 6     # 6 AM
    FRIDAY_AFTERNOON_HOUR = 16

    def run(self, repo_root: Path, hunks: List[DiffHunk],
            config) -> List[Finding]:
        findings: List[Finding] = []

        # Get diff stats
        diff_stats = self._get_diff_stats(repo_root)
        commit_meta = self._get_commit_meta(repo_root)

        # 1. Size risk
        findings += self._check_size(repo_root, diff_stats)

        # 2. Time risk
        findings += self._check_time(repo_root, commit_meta)

        # 3. Message risk
        findings += self._check_message(repo_root, commit_meta)

        # 4. Tangled changes (multiple unrelated files)
        findings += self._check_tangled(repo_root, diff_stats)

        # 5. Author experience
        findings += self._check_author(repo_root, commit_meta)

        # 6. Recent reverts
        findings += self._check_recent_reverts(repo_root)

        for f in findings:
            if not f.rule_id.startswith("L0f"):
                f.rule_id = f"L0f.{f.rule_id}"

        return findings

    def _run_git(self, repo_root: Path, args: list) -> str:
        try:
            proc = subprocess.run(
                ["git", "-C", str(repo_root), *args],
                capture_output=True, text=True, check=False, timeout=10,
            )
            return proc.stdout
        except Exception:
            return ""

    def _get_diff_stats(self, repo_root: Path) -> dict:
        out = self._run_git(repo_root, ["diff", "--stat", "HEAD"])
        lines_changed = 0
        files_changed = set()
        for line in out.splitlines():
            m = re.match(r"^\s*([^\s|]+)\s+\|\s+(\d+)\s", line)
            if m:
                files_changed.add(m.group(1).strip())
                lines_changed += int(m.group(2))
        return {"lines_changed": lines_changed, "files_changed": len(files_changed),
                "files": files_changed}

    def _get_commit_meta(self, repo_root: Path) -> dict:
        # get last commit's author, time, message
        out = self._run_git(repo_root, ["log", "-1", "--pretty=format:%an|%aI|%s"])
        parts = out.split("|", 2)
        if len(parts) < 3:
            return {}
        author, time_str, message = parts
        try:
            commit_time = datetime.fromisoformat(time_str)
        except Exception:
            return {}
        # get total commits by this author
        author_commits_out = self._run_git(
            repo_root, ["rev-list", "--count", "--author", author, "HEAD"]
        )
        try:
            author_total_commits = int(author_commits_out.strip())
        except Exception:
            author_total_commits = 0
        return {
            "author": author,
            "time": commit_time,
            "message": message,
            "author_total_commits": author_total_commits,
        }

    def _check_size(self, repo_root: Path, stats: dict) -> List[Finding]:
        findings: List[Finding] = []
        if stats["lines_changed"] > self.LARGE_COMMIT_LINES:
            risk_ratio = stats["lines_changed"] / self.LARGE_COMMIT_LINES
            findings.append(Finding(
                layer=self.id,
                rule_id="L0f.large_commit_lines",
                message=f"Large commit: {stats['lines_changed']} lines changed ({risk_ratio:.1f}x threshold) — research shows 3-4x bug risk",
                file="<commit>", start_line=0,
                severity=Severity.MEDIUM, confidence=0.6,
                blast_radius=BlastRadius.MODULE, exploitability=0.0,
                cwe="CWE-1058",
                fix_suggestion="Split into smaller, focused commits (under 300 lines)",
                raw={"lines_changed": stats["lines_changed"]},
            ))
        if stats["files_changed"] > self.LARGE_COMMIT_FILES:
            findings.append(Finding(
                layer=self.id,
                rule_id="L0f.large_commit_files",
                message=f"Large commit: {stats['files_changed']} files changed — likely tangled changes",
                file="<commit>", start_line=0,
                severity=Severity.LOW, confidence=0.55,
                blast_radius=BlastRadius.MODULE, exploitability=0.0,
                cwe="CWE-1058",
                fix_suggestion="One logical change per commit",
                raw={"files_changed": stats["files_changed"]},
            ))
        return findings

    def _check_time(self, repo_root: Path, meta: dict) -> List[Finding]:
        findings: List[Finding] = []
        if not meta:
            return findings
        commit_time = meta["time"]
        hour = commit_time.hour
        weekday = commit_time.weekday()  # 0=Mon, 6=Sun

        if self.LATE_NIGHT_START <= hour or hour < self.LATE_NIGHT_END:
            findings.append(Finding(
                layer=self.id,
                rule_id="L0f.late_night",
                message=f"Late-night commit ({hour:02d}:00) — research shows 2x bug risk",
                file="<commit>", start_line=0,
                severity=Severity.LOW, confidence=0.5,
                blast_radius=BlastRadius.FUNCTION, exploitability=0.0,
                cwe="CWE-1058",
                fix_suggestion="Review again in the morning with fresh eyes",
                raw={"hour": hour},
            ))

        if weekday >= 5:  # Saturday or Sunday
            findings.append(Finding(
                layer=self.id,
                rule_id="L0f.weekend",
                message="Weekend commit — 1.5x bug risk per research",
                file="<commit>", start_line=0,
                severity=Severity.LOW, confidence=0.45,
                blast_radius=BlastRadius.FUNCTION, exploitability=0.0,
                cwe="CWE-1058",
                raw={"weekday": weekday},
            ))

        # Friday afternoon (4 PM+) — deploy before weekend
        if weekday == 4 and hour >= self.FRIDAY_AFTERNOON_HOUR:
            findings.append(Finding(
                layer=self.id,
                rule_id="L0f.friday_afternoon",
                message="Friday afternoon commit — 2x bug risk (deploy before weekend pattern)",
                file="<commit>", start_line=0,
                severity=Severity.MEDIUM, confidence=0.55,
                blast_radius=BlastRadius.MODULE, exploitability=0.0,
                cwe="CWE-1058",
                fix_suggestion="Delay until Monday, or deploy Monday morning",
                raw={"hour": hour, "weekday": weekday},
            ))
        return findings

    def _check_message(self, repo_root: Path, meta: dict) -> List[Finding]:
        findings: List[Finding] = []
        if not meta:
            return findings
        msg = meta["message"]
        msg_lower = msg.lower()

        for pattern, label, conf in RISKY_MESSAGE_PATTERNS:
            if re.search(pattern, msg, re.IGNORECASE):
                findings.append(Finding(
                    layer=self.id,
                    rule_id=f"L0f.message_risk",
                    message=f"Risky commit message ({label}): \"{msg[:80]}\"",
                    file="<commit>", start_line=0,
                    severity=Severity.LOW, confidence=conf,
                    blast_radius=BlastRadius.FUNCTION, exploitability=0.0,
                    cwe="CWE-1058",
                    fix_suggestion="Write a clear, descriptive commit message",
                    raw={"message": msg, "pattern_matched": label},
                ))
                break  # one finding per commit

        # Empty/too short message
        if len(msg.strip()) < 10:
            findings.append(Finding(
                layer=self.id,
                rule_id="L0f.short_message",
                message=f"Commit message too short ({len(msg)} chars): \"{msg}\"",
                file="<commit>", start_line=0,
                severity=Severity.LOW, confidence=0.5,
                blast_radius=BlastRadius.FUNCTION, exploitability=0.0,
                cwe="CWE-1058",
                fix_suggestion="Describe what changed and why (at least 30 chars)",
                raw={"message": msg},
            ))
        return findings

    def _check_tangled(self, repo_root: Path, stats: dict) -> List[Finding]:
        """Tangled commit = changes to many unrelated directories."""
        findings: List[Finding] = []
        if stats["files_changed"] < 5:
            return findings
        dirs = set()
        for f in stats["files"]:
            parts = f.split("/")
            if len(parts) > 1:
                dirs.add(parts[0])
            else:
                dirs.add(".")
        if len(dirs) >= 3:
            findings.append(Finding(
                layer=self.id,
                rule_id="L0f.tangled",
                message=f"Tangled commit: changes span {len(dirs)} unrelated directories ({', '.join(list(dirs)[:5])})",
                file="<commit>", start_line=0,
                severity=Severity.LOW, confidence=0.5,
                blast_radius=BlastRadius.MODULE, exploitability=0.0,
                cwe="CWE-1058",
                fix_suggestion="Split into one commit per logical change",
                raw={"directories": list(dirs)},
            ))
        return findings

    def _check_author(self, repo_root: Path, meta: dict) -> List[Finding]:
        findings: List[Finding] = []
        if not meta:
            return findings
        total = meta["author_total_commits"]
        # New contributor: <10 lifetime commits
        if 0 < total < 10:
            findings.append(Finding(
                layer=self.id,
                rule_id="L0f.new_author",
                message=f"New contributor ({meta['author']}, {total} lifetime commits) — 1.5x bug risk",
                file="<commit>", start_line=0,
                severity=Severity.INFO, confidence=0.5,
                blast_radius=BlastRadius.FUNCTION, exploitability=0.0,
                cwe="CWE-1058",
                fix_suggestion="Pair-program review with an experienced contributor",
                raw={"author": meta["author"], "total_commits": total},
            ))
        return findings

    def _check_recent_reverts(self, repo_root: Path) -> List[Finding]:
        """If there's been a revert in the last 7 days, the diff is at higher risk."""
        findings: List[Finding] = []
        out = self._run_git(repo_root, [
            "log", "--since=7 days ago", "--grep=revert", "-i",
            "--pretty=format:%h|%s",
        ])
        if out.strip():
            reverts = out.strip().splitlines()
            findings.append(Finding(
                layer=self.id,
                rule_id="L0f.recent_reverts",
                message=f"{len(reverts)} revert(s) in the last 7 days — high regression risk",
                file="<commit>", start_line=0,
                severity=Severity.MEDIUM, confidence=0.6,
                blast_radius=BlastRadius.MODULE, exploitability=0.0,
                cwe="CWE-1058",
                fix_suggestion="Investigate why reverts are happening — there may be an upstream issue",
                raw={"reverts": reverts[:5]},
            ))
        return findings
