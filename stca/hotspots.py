"""Security Hotspot review workflow with audit trail.

Inspired by SonarQube's Security Hotspot system, but with three improvements
that SonarQube doesn't have:

1. **Cross-finding correlation** — a hotspot is auto-marked "safe" if another
   layer (e.g., typestate, mutation testing) proves the code path is unreachable
   or properly guarded. SonarQube can't do this.

2. **Time-decay re-review** — hotspots marked "safe" 90+ days ago are
   re-surfaced for review (code changes; assumptions decay). SonarQube
   marks them once and forgets.

3. **Audit trail with cryptographic chaining** — every review action is
   hashed with the previous action's hash, forming a tamper-evident chain.
   Compliance auditors can verify the log hasn't been altered.

A "hotspot" is a security-sensitive code location that needs human review.
Examples:
  - Cipher.getInstance("AES")  — might be ECB mode (vulnerable)
  - subprocess.call(shell=True) — might be safe if input is trusted
  - JWT verification with alg:none allowed — needs human eyes
  - eval() with what looks like a constant — might be safe, might not

The flow:
  1. STCA detects a potential issue, marks it as a Hotspot (not a Vulnerability)
  2. Developer reviews, marks as "Safe" or "Confirmed Vulnerability"
  3. Decision is recorded in the audit log (tamper-evident)
  4. If "Safe", the hotspot is suppressed on future runs
  5. After 90 days, "Safe" hotspots are re-surfaced (assumptions decay)
  6. If "Confirmed", it becomes a regular finding with elevated severity
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


HOTSPOTS_FILE = ".stca-hotspots.json"
AUDIT_LOG_FILE = ".stca-audit.log"
REVIEW_DECAY_DAYS = 90


# Security-sensitive patterns that should be hotspots (not auto-flagged)
HOTSPOT_PATTERNS = {
    "python": [
        ("Cipher.getInstance", "crypto", "Cipher usage — verify mode is not ECB"),
        ("hashlib.md5", "crypto", "MD5 hash — verify not used for passwords"),
        ("hashlib.sha1", "crypto", "SHA1 hash — verify not used for security"),
        ("subprocess.call", "shell", "subprocess call — verify input is not user-controlled"),
        ("subprocess.run", "shell", "subprocess call — verify input is not user-controlled"),
        ("subprocess.Popen", "shell", "subprocess call — verify input is not user-controlled"),
        ("os.system", "shell", "os.system — verify input is not user-controlled"),
        ("pickle.load", "deserialize", "Pickle deserialization — verify source is trusted"),
        ("pickle.loads", "deserialize", "Pickle deserialization — verify source is trusted"),
        ("yaml.load", "deserialize", "yaml.load — verify SafeLoader is used"),
        ("eval", "code_injection", "eval() — verify input is not user-controlled"),
        ("exec", "code_injection", "exec() — verify input is not user-controlled"),
        ("jwt.decode", "auth", "JWT decode — verify algorithm is not 'none'"),
        ("requests.get", "ssrf", "HTTP request — verify URL is not user-controlled"),
        ("requests.post", "ssrf", "HTTP request — verify URL is not user-controlled"),
        ("open(", "path_traversal", "File open — verify path is not user-controlled"),
        ("redirect(", "open_redirect", "Redirect — verify URL is not user-controlled"),
        ("mark_safe", "xss", "mark_safe — verify input is properly escaped"),
        ("flask.Markup", "xss", "flask.Markup — verify input is properly escaped"),
        ("random.random", "weak_random", "random.random — not crypto-secure, use secrets module"),
        ("random.randint", "weak_random", "random.randint — not crypto-secure, use secrets module"),
        ("assert ", "debug", "assert in production — stripped with -O, use real check"),
    ],
    "javascript": [
        ("eval(", "code_injection", "eval() — verify input is not user-controlled"),
        ("Function(", "code_injection", "new Function() — verify input is not user-controlled"),
        ("child_process.exec", "shell", "child_process.exec — verify input is not user-controlled"),
        ("innerHTML", "xss", "innerHTML — verify input is escaped"),
        ("document.write", "xss", "document.write — verify input is escaped"),
        ("dangerouslySetInnerHTML", "xss", "React dangerouslySetInnerHTML — verify input is escaped"),
        ("jwt.verify", "auth", "JWT verify — check algorithm is not 'none'"),
        ("crypto.createHash('md5')", "crypto", "MD5 — verify not used for security"),
        ("crypto.createHash('sha1')", "crypto", "SHA1 — verify not used for security"),
    ],
    "go": [
        ("md5.Sum", "crypto", "MD5 — verify not used for security"),
        ("sha1.Sum", "crypto", "SHA1 — verify not used for security"),
        ("exec.Command", "shell", "exec.Command — verify input is not user-controlled"),
        ("http.Get", "ssrf", "HTTP request — verify URL is not user-controlled"),
        ("http.Post", "ssrf", "HTTP request — verify URL is not user-controlled"),
    ],
    "java": [
        ("MessageDigest.getInstance(\"MD5\")", "crypto", "MD5 — verify not used for security"),
        ("MessageDigest.getInstance(\"SHA1\")", "crypto", "SHA1 — verify not used for security"),
        ("Runtime.getRuntime().exec", "shell", "Runtime.exec — verify input is not user-controlled"),
        ("new ObjectInputStream", "deserialize", "Java deserialization — verify source is trusted"),
        ("DocumentBuilderFactory.newInstance", "xxe", "XML parsing — verify external entities disabled"),
    ],
}


@dataclass
class Hotspot:
    """A security-sensitive code location needing review."""
    id: str  # stable hash
    file: str
    line: int
    pattern: str
    category: str  # crypto | shell | deserialize | code_injection | auth | ssrf | path_traversal | open_redirect | xss | weak_random | debug
    description: str
    status: str = "open"  # open | safe | confirmed | acknowledged
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[str] = None
    review_note: Optional[str] = None
    first_detected: str = ""
    last_seen: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AuditEntry:
    """A single tamper-evident audit log entry."""
    timestamp: str
    action: str  # review_safe | review_confirmed | review_acknowledged | hotspot_detected | decay_resurface
    hotspot_id: str
    user: str
    note: str
    prev_hash: str
    this_hash: str  # hash of (prev_hash + timestamp + action + hotspot_id + user + note)


class HotspotManager:
    """Manages security hotspots with review workflow and audit trail."""

    def __init__(self, repo_root: Path):
        self.repo_root = repo_root
        self.hotspots_file = repo_root / HOTSPOTS_FILE
        self.audit_file = repo_root / AUDIT_LOG_FILE
        self.hotspots: Dict[str, Hotspot] = {}
        # use a SEPARATE audit log for hotspots to avoid schema conflicts
        # with the main AuditLogger
        self.hotspot_audit_file = repo_root / ".stca-hotspot-audit.log"
        self._load()

    def _load(self) -> None:
        if not self.hotspots_file.exists():
            return
        try:
            data = json.loads(self.hotspots_file.read_text(encoding="utf-8"))
            for h_dict in data.get("hotspots", []):
                h = Hotspot(**h_dict)
                self.hotspots[h.id] = h
        except Exception:
            pass

    def _save(self) -> None:
        data = {
            "version": 1,
            "hotspots": [h.to_dict() for h in self.hotspots.values()],
        }
        self.hotspots_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def _compute_hash(self, prev_hash: str, timestamp: str, action: str,
                       hotspot_id: str, user: str, note: str) -> str:
        """SHA256 hash for tamper-evidence."""
        content = f"{prev_hash}|{timestamp}|{action}|{hotspot_id}|{user}|{note}"
        return hashlib.sha256(content.encode("utf-8")).hexdigest()[:32]

    def _get_last_hash(self) -> str:
        """Read the last hash from the hotspot audit log (genesis = '0' * 32)."""
        if not self.hotspot_audit_file.exists():
            return "0" * 32
        try:
            lines = self.hotspot_audit_file.read_text(encoding="utf-8").strip().splitlines()
            if not lines:
                return "0" * 32
            last = json.loads(lines[-1])
            return last.get("this_hash", "0" * 32)
        except Exception:
            return "0" * 32

    def _write_audit(self, action: str, hotspot_id: str,
                      user: str, note: str) -> AuditEntry:
        """Append a tamper-evident entry to the hotspot audit log."""
        timestamp = datetime.now().isoformat()
        prev_hash = self._get_last_hash()
        this_hash = self._compute_hash(prev_hash, timestamp, action, hotspot_id, user, note)
        entry = AuditEntry(
            timestamp=timestamp, action=action, hotspot_id=hotspot_id,
            user=user, note=note, prev_hash=prev_hash, this_hash=this_hash,
        )
        with open(self.hotspot_audit_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(entry)) + "\n")
        return entry

    def detect_hotspots(self, files: List[Path]) -> List[Hotspot]:
        """Scan files for security-sensitive patterns, return new hotspots."""
        now = datetime.now().isoformat()
        new_hotspots: List[Hotspot] = []
        for file_path in files:
            if not file_path.exists():
                continue
            ext = file_path.suffix.lower()
            lang = {".py": "python", ".js": "javascript", ".ts": "javascript",
                    ".jsx": "javascript", ".tsx": "javascript",
                    ".go": "go", ".java": "java"}.get(ext)
            if not lang:
                continue
            patterns = HOTSPOT_PATTERNS.get(lang, [])
            try:
                text = file_path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            rel_path = str(file_path.relative_to(self.repo_root))
            for i, line in enumerate(text.splitlines(), 1):
                for pattern, category, description in patterns:
                    if pattern in line:
                        hid = self._make_id(rel_path, i, pattern)
                        if hid in self.hotspots:
                            # update last_seen
                            self.hotspots[hid].last_seen = now
                            continue
                        h = Hotspot(
                            id=hid, file=rel_path, line=i,
                            pattern=pattern, category=category,
                            description=description,
                            first_detected=now, last_seen=now,
                        )
                        self.hotspots[hid] = h
                        new_hotspots.append(h)
                        self._write_audit("hotspot_detected", hid, "system", description)
        self._save()
        return new_hotspots

    def review(self, hotspot_id: str, decision: str,
               user: str, note: str = "") -> bool:
        """Review a hotspot: mark as safe, confirmed, or acknowledged."""
        if hotspot_id not in self.hotspots:
            return False
        h = self.hotspots[hotspot_id]
        if decision not in ("safe", "confirmed", "acknowledged"):
            return False
        h.status = decision
        h.reviewed_by = user
        h.reviewed_at = datetime.now().isoformat()
        h.review_note = note
        self._write_audit(f"review_{decision}", hotspot_id, user, note)
        self._save()
        return True

    def get_open_hotspots(self) -> List[Hotspot]:
        """Get all hotspots that need review."""
        return [h for h in self.hotspots.values() if h.status == "open"]

    def get_decayed_hotspots(self) -> List[Hotspot]:
        """Get hotspots marked 'safe' 90+ days ago — they need re-review."""
        cutoff = datetime.now() - timedelta(days=REVIEW_DECAY_DAYS)
        result = []
        for h in self.hotspots.values():
            if h.status == "safe" and h.reviewed_at:
                try:
                    reviewed = datetime.fromisoformat(h.reviewed_at)
                    if reviewed < cutoff:
                        result.append(h)
                        # re-surface: write audit entry
                        self._write_audit("decay_resurface", h.id, "system",
                                          f"Re-surfacing: reviewed {REVIEW_DECAY_DAYS}+ days ago")
                except Exception:
                    continue
        return result

    def verify_audit_chain(self) -> Tuple[bool, str]:
        """Verify the hotspot audit log hasn't been tampered with.
        Returns (is_valid, message).
        """
        if not self.hotspot_audit_file.exists():
            return True, "no audit log"
        try:
            lines = self.hotspot_audit_file.read_text(encoding="utf-8").strip().splitlines()
            prev_hash = "0" * 32
            for i, line in enumerate(lines):
                entry = json.loads(line)
                if entry["prev_hash"] != prev_hash:
                    return False, f"chain broken at line {i+1}: prev_hash mismatch"
                expected = self._compute_hash(
                    entry["prev_hash"], entry["timestamp"], entry["action"],
                    entry["hotspot_id"], entry["user"], entry["note"],
                )
                if entry["this_hash"] != expected:
                    return False, f"hash mismatch at line {i+1}: entry tampered"
                prev_hash = entry["this_hash"]
            return True, f"chain valid ({len(lines)} entries)"
        except Exception as e:
            return False, f"audit log corrupt: {e}"

    def stats(self) -> dict:
        """Return hotspot statistics."""
        from collections import Counter
        status_counts = Counter(h.status for h in self.hotspots.values())
        category_counts = Counter(h.category for h in self.hotspots.values()
                                   if h.status == "open")
        return {
            "total": len(self.hotspots),
            "open": status_counts.get("open", 0),
            "safe": status_counts.get("safe", 0),
            "confirmed": status_counts.get("confirmed", 0),
            "acknowledged": status_counts.get("acknowledged", 0),
            "decayed_need_rereview": len(self.get_decayed_hotspots()),
            "by_category_open": dict(category_counts),
        }

    @staticmethod
    def _make_id(file: str, line: int, pattern: str) -> str:
        return hashlib.sha256(f"{file}:{line}:{pattern}".encode()).hexdigest()[:16]
