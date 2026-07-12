"""STCA LSP Server — real-time squiggles in editors (VS Code, Neovim, JetBrains)."""
from __future__ import annotations
import argparse, json, sys, threading
from pathlib import Path
from typing import Dict, List, Optional

import logging
_logger = logging.getLogger(__name__.replace('stca.', ''))

class LSPServer:
    def __init__(self, repo_root: Optional[Path] = None):
        self.repo_root = repo_root or Path.cwd()
        self.workspace_files: Dict[str, str] = {}
        self.debounce_timers: Dict[str, threading.Timer] = {}
        self.debounce_ms = 500

    def run(self):
        while True:
            try:
                message = self._read_message()
                if message is None: break
                self._handle_message(message)
            except KeyboardInterrupt: break
            except Exception as e:
                sys.stderr.write(f"LSP error: {e}\n")

    def _read_message(self):
        headers: Dict[str, str] = {}
        while True:
            line = sys.stdin.readline()
            if not line: return None
            line = line.strip()
            if not line: break
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip().lower()] = value.strip()
        content_length = int(headers.get("content-length", 0))
        if content_length == 0: return None
        body = sys.stdin.read(content_length)
        try: return json.loads(body)
        except: return None

    def _send_message(self, message: dict):
        body = json.dumps(message)
        sys.stdout.write(f"Content-Length: {len(body)}\r\n\r\n")
        sys.stdout.write(body)
        sys.stdout.flush()

    def _handle_message(self, message: dict):
        method = message.get("method")
        id_ = message.get("id")
        params = message.get("params", {})
        if method == "initialize":
            self._send_message({"jsonrpc": "2.0", "id": id_, "result": {
                "capabilities": {"textDocumentSync": {"openClose": True, "change": 1, "save": {"includeText": False}},
                                 "hoverProvider": True, "codeActionProvider": True},
                "serverInfo": {"name": "stca-lsp", "version": "1.0.0"}}})
        elif method == "initialized": pass
        elif method == "shutdown": self._send_message({"jsonrpc": "2.0", "id": id_, "result": None})
        elif method == "exit": sys.exit(0)
        elif method == "textDocument/didOpen":
            doc = params.get("textDocument", {})
            self.workspace_files[doc.get("uri", "")] = doc.get("text", "")
            self._schedule_analysis(doc.get("uri", ""))
        elif method == "textDocument/didChange":
            doc = params.get("textDocument", {})
            changes = params.get("contentChanges", [])
            if changes: self.workspace_files[doc.get("uri", "")] = changes[0].get("text", "")
            self._schedule_analysis(doc.get("uri", ""))
        elif method == "textDocument/didSave":
            self._schedule_analysis(params.get("textDocument", {}).get("uri", ""), force=True)
        elif method == "textDocument/hover":
            # v4.38: Real hover — show rule documentation for findings on this line
            hover = self._get_hover_info(params)
            self._send_message({"jsonrpc": "2.0", "id": id_, "result": hover})
        elif method == "textDocument/codeAction":
            # v4.38: Real code actions — offer "Apply auto-fix" for findings on this line
            actions = self._get_code_actions(params)
            self._send_message({"jsonrpc": "2.0", "id": id_, "result": actions})

    def _schedule_analysis(self, uri: str, force: bool = False):
        if uri in self.debounce_timers: self.debounce_timers[uri].cancel()
        timer = threading.Timer(self.debounce_ms / 1000.0, lambda: self._analyze_and_publish(uri))
        timer.daemon = True
        timer.start()
        self.debounce_timers[uri] = timer

    def _analyze_and_publish(self, uri: str):
        text = self.workspace_files.get(uri, "")
        if not text: return
        path = Path(uri[7:] if uri.startswith("file://") else uri)
        findings = self._analyze_text(path, text)
        # v4.38: Cache findings for hover/codeAction lookups
        self._findings_cache[uri] = findings
        diagnostics = [self._finding_to_diagnostic(f) for f in findings]
        self._send_message({"jsonrpc": "2.0", "method": "textDocument/publishDiagnostics",
                            "params": {"uri": uri, "diagnostics": diagnostics}})

    def _analyze_text(self, path: Path, text: str) -> List[dict]:
        import tempfile
        suffix = path.suffix or ".py"
        findings: List[dict] = []
        with tempfile.NamedTemporaryFile(mode='w', suffix=suffix, delete=False, dir=str(self.repo_root)) as tmp:
            tmp.write(text)
            tmp_path = Path(tmp.name)
        try:
            if suffix == ".py":
                from ..nullness import NullnessAnalyzer
                for issue in NullnessAnalyzer().analyze_file(tmp_path, self.repo_root):
                    findings.append({"rule_id": "nullness", "file": str(path), "line": issue.line,
                                     "message": issue.reason, "severity": "warning", "fix": ""})
            elif suffix in (".js", ".jsx", ".ts", ".tsx"):
                from ..js_pattern_scanner import scan_js_patterns
                for hit in scan_js_patterns(tmp_path, self.repo_root):
                    findings.append({"rule_id": hit.rule_id, "file": hit.file, "line": hit.line,
                                     "message": hit.message, "severity": hit.severity, "fix": hit.fix})
        except Exception: pass  # v4.5: suppressed — add logging
        finally: tmp_path.unlink(missing_ok=True)
        return findings

    def _finding_to_diagnostic(self, finding: dict) -> dict:
        sev_map = {"critical": 1, "high": 1, "medium": 2, "low": 3, "info": 3}
        return {"range": {"start": {"line": max(0, finding.get("line", 1) - 1), "character": 0},
                          "end": {"line": max(0, finding.get("line", 1) - 1), "character": 80}},
                "severity": sev_map.get(finding.get("severity", "medium").lower(), 2),
                "code": finding.get("rule_id", ""), "source": "stca", "message": finding.get("message", "")}

    # v4.38: Cache findings per file for hover/codeAction lookups
    # Key: file URI, Value: list of findings
    _findings_cache: Dict[str, List[dict]] = {}

    def _get_hover_info(self, params: dict) -> Optional[dict]:
        """Return hover info for findings on the cursor's line.

        Shows the rule_id, message, severity, confidence, and fix suggestion
        for any finding at the hovered position.
        """
        uri = params.get("textDocument", {}).get("uri", "")
        position = params.get("position", {})
        line = position.get("line", 0) + 1  # LSP is 0-indexed

        findings = self._findings_cache.get(uri, [])
        line_findings = [f for f in findings if f.get("line", 0) == line]
        if not line_findings:
            return None

        # Build markdown hover content
        lines = []
        for f in line_findings:
            sev = f.get("severity", "medium").upper()
            rule_id = f.get("rule_id", "")
            msg = f.get("message", "")
            lines.append(f"**STCA {sev}** — `{rule_id}`")
            lines.append(f"\n{msg}")
            if f.get("fix"):
                lines.append(f"\n**Fix:** {f['fix']}")
            lines.append("\n---")

        return {
            "contents": {"kind": "markdown", "value": "\n".join(lines)},
        }

    def _get_code_actions(self, params: dict) -> List[dict]:
        """Return code actions (quick fixes) for findings in the selected range.

        Each finding with an auto-fix pattern gets a "Apply STCA fix" code action.
        Selecting the action triggers a workspace edit that applies the fix.
        """
        uri = params.get("textDocument", {}).get("uri", "")
        range_ = params.get("range", {})
        start_line = range_.get("start", {}).get("line", 0) + 1
        end_line = range_.get("end", {}).get("line", 0) + 1

        findings = self._findings_cache.get(uri, [])
        range_findings = [f for f in findings
                         if start_line <= f.get("line", 0) <= end_line]
        if not range_findings:
            return []

        actions = []
        for f in range_findings:
            rule_id = f.get("rule_id", "")
            # Check if an auto-fix exists for this rule
            has_fix = self._has_autofix(rule_id)
            if has_fix:
                actions.append({
                    "title": f"STCA: Apply fix for {rule_id}",
                    "kind": "quickfix",
                    "command": {
                        "title": "Apply STCA auto-fix",
                        "command": "stca.applyFix",
                        "arguments": [uri, rule_id, f.get("line", 1)],
                    },
                })
            # Always offer "Show rule details"
            actions.append({
                "title": f"STCA: Show details for {rule_id}",
                "kind": "source",
                "command": {
                    "title": "Show STCA rule details",
                    "command": "stca.showRule",
                    "arguments": [rule_id],
                },
            })

        return actions

    def _has_autofix(self, rule_id: str) -> bool:
        """Check if an auto-fix pattern exists for the given rule_id."""
        try:
            from ..layers.l8_autofix import FIX_PATTERNS
            for pattern in FIX_PATTERNS:
                if rule_id.startswith(pattern.rule_prefix) or pattern.rule_prefix in rule_id:
                    return True
        except Exception:
            pass
        return False

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", default=None)
    args = parser.parse_args()
    server = LSPServer(Path(args.repo_root) if args.repo_root else None)
    server.run()

if __name__ == "__main__":
    main()
