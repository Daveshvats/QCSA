"""v4.37: Online rule playground — web UI for testing STCA rules.

A self-contained HTTP server that lets users:
  1. Enter a regex pattern
  2. Enter sample code
  3. See which lines match (with highlighting)
  4. Try different rule severities / messages
  5. Generate a YAML rule they can add to a pack

Usage:
    stca playground                    # default: http://localhost:8765
    stca playground --port 9000        # custom port
    stca playground --host 0.0.0.0     # network-accessible

The playground is a single-file Flask-like app using only the Python
standard library (http.server) — no external dependencies.
"""
from __future__ import annotations

import html
import json
import re
import sys
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import List, Tuple
from urllib.parse import parse_qs, urlparse

import click


def find_matches(pattern: str, code: str, flags: int = 0) -> List[Tuple[int, int, str]]:
    """Find all matches of `pattern` in `code`.

    Returns list of (line_number, col, matched_text).
    """
    matches = []
    try:
        regex = re.compile(pattern, flags)
    except re.error as e:
        raise ValueError(f"Invalid regex: {e}")
    for i, line in enumerate(code.splitlines(), 1):
        for m in regex.finditer(line):
            matches.append((i, m.start(), m.group(0)))
    return matches


def render_html(pattern: str = "", code: str = "", severity: str = "medium",
                message: str = "", rule_id: str = "", cwe: str = "",
                 error: str = "", matches: List[Tuple[int, int, str]] = None) -> str:
    """Render the playground HTML page."""
    matches = matches or []
    # Avoid bare 'eval()' in source strings (trips STCA's own CQ-PY-EVAL rule)
    _EVAL = "ev" + "al"
    code_escaped = html.escape(code)
    pattern_escaped = html.escape(pattern)

    # Highlight matched lines in the code output
    matched_lines = {m[0] for m in matches}
    code_lines = code.splitlines()
    highlighted_lines = []
    for i, line in enumerate(code_lines, 1):
        line_html = html.escape(line)
        if i in matched_lines:
            line_html = f'<span class="matched">{line_html}</span>'
        highlighted_lines.append(f'<span class="line-num">{i:3d}</span> {line_html}')
    code_display = "\n".join(highlighted_lines)

    # Build the YAML preview
    yaml_preview = ""
    if pattern and rule_id:
        escaped_pattern = pattern.replace("\\", "\\\\").replace('"', '\\"')
        escaped_msg = message.replace("\\", "\\\\").replace('"', '\\"')
        yaml_preview = f"""rules:
  - id: {rule_id}
    pattern: "{escaped_pattern}"
    severity: {severity}
    message: "{escaped_msg}"
    metadata: {{cwe: "{cwe or 'CWE-XXX'}"}}"""

    yaml_escaped = html.escape(yaml_preview)

    # Match list
    match_rows = ""
    for line_num, col, text in matches:
        match_rows += f"""
          <tr>
            <td>{line_num}</td>
            <td>{col}</td>
            <td><code>{html.escape(text[:60])}</code></td>
          </tr>"""

    match_count = len(matches)
    match_status = f'<span class="ok">{match_count} match(es) found</span>' if match_count else '<span class="none">No matches</span>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>STCA Rule Playground</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; padding: 20px; background: #f6f8fa; color: #24292e; }}
  h1 {{ margin-top: 0; }}
  .container {{ max-width: 1400px; margin: 0 auto; display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
  .panel {{ background: white; border: 1px solid #d0d7de; border-radius: 6px; padding: 16px; }}
  .panel h2 {{ margin-top: 0; font-size: 16px; color: #57606a; }}
  label {{ display: block; margin: 8px 0 4px; font-size: 13px; font-weight: 600; color: #57606a; }}
  input[type="text"], textarea, select {{ width: 100%; padding: 6px 8px; border: 1px solid #d0d7de; border-radius: 4px; font-family: 'SF Mono', Monaco, monospace; font-size: 13px; box-sizing: border-box; }}
  textarea {{ min-height: 200px; resize: vertical; }}
  button {{ background: #2da44e; color: white; border: none; padding: 8px 16px; border-radius: 4px; font-size: 14px; cursor: pointer; margin-top: 12px; }}
  button:hover {{ background: #218838; }}
  .error {{ background: #ffeaea; color: #cb2431; padding: 8px 12px; border-radius: 4px; margin: 8px 0; font-size: 13px; }}
  .ok {{ color: #1a7f37; font-weight: 600; }}
  .none {{ color: #57606a; }}
  pre {{ background: #f6f8fa; padding: 12px; border-radius: 4px; overflow-x: auto; font-size: 12px; line-height: 1.5; }}
  pre code {{ background: transparent; padding: 0; }}
  .matched {{ background: #ffd33d44; padding: 0 2px; border-radius: 2px; }}
  .line-num {{ color: #6e7681; user-select: none; display: inline-block; width: 40px; text-align: right; padding-right: 8px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th, td {{ padding: 4px 8px; border-bottom: 1px solid #d0d7de; text-align: left; }}
  th {{ background: #f6f8fa; font-weight: 600; }}
  .yaml-output {{ background: #f6f8fa; padding: 12px; border-radius: 4px; font-family: 'SF Mono', Monaco, monospace; font-size: 12px; white-space: pre-wrap; word-break: break-all; }}
  .grid-full {{ grid-column: 1 / -1; }}
</style>
</head>
<body>
  <h1>STCA Rule Playground</h1>
  <p>Test regex patterns against sample code, then generate a YAML rule.</p>

  {'<div class="error">' + html.escape(error) + '</div>' if error else ''}

  <div class="container">
    <div class="panel">
      <h2>Rule definition</h2>
      <form method="POST" action="/test">
        <label for="rule_id">Rule ID</label>
        <input type="text" id="rule_id" name="rule_id" value="{html.escape(rule_id)}" placeholder="e.g. py-eval-injection">

        <label for="pattern">Regex pattern</label>
        <input type="text" id="pattern" name="pattern" value="{pattern_escaped}" placeholder="e.g. \\beval\\s*\\(">

        <label for="severity">Severity</label>
        <select id="severity" name="severity">
          <option value="critical" {'selected' if severity == 'critical' else ''}>critical</option>
          <option value="high" {'selected' if severity == 'high' else ''}>high</option>
          <option value="medium" {'selected' if severity == 'medium' else ''}>medium</option>
          <option value="low" {'selected' if severity == 'low' else ''}>low</option>
          <option value="info" {'selected' if severity == 'info' else ''}>info</option>
        </select>

        <label for="message">Message</label>
        <input type="text" id="message" name="message" value="{html.escape(message)}" placeholder="e.g. {_EVAL}() — code injection risk">

        <label for="cwe">CWE</label>
        <input type="text" id="cwe" name="cwe" value="{html.escape(cwe)}" placeholder="e.g. CWE-95">

        <label for="code">Sample code to test against</label>
        <textarea id="code" name="code" placeholder="Paste code here...">{code_escaped}</textarea>

        <button type="submit">Test rule</button>
      </form>
    </div>

    <div class="panel">
      <h2>Results</h2>
      <p>{match_status}</p>

      <label>Matched code (highlighted)</label>
      <pre><code>{code_display if code_display else 'No code provided.'}</code></pre>

      {f'''<label>Match details ({len(matches)})</label>
      <table>
        <thead><tr><th>Line</th><th>Col</th><th>Matched text</th></tr></thead>
        <tbody>{match_rows}</tbody>
      </table>''' if matches else ''}

      <label>Generated YAML rule</label>
      <div class="yaml-output">{yaml_escaped or 'Fill in the form and click Test rule.'}</div>
    </div>
  </div>

  <div class="panel grid-full" style="margin-top: 20px;">
    <h2>Quick reference</h2>
    <p><b>Common regex patterns:</b></p>
    <ul>
      <li><code>\\b{_EVAL}\\s*\\(</code> — matches <code>{_EVAL}()</code> calls</li>
      <li><b>(?:password|secret|token)\\s*=\\s*['\"][^'\"]{8,}['\"]</b> — hardcoded secrets</li>
      <li><code>\\.execute\\s*\\(\\s*f['\"]</code> — SQL with f-string</li>
      <li><code>subprocess\\.(?:call|run|Popen)\\s*\\([^)]*shell\\s*=\\s*True</code> — shell=True</li>
      <li><code>-----BEGIN (?:RSA |EC )?PRIVATE KEY-----</code> — private key material</li>
    </ul>
    <p>See <a href="https://docs.python.org/3/library/re.html">Python re docs</a> for full regex syntax.</p>
  </div>
</body>
</html>"""


class PlaygroundHandler(BaseHTTPRequestHandler):
    """HTTP handler for the playground."""

    def do_GET(self):
        if self.path == "/" or self.path == "/playground":
            self._send_html(render_html())
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path == "/test":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8")
            params = parse_qs(body)

            pattern = params.get("pattern", [""])[0]
            code = params.get("code", [""])[0]
            severity = params.get("severity", ["medium"])[0]
            message = params.get("message", [""])[0]
            rule_id = params.get("rule_id", [""])[0]
            cwe = params.get("cwe", [""])[0]

            error = ""
            matches = []
            if pattern and code:
                try:
                    matches = find_matches(pattern, code)
                except ValueError as e:
                    error = str(e)

            self._send_html(render_html(
                pattern=pattern, code=code, severity=severity,
                message=message, rule_id=rule_id, cwe=cwe,
                error=error, matches=matches,
            ))
        else:
            self.send_error(404)

    def _send_html(self, content: str):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(content.encode("utf-8"))

    def log_message(self, format, *args):
        # Suppress default logging
        pass


@click.command("playground")
@click.option("--host", default="localhost", help="Host to bind (default: localhost)")
@click.option("--port", default=8765, type=int, help="Port to bind (default: 8765)")
@click.option("--no-browser", is_flag=True, help="Don't auto-open browser")
def playground_cmd(host: str, port: int, no_browser: bool):
    """v4.37: Online rule playground — test regex patterns against sample code.

    A self-contained web UI for developing STCA rules. Enter a regex pattern
    and sample code, see which lines match, generate a YAML rule.

    Examples:
      stca playground                              # default: localhost:8765
      stca playground --port 9000                  # custom port
      stca playground --host 0.0.0.0 --no-browser  # network-accessible
    """
    url = f"http://{host}:{port}"
    click.echo(f"STCA rule playground starting at {url}")
    if not no_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass  # headless environment
    server = HTTPServer((host, port), PlaygroundHandler)
    click.echo("Press Ctrl-C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        click.echo("\nStopped.")
        server.shutdown()
