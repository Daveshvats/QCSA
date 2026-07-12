"""HTML dashboard generator — self-contained single-file dashboard.

Renders:
  - summary cards (total findings, by severity, by decision)
  - severity pie chart (ECharts)
  - category bar chart (ECharts)
  - top files / top rules tables
  - filterable findings table (with JS)

Uses ECharts via CDN — the file is self-contained HTML but requires an
internet connection to render charts. Falls back to text tables offline.
"""
from __future__ import annotations

import html
import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


_SEV_COLOR = {
    "critical": "#dc2626",
    "high":     "#ea580c",
    "medium":   "#ca8a04",
    "low":      "#2563eb",
    "info":     "#6b7280",
}

_SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def _escape(s: Any) -> str:
    return html.escape(str(s or ""))


def _norm_findings(findings_json: Optional[Any]) -> List[dict]:
    """Normalize findings from a PipelineResult.to_dict() payload or a raw list."""
    if not findings_json:
        return []
    if isinstance(findings_json, dict):
        # PipelineResult.to_dict()
        findings = findings_json.get("findings", [])
    elif isinstance(findings_json, list):
        findings = findings_json
    else:
        return []
    out: List[dict] = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        # accept either Finding.to_dict() or flat finding dicts
        sev = f.get("severity", "medium")
        if hasattr(sev, "value"):
            sev = sev.value
        out.append({
            "rule_id":   f.get("rule_id", ""),
            "file":      f.get("file", ""),
            "line":      f.get("start_line") or f.get("line", 0),
            "severity":  sev,
            "category":  f.get("category", "correctness"),
            "confidence": float(f.get("confidence", 0.5)),
            "message":   f.get("message") or f.get("description", ""),
            "cwe":       f.get("cwe", ""),
            "layer":     f.get("layer", ""),
        })
    return out


def generate_dashboard(repo_root: Path, out_path: Path,
                        findings_json: Optional[Any] = None,
                        title: Optional[str] = None) -> Path:
    """Generate a self-contained HTML dashboard.

    Args:
        repo_root:        repository root (used for title and relative paths)
        out_path:         where to write the HTML file
        findings_json:    optional PipelineResult.to_dict() payload or list of findings.
                          If None, runs a quick scan (crypto + modern_attacks) for demo.
    Returns:
        The Path to the written file.
    """
    findings = _norm_findings(findings_json)
    if findings_json is None:
        # demo: light scan so the dashboard isn't empty
        try:
            from .. import crypto_audit, modern_attacks
            for cf in crypto_audit.analyze_repo_crypto(repo_root)[:200]:
                findings.append({
                    "rule_id": cf.rule_id, "file": cf.file, "line": cf.line,
                    "severity": cf.severity, "category": "security",
                    "confidence": cf.confidence, "message": cf.description,
                    "cwe": cf.cwe, "layer": "L0"})
            for mf in modern_attacks.scan_repo_modern_attacks(repo_root)[:200]:
                findings.append({
                    "rule_id": mf.rule_id, "file": mf.file, "line": mf.line,
                    "severity": mf.severity, "category": mf.category,
                    "confidence": mf.confidence, "message": mf.description,
                    "cwe": mf.cwe, "layer": "L0"})
        except Exception:
            pass

    by_sev = Counter(f["severity"] for f in findings)
    by_cat = Counter(f["category"] for f in findings)
    by_rule = Counter(f["rule_id"] for f in findings)
    by_file = Counter(f["file"] for f in findings)

    total = len(findings)
    critical = by_sev.get("critical", 0)
    high = by_sev.get("high", 0)

    title = title or f"STCA Dashboard — {repo_root.name}"

    # ----- severity pie data -----
    sev_data = [{"name": s, "value": by_sev.get(s, 0), "itemStyle": {"color": _SEV_COLOR[s]}}
                 for s in _SEV_ORDER if by_sev.get(s, 0) > 0]
    # ----- category bar data -----
    cat_names = sorted(by_cat.keys())
    cat_values = [by_cat[c] for c in cat_names]
    # ----- top files / rules -----
    top_files = by_file.most_common(10)
    top_rules = by_rule.most_common(10)

    # ----- findings rows HTML -----
    rows_html_parts: List[str] = []
    for i, f in enumerate(findings):
        sev = f["severity"]
        color = _SEV_COLOR.get(sev, "#6b7280")
        rows_html_parts.append(
            "<tr data-sev=\"" + sev + "\" data-cat=\"" + _escape(f["category"]) + "\" "
            "data-file=\"" + _escape(f["file"]) + "\" data-rule=\"" + _escape(f["rule_id"]) + "\">"
            f"<td>{i+1}</td>"
            f"<td><span class=\"badge\" style=\"background:{color}\">{sev.upper()}</span></td>"
            f"<td>{_escape(f['rule_id'])}</td>"
            f"<td>{_escape(f['category'])}</td>"
            f"<td class=\"mono\">{_escape(f['file'])}:{f['line']}</td>"
            f"<td>{_escape(f['message'])[:200]}</td>"
            f"<td>{f['confidence']*100:.0f}%</td>"
            f"<td>{_escape(f['cwe'])}</td>"
            "</tr>"
        )
    rows_html = "\n".join(rows_html_parts)

    top_files_rows = "\n".join(
        f"<tr><td class='mono'>{_escape(f)}</td><td>{c}</td></tr>"
        for f, c in top_files
    ) or "<tr><td colspan='2'>No findings</td></tr>"

    top_rules_rows = "\n".join(
        f"<tr><td class='mono'>{_escape(r)}</td><td>{c}</td></tr>"
        for r, c in top_rules
    ) or "<tr><td colspan='2'>No findings</td></tr>"

    summary_cards = f"""
    <div class="card"><div class="small">Total findings</div><div class="big">{total}</div></div>
    <div class="card"><div class="small">Critical</div><div class="big" style="color:{_SEV_COLOR['critical']}">{critical}</div></div>
    <div class="card"><div class="small">High</div><div class="big" style="color:{_SEV_COLOR['high']}">{high}</div></div>
    <div class="card"><div class="small">Medium</div><div class="big" style="color:{_SEV_COLOR['medium']}">{by_sev.get('medium',0)}</div></div>
    <div class="card"><div class="small">Low</div><div class="big" style="color:{_SEV_COLOR['low']}">{by_sev.get('low',0)}</div></div>
    <div class="card"><div class="small">Info</div><div class="big" style="color:{_SEV_COLOR['info']}">{by_sev.get('info',0)}</div></div>
    """

    payload_json = json.dumps({
        "sev_data": sev_data,
        "cat_names": cat_names,
        "cat_values": cat_values,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "repo": str(repo_root),
        "total": total,
    })

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>{_escape(title)}</title>
  <script src="https://cdn.jsdelivr.net/npm/echarts@5.4.3/dist/echarts.min.js"></script>
  <style>
    body {{ font-family: -apple-system, "Segoe UI", Roboto, sans-serif; margin: 1.5em; background: #fafafa; color: #111; }}
    h1, h2, h3 {{ color: #111; }}
    .header {{ display: flex; justify-content: space-between; align-items: center;
               padding: 1em 1.5em; border-radius: 8px; color: white;
               background: linear-gradient(135deg, #1e293b, #475569); margin-bottom: 1em; }}
    .summary {{ display: flex; gap: 1em; margin: 1em 0; flex-wrap: wrap; }}
    .card {{ background: white; padding: 1em 1.5em; border-radius: 8px;
             box-shadow: 0 1px 3px rgba(0,0,0,0.1); min-width: 120px; text-align: center; }}
    .big {{ font-size: 2em; font-weight: 700; margin-top: 4px; }}
    .small {{ font-size: 0.85em; color: #6b7280; text-transform: uppercase; letter-spacing: 0.04em; }}
    .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px;
              color: white; font-size: 0.85em; font-weight: 600; }}
    .grid {{ display: grid; grid-template-columns: 1fr 2fr; gap: 1em; margin: 1em 0; }}
    .chart {{ background: white; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);
              padding: 1em; min-height: 320px; }}
    table {{ width: 100%; border-collapse: collapse; background: white;
             box-shadow: 0 1px 3px rgba(0,0,0,0.1); border-radius: 8px; overflow: hidden; }}
    th, td {{ padding: 6px 10px; text-align: left; border-bottom: 1px solid #eee; font-size: 0.85em; }}
    th {{ background: #f3f4f6; font-weight: 600; }}
    .mono {{ font-family: "SF Mono", Monaco, monospace; font-size: 0.85em; color: #4b5563; }}
    .filters {{ display: flex; gap: 0.5em; margin: 1em 0; flex-wrap: wrap; align-items: center; }}
    .filters input, .filters select {{ padding: 6px 10px; border: 1px solid #d1d5db; border-radius: 6px; font-size: 0.85em; }}
    .filters label {{ font-size: 0.85em; color: #6b7280; }}
  </style>
</head>
<body>
  <div class="header">
    <h1>{_escape(title)}</h1>
    <div style="text-align: right;">
      <div style="font-size: 1.4em; font-weight: 700;">{total} findings</div>
      <div class="small">{datetime.now().isoformat(timespec='seconds')}</div>
    </div>
  </div>

  <div class="summary">{summary_cards}</div>

  <div class="grid">
    <div id="sev-pie" class="chart"></div>
    <div id="cat-bar" class="chart"></div>
  </div>

  <h2>Top Files</h2>
  <table><thead><tr><th>File</th><th>Findings</th></tr></thead><tbody>{top_files_rows}</tbody></table>

  <h2>Top Rules</h2>
  <table><thead><tr><th>Rule ID</th><th>Count</th></tr></thead><tbody>{top_rules_rows}</tbody></table>

  <h2>All Findings</h2>
  <div class="filters">
    <label>Severity:
      <select id="f-sev">
        <option value="">all</option>
        <option value="critical">critical</option>
        <option value="high">high</option>
        <option value="medium">medium</option>
        <option value="low">low</option>
        <option value="info">info</option>
      </select>
    </label>
    <label>Category:
      <select id="f-cat">
        <option value="">all</option>
        {''.join(f'<option value="{c}">{c}</option>' for c in cat_names)}
      </select>
    </label>
    <label>Search:
      <input type="text" id="f-search" placeholder="file / rule / message">
    </label>
    <span class="small" id="f-count">{total} rows</span>
  </div>
  <table id="findings-table">
    <thead>
      <tr><th>#</th><th>Sev</th><th>Rule</th><th>Category</th><th>File:Line</th><th>Message</th><th>Conf</th><th>CWE</th></tr>
    </thead>
    <tbody>{rows_html or '<tr><td colspan="8">No findings</td></tr>'}</tbody>
  </table>

  <p class="small" style="margin-top: 2em;">Generated by STCA Pipeline — deterministic-first, type-2 fuzzy aggregated.</p>

  <script>
    var payload = {payload_json};

    // Severity pie
    var sevChart = echarts.init(document.getElementById('sev-pie'));
    sevChart.setOption({{
      title: {{ text: 'Findings by Severity', left: 'center' }},
      tooltip: {{ trigger: 'item' }},
      series: [{{ type: 'pie', radius: ['40%', '70%'], data: payload.sev_data,
                  label: {{ formatter: '{{b}}: {{c}}' }} }}]
    }});

    // Category bar
    var catChart = echarts.init(document.getElementById('cat-bar'));
    catChart.setOption({{
      title: {{ text: 'Findings by Category', left: 'center' }},
      tooltip: {{ trigger: 'axis' }},
      xAxis: {{ type: 'category', data: payload.cat_names, axisLabel: {{ rotate: 30 }} }},
      yAxis: {{ type: 'value' }},
      series: [{{ type: 'bar', data: payload.cat_values,
                  itemStyle: {{ color: '#4f46e5' }} }}]
    }});

    // Filter
    var rows = document.querySelectorAll('#findings-table tbody tr');
    function applyFilters() {{
      var sev = document.getElementById('f-sev').value;
      var cat = document.getElementById('f-cat').value;
      var q = document.getElementById('f-search').value.toLowerCase();
      var visible = 0;
      rows.forEach(function(r) {{
        var matchSev = !sev || r.getAttribute('data-sev') === sev;
        var matchCat = !cat || r.getAttribute('data-cat') === cat;
        var matchQ = !q || r.textContent.toLowerCase().indexOf(q) >= 0;
        if (matchSev && matchCat && matchQ) {{ r.style.display = ''; visible++; }}
        else {{ r.style.display = 'none'; }}
      }});
      document.getElementById('f-count').textContent = visible + ' rows';
    }}
    document.getElementById('f-sev').addEventListener('change', applyFilters);
    document.getElementById('f-cat').addEventListener('change', applyFilters);
    document.getElementById('f-search').addEventListener('input', applyFilters);
    window.addEventListener('resize', function() {{
      sevChart.resize(); catChart.resize();
    }});
  </script>
</body>
</html>"""

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(page, encoding="utf-8")
    return out_path
