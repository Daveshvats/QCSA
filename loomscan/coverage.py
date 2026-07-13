"""Code coverage integration — parse coverage reports and track trends.

Supports:
  - Python: coverage.py JSON reports (`.coverage` → `coverage.json`)
  - Java: JaCoCo XML reports (`jacoco.xml`)
  - JavaScript/TypeScript: Istanbul/nyc JSON reports (`coverage/coverage-final.json`)
  - Go: `go test -coverprofile=coverage.out`

What this module does:
  1. Parses coverage reports into a unified format
  2. Tracks coverage % per file over time (in `.loomscan-coverage-history.json`)
  3. Flags files whose coverage dropped since last run
  4. Flags changed files (in the diff) that have <N% coverage
  5. Integrates with the FIS — low-coverage findings get higher severity
     (because uncovered code is riskier to change)

This is the SonarQube-equivalent coverage feature, but as a CLI tool.
"""
from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field


COVERAGE_HISTORY_FILE = ".loomscan-coverage-history.json"


@dataclass
class FileCoverage:
    """Coverage for a single file."""
    file: str
    line_rate: float  # 0..1
    branch_rate: float  # 0..1, or 0 if not measured
    lines_covered: int = 0
    lines_total: int = 0
    uncovered_lines: List[int] = field(default_factory=list)


@dataclass
class CoverageReport:
    """A parsed coverage report."""
    tool: str  # 'coverage.py' | 'jacoco' | 'istanbul' | 'go'
    files: Dict[str, FileCoverage] = field(default_factory=dict)
    overall_line_rate: float = 0.0
    overall_branch_rate: float = 0.0
    timestamp: str = ""

    @property
    def overall_line_pct(self) -> float:
        return self.overall_line_rate * 100


def parse_coverage_py(report_path: Path) -> Optional[CoverageReport]:
    """Parse a coverage.py JSON report."""
    if not report_path.exists():
        return None
    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
    except Exception:
        return None
    report = CoverageReport(tool="coverage.py", timestamp=datetime.now().isoformat())
    for file, file_data in data.get("files", {}).items():
        summary = file_data.get("summary", {})
        uncovered = []
        # parse missing_lines
        for entry in file_data.get("missing_lines", []):
            if isinstance(entry, list):
                uncovered.extend(range(entry[0], entry[1] + 1))
            elif isinstance(entry, int):
                uncovered.append(entry)
        fc = FileCoverage(
            file=file,
            line_rate=summary.get("percent_covered", 0) / 100,
            branch_rate=summary.get("covered_branches", 0) / max(summary.get("num_branches", 1), 1),
            lines_covered=summary.get("covered_lines", 0),
            lines_total=summary.get("num_statements", 0),
            uncovered_lines=uncovered,
        )
        report.files[file] = fc
    totals = data.get("totals", {})
    report.overall_line_rate = totals.get("percent_covered", 0) / 100
    report.overall_branch_rate = totals.get("covered_branches", 0) / max(totals.get("num_branches", 1), 1)
    return report


def parse_jacoco(report_path: Path) -> Optional[CoverageReport]:
    """Parse a JaCoCo XML report."""
    if not report_path.exists():
        return None
    try:
        tree = ET.parse(report_path)
    except Exception:
        return None
    root = tree.getroot()
    report = CoverageReport(tool="jacoco", timestamp=datetime.now().isoformat())
    for pkg in root.findall("package"):
        pkg_name = pkg.get("name", "")
        for sf in pkg.findall("sourcefile"):
            file_name = sf.get("name", "")
            file_path = f"{pkg_name}/{file_name}" if pkg_name else file_name
            line_counter = sf.find("counter[@type='LINE']")
            branch_counter = sf.find("counter[@type='BRANCH']")
            line_rate = 0.0
            branch_rate = 0.0
            lines_covered = 0
            lines_total = 0
            if line_counter is not None:
                covered = int(line_counter.get("covered", 0))
                missed = int(line_counter.get("missed", 0))
                lines_total = covered + missed
                lines_covered = covered
                line_rate = covered / lines_total if lines_total > 0 else 0.0
            if branch_counter is not None:
                covered = int(branch_counter.get("covered", 0))
                missed = int(branch_counter.get("missed", 0))
                total = covered + missed
                branch_rate = covered / total if total > 0 else 0.0
            # collect uncovered lines
            uncovered = []
            for line in sf.findall("line"):
                if line.get("mi", "0") != "0" and line.get("ci", "0") == "0":
                    uncovered.append(int(line.get("nr", 0)))
            report.files[file_path] = FileCoverage(
                file=file_path, line_rate=line_rate, branch_rate=branch_rate,
                lines_covered=lines_covered, lines_total=lines_total,
                uncovered_lines=uncovered,
            )
    # overall
    line_counter = root.find("counter[@type='LINE']")
    branch_counter = root.find("counter[@type='BRANCH']")
    if line_counter is not None:
        covered = int(line_counter.get("covered", 0))
        missed = int(line_counter.get("missed", 0))
        total = covered + missed
        report.overall_line_rate = covered / total if total > 0 else 0.0
    if branch_counter is not None:
        covered = int(branch_counter.get("covered", 0))
        missed = int(branch_counter.get("missed", 0))
        total = covered + missed
        report.overall_branch_rate = covered / total if total > 0 else 0.0
    return report


def parse_istanbul(report_path: Path) -> Optional[CoverageReport]:
    """Parse an Istanbul/nyc JSON report (coverage-final.json)."""
    if not report_path.exists():
        return None
    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
    except Exception:
        return None
    report = CoverageReport(tool="istanbul", timestamp=datetime.now().isoformat())
    total_covered = 0
    total_statements = 0
    for file_path, file_data in data.items():
        s = file_data.get("s", {})  # statement counts
        total = sum(s.values())
        covered = sum(1 for v in s.values() if v > 0)
        line_rate = covered / len(s) if s else 0.0
        b = file_data.get("b", {})  # branch counts
        branch_total = sum(len(v) for v in b.values())
        branch_covered = sum(1 for v in b.values() for x in v if x > 0)
        branch_rate = branch_covered / branch_total if branch_total > 0 else 0.0
        # collect uncovered statement lines
        uncovered = []
        statement_map = file_data.get("statementMap", {})
        for sid, count in s.items():
            if count == 0 and sid in statement_map:
                loc = statement_map[sid]
                uncovered.append(loc.get("start", {}).get("line", 0))
        report.files[file_path] = FileCoverage(
            file=file_path, line_rate=line_rate, branch_rate=branch_rate,
            lines_covered=covered, lines_total=len(s),
            uncovered_lines=uncovered,
        )
        total_covered += covered
        total_statements += len(s)
    report.overall_line_rate = total_covered / total_statements if total_statements > 0 else 0.0
    return report


def parse_go_coverage(report_path: Path) -> Optional[CoverageReport]:
    """Parse a Go coverage profile (coverage.out)."""
    if not report_path.exists():
        return None
    report = CoverageReport(tool="go", timestamp=datetime.now().isoformat())
    file_data: Dict[str, Tuple[int, int]] = {}  # file → (covered, total)
    try:
        for line in report_path.read_text(encoding="utf-8").splitlines():
            # format: file:startLine.startCol,endLine.endCol numStmts count
            parts = line.split(":")
            if len(parts) != 2:
                continue
            file = parts[0]
            if file == "mode":
                continue
            rest = parts[1].split()
            if len(rest) < 3:
                continue
            num_stmts = int(rest[1])
            count = int(rest[2])
            covered, total = file_data.get(file, (0, 0))
            total += num_stmts
            if count > 0:
                covered += num_stmts
            file_data[file] = (covered, total)
    except Exception:
        return None
    total_covered = 0
    total_total = 0
    for file, (covered, total) in file_data.items():
        report.files[file] = FileCoverage(
            file=file, line_rate=covered / total if total > 0 else 0,
            branch_rate=0, lines_covered=covered, lines_total=total,
        )
        total_covered += covered
        total_total += total
    report.overall_line_rate = total_covered / total_total if total_total > 0 else 0
    return report


def find_coverage_report(repo_root: Path) -> Optional[CoverageReport]:
    """Auto-discover and parse a coverage report in the repo."""
    candidates = [
        (repo_root / "coverage.json", parse_coverage_py),
        (repo_root / ".coverage.json", parse_coverage_py),
        (repo_root / "target" / "site" / "jacoco" / "jacoco.xml", parse_jacoco),
        (repo_root / "jacoco.xml", parse_jacoco),
        (repo_root / "coverage" / "coverage-final.json", parse_istanbul),
        (repo_root / ".nyc_output" / "coverage-final.json", parse_istanbul),
        (repo_root / "coverage.out", parse_go_coverage),
        (repo_root / "coverage.txt", parse_go_coverage),
    ]
    for path, parser in candidates:
        if path.exists():
            report = parser(path)
            if report:
                return report
    return None


def track_coverage_history(repo_root: Path,
                            report: CoverageReport) -> Dict[str, float]:
    """Track coverage per file over time. Returns files with coverage drops.

    Returns: {file: drop_percentage} for files that dropped >5%.
    """
    history_file = repo_root / COVERAGE_HISTORY_FILE
    history: Dict = {}
    if history_file.exists():
        try:
            history = json.loads(history_file.read_text(encoding="utf-8"))
        except Exception:
            history = {}

    drops: Dict[str, float] = {}
    now = datetime.now().isoformat()
    history.setdefault("files", {})
    for file, fc in report.files.items():
        prev_rate = history["files"].get(file, {}).get("line_rate")
        history["files"][file] = {
            "line_rate": fc.line_rate,
            "branch_rate": fc.branch_rate,
            "last_updated": now,
        }
        if prev_rate is not None:
            drop = prev_rate - fc.line_rate
            if drop > 0.05:  # 5% drop
                drops[file] = drop

    history["last_scan"] = now
    history["overall_line_rate"] = report.overall_line_rate
    history_file.write_text(json.dumps(history, indent=2), encoding="utf-8")
    return drops


def coverage_summary(repo_root: Path) -> dict:
    """Get a coverage summary for the repo."""
    report = find_coverage_report(repo_root)
    if not report:
        return {"available": False, "message": "No coverage report found. Run your test suite with coverage enabled."}
    return {
        "available": True,
        "tool": report.tool,
        "overall_line_coverage": f"{report.overall_line_rate * 100:.1f}%",
        "overall_branch_coverage": f"{report.overall_branch_rate * 100:.1f}%",
        "files_with_coverage": len(report.files),
        "timestamp": report.timestamp,
    }
