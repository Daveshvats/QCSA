"""v4.37: PR comment bot — post STCA findings as GitHub PR review comments.

Reads the GitHub Actions event payload, runs STCA on the PR diff, and
posts findings as inline review comments via the GitHub API.

Usage (in GitHub Actions):
    stca bot --repo $GITHUB_WORKSPACE --pr ${{ github.event.pull_request.number }} \
            --token ${{ secrets.GITHUB_TOKEN }} --event $GITHUB_EVENT_PATH

The bot:
  1. Parses the PR event payload to get the PR number, head SHA, and diff
  2. Runs `stca check` on the PR diff (diff-aware — only new findings)
  3. Groups findings by file
  4. Posts a PR review with inline comments at each finding's line
  5. Posts a summary comment with the count by severity
  6. Sets the review status: APPROVED (0 findings), COMMENTED (1+), REQUEST_CHANGES (critical)

Exit codes:
  0 = bot ran successfully
  1 = bot ran, found blocking findings (critical/high)
  2 = bot error (bad config, API failure)
"""
from __future__ import annotations

import json
import os
import sys
import subprocess
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass

import click


@dataclass
class Finding:
    rule_id: str
    file: str
    line: int
    severity: str
    message: str
    confidence: float


def run_stca_check(repo_root: Path, base: str = "origin/main") -> List[Finding]:
    """Run `stca check --json` and parse findings."""
    env = os.environ.copy()
    env["PYTHONPATH"] = str(repo_root) + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run(
        [sys.executable, "-c", "from stca.cli import main; main()",
         "check", "--base", base, "--json"],
        cwd=repo_root, capture_output=True, text=True, env=env, timeout=300,
    )
    if proc.returncode not in (0, 1):
        raise RuntimeError(f"stca check failed (exit {proc.returncode}): {proc.stderr}")
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"stca check returned invalid JSON: {e}") from e
    findings = []
    for f in data.get("findings", []):
        findings.append(Finding(
            rule_id=f.get("rule_id", ""),
            file=f.get("file", ""),
            line=f.get("start_line", 1),
            severity=f.get("severity", "medium"),
            message=f.get("message", ""),
            confidence=f.get("confidence", 0.0),
        ))
    return findings


def post_pr_review(
    repo_owner: str,
    repo_name: str,
    pr_number: int,
    head_sha: str,
    findings: List[Finding],
    github_token: str,
    event_name: str,
) -> Dict:
    """Post a PR review with inline comments via the GitHub API.

    Returns the API response.
    """
    import urllib.request
    import urllib.error

    api_base = f"https://api.github.com/repos/{repo_owner}/{repo_name}/pulls/{pr_number}/reviews"

    # Group findings by file
    by_file: Dict[str, List[Finding]] = {}
    for f in findings:
        by_file.setdefault(f.file, []).append(f)

    # Build inline comments (GitHub review comments API)
    comments = []
    for file, file_findings in by_file.items():
        for f in file_findings:
            comments.append({
                "path": file,
                "line": f.line,
                "side": "RIGHT",
                "body": f"**STCA {f.severity.upper()}** — `{f.rule_id}`\n\n{f.message}\n\n_Confidence: {f.confidence:.0%}_",
            })

    # Determine review event: APPROVE / COMMENT / REQUEST_CHANGES
    has_critical = any(f.severity.lower() == "critical" for f in findings)
    has_high = any(f.severity.lower() == "high" for f in findings)

    if not findings:
        event = "APPROVE"
        body = "STCA found no issues in this PR."
    elif has_critical or has_high:
        event = "REQUEST_CHANGES"
        body = f"STCA found {len(findings)} issue(s) in this PR, including critical/high severity. Please address them before merging."
    else:
        event = "COMMENT"
        body = f"STCA found {len(findings)} issue(s) in this PR (medium/low severity)."

    # Add summary by severity
    sev_counts = {}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
    if sev_counts:
        body += "\n\n### Summary by severity\n"
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in sev_counts:
                body += f"- **{sev}**: {sev_counts[sev]}\n"

    # Cap at 50 inline comments (GitHub API limit per review)
    capped_comments = comments[:50]
    if len(comments) > 50:
        body += f"\n\n_(Showing 50 of {len(comments)} inline comments — see full report in the STCA action run.)_"

    payload = {
        "commit_id": head_sha,
        "body": body,
        "event": event,
        "comments": capped_comments,
    }

    req = urllib.request.Request(
        api_base,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {github_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8") if e.fp else ""
        raise RuntimeError(f"GitHub API error {e.code}: {error_body}") from e


def parse_pr_event(event_path: Path) -> Dict:
    """Parse the GitHub Actions event payload to extract PR info."""
    with open(event_path) as f:
        event = json.load(f)
    pr = event.get("pull_request", {})
    return {
        "pr_number": pr.get("number"),
        "head_sha": pr.get("head", {}).get("sha"),
        "repo_owner": event.get("repository", {}).get("owner", {}).get("login"),
        "repo_name": event.get("repository", {}).get("name"),
        "base_ref": pr.get("base", {}).get("ref", "main"),
    }


@click.command("bot")
@click.option("--repo", default=".", help="Repository root")
@click.option("--pr", "pr_number", type=int, help="PR number (defaults to event payload)")
@click.option("--token", help="GitHub token (defaults to GITHUB_TOKEN env var)")
@click.option("--event", "event_path", help="Path to GitHub event payload (defaults to GITHUB_EVENT_PATH)")
@click.option("--dry-run", is_flag=True, help="Don't post comments, just print what would be posted")
def bot_cmd(repo: str, pr_number: Optional[int], token: Optional[str],
            event_path: Optional[str], dry_run: bool):
    """v4.37: PR comment bot — post STCA findings as GitHub PR review comments.

    Reads the PR diff, runs STCA, posts inline review comments via the GitHub API.

    Examples:
      stca bot --repo . --pr 42 --token $GITHUB_TOKEN
      stca bot --dry-run          # print without posting
    """
    repo_root = Path(repo).resolve()
    github_token = token or os.environ.get("GITHUB_TOKEN")
    event_path_str = event_path or os.environ.get("GITHUB_EVENT_PATH")

    # Parse event payload if available
    pr_info = {}
    if event_path_str and Path(event_path_str).exists():
        try:
            pr_info = parse_pr_event(Path(event_path_str))
        except Exception as e:
            click.echo(f"Warning: failed to parse event payload: {e}", err=True)

    pr_num = pr_number or pr_info.get("pr_number")
    head_sha = pr_info.get("head_sha", "HEAD")
    repo_owner = pr_info.get("repo_owner", "")
    repo_name = pr_info.get("repo_name", "")
    base_ref = pr_info.get("base_ref", "origin/main")

    if not pr_num:
        click.echo("Error: PR number required (use --pr or run in GitHub Actions)", err=True)
        sys.exit(2)

    if not dry_run and not github_token:
        click.echo("Error: GitHub token required (use --token or set GITHUB_TOKEN)", err=True)
        sys.exit(2)

    click.echo(f"STCA bot — PR #{pr_num} in {repo_owner}/{repo_name}")
    click.echo(f"Running STCA check (base: {base_ref})...")

    try:
        findings = run_stca_check(repo_root, base=base_ref)
    except Exception as e:
        click.echo(f"Error: STCA check failed: {e}", err=True)
        sys.exit(2)

    click.echo(f"Found {len(findings)} findings")

    if dry_run:
        click.echo("\n=== Dry run — would post these comments ===")
        for f in findings[:10]:
            click.echo(f"  {f.severity.upper()} {f.rule_id} @ {f.file}:{f.line}")
            click.echo(f"    {f.message[:80]}")
        if len(findings) > 10:
            click.echo(f"  ... and {len(findings) - 10} more")
        return

    # Post the review
    try:
        response = post_pr_review(
            repo_owner=repo_owner,
            repo_name=repo_name,
            pr_number=pr_num,
            head_sha=head_sha,
            findings=findings,
            github_token=github_token,
            event_name="pull_request",
        )
        click.echo(f"Posted review: {response.get('html_url', 'unknown')}")
    except Exception as e:
        click.echo(f"Error: failed to post review: {e}", err=True)
        sys.exit(2)

    # Exit code based on findings
    has_blocking = any(f.severity.lower() in ("critical", "high") for f in findings)
    if has_blocking:
        click.echo("Exiting with code 1 (blocking findings found)")
        sys.exit(1)
    sys.exit(0)
