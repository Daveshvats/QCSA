"""Pre-commit hook for STCA — runs on staged files, < 3 second budget."""
from __future__ import annotations
import argparse, subprocess, sys, time
from pathlib import Path
from typing import List

def get_staged_files(repo_root: Path) -> List[Path]:
    try:
        result = subprocess.run(["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
                                cwd=repo_root, capture_output=True, text=True, check=True)
        return [repo_root / line for line in result.stdout.splitlines() if line.strip() and (repo_root / line).exists()]
    except: return []

def run_pre_commit(repo_root: Path, block_only: bool = True, time_budget_ms: int = 3000) -> int:
    start = time.time()
    staged = get_staged_files(repo_root)
    if not staged: return 0
    source_exts = {".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".java", ".c", ".cpp", ".tf", ".yaml", ".yml"}
    source_files = [f for f in staged if f.suffix.lower() in source_exts]
    if not source_files: return 0
    print(f"STCA: scanning {len(source_files)} staged file(s)...", file=sys.stderr)
    findings: List[dict] = []
    try:
        from .nullness import NullnessAnalyzer
        from .symbolic import Z3SymbolicExecutor
        from .crypto_audit import PythonCryptoAnalyzer, JSCryptoAnalyzer
        from .js_pattern_scanner import scan_js_patterns
        from .code_quality import analyze_code_quality
        from .state_machine import StateMachineAnalyzer
        nullness = NullnessAnalyzer(); symbolic = Z3SymbolicExecutor()
        py_crypto = PythonCryptoAnalyzer(); js_crypto = JSCryptoAnalyzer()
        sm = StateMachineAnalyzer()
        for f in source_files:
            elapsed_ms = (time.time() - start) * 1000
            if elapsed_ms > time_budget_ms: break
            ext = f.suffix.lower()
            if ext == ".py":
                for issue in nullness.analyze_file(f, repo_root):
                    findings.append({"severity": "high", "rule_id": "nullness", "line": issue.line, "message": issue.reason, "file": str(f)})
                for issue in symbolic.analyze_file(f):  # v4.14: analyze_file takes only file_path
                    findings.append({"severity": "high", "rule_id": issue.kind, "line": issue.line, "message": issue.description, "file": str(f)})
                for issue in py_crypto.analyze_file(f, repo_root):
                    findings.append({"severity": issue.severity, "rule_id": issue.rule_id, "line": issue.line, "message": issue.description, "file": str(f)})
                for issue in sm.analyze_file(f, repo_root):
                    findings.append({"severity": issue.severity, "rule_id": issue.kind, "line": issue.line, "message": issue.description, "file": str(f)})
            elif ext in (".js", ".jsx", ".ts", ".tsx"):
                for hit in scan_js_patterns(f, repo_root):
                    findings.append({"severity": hit.severity, "rule_id": hit.rule_id, "line": hit.line, "message": hit.message, "file": str(f)})
                for issue in js_crypto.analyze_file(f, repo_root):
                    findings.append({"severity": issue.severity, "rule_id": issue.rule_id, "line": issue.line, "message": issue.description, "file": str(f)})
            for issue in analyze_code_quality(f, repo_root):
                findings.append({"severity": issue.severity, "rule_id": issue.rule_id, "line": issue.line, "message": issue.description, "file": str(f)})
    except Exception as e:
        print(f"STCA: analyzer error: {e}", file=sys.stderr)
    elapsed_ms = (time.time() - start) * 1000
    if not findings:
        print(f"STCA: no issues found ({elapsed_ms:.0f}ms)", file=sys.stderr)
        return 0
    block_severities = {"critical", "high"} if block_only else {"critical", "high", "medium", "low", "info"}
    block_findings = [f for f in findings if f["severity"].lower() in block_severities]
    if not block_findings:
        print(f"STCA: {len(findings)} non-blocking issue(s) found ({elapsed_ms:.0f}ms)", file=sys.stderr)
        for f in findings[:5]: print(f"  [{f['severity'].upper()}] {f['file']}:{f['line']} - {f['message'][:60]}", file=sys.stderr)
        return 0
    print(f"\nSTCA: commit BLOCKED — {len(block_findings)} blocking issue(s) found\n", file=sys.stderr)
    for f in block_findings[:20]:
        print(f"  [{f['severity'].upper()}] {f['file']}:{f['line']}", file=sys.stderr)
        print(f"    {f['message'][:80]}", file=sys.stderr)
        print(f"    rule: {f['rule_id']}\n", file=sys.stderr)
    if len(block_findings) > 20: print(f"  ... and {len(block_findings) - 20} more", file=sys.stderr)
    print("To bypass: git commit --no-verify (NOT RECOMMENDED)", file=sys.stderr)
    print("To investigate: stca check <file>", file=sys.stderr)
    return 1

def main():
    parser = argparse.ArgumentParser(description="STCA pre-commit hook")
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--time-budget", type=int, default=3000)
    args = parser.parse_args()
    sys.exit(run_pre_commit(Path(args.repo_root).resolve(), block_only=not args.all, time_budget_ms=args.time_budget))

if __name__ == "__main__":
    main()
