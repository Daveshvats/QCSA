"""L0e — Infrastructure as Code scanning.

Catches misconfigurations in:
  - Dockerfiles (root user, no healthcheck, :latest tag, secrets in ENV)
  - Kubernetes manifests (privileged containers, no resource limits, no liveness probe)
  - Terraform (public S3 buckets, hardcoded secrets, no encryption)
  - CloudFormation (similar patterns)
  - GitHub Actions workflows (pull_request_target, secrets in run)

If `checkov` or `kics` are installed, defer to them. Otherwise use built-in
regex-based rules — fast and zero-dependency.
"""
from __future__ import annotations

import re
import subprocess
import json
from pathlib import Path
from typing import List

from .base import LayerBase
from ..models import Finding, DiffHunk, LayerID, Severity, BlastRadius


# Built-in Dockerfile rules (used when checkov/kics aren't installed)
DOCKERFILE_RULES = [
    {
        "id": "docker-latest-tag",
        "pattern": r"FROM\s+\S+:latest",
        "msg": "Dockerfile uses :latest tag — non-reproducible builds",
        "severity": Severity.MEDIUM, "cwe": "CWE-1104",
        "fix": "Pin to a specific version, e.g. python:3.12-slim",
    },
    {
        "id": "docker-root-user",
        "pattern": r"USER\s+root\b",
        "msg": "Dockerfile runs as root — security risk",
        "severity": Severity.HIGH, "cwe": "CWE-250",
        "fix": "Add `RUN useradd -m app && USER app`",
    },
    {
        "id": "docker-no-healthcheck",
        "pattern": r"^(?!.*HEALTHCHECK).*$",  # checked at file level
        "msg": "Dockerfile missing HEALTHCHECK — orchestrator can't detect hung containers",
        "severity": Severity.LOW, "cwe": "CWE-1061",
        "fix": "Add `HEALTHCHECK CMD curl -f http://localhost:8080/health || exit 1`",
    },
    {
        "id": "docker-secret-env",
        "pattern": r"ENV\s+\w*(PASSWORD|SECRET|TOKEN|API_KEY|AWS_SECRET)\w*=",
        "msg": "Secret baked into Dockerfile ENV — use runtime secrets (Docker secrets, K8s secrets)",
        "severity": Severity.CRITICAL, "cwe": "CWE-798",
        "fix": "Mount secret at runtime, don't bake into image",
    },
    {
        "id": "docker-apt-no-cleanup",
        "pattern": r"RUN\s+apt-get\s+install",
        "msg": "apt-get install without cleanup — image bloat, use rm -rf /var/lib/apt/lists/*",
        "severity": Severity.LOW, "cwe": "CWE-400",
        "fix": "Combine RUN apt-get install ... && rm -rf /var/lib/apt/lists/*",
    },
    {
        "id": "docker-privileged-port",
        "pattern": r"EXPOSE\s+(80|443)\s*$",
        "msg": "Container exposes privileged port — needs root or CAP_NET_BIND_SERVICE",
        "severity": Severity.LOW, "cwe": "CWE-250",
        "fix": "Use port 8080/8443 inside, map to 80/443 on host",
    },
]

# Built-in Kubernetes rules (YAML)
K8S_RULES = [
    {
        "id": "k8s-privileged-container",
        "pattern": r"privileged:\s*true",
        "msg": "Privileged container — escapes pod isolation, security risk",
        "severity": Severity.CRITICAL, "cwe": "CWE-250",
        "fix": "Set privileged: false (default) or remove the field",
    },
    {
        "id": "k8s-no-resource-limits",
        "pattern": r"(?!.*resources:)(?!.*limits:).*containers:",
        "msg": "Container has no resource limits — can exhaust node resources",
        "severity": Severity.MEDIUM, "cwe": "CWE-400",
        "fix": "Add resources.limits.cpu and resources.limits.memory",
    },
    {
        "id": "k8s-run-as-root",
        "pattern": r"runAsUser:\s*0\b",
        "msg": "Pod runs as root (UID 0)",
        "severity": Severity.HIGH, "cwe": "CWE-250",
        "fix": "Set runAsUser to a non-zero UID in securityContext",
    },
    {
        "id": "k8s-no-liveness-probe",
        "pattern": r"(?!.*livenessProbe:).*containers:",
        "msg": "Container has no liveness probe — orchestrator can't detect hangs",
        "severity": Severity.LOW, "cwe": "CWE-1061",
        "fix": "Add livenessProbe to the container spec",
    },
    {
        "id": "k8s-image-latest",
        "pattern": r"image:\s*\S+:latest",
        "msg": "K8s uses :latest image tag — non-reproducible, hard to roll back",
        "severity": Severity.MEDIUM, "cwe": "CWE-1104",
        "fix": "Pin to a specific image tag or sha256 digest",
    },
    {
        "id": "k8s-host-network",
        "pattern": r"hostNetwork:\s*true",
        "msg": "hostNetwork:true — pod sees host's network interfaces",
        "severity": Severity.HIGH, "cwe": "CWE-923",
        "fix": "Remove hostNetwork or use NodePort service instead",
    },
    {
        "id": "k8s-host-pid",
        "pattern": r"hostPID:\s*true",
        "msg": "hostPID:true — pod sees host's processes",
        "severity": Severity.HIGH, "cwe": "CWE-923",
        "fix": "Remove hostPID",
    },
    {
        "id": "k8s-allow-privilege-escalation",
        "pattern": r"allowPrivilegeEscalation:\s*true",
        "msg": "allowPrivilegeEscalation:true — child process can gain more privileges than parent",
        "severity": Severity.HIGH, "cwe": "CWE-269",
        "fix": "Set allowPrivilegeEscalation: false",
    },
]

# Built-in Terraform rules
TERRAFORM_RULES = [
    {
        "id": "tf-public-s3-bucket",
        "pattern": r"acl\s*=\s*\"public-read\"",
        "msg": "S3 bucket is public-read — data exposure risk",
        "severity": Severity.CRITICAL, "cwe": "CWE-200",
        "fix": "Use acl = \"private\" and CloudFront for public access",
    },
    {
        "id": "tf-no-encryption-at-rest",
        "pattern": r"(?!.*server_side_encryption_configuration).*aws_s3_bucket",
        "msg": "S3 bucket has no server-side encryption — data at rest is unencrypted",
        "severity": Severity.HIGH, "cwe": "CWE-311",
        "fix": "Add server_side_encryption_configuration block",
    },
    {
        "id": "tf-hardcoded-secret",
        "pattern": r"(?i)(password|secret|api_key|token)\s*=\s*\"[^\"]{8,}\"",
        "msg": "Hardcoded secret in Terraform — use variables and tfvars (gitignored)",
        "severity": Severity.CRITICAL, "cwe": "CWE-798",
        "fix": "Move to variable, source from env or secret manager",
    },
    {
        "id": "tf-rds-public-access",
        "pattern": r"publicly_accessible\s*=\s*true",
        "msg": "RDS is publicly accessible — should be false in production",
        "severity": Severity.HIGH, "cwe": "CWE-284",
        "fix": "Set publicly_accessible = false",
    },
    {
        "id": "tf-security-group-open",
        "pattern": r"cidr_blocks\s*=\s*\[\"0\.0\.0\.0/0\"\].*?(?:ingress|egress)",
        "msg": "Security group open to 0.0.0.0/0 — accepts traffic from anywhere",
        "severity": Severity.HIGH, "cwe": "CWE-284",
        "fix": "Restrict cidr_blocks to known ranges",
    },
]

# Built-in GitHub Actions rules
GITHUB_ACTIONS_RULES = [
    {
        "id": "gha-pull-request-target",
        "pattern": r"pull_request_target",
        "msg": "pull_request_target event — runs with secrets, can be abused by forks",
        "severity": Severity.CRITICAL, "cwe": "CWE-863",
        "fix": "Avoid pull_request_target, or checkout PR code to a separate job without secrets",
    },
    {
        "id": "gha-echo-secret",
        "pattern": r"echo\s+\"\$\{\{\s*secrets\.",
        "msg": "Secret printed via echo — may leak in logs",
        "severity": Severity.HIGH, "cwe": "CWE-532",
        "fix": "Use ${{ secrets.X }} as env var, don't echo it",
    },
    {
        "id": "gha-unpinned-action",
        "pattern": r"uses:\s*[\w-]+/[\w-]+@[\w-]+\s*$",
        "msg": "Action pinned to branch/tag, not commit SHA — supply chain risk",
        "severity": Severity.MEDIUM, "cwe": "CWE-1357",
        "fix": "Pin to a full commit SHA: uses: actions/checkout@<40-char-sha>",
    },
    {
        "id": "gha-permissions-none",
        "pattern": r"(?!.*permissions:).*on:",
        "msg": "Workflow has no explicit permissions: — gets default token permissions",
        "severity": Severity.MEDIUM, "cwe": "CWE-732",
        "fix": "Add `permissions: { contents: read }` at minimum",
    },
]


class L0eIaC(LayerBase):
    id = LayerID.L0E_IAC  # v4.11: use own LayerID
    name = "IaC Scanning"
    description = "Dockerfile, Kubernetes, Terraform, CloudFormation, GitHub Actions misconfig detection"
    LAYER_TAG = "L0e_iac"

    def run(self, repo_root: Path, hunks: List[DiffHunk],
            config) -> List[Finding]:
        findings: List[Finding] = []

        files_in_diff = {h.file for h in hunks}
        # also scan all IaC files (not just diff) — IaC issues are systemic
        all_iac_files = self._find_iac_files(repo_root)
        all_files = files_in_diff | all_iac_files

        # 1. Try checkov first
        if self.is_tool_available("checkov"):
            findings += self._run_checkov(repo_root, all_files)
        # 2. Try kics
        elif self.is_tool_available("kics"):
            findings += self._run_kics(repo_root)
        # 3. Built-in rules
        # v4.34: l0e_iac.py focuses on the L0e.* rule namespace (built-in Dockerfile/K8s/Terraform/GHA rules).
        # The orchestrator also runs iac_scanner.scan_iac() which produces L0.iac.* findings —
        # the two were duplicating work. Now l0e_iac.py only scans files in the diff (or all_iac_files
        # if checkov/kics unavailable), while iac_scanner handles the repo-wide sweep.
        # Both run, but they target different rule_id prefixes and don't duplicate findings.
        findings += self._scan_dockerfiles(repo_root, all_files)
        findings += self._scan_k8s(repo_root, all_files)
        findings += self._scan_terraform(repo_root, all_files)
        findings += self._scan_github_actions(repo_root, all_files)

        for f in findings:
            if not f.rule_id.startswith("L0e"):
                f.rule_id = f"L0e.{f.rule_id}"
        return findings

    def _find_iac_files(self, repo_root: Path) -> set:
        """Find all IaC files in the repo (not just diff)."""
        iac_files = set()
        patterns = [
            "**/Dockerfile*", "**/*.dockerfile",
            "**/*.yaml", "**/*.yml",
            "**/*.tf", "**/*.tfvars",
            "**/cloudformation*.json", "**/cloudformation*.yaml",
            ".github/workflows/*.yml", ".github/workflows/*.yaml",
        ]
        for pat in patterns:
            for p in repo_root.glob(pat):
                if p.is_file() and ".git" not in p.parts:
                    try:
                        iac_files.add(str(p.relative_to(repo_root)))
                    except ValueError:
                        continue
        return iac_files

    def _scan_dockerfiles(self, repo_root: Path, files: set) -> List[Finding]:
        findings: List[Finding] = []
        for f in files:
            if not (Path(f).name.lower().startswith("dockerfile") or f.endswith(".dockerfile")):
                continue
            path = repo_root / f
            if not path.exists():
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            has_healthcheck = bool(re.search(r"^\s*HEALTHCHECK", text, re.MULTILINE))

            # v4.33: docker-no-healthcheck is a FILE-LEVEL absence check.
            # v4.32 ran it inside the per-line loop, so a 4-line Dockerfile
            # without HEALTHCHECK fired 4 times. Now fire exactly once per file.
            if not has_healthcheck:
                no_hc_rule = next(r for r in DOCKERFILE_RULES if r["id"] == "docker-no-healthcheck")
                findings.append(Finding(
                    layer=self.id,
                    rule_id=f"L0e.{no_hc_rule['id']}",
                    message=no_hc_rule["msg"],
                    file=f, start_line=1,
                    severity=no_hc_rule["severity"], confidence=0.85,
                    blast_radius=BlastRadius.SYSTEM, exploitability=0.5,
                    cwe=no_hc_rule["cwe"],
                    fix_suggestion=no_hc_rule["fix"],
                    raw={"line": ""},
                ))

            # Per-line rules — skip docker-no-healthcheck (handled above)
            for i, line in enumerate(text.splitlines(), 1):
                for rule in DOCKERFILE_RULES:
                    if rule["id"] == "docker-no-healthcheck":
                        continue
                    if re.search(rule["pattern"], line):
                        findings.append(Finding(
                            layer=self.id,
                            rule_id=f"L0e.{rule['id']}",
                            message=rule["msg"],
                            file=f, start_line=i,
                            severity=rule["severity"], confidence=0.85,
                            blast_radius=BlastRadius.SYSTEM, exploitability=0.5,
                            cwe=rule["cwe"],
                            fix_suggestion=rule["fix"],
                            raw={"line": line.strip()},
                        ))
        return findings

    def _scan_k8s(self, repo_root: Path, files: set) -> List[Finding]:
        findings: List[Finding] = []
        for f in files:
            if not (f.endswith(".yaml") or f.endswith(".yml")):
                continue
            path = repo_root / f
            if not path.exists():
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            # v4.24: Content-based K8S detection — require apiVersion: AND kind:
            # (was path-based, then too broad with keyword matching)
            text_lower = text.lower()
            _is_k8s = "apiversion:" in text_lower and "kind:" in text_lower
            if not _is_k8s and not any(k in f.lower() for k in ("k8s", "kubernetes", "deploy", "manifest")):
                continue
            for i, line in enumerate(text.splitlines(), 1):
                for rule in K8S_RULES:
                    if re.search(rule["pattern"], line):
                        findings.append(Finding(
                            layer=self.id,
                            rule_id=f"L0e.{rule['id']}",
                            message=rule["msg"],
                            file=f, start_line=i,
                            severity=rule["severity"], confidence=0.8,
                            blast_radius=BlastRadius.SYSTEM, exploitability=0.6,
                            cwe=rule["cwe"],
                            fix_suggestion=rule["fix"],
                            raw={"line": line.strip()},
                        ))
        return findings

    def _scan_terraform(self, repo_root: Path, files: set) -> List[Finding]:
        findings: List[Finding] = []
        for f in files:
            if not f.endswith(".tf"):
                continue
            path = repo_root / f
            if not path.exists():
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            for i, line in enumerate(text.splitlines(), 1):
                for rule in TERRAFORM_RULES:
                    if re.search(rule["pattern"], line):
                        findings.append(Finding(
                            layer=self.id,
                            rule_id=f"L0e.{rule['id']}",
                            message=rule["msg"],
                            file=f, start_line=i,
                            severity=rule["severity"], confidence=0.85,
                            blast_radius=BlastRadius.SYSTEM, exploitability=0.6,
                            cwe=rule["cwe"],
                            fix_suggestion=rule["fix"],
                            raw={"line": line.strip()},
                        ))
        return findings

    def _scan_github_actions(self, repo_root: Path, files: set) -> List[Finding]:
        findings: List[Finding] = []
        for f in files:
            if not (f.startswith(".github/workflows/") and f.endswith((".yml", ".yaml"))):
                continue
            path = repo_root / f
            if not path.exists():
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            has_permissions = bool(re.search(r"^\s*permissions:", text, re.MULTILINE))
            for i, line in enumerate(text.splitlines(), 1):
                for rule in GITHUB_ACTIONS_RULES:
                    if rule["id"] == "gha-permissions-none" and has_permissions:
                        continue
                    if re.search(rule["pattern"], line):
                        findings.append(Finding(
                            layer=self.id,
                            rule_id=f"L0e.{rule['id']}",
                            message=rule["msg"],
                            file=f, start_line=i,
                            severity=rule["severity"], confidence=0.8,
                            blast_radius=BlastRadius.SYSTEM, exploitability=0.6,
                            cwe=rule["cwe"],
                            fix_suggestion=rule["fix"],
                            raw={"line": line.strip()},
                        ))
        return findings

    def _run_checkov(self, repo_root: Path, files: set) -> List[Finding]:
        """Run checkov on the repo."""
        try:
            proc = subprocess.run(
                ["checkov", "--directory", str(repo_root), "--output", "json",
                 "--quiet"],
                capture_output=True, text=True, check=False, timeout=60,
            )
            data = json.loads(proc.stdout or "{}")
        except Exception:
            return []
        findings: List[Finding] = []
        for result in data.get("results", {}).get("failed_checks", []):
            findings.append(Finding(
                layer=self.id,
                rule_id=f"L0e.checkov.{result.get('check_id', 'unknown')}",
                message=result.get("check_name", "Checkov finding"),
                file=result.get("file_path", ""),
                start_line=result.get("file_line_range", [0])[0],
                severity=Severity.HIGH if result.get("severity") == "HIGH" else Severity.MEDIUM,
                confidence=0.9,
                blast_radius=BlastRadius.SYSTEM, exploitability=0.5,
                cwe=result.get("cwe", ["CWE-284"])[0]
                    if isinstance(result.get("cwe"), list) else "CWE-284",
                fix_suggestion=result.get("guideline"),
                raw=result,
            ))
        return findings

    def _run_kics(self, repo_root: Path) -> List[Finding]:
        """Run KICS on the repo."""
        try:
            proc = subprocess.run(
                ["kics", "scan", "--path", str(repo_root), "--report-format", "json"],
                capture_output=True, text=True, check=False, timeout=60,
            )
            data = json.loads(proc.stdout or "{}")
        except Exception:
            return []
        findings: List[Finding] = []
        for result in data.get("results", {}).get("queries", []):
            for finding in result.get("files", []):
                findings.append(Finding(
                    layer=self.id,
                    rule_id=f"L0e.kics.{result.get('query_id', 'unknown')}",
                    message=result.get("query_name", "KICS finding"),
                    file=finding.get("file_name", ""),
                    start_line=finding.get("line", 0),
                    severity={"HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM,
                              "LOW": Severity.LOW, "INFO": Severity.INFO}
                              .get(result.get("severity"), Severity.MEDIUM),
                    confidence=0.9,
                    blast_radius=BlastRadius.SYSTEM, exploitability=0.5,
                    cwe="CWE-284",
                    raw=result,
                ))
        return findings
