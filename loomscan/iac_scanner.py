"""IaC scanner — Terraform, Dockerfile, Kubernetes, CloudFormation, Helm, Pulumi.

v2.8: Expanded with CloudFront, ALB, S3 encryption, IAM inline policies,
RDS snapshot, Lambda env vars, ECR, CloudWatch, and more.
"""
from __future__ import annotations
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List

@dataclass
class IaCFinding:
    file: str; line: int; rule_id: str; severity: str; description: str; fix: str; cwe: str = "CWE-732"; confidence: float = 0.85

TERRAFORM_RULES = [
    # S3
    ("TF-AWS-S3-PUBLIC-ACL", r'resource\s+"aws_s3_bucket"\s+[\s\S]*?acl\s*=\s*"public-read', "critical", "S3 public-read ACL", "Set acl=private"),
    ("TF-AWS-S3-NO-ENCRYPTION", r'resource\s+"aws_s3_bucket"\s+"[^"]+"\s*\{(?![^}]*server_side_encryption)', "high", "S3 no encryption", "Add server_side_encryption_configuration"),
    ("TF-AWS-S3-NO-VERSIONING", r'resource\s+"aws_s3_bucket"\s+"[^"]+"\s*\{(?![^}]*versioning)', "low", "S3 no versioning — no ransomware protection", "Add versioning { enabled = true }"),
    ("TF-AWS-S3-NO-LOGGING", r'resource\s+"aws_s3_bucket"\s+"[^"]+"\s*\{(?![^}]*logging)', "low", "S3 no access logging", "Add logging { target_bucket = ... }"),
    # IAM
    ("TF-AWS-IAM-WILDCARD-ACTION", r'action\s*=\s*\["\*"\]', "critical", "IAM wildcard action", "Scope actions"),
    ("TF-AWS-IAM-WILDCARD-RESOURCE", r'resource\s*=\s*\["\*"\]', "high", "IAM wildcard resource", "Scope to ARNs"),
    ("TF-AWS-IAM-INLINE-POLICY", r'policy\s*=\s*<<-?EOF', "medium", "IAM inline policy — hard to audit", "Use aws_iam_policy resource"),
    # Security Groups
    ("TF-AWS-SG-WILDCARD-CIDR", r'cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]', "high", "SG 0.0.0.0/0", "Restrict CIDR"),
    ("TF-AWS-SG-SSH-OPEN", r'from_port\s*=\s*22[\s\S]*?cidr_blocks\s*=\s*\["0\.0\.0\.0/0"', "high", "SSH open to world", "Restrict to bastion IP"),
    ("TF-AWS-SG-RDP-OPEN", r'from_port\s*=\s*3389[\s\S]*?cidr_blocks\s*=\s*\["0\.0\.0\.0/0"', "high", "RDP open to world", "Restrict to admin IP"),
    ("TF-AWS-SG-DB-OPEN", r'from_port\s*=\s*(?:3306|5432|1433|27017|6379)[\s\S]*?cidr_blocks\s*=\s*\["0\.0\.0\.0/0"', "critical", "Database port open to world", "Restrict to app SG"),
    # RDS
    ("TF-AWS-RDS-PUBLIC", r'publicly_accessible\s*=\s*true', "critical", "RDS publicly accessible", "Set false"),
    ("TF-AWS-RDS-NO-ENCRYPTION", r'resource\s+"aws_db_instance"(?![^}]*storage_encrypted\s*=\s*true)', "high", "RDS no encryption", "Add storage_encrypted = true"),
    ("TF-AWS-RDS-NO-BACKUP", r'resource\s+"aws_db_instance"(?![^}]*backup_retention_period)', "medium", "RDS no backup retention", "Add backup_retention_period = 7"),
    ("TF-AWS-RDS-SNAPSHOT-PUBLIC", r'resource\s+"aws_db_snapshot"[^}]*shared', "high", "RDS snapshot shared — verify not public", "Verify accounts list"),
    # Lambda
    ("TF-AWS-LAMBDA-NO-DEAD-LETTER", r'resource\s+"aws_lambda_function"(?![^}]*dead_letter_config)', "medium", "Lambda no dead-letter queue", "Add dead_letter_config"),
    ("TF-AWS-LAMBDA-ENV-SECRET", r'resource\s+"aws_lambda_function"[\s\S]*?environment\s*\{[\s\S]*?(?:password|secret|key|token)\s*=', "high", "Lambda env var contains secret", "Use AWS Secrets Manager"),
    # CloudFront
    ("TF-AWS-CF-NO-WAF", r'resource\s+"aws_cloudfront_distribution"(?![^}]*web_acl_id)', "medium", "CloudFront no WAF", "Add web_acl_id"),
    ("TF-AWS-CF-HTTP-ALLOWED", r'resource\s+"aws_cloudfront_distribution"[\s\S]*?allowed_methods[^}]*GET[^}]*HEAD', "low", "CloudFront allows HTTP", "Redirect HTTP to HTTPS"),
    ("TF-AWS-CF-NO-LOGGING", r'resource\s+"aws_cloudfront_distribution"(?![^}]*logging_config)', "low", "CloudFront no logging", "Add logging_config"),
    ("TF-AWS-CF-PRICE-CLASS", r'price_class\s*=\s*"PriceClass_100"', "low", "CloudFront PriceClass_100 — NA/EU only", "Verify intentional"),
    # ALB/ELB
    ("TF-AWS-ALB-HTTP-ONLY", r'resource\s+"aws_lb"[^}]*load_balancer_type\s*=\s*"application"[^}]*(?:port\s*=\s*80|protocol\s*=\s*"HTTP")', "high", "ALB HTTP only — no HTTPS", "Add HTTPS listener"),
    ("TF-AWS-ALB-NO-ACCESS-LOGS", r'resource\s+"aws_lb"(?![^}]*access_logs)', "low", "ALB no access logs", "Add access_logs block"),
    ("TF-AWS-ALB-NO-DELETION-PROTECTION", r'resource\s+"aws_lb"(?![^}]*deletion_protection\s*=\s*true)', "medium", "ALB no deletion protection", "Add deletion_protection = true"),
    # ECR
    ("TF-AWS-ECR-NO-IMMUTABLE", r'resource\s+"aws_ecr_repository"(?![^}]*image_tag_mutability\s*=\s*"IMMUTABLE")', "low", "ECR tags mutable — supply chain risk", "Set image_tag_mutability = IMMUTABLE"),
    ("TF-AWS-ECR-NO-SCAN", r'resource\s+"aws_ecr_repository"(?![^}]*scan_on_push\s*=\s*true)', "medium", "ECR no scan-on-push", "Add scan_on_push = true"),
    # CloudWatch
    ("TF-AWS-CW-NO-ALARM", r'resource\s+"aws_cloudwatch_metric_alarm"(?![^}]*alarm_actions)', "low", "CloudWatch alarm no action", "Add alarm_actions (SNS)"),
    # EKS
    ("TF-AWS-EKS-PUBLIC-ENDPOINT", r'resource\s+"aws_eks_cluster"[\s\S]*?endpoint_public_access\s*=\s*true', "high", "EKS public API endpoint", "Set endpoint_public_access = false"),
    # SNS/SQS
    ("TF-AWS-SNS-PUBLIC", r'resource\s+"aws_sns_topic_policy"[\s\S]*?Principal\s*=\s*"\*"', "high", "SNS topic public — anyone can publish", "Restrict Principal"),
    ("TF-AWS-SQS-PUBLIC", r'resource\s+"aws_sqs_queue_policy"[\s\S]*?Principal\s*=\s*"\*"', "high", "SQS queue public", "Restrict Principal"),
    # KMS
    ("TF-AWS-KMS-ROTATION", r'resource\s+"aws_kms_key"(?![^}]*enable_key_rotation\s*=\s*true)', "medium", "KMS key no rotation", "Add enable_key_rotation = true"),
    # Azure
    ("TF-AZURE-STORAGE-NO-HTTPS", r'enable_https_traffic_only\s*=\s*false', "high", "Azure storage allows HTTP", "Set true"),
    ("TF-AZURE-NSG-SSH-OPEN", r'destination_port_range\s*=\s*"22"[\s\S]*?source_address_prefix\s*=\s*"\*"', "high", "Azure NSG SSH open", "Restrict source"),
    # GCP
    ("TF-GCP-STORAGE-PUBLIC", r'members\s*=\s*\["allUsers"\]', "critical", "GCP bucket public", "Remove allUsers"),
    ("TF-GCP-FIREWALL-SSH-OPEN", r'allow\s*\{[^}]*protocol\s*=\s*"tcp"[^}]*ports\s*=\s*\["22"\][\s\S]*?source_ranges\s*=\s*\["0\.0\.0\.0/0"\]', "high", "GCP firewall SSH open", "Restrict source_ranges"),
]

DOCKERFILE_RULES = [
    ("DOCKER-ROOT-USER", r'^\s*USER\s+root\b', "high", "Container runs as root", "Use non-root user"),
    ("DOCKER-SECRET-ENV", r'^\s*ENV\s+\w*(?:PASSWORD|SECRET|KEY|TOKEN)\w*\s*=', "critical", "Secret in ENV", "Pass at runtime"),
    ("DOCKER-ADD-URL", r'^\s*ADD\s+https?://', "medium", "ADD with remote URL", "Use curl+COPY"),
    ("DOCKER-APT-NO-CLEAN", r'^\s*RUN\s+apt-get\s+install(?!.*rm\s+-rf\s+/var/lib/apt)', "low", "apt-get without cleanup", "Add rm -rf"),
    ("DOCKER-NO-PIN-VERSION", r'^\s*FROM\s+\w+:\s*latest\b', "medium", "FROM :latest", "Pin version"),
    ("DOCKER-NO-HEALTHCHECK", None, "medium", "No HEALTHCHECK", "Add HEALTHCHECK"),
    ("DOCKER-COPY-DOT", r'^\s*COPY\s+\.\s+', "low", "COPY . — may leak secrets", "Use .dockerignore"),
    ("DOCKER-CHMOD-777", r'chmod\s+777', "high", "chmod 777 — world-writable", "Use least privilege (755 or 644)"),
    ("DOCKER-APT-NO-FIX", r'apt-get\s+install(?!.*-y\s+--no-install-recommends)', "low", "apt-get without --no-install-recommends", "Add flag to reduce image size"),
]

K8S_RULES = [
    ("K8S-PRIVILEGED-CONTAINER", r"privileged:\s*true", "critical", "Privileged container", "Set privileged: false"),
    ("K8S-RUN-AS-ROOT", r"runAsUser:\s*0\b", "high", "Runs as root (UID 0)", "Use non-zero UID"),
    ("K8S-HOST-PATH", r"hostPath:\s*", "high", "hostPath mount", "Use emptyDir/PVC"),
    ("K8S-HOST-NETWORK", r"hostNetwork:\s*true", "high", "hostNetwork", "Set false"),
    ("K8S-HOST-PID", r"hostPID:\s*true", "high", "hostPID", "Set false"),
    ("K8S-HOST-IPC", r"hostIPC:\s*true", "high", "hostIPC", "Set false"),
    ("K8S-IMAGE-LATEST", r"image:\s*\w+:latest\b", "medium", ":latest tag", "Pin version"),
    ("K8S-NO-RESOURCE-LIMITS", None, "medium", "No resource limits", "Add resources.limits"),
    ("K8S-NO-SECURITY-CONTEXT", None, "medium", "No securityContext", "Add securityContext"),
    ("K8S-NO-READ-ONLY-ROOTFS", None, "low", "Root filesystem writable", "Set readOnlyRootFilesystem: true"),
    ("K8S-NO-LIVENESS-PROBE", None, "low", "No livenessProbe", "Add livenessProbe"),
    ("K8S-NO-READINESS-PROBE", None, "low", "No readinessProbe", "Add readinessProbe"),
    ("K8S-PRIVILEGE-ESCALATION", r"allowPrivilegeEscalation:\s*true", "high", "allowPrivilegeEscalation: true", "Set false"),
    ("K8S-CAPABILITIES-ADD-ALL", r"add:\s*-\s*\*", "high", "Adds all Linux capabilities", "Remove or specify only needed"),
    ("K8S-NO-NETWORK-POLICY", None, "low", "No NetworkPolicy — all pods can communicate", "Add NetworkPolicy"),
]

CLOUDFORMATION_RULES = [
    ("CFN-S3-PUBLIC-READ", r'"(?:AccessControl|ACL)"\s*:\s*"PublicRead', "critical", "S3 PublicRead ACL", "Set to Private"),
    ("CFN-S3-NO-ENCRYPTION", r'"Type"\s*:\s*"AWS::S3::Bucket"(?![^}]*BucketEncryption)', "high", "S3 no encryption", "Add BucketEncryption"),
    ("CFN-SG-WILDCARD-CIDR", r'"CidrIp"\s*:\s*"0\.0\.0\.0/0"', "high", "SG 0.0.0.0/0", "Restrict"),
    ("CFN-IAM-WILDCARD-ACTION", r'"Action"\s*:\s*"\*"', "critical", "IAM wildcard", "Scope actions"),
    ("CFN-IAM-WILDCARD-RESOURCE", r'"Resource"\s*:\s*"\*"', "high", "IAM wildcard resource", "Scope to ARNs"),
    ("CFN-DB-PUBLIC", r'"PubliclyAccessible"\s*:\s*true', "critical", "RDS public", "Set false"),
    ("CFN-DB-NO-ENCRYPTION", r'"Type"\s*:\s*"AWS::RDS::DBInstance"(?![^}]*StorageEncrypted)', "high", "RDS no encryption", "Add StorageEncrypted: true"),
    ("CFN-CLOUDFRONT-NO-WAF", r'"Type"\s*:\s*"AWS::CloudFront::Distribution"(?![^}]*WebACLId)', "medium", "CloudFront no WAF", "Add WebACLId"),
    ("CFN-CLOUDFRONT-HTTP", r'"ViewerProtocolPolicy"\s*:\s*"allow-all"', "high", "CloudFront allows HTTP", "Use redirect-to-https"),
    ("CFN-ALB-HTTP-ONLY", r'"Type"\s*:\s*"AWS::ElasticLoadBalancingV2::Listener"[\s\S]*?"Protocol"\s*:\s*"HTTP"', "high", "ALB HTTP listener — no HTTPS", "Add HTTPS listener"),
    ("CFN-LAMBDA-ENV-SECRET", r'"Type"\s*:\s*"AWS::Lambda::Function"[\s\S]*?(?:PASSWORD|SECRET|KEY|TOKEN)', "high", "Lambda env contains secret", "Use Secrets Manager"),
    ("CFN-KMS-NO-ROTATION", r'"Type"\s*:\s*"AWS::KMS::Key"(?![^}]*EnableKeyRotation)', "medium", "KMS no rotation", "Add EnableKeyRotation: true"),
]

def scan_terraform(file_path, repo_root=None):
    if not file_path.exists() or file_path.suffix != ".tf": return []
    rel = str(file_path.relative_to(repo_root)) if repo_root else str(file_path)
    try: source = file_path.read_text(encoding="utf-8")
    except: return []
    findings = []
    for rule_id, pattern, severity, desc, fix in TERRAFORM_RULES:
        if pattern is None: continue
        for m in re.finditer(pattern, source, re.MULTILINE):
            findings.append(IaCFinding(file=rel, line=source[:m.start()].count("\n")+1, rule_id=f"L0.iac.{rule_id}", severity=severity, description=desc, fix=fix))
    return findings

def scan_dockerfile(file_path, repo_root=None):
    if not file_path.exists() or not file_path.name.lower().startswith("dockerfile"): return []
    rel = str(file_path.relative_to(repo_root)) if repo_root else str(file_path)
    try: source = file_path.read_text(encoding="utf-8")
    except: return []
    findings = []
    lines = source.splitlines()
    # v4.35: Skip Dockerfile rules that L0eIaC layer already covers with
    # autofix support. The L0e.* findings have L8 autofix patterns wired;
    # the L0.iac.* equivalents did NOT, so keeping both produced duplicate
    # findings with no autofix benefit. The skipped rules are:
    #   DOCKER-ROOT-USER         (≡ L0e.docker-root-user, has autofix)
    #   DOCKER-SECRET-ENV        (≡ L0e.docker-secret-env, has autofix)
    #   DOCKER-APT-NO-CLEAN      (≡ L0e.docker-apt-no-cleanup, has autofix)
    #   DOCKER-NO-PIN-VERSION    (≡ L0e.docker-latest-tag, has autofix)
    #   DOCKER-NO-HEALTHCHECK    (≡ L0e.docker-no-healthcheck, has autofix)
    # The remaining iac_scanner Dockerfile rules (DOCKER-ADD-URL, DOCKER-COPY-DOT,
    # DOCKER-CHMOD-777, DOCKER-APT-NO-FIX) have NO L0e equivalent, so they stay.
    _L0E_OVERLAP = {
        "DOCKER-ROOT-USER", "DOCKER-SECRET-ENV", "DOCKER-APT-NO-CLEAN",
        "DOCKER-NO-PIN-VERSION", "DOCKER-NO-HEALTHCHECK",
    }
    for rule_id, pattern, severity, desc, fix in DOCKERFILE_RULES:
        if rule_id in _L0E_OVERLAP:
            continue  # L0eIaC layer handles these (with autofix support)
        if pattern is None:
            continue  # absence-based checks all moved to L0e
        for i, line in enumerate(lines, 1):
            if re.search(pattern, line, re.IGNORECASE):
                findings.append(IaCFinding(file=rel, line=i, rule_id=f"L0.iac.{rule_id}", severity=severity, description=desc, fix=fix))
    return findings

def scan_kubernetes(file_path, repo_root=None):
    if not file_path.exists() or file_path.suffix.lower() not in (".yaml",".yml"): return []
    try: source = file_path.read_text(encoding="utf-8")
    except: return []
    if "apiVersion:" not in source or "kind:" not in source: return []
    rel = str(file_path.relative_to(repo_root)) if repo_root else str(file_path)
    findings = []
    lines = source.splitlines()
    # v4.35: Skip K8s rules that L0eIaC layer already covers with autofix.
    # Same rationale as scan_dockerfile — L0e.* findings have L8 autofix
    # patterns wired; the L0.iac.* equivalents did NOT.
    _L0E_OVERLAP_K8S = {
        "K8S-PRIVILEGED-CONTAINER",    # ≡ L0e.k8s-privileged-container (autofix)
        "K8S-RUN-AS-ROOT",             # ≡ L0e.k8s-run-as-root (autofix)
        "K8S-HOST-NETWORK",            # ≡ L0e.k8s-host-network (autofix)
        "K8S-HOST-PID",                # ≡ L0e.k8s-host-pid (autofix)
        "K8S-IMAGE-LATEST",            # ≡ L0e.k8s-image-latest (autofix)
        "K8S-NO-RESOURCE-LIMITS",      # ≡ L0e.k8s-no-resource-limits (autofix)
        "K8S-NO-LIVENESS-PROBE",       # ≡ L0e.k8s-no-liveness-probe
        "K8S-PRIVILEGE-ESCALATION",    # ≡ L0e.k8s-allow-privilege-escalation
    }
    for rule_id, pattern, severity, desc, fix in K8S_RULES:
        if rule_id in _L0E_OVERLAP_K8S:
            continue
        if pattern is None:
            # Absence-based checks (only the ones with NO L0e equivalent)
            if rule_id == "K8S-NO-SECURITY-CONTEXT" and "securityContext:" not in source:
                findings.append(IaCFinding(file=rel, line=1, rule_id=f"L0.iac.{rule_id}", severity=severity, description=desc, fix=fix))
            elif rule_id == "K8S-NO-READ-ONLY-ROOTFS" and "readOnlyRootFilesystem" not in source:
                findings.append(IaCFinding(file=rel, line=1, rule_id=f"L0.iac.{rule_id}", severity=severity, description=desc, fix=fix))
            elif rule_id == "K8S-NO-READINESS-PROBE" and "readinessProbe:" not in source:
                findings.append(IaCFinding(file=rel, line=1, rule_id=f"L0.iac.{rule_id}", severity=severity, description=desc, fix=fix))
            elif rule_id == "K8S-NO-NETWORK-POLICY" and "NetworkPolicy" not in source:
                findings.append(IaCFinding(file=rel, line=1, rule_id=f"L0.iac.{rule_id}", severity=severity, description=desc, fix=fix))
            continue
        for i, line in enumerate(lines, 1):
            if re.search(pattern, line):
                findings.append(IaCFinding(file=rel, line=i, rule_id=f"L0.iac.{rule_id}", severity=severity, description=desc, fix=fix))
    return findings

def scan_cloudformation(file_path, repo_root=None):
    if not file_path.exists() or file_path.suffix.lower() not in (".json",".yaml",".yml"): return []
    try: source = file_path.read_text(encoding="utf-8")
    except: return []
    if "AWSTemplateFormatVersion" not in source and "Resources" not in source: return []
    rel = str(file_path.relative_to(repo_root)) if repo_root else str(file_path)
    findings = []
    for rule_id, pattern, severity, desc, fix in CLOUDFORMATION_RULES:
        for m in re.finditer(pattern, source, re.MULTILINE):
            findings.append(IaCFinding(file=rel, line=source[:m.start()].count("\n")+1, rule_id=f"L0.iac.{rule_id}", severity=severity, description=desc, fix=fix))
    return findings

def scan_helm(file_path, repo_root=None):
    if not file_path.exists(): return []
    if file_path.name not in ("values.yaml","values.yml","values-prod.yaml","values-prod.yml"): return []
    if "chart" not in str(file_path).lower() and "helm" not in str(file_path).lower(): return []
    rel = str(file_path.relative_to(repo_root)) if repo_root else str(file_path)
    try: source = file_path.read_text(encoding="utf-8")
    except: return []
    findings = []
    for i, line in enumerate(source.splitlines(), 1):
        if "privileged: true" in line:
            findings.append(IaCFinding(file=rel,line=i,rule_id="L0.iac.HELM-PRIVILEGED",severity="critical",description="Helm privileged: true",fix="Set false"))
        if "runAsUser: 0" in line:
            findings.append(IaCFinding(file=rel,line=i,rule_id="L0.iac.HELM-RUN-AS-ROOT",severity="high",description="Helm runs as root",fix="Use non-zero UID"))
        if "repository:" in source and "tag: latest" in source:
            findings.append(IaCFinding(file=rel,line=1,rule_id="L0.iac.HELM-IMAGE-LATEST",severity="medium",description="Helm :latest tag",fix="Pin version"))
            break
    return findings

def scan_pulumi(file_path, repo_root=None):
    if not file_path.exists(): return []
    if "pulumi" not in file_path.name.lower() and "pulumi" not in str(file_path).lower(): return []
    rel = str(file_path.relative_to(repo_root)) if repo_root else str(file_path)
    try: source = file_path.read_text(encoding="utf-8")
    except: return []
    findings = []
    if "aws.s3.Bucket" in source and "acl:" in source and "public-read" in source:
        findings.append(IaCFinding(file=rel,line=1,rule_id="L0.iac.PULUMI-S3-PUBLIC",severity="critical",description="Pulumi S3 public-read",fix="Set acl: private"))
    if "aws.securityGroup" in source and "0.0.0.0/0" in source:
        findings.append(IaCFinding(file=rel,line=1,rule_id="L0.iac.PULUMI-SG-OPEN",severity="high",description="Pulumi SG 0.0.0.0/0",fix="Restrict CIDR"))
    if "aws.cloudfront.Distribution" in source and "webAclId" not in source:
        findings.append(IaCFinding(file=rel,line=1,rule_id="L0.iac.PULUMI-CF-NO-WAF",severity="medium",description="Pulumi CloudFront no WAF",fix="Add webAclId"))
    return findings

def scan_iac(repo_root, max_files=100):
    findings = []
    skip_dirs = {".git","__pycache__",".venv","venv","node_modules",".loomscan-cache","build","dist"}
    count = 0
    for p in repo_root.rglob("*"):
        if not p.is_file() or any(part in skip_dirs for part in p.parts): continue
        name = p.name.lower()
        if p.suffix == ".tf": findings += scan_terraform(p, repo_root)
        elif name.startswith("dockerfile"): findings += scan_dockerfile(p, repo_root)
        elif p.suffix in (".yaml",".yml"):
            findings += scan_kubernetes(p, repo_root)
            findings += scan_cloudformation(p, repo_root)
            findings += scan_helm(p, repo_root)
        elif p.suffix == ".json": findings += scan_cloudformation(p, repo_root)
        if "pulumi" in str(p).lower(): findings += scan_pulumi(p, repo_root)
        count += 1
        if count >= max_files: break
    return findings
