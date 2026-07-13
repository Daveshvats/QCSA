"""Advanced secret detection with TruffleHog + historical git scan.

Replaces the regex-only gitleaks wrapper with a multi-tool approach:

1. **TruffleHog** (--regex --entropy) — entropy-based detection catches
   custom secret formats that no regex knows. This is the open-source
   equivalent of GitGuardian's ML detection.

2. **Historical scan** — scans EVERY commit in git history, not just the
   current diff. Catches secrets leaked years ago that are still in history.

3. **Verification** — TruffleHog can verify if a detected secret is still
   active (calls the API to check). This eliminates false positives on
   rotated/revoked secrets.

4. **Entropy fallback** — if TruffleHog isn't installed, we have a built-in
   Shannon entropy detector that flags high-entropy strings (likely secrets).

References:
  - https://github.com/trufflesecurity/trufflehog
  - Shannon entropy: https://en.wikipedia.org/wiki/Entropy_(information_theory)
"""
from __future__ import annotations

import math
import re
import subprocess
import shutil
import json
from pathlib import Path
from typing import List, Set, Tuple
from dataclasses import dataclass

from .models import Finding, Severity, BlastRadius, LayerID


# Shannon entropy threshold — strings above this are "suspicious"
ENTROPY_THRESHOLD = 4.5
MIN_SECRET_LENGTH = 20

# Known secret prefixes (high-confidence)
SECRET_PREFIXES = [
    "AKIA", "AGPA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA",  # AWS
    "sk-", "sk_live_", "rk_live_",  # Stripe
    "ghp_", "gho_", "ghu_", "ghs_", "ghr_",  # GitHub
    "glpat-",  # GitLab
    "xoxb-", "xoxp-",  # Slack
    "AIza",  # Google API
    "eyJ",  # JWT
]

# v4.34: 50+ additional secret patterns — regex-based, high-confidence
# Each entry: (rule_id_suffix, regex, secret_type, confidence, cwe)
SECRET_PATTERNS_V434 = [
    # === Cloud provider credentials ===
    ("aws-secret-key", r"aws_secret_access_key\s*=\s*['\"]([A-Za-z0-9/+=]{40})['\"]", "aws", 0.95, "CWE-798"),
    ("aws-access-key-env", r"AWS_ACCESS_KEY_ID\s*=\s*['\"](AKIA[0-9A-Z]{16})['\"]", "aws", 0.95, "CWE-798"),
    ("aws-session-token", r"aws_session_token\s*=\s*['\"]([A-Za-z0-9/+=]{100,})['\"]", "aws", 0.9, "CWE-798"),
    ("azure-storage-key", r"DefaultEndpointsProtocol=https;AccountName=\w+;AccountKey=([A-Za-z0-9+/=]{50,})", "azure", 0.95, "CWE-798"),
    ("azure-tenant-id", r"tenantId\s*[:=]\s*['\"]([0-9a-f-]{36})['\"]", "azure", 0.7, "CWE-798"),
    ("azure-client-secret", r"clientSecret\s*[:=]\s*['\"]([A-Za-z0-9@_~.\-]{30,})['\"]", "azure", 0.85, "CWE-798"),
    ("gcp-service-account", r'"type":\s*"service_account"[^}]*"private_key":\s*"-----BEGIN PRIVATE KEY-----', "gcp", 0.99, "CWE-798"),
    ("gcp-api-key", r"AIza[0-9A-Za-z\-_]{35}", "gcp", 0.9, "CWE-798"),
    ("gcp-oauth-client", r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com", "gcp", 0.85, "CWE-798"),
    ("digitalocean-token", r"do_token\s*[:=]\s*['\"](dop_v1_[a-f0-9]{64})['\"]", "digitalocean", 0.95, "CWE-798"),
    ("linode-token", r"linode_token\s*[:=]\s*['\"](lin_[a-f0-9]{40})['\"]", "linode", 0.95, "CWE-798"),
    ("vultr-token", r"vultr_api_key\s*[:=]\s*['\"]([A-Z0-9]{36})['\"]", "vultr", 0.9, "CWE-798"),
    # === VCS / CI tokens ===
    ("github-classic-pat", r"\bghp_[A-Za-z0-9]{36}\b", "github", 0.95, "CWE-798"),
    ("github-oauth-pat", r"\bgho_[A-Za-z0-9]{36}\b", "github", 0.95, "CWE-798"),
    ("github-user-token", r"\bghu_[A-Za-z0-9]{36}\b", "github", 0.95, "CWE-798"),
    ("github-server-token", r"\bghs_[A-Za-z0-9]{36}\b", "github", 0.95, "CWE-798"),
    ("github-refresh-token", r"\bghr_[A-Za-z0-9]{76}\b", "github", 0.95, "CWE-798"),
    ("gitlab-pat", r"\bglpat-[A-Za-z0-9_-]{20}\b", "gitlab", 0.95, "CWE-798"),
    ("gitlab-runner", r"GR1348941[A-Za-z0-9_-]{20}", "gitlab", 0.95, "CWE-798"),
    ("bitbucket-app-password", r"bb_[a-f0-9]{32}", "bitbucket", 0.9, "CWE-798"),
    ("circleci-token", r"cc[0-9a-f]{27,}", "circleci", 0.9, "CWE-798"),
    ("travis-token", r"travis_token\s*[:=]\s*['\"]([A-Za-z0-9]{20,})['\"]", "travis", 0.85, "CWE-798"),
    ("jenkins-api", r"jenkins_api_key\s*[:=]\s*['\"]([a-f0-9]{32,})['\"]", "jenkins", 0.85, "CWE-798"),
    ("buildkite-token", r"bkua_[a-f0-9]{32}", "buildkite", 0.9, "CWE-798"),
    # === SaaS / communication ===
    ("slack-bot-token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}", "slack", 0.95, "CWE-798"),
    ("slack-webhook", r"https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+", "slack", 0.95, "CWE-798"),
    ("discord-bot-token", r"\b(MTA|NTA|NzA|ODA|OTE)\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{30,}", "discord", 0.9, "CWE-798"),
    ("discord-webhook", r"https://(?:ptb\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+", "discord", 0.9, "CWE-798"),
    ("twilio-api-key", r"SK[0-9a-fA-F]{32}", "twilio", 0.9, "CWE-798"),
    ("twilio-account-sid", r"AC[a-z0-9]{32}", "twilio", 0.85, "CWE-798"),
    ("sendgrid-api-key", r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b", "sendgrid", 0.95, "CWE-798"),
    ("mailgun-api-key", r"key-[0-9a-zA-Z]{32}", "mailgun", 0.9, "CWE-798"),
    ("mailchimp-api-key", r"[0-9a-f]{32}-us[0-9]{1,2}", "mailchimp", 0.9, "CWE-798"),
    ("postmark-server-token", r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", "postmark", 0.5, "CWE-798"),
    ("pagerduty-api-key", r"\+API_[A-Za-z0-9]{20,}", "pagerduty", 0.85, "CWE-798"),
    ("opsgenie-api-key", r"opsgenie_api_key\s*[:=]\s*['\"]([a-f0-9]{32,})['\"]", "opsgenie", 0.85, "CWE-798"),
    # === Payment providers ===
    ("stripe-secret-key", r"\bsk_live_[A-Za-z0-9]{24,}", "stripe", 0.99, "CWE-798"),
    ("stripe-restricted-key", r"\brk_live_[A-Za-z0-9]{24,}", "stripe", 0.99, "CWE-798"),
    ("stripe-test-key", r"\bsk_test_[A-Za-z0-9]{24,}", "stripe", 0.85, "CWE-798"),
    ("stripe-publishable", r"\bpk_live_[A-Za-z0-9]{24,}", "stripe", 0.6, "CWE-798"),
    ("paypal-client-secret", r"client_secret\s*[:=]\s*['\"](EH[A-Za-z0-9]{40,})['\"]", "paypal", 0.85, "CWE-798"),
    ("square-access-token", r"\bsq0atp-[A-Za-z0-9_-]{22}", "square", 0.95, "CWE-798"),
    ("square-secret", r"\bsq0csp-[A-Za-z0-9_-]{43}", "square", 0.95, "CWE-798"),
    # === Database URLs (with embedded credentials) ===
    ("postgres-url", r"postgres(?:ql)?://[^:\s]+:([^@\s]+)@[^\s]+", "postgres", 0.85, "CWE-798"),
    ("mysql-url", r"mysql://[^:\s]+:([^@\s]+)@[^\s]+", "mysql", 0.85, "CWE-798"),
    ("mongodb-url", r"mongodb(?:\+srv)?://[^:\s]+:([^@\s]+)@[^\s]+", "mongodb", 0.85, "CWE-798"),
    ("redis-url", r"redis://[^:\s]*:([^@\s]+)@[^\s]+", "redis", 0.85, "CWE-798"),
    ("amqp-url", r"amqp://[^:\s]+:([^@\s]+)@[^\s]+", "amqp", 0.85, "CWE-798"),
    # === Private keys ===
    ("rsa-private-key", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----", "private_key", 0.99, "CWE-321"),
    ("pgp-private-key", r"-----BEGIN PGP PRIVATE KEY BLOCK-----", "private_key", 0.99, "CWE-321"),
    ("ssh-private-key", r"-----BEGIN OPENSSH PRIVATE KEY-----", "private_key", 0.99, "CWE-321"),
    # === Generic secrets / passwords ===
    ("generic-password-assign", r"(?:password|passwd|pwd)\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]", "password", 0.7, "CWE-798"),
    ("generic-secret-assign", r"(?:secret|api[_-]?key|auth[_-]?token|access[_-]?token)\s*[:=]\s*['\"]([A-Za-z0-9+/=_-]{16,})['\"]", "secret", 0.75, "CWE-798"),
    ("bearer-token", r"Bearer\s+([A-Za-z0-9_/+\.-]{20,})", "bearer", 0.7, "CWE-798"),
    ("authorization-header", r"Authorization\s*[:=]\s*['\"](?:Basic|Bearer)\s+([A-Za-z0-9+/=]{16,})['\"]", "auth", 0.8, "CWE-798"),
    # === Framework-specific ===
    ("django-secret-key", r"SECRET_KEY\s*=\s*['\"]([A-Za-z0-9!@#$%^&*()_+\-={}\[\]:;<>?,./]{50,})['\"]", "django", 0.85, "CWE-798"),
    ("flask-secret-key", r"app\.secret_key\s*=\s*['\"]([A-Za-z0-9!@#$%^&*()_+\-={}\[\]:;<>?,./]{16,})['\"]", "flask", 0.85, "CWE-798"),
    ("rails-secret-key-base", r"secret_key_base\s*=\s*['\"]([A-Za-z0-9]{30,})['\"]", "rails", 0.85, "CWE-798"),
    ("jwt-secret", r"jwt[_-]?secret\s*[:=]\s*['\"]([A-Za-z0-9]{20,})['\"]", "jwt", 0.85, "CWE-798"),
    ("nextauth-secret", r"NEXTAUTH_SECRET\s*=\s*['\"]([A-Za-z0-9]{20,})['\"]", "nextauth", 0.85, "CWE-798"),
    ("supabase-anon-key", r"NEXT_PUBLIC_SUPABASE_ANON_KEY\s*=\s*['\"](eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)['\"]", "supabase", 0.7, "CWE-798"),
    ("supabase-service-key", r"SUPABASE_SERVICE_ROLE_KEY\s*=\s*['\"](eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)['\"]", "supabase", 0.95, "CWE-798"),
    # === Package manager tokens ===
    ("npm-token", r"//registry\.npmjs\.org/:_authToken=([A-Za-z0-9]{36,})", "npm", 0.95, "CWE-798"),
    ("pypi-token", r"pypi-AgEI[A-Za-z0-9_-]{60,}", "pypi", 0.95, "CWE-798"),
    ("cargo-token", r"cargo_token\s*[:=]\s*['\"](ci[A-Za-z0-9]{30,})['\"]", "cargo", 0.9, "CWE-798"),
    ("dockerhub-token", r"DOCKERHUB_TOKEN\s*=\s*['\"](dckr_pat_[A-Za-z0-9_-]{27,})['\"]", "dockerhub", 0.95, "CWE-798"),
    # === Monitoring / observability ===
    ("datadog-api-key", r"DATADOG_API_KEY\s*[:=]\s*['\"]([a-f0-9]{32})['\"]", "datadog", 0.9, "CWE-798"),
    ("datadog-app-key", r"DATADOG_APP_KEY\s*[:=]\s*['\"]([a-f0-9]{40})['\"]", "datadog", 0.9, "CWE-798"),
    ("newrelic-license", r"NEW_RELIC_LICENSE_KEY\s*[:=]\s*['\"]([a-f0-9]{40})['\"]", "newrelic", 0.95, "CWE-798"),
    ("sentry-dsn", r"https?://[a-f0-9]{32}@[\w.-]+/\d+", "sentry", 0.85, "CWE-798"),
    ("splunk-hec-token", r"SPLUNK_HEC_TOKEN\s*[:=]\s*['\"]([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['\"]", "splunk", 0.85, "CWE-798"),
    # === Hashed secrets (still leak) ===
    ("bcrypt-hash", r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}", "bcrypt_hash", 0.4, "CWE-798"),
    ("jwt-token", r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", "jwt", 0.9, "CWE-532"),
    # === Cloudflare / CDN ===
    ("cloudflare-api-key", r"CLOUDFLARE_API_KEY\s*[:=]\s*['\"]([a-f0-9]{37})['\"]", "cloudflare", 0.9, "CWE-798"),
    ("cloudflare-origin-pull", r"-----BEGIN ORIGIN PULL CERTIFICATE-----", "cloudflare", 0.9, "CWE-798"),
    ("fastly-api-token", r"FASTLY_API_TOKEN\s*[:=]\s*['\"]([A-Za-z0-9_-]{32,})['\"]", "fastly", 0.85, "CWE-798"),
    # === Hashicorp ===
    ("vault-token", r"\bs\.[A-Za-z0-9]{24}\b", "vault", 0.8, "CWE-798"),
    ("terraform-token", r"TF_TOKEN_[A-Z_]+\s*=\s*['\"]([A-Za-z0-9._-]{20,})['\"]", "terraform", 0.85, "CWE-798"),
    ("consul-token", r"CONSUL_HTTP_TOKEN\s*[:=]\s*['\"]([a-f0-9-]{36})['\"]", "consul", 0.85, "CWE-798"),
    # === Twilio / SendGrid variants ===
    ("twilio-app-sid", r"AP[a-z0-9]{32}", "twilio", 0.6, "CWE-798"),
    ("stripe-webhook-secret", r"\bwhsec_[A-Za-z0-9]{24,}", "stripe", 0.95, "CWE-798"),
    # === GitHub Actions / CI ===
    ("gha-token", r"ghs_[A-Za-z0-9]{36}", "github", 0.9, "CWE-798"),
    ("netlify-token", r"NETLIFY_AUTH_TOKEN\s*[:=]\s*['\"]([A-Za-z0-9_-]{40,})['\"]", "netlify", 0.85, "CWE-798"),
    ("vercel-token", r"VERCEL_TOKEN\s*[:=]\s*['\"]([A-Za-z0-9]{24,})['\"]", "vercel", 0.85, "CWE-798"),
    ("heroku-api-key", r"HEROKU_API_KEY\s*[:=]\s*['\"]([a-f0-9]{32,})['\"]", "heroku", 0.9, "CWE-798"),
    # === Misc SaaS ===
    ("openai-api-key", r"\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b", "openai", 0.95, "CWE-798"),
    ("anthropic-api-key", r"\bsk-ant-[A-Za-z0-9_-]{40,}\b", "anthropic", 0.95, "CWE-798"),
    ("huggingface-token", r"hf_[A-Za-z0-9]{30,}", "huggingface", 0.9, "CWE-798"),
    ("figma-token", r"figd_[A-Za-z0-9_-]{40,}", "figma", 0.85, "CWE-798"),
    ("notion-token", r"secret_[A-Za-z0-9]{43}", "notion", 0.9, "CWE-798"),
    ("asana-pat", r"\d+/[a-f0-9]{40}", "asana", 0.7, "CWE-798"),
    ("linear-api-key", r"lin_api_[A-Za-z0-9_]{40}", "linear", 0.9, "CWE-798"),
    ("jira-pat", r"ATATT3[A-Za-z0-9_-]{180,}", "jira", 0.85, "CWE-798"),
    ("shopify-token", r"shpat_[A-Fa-f0-9]{32}", "shopify", 0.95, "CWE-798"),
    ("shopify-app-secret", r"shpss_[A-Fa-f0-9]{32}", "shopify", 0.95, "CWE-798"),
    ("shopify-app", r"shpca_[A-Fa-f0-9]{32}", "shopify", 0.9, "CWE-798"),
    ("etsy-api-key", r"etsy_api_key\s*[:=]\s*['\"]([a-z0-9]{24,})['\"]", "etsy", 0.7, "CWE-798"),
    ("lob-api-key", r"\b(live|test)_[a-f0-9]{30,}\b", "lob", 0.85, "CWE-798"),
    # === v4.35: 100+ additional patterns (target: 200+ total) ===
    # === More cloud providers ===
    ("alibaba-access-key", r"\bLTAI[0-9A-Za-z]{12,30}\b", "alibaba", 0.95, "CWE-798"),
    ("alibaba-secret-key", r"\baccess_key_secret\s*[:=]\s*['\"]([A-Za-z0-9+/=]{30})['\"]", "alibaba", 0.9, "CWE-798"),
    ("tencent-cloud-secret", r"\bTC3-SecretKey\s*[:=]\s*['\"]([A-Za-z0-9]{36})['\"]", "tencent", 0.9, "CWE-798"),
    ("oracle-cloud-token", r"\bOCI_API_KEY\s*[:=]\s*['\"]([A-Za-z0-9+/=]{40,})['\"]", "oracle", 0.85, "CWE-798"),
    ("ibm-cloud-api", r"\bIBM_CLOUD_API_KEY\s*[:=]\s*['\"]([A-Za-z0-9_-]{44})['\"]", "ibm", 0.9, "CWE-798"),
    ("huawei-cloud-token", r"\bHUAWEI_CLOUD_(?:AK|SK)\s*[:=]\s*['\"]([A-Z0-9]{20})['\"]", "huawei", 0.85, "CWE-798"),
    # === More VCS / DevOps ===
    ("gitea-token", r"\bgt_[A-Za-z0-9]{36,}", "gitea", 0.9, "CWE-798"),
    ("codecommit-https", r"https://codecommit\.[a-z-]+amazonaws\.com/v1/repos/[^/]+/[^?]+\?token=", "codecommit", 0.85, "CWE-798"),
    ("drone-ci-token", r"\bDRONE_TOKEN\s*[:=]\s*['\"]([A-Za-z0-9]{32,})['\"]", "drone", 0.85, "CWE-798"),
    ("argocd-token", r"\bargocd\.token\s*[:=]\s*['\"](eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)['\"]", "argocd", 0.9, "CWE-798"),
    ("tekton-webhook", r"\bTEKTON_WEBHOOK\s*[:=]\s*['\"]([A-Za-z0-9_-]{32,})['\"]", "tekton", 0.8, "CWE-798"),
    ("spinnaker-token", r"\bSPINNAKER_API_TOKEN\s*[:=]\s*['\"]([A-Za-z0-9_-]{32,})['\"]", "spinnaker", 0.85, "CWE-798"),
    ("concourse-webhook", r"\bCONCOURSE_WEBHOOK\s*[:=]\s*['\"]([a-f0-9]{40,})['\"]", "concourse", 0.8, "CWE-798"),
    ("flux-webhook", r"\bFLUX_WEBHOOK\s*[:=]\s*['\"]([a-f0-9]{40,})['\"]", "flux", 0.8, "CWE-798"),
    ("rancher-token", r"\bRANCHER_(?:ACCESS|SECRET)_KEY\s*[:=]\s*['\"]([A-Za-z0-9_-]{32,})['\"]", "rancher", 0.9, "CWE-798"),
    ("portainer-token", r"\bPORTAINER_TOKEN\s*[:=]\s*['\"](Bearer\s+[A-Za-z0-9_.=/+-]{32,})['\"]", "portainer", 0.85, "CWE-798"),
    # === More SaaS / Communication ===
    ("intercom-token", r"\bintercom[_-]?(?:access|api)[_-]?token\s*[:=]\s*['\"]([A-Za-z0-9_-]{60})['\"]", "intercom", 0.9, "CWE-798"),
    ("zendesk-token", r"\bzendesk[_-]?api[_-]?token\s*[:=]\s*['\"]([A-Za-z0-9]{40})['\"]", "zendesk", 0.9, "CWE-798"),
    ("freshdesk-token", r"\bfreshdesk[_-]?api[_-]?key\s*[:=]\s*['\"]([A-Za-z0-9]{32})['\"]", "freshdesk", 0.85, "CWE-798"),
    ("helpscout-token", r"\bHELPSCOUT_(?:APP|API)_ID\s*[:=]\s*['\"]([a-f0-9]{40})['\"]", "helpscout", 0.85, "CWE-798"),
    ("zapier-webhook", r"https://hooks\.zapier\.com/hooks/catch/\d+/\d+/[A-Za-z0-9]+", "zapier", 0.85, "CWE-798"),
    ("ifttt-webhook", r"https://maker\.ifttt\.com/trigger/\w+/with/key/[A-Za-z0-9_-]+", "ifttt", 0.85, "CWE-798"),
    ("n8n-webhook", r"https://[\w.-]+/webhook/[a-f0-9-]{36}", "n8n", 0.7, "CWE-798"),
    ("twilio-config-token", r"\bFC\.[A-Za-z0-9]{32}", "twilio", 0.9, "CWE-798"),
    ("twilio-account-2", r"\bAC[a-z0-9]{32}\.[a-z0-9]{32}", "twilio", 0.9, "CWE-798"),
    ("plivo-auth", r"\bPLIVO_AUTH_TOKEN\s*[:=]\s*['\"]([A-Za-z0-9]{40,})['\"]", "plivo", 0.85, "CWE-798"),
    ("nexmo-key", r"\bNEXMO_(?:API_KEY|API_SECRET)\s*[:=]\s*['\"]([A-Za-z0-9]{16,})['\"]", "nexmo", 0.85, "CWE-798"),
    ("vonage-key", r"\bVONAGE_(?:API_KEY|API_SECRET)\s*[:=]\s*['\"]([A-Za-z0-9]{16,})['\"]", "vonage", 0.85, "CWE-798"),
    ("messagebird-key", r"\bMessageBird\s*[:=]\s*['\"](live_[A-Za-z0-9_-]{40,})['\"]", "messagebird", 0.9, "CWE-798"),
    ("bandwidth-token", r"\bBANDWIDTH_(?:API|USER)_TOKEN\s*[:=]\s*['\"]([A-Za-z0-9_-]{32,})['\"]", "bandwidth", 0.85, "CWE-798"),
    ("telnyx-key", r"\bTELNYX_API_KEY\s*[:=]\s*['\"](KEY[A-Za-z0-9_-]{40,})['\"]", "telnyx", 0.9, "CWE-798"),
    # === More payments ===
    ("adyon-key", r"\bADYON_API_KEY\s*[:=]\s*['\"]([A-Za-z0-9_-]{32,})['\"]", "adyen", 0.85, "CWE-798"),
    ("braintree-private", r"\bbraintree_private_key\s*[:=]\s*['\"]([a-f0-9]{64,})['\"]", "braintree", 0.9, "CWE-798"),
    ("worldpay-token", r"\bWORLDPAY_SERVICE_KEY\s*[:=]\s*['\"]([A-Za-z0-9_-]{32,})['\"]", "worldpay", 0.85, "CWE-798"),
    ("checkout-com-secret", r"\bCHECKOUT_COM_SECRET_KEY\s*[:=]\s*['\"](sk_[A-Za-z0-9_-]{40,})['\"]", "checkout", 0.9, "CWE-798"),
    ("mollie-key", r"\bmollie_api_key\s*[:=]\s*['\"](live_[A-Za-z0-9]{30,})['\"]", "mollie", 0.9, "CWE-798"),
    ("razorpay-key", r"\brazorpay_(?:key_id|key_secret)\s*[:=]\s*['\"]([A-Za-z0-9_-]{20,})['\"]", "razorpay", 0.85, "CWE-798"),
    ("paystack-secret", r"\bPAYSTACK_SECRET_KEY\s*[:=]\s*['\"](sk_(?:test|live)_[A-Za-z0-9]{40,})['\"]", "paystack", 0.9, "CWE-798"),
    ("flutterwave-key", r"\bFLW_SECRET_KEY\s*[:=]\s*['\"](FLWSEC-[A-Za-z0-9_-]{32,})['\"]", "flutterwave", 0.9, "CWE-798"),
    ("dwolla-key", r"\bDWOLLA_(?:CLIENT|APP)_SECRET\s*[:=]\s*['\"]([A-Za-z0-9_-]{40,})['\"]", "dwolla", 0.85, "CWE-798"),
    ("plaid-client", r"\bPLAID_CLIENT_ID\s*[:=]\s*['\"]([a-f0-9]{24})['\"]", "plaid", 0.85, "CWE-798"),
    ("plaid-secret", r"\bPLAID_SECRET\s*[:=]\s*['\"]([a-f0-9]{30})['\"]", "plaid", 0.95, "CWE-798"),
    ("coinbase-api", r"\bCOINBASE_API_KEY\s*[:=]\s*['\"]([A-Za-z0-9_-]{40,})['\"]", "coinbase", 0.85, "CWE-798"),
    ("coinmarketcap", r"\bCMC_PRO_API_KEY\s*[:=]\s*['\"]([a-f0-9-]{36})['\"]", "coinmarketcap", 0.85, "CWE-798"),
    # === More database URLs ===
    ("mssql-url", r"mssql://[^:\s]+:([^@\s]+)@[^\s]+", "mssql", 0.85, "CWE-798"),
    ("oracle-url", r"oracle://[^:\s]+:([^@\s]+)@[^\s]+", "oracle", 0.85, "CWE-798"),
    ("cassandra-url", r"cassandra://[^:\s]+:([^@\s]+)@[^\s]+", "cassandra", 0.85, "CWE-798"),
    ("couchbase-url", r"couchbase://[^:\s]+:([^@\s]+)@[^\s]+", "couchbase", 0.85, "CWE-798"),
    ("couchdb-url", r"couchdb://[^:\s]+:([^@\s]+)@[^\s]+", "couchdb", 0.85, "CWE-798"),
    ("elasticsearch-url", r"https?://[^:\s]+:([^@\s]+)@[^\s]*elasticsearch[^\s]*", "elasticsearch", 0.85, "CWE-798"),
    ("snowflake-url", r"snowflake://[^:\s]+:([^@\s]+)@[^\s]+", "snowflake", 0.85, "CWE-798"),
    ("bigquery-creds", r'"type":\s*"service_account"[^}]*"project_id":\s*"[^"]+"[^}]*"client_email":\s*"[^"]+"', "gcp", 0.95, "CWE-798"),
    ("redshift-url", r"redshift://[^:\s]+:([^@\s]+)@[^\s]+", "redshift", 0.85, "CWE-798"),
    ("clickhouse-url", r"clickhouse://[^:\s]+:([^@\s]+)@[^\s]+|clickhouse:(?:\{|https?://[^:\s]+:([^@\s]+)@)", "clickhouse", 0.85, "CWE-798"),
    ("influxdb-url", r"http[s]?://[^:\s]+:([^@\s]+)@[^\s]*influxdb", "influxdb", 0.85, "CWE-798"),
    ("scylla-url", r"scylla://[^:\s]+:([^@\s]+)@[^\s]+", "scylla", 0.85, "CWE-798"),
    # === More private keys ===
    ("ec-private-key", r"-----BEGIN EC PRIVATE KEY-----", "private_key", 0.99, "CWE-321"),
    ("dsa-private-key", r"-----BEGIN DSA PRIVATE KEY-----", "private_key", 0.99, "CWE-321"),
    ("openssl-private-key", r"-----BEGIN OPENSSL PRIVATE KEY-----", "private_key", 0.99, "CWE-321"),
    ("x509-cert-combined", r"-----BEGIN CERTIFICATE-----[\s\S]*?-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "private_key", 0.99, "CWE-321"),
    ("keystore-jks", r"\b\.jks\b|keystore\.jks", "keystore", 0.5, "CWE-321"),
    ("p12-file", r"\b\.p12\b|\.pfx\b", "keystore", 0.5, "CWE-321"),
    ("ssh-config", r"\bHost\s+\w+[\s\S]*?IdentityFile\s+~?/\.ssh/", "ssh", 0.6, "CWE-321"),
    # === More generic patterns ===
    ("env-file-secret", r"^(?:AWS_|GCP_|AZURE_|STRIPE_|GITHUB_|GITLAB_)[A-Z_]+=\s*[\"']?[A-Za-z0-9+/=_-]{20,}", "env_file", 0.7, "CWE-798"),
    ("aws-creds-file", r"\[default\][\s\S]*?aws_access_key_id\s*=\s*AKIA[A-Z0-9]{16}", "aws_creds", 0.95, "CWE-798"),
    ("aws-creds-file-2", r"\[default\][\s\S]*?aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}", "aws_creds", 0.95, "CWE-798"),
    ("docker-config-auth", r'"auth":\s*"[A-Za-z0-9+/=]{40,}"', "docker_auth", 0.85, "CWE-798"),
    ("kube-config-token", r"\btoken:\s*[A-Za-z0-9_.+/=-]{40,}", "k8s_token", 0.85, "CWE-798"),
    ("kube-config-cert", r"\bclient-certificate-data:\s*[A-Za-z0-9+/=]{100,}", "k8s_cert", 0.85, "CWE-798"),
    ("npmrc-auth-token", r"//[\w.-]+/:_authToken=[A-Za-z0-9_-]{36,}", "npm", 0.95, "CWE-798"),
    ("pypirc-token", r"\bpypi[A-Za-z0-9_-]{60,}", "pypi", 0.95, "CWE-798"),
    ("netrc-machine", r"machine\s+\S+\s+login\s+\S+\s+password\s+\S+", "netrc", 0.7, "CWE-798"),
    # === More framework secrets ===
    ("express-session-secret", r"app\.use\s*\(\s*session\s*\([^)]*secret\s*:\s*['\"]([A-Za-z0-9!@#$%^&*()_+\-={}\[\]:;<>?,./]{20,})['\"]", "express", 0.85, "CWE-798"),
    ("passport-jwt-secret", r"passport\.use\s*\(\s*new\s+JwtStrategy\s*\([^)]*secretOrKey\s*:\s*['\"]([A-Za-z0-9]{20,})['\"]", "passport", 0.85, "CWE-798"),
    ("rails-credentials-yml", r"\bsecret_key_base:\s*['\"]([A-Za-z0-9]{30,})['\"]", "rails", 0.9, "CWE-798"),
    ("rails-devise-secret", r"\bDevise\.secret_key\s*=\s*['\"]([A-Za-z0-9]{30,})['\"]", "rails", 0.85, "CWE-798"),
    ("django-allowed-hosts", r"ALLOWED_HOSTS\s*=\s*\[[^\]]*['\"]\*['\"]", "django", 0.7, "CWE-918"),
    ("django-debug-true", r"DEBUG\s*=\s*True", "django", 0.6, "CWE-489"),
    ("flask-debug-true", r"app\.run\s*\([^)]*debug\s*=\s*True", "flask", 0.7, "CWE-489"),
    ("fastapi-secret-key", r"SECRET_KEY\s*=\s*['\"]([A-Za-z0-9!@#$%^&*()_+\-={}\[\]:;<>?,./]{20,})['\"]", "fastapi", 0.85, "CWE-798"),
    ("spring-boot-secret", r"spring\.security\.user\.password\s*=\s*([A-Za-z0-9!@#$%^&*()_+\-={}\[\]:;<>?,./]{8,})", "spring", 0.85, "CWE-798"),
    ("actix-secret", r"actix_web::cookie::Key::from\s*\(&\[", "actix", 0.8, "CWE-798"),
    ("laravel-app-key", r"APP_KEY=base64:[A-Za-z0-9+/=]{43}", "laravel", 0.9, "CWE-798"),
    ("symfony-secret", r"secret\s*:\s*['\"]([A-Za-z0-9]{30,})['\"]", "symfony", 0.85, "CWE-798"),
    ("aspnet-machine-key", r"machineKey\s+validationKey\s*=\s*[\"'][A-Fa-f0-9]{40,}", "aspnet", 0.95, "CWE-798"),
    # === More SaaS / API ===
    ("twilio-sync-token", r"\bIS\.[A-Za-z0-9]{32}", "twilio", 0.85, "CWE-798"),
    ("auth0-client-secret", r"AUTH0_CLIENT_SECRET\s*=\s*['\"]([A-Za-z0-9_-]{40,})['\"]", "auth0", 0.9, "CWE-798"),
    ("auth0-management-token", r"eyJhbGciOi[^.]+\.[^.]+\.[^.]+", "auth0", 0.6, "CWE-798"),
    ("okta-token", r"\bOKTA_API_TOKEN\s*=\s*['\"]([A-Za-z0-9_-]{40,})['\"]", "okta", 0.9, "CWE-798"),
    ("auth0-domain", r"https://[\w-]+\.auth0\.com/", "auth0", 0.4, "CWE-798"),
    ("firebase-token", r"\bfirebase-adminsdk[^\"]+\.json", "firebase", 0.85, "CWE-798"),
    ("supabase-anon-key-2", r"\bNEXT_PUBLIC_SUPABASE_ANON_KEY\s*=\s*['\"](eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)['\"]", "supabase", 0.7, "CWE-798"),
    ("supabase-service-key-2", r"\bSUPABASE_SERVICE_ROLE_KEY\s*=\s*['\"](eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)['\"]", "supabase", 0.95, "CWE-798"),
    ("clerk-secret-key", r"\bCLERK_SECRET_KEY\s*=\s*['\"](sk_(?:test|live)_[A-Za-z0-9]{40,})['\"]", "clerk", 0.95, "CWE-798"),
    ("clerk-frontend", r"\bNEXT_PUBLIC_CLERK_PUBLISHABLE_KEY\s*=\s*['\"](pk_(?:test|live)_[A-Za-z0-9]{40,})['\"]", "clerk", 0.6, "CWE-798"),
    ("stytch-secret", r"\bSTYTCH_SECRET_KEY\s*=\s*['\"](secret-[\w-]{40,})['\"]", "stytch", 0.95, "CWE-798"),
    ("cognito-pool-id", r"\bap-[a-z]+-\d_[A-Za-z0-9]+_[A-Za-z0-9]+", "cognito", 0.5, "CWE-200"),
    # === More cloudflare / CDN ===
    ("cloudflare-origin-ca", r"\borigin-ca-key-[A-Za-z0-9]{32,}", "cloudflare", 0.9, "CWE-798"),
    ("cloudflare-r2-key", r"\bCLOUDFLARE_R2_(?:ACCESS|SECRET)_KEY\s*=\s*['\"]([A-Za-z0-9]{32,})['\"]", "cloudflare", 0.9, "CWE-798"),
    ("cloudflare-stream-key", r"\bCLOUDFLARE_STREAM_KEY\s*=\s*['\"]([A-Za-z0-9]{40})['\"]", "cloudflare", 0.85, "CWE-798"),
    ("akamai-token", r"\bAKAMAI_(?:CLIENT|ACCESS)_TOKEN\s*=\s*['\"]([A-Za-z0-9_-]{20,})['\"]", "akamai", 0.85, "CWE-798"),
    ("akamai-secret", r"\bAKAMAI_CLIENT_SECRET\s*=\s*['\"]([A-Za-z0-9+/_-]{40,})['\"]", "akamai", 0.95, "CWE-798"),
    ("aws-cloudfront-key", r"\bAWS_CLOUDFRONT_KEY_PAIR_ID\s*=\s*['\"](APK[A-Z0-9]{12,})['\"]", "aws", 0.9, "CWE-798"),
    ("aws-cloudfront-private", r"\bAWS_CLOUDFRONT_PRIVATE_KEY\s*=\s*['\"](-----BEGIN)", "aws", 0.95, "CWE-798"),
    # === More Hashicorp ===
    ("nomad-token", r"\bNOMAD_TOKEN\s*[:=]\s*['\"]([a-f0-9-]{36})['\"]", "nomad", 0.85, "CWE-798"),
    ("boundary-token", r"\bBOUNDARY_TOKEN\s*[:=]\s*['\"]([A-Za-z0-9_-]{20,})['\"]", "boundary", 0.85, "CWE-798"),
    ("packer-token", r"\bPACKER_(?:ATLAS|HCP)_TOKEN\s*[:=]\s*['\"]([A-Za-z0-9_-]{20,})['\"]", "packer", 0.85, "CWE-798"),
    ("waypoint-token", r"\bWAYPOINT_TOKEN\s*[:=]\s*['\"]([A-Za-z0-9_-]{20,})['\"]", "waypoint", 0.85, "CWE-798"),
    # === More monitoring ===
    ("grafana-token", r"\bGRAFANA_API_KEY\s*[:=]\s*['\"](eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)['\"]", "grafana", 0.9, "CWE-798"),
    ("grafana-service-account", r"\bglsa_[A-Za-z0-9_]{32,}", "grafana", 0.95, "CWE-798"),
    ("prometheus-basic-auth", r"\bPROMETHEUS_(?:BASIC_AUTH|PASSWORD)\s*[:=]\s*['\"]([A-Za-z0-9_-]{20,})['\"]", "prometheus", 0.85, "CWE-798"),
    ("lightstep-token", r"\bLIGHTSTEP_ACCESS_TOKEN\s*[:=]\s*['\"]([A-Za-z0-9_-]{40,})['\"]", "lightstep", 0.85, "CWE-798"),
    ("honeycomb-key", r"\bHONEYCOMB_API_KEY\s*[:=]\s*['\"]([a-f0-9]{32})['\"]", "honeycomb", 0.9, "CWE-798"),
    ("honeycomb-dataset", r"\bHONEYCOMB_DATASET\s*[:=]\s*['\"]([A-Za-z0-9_-]{20,})['\"]", "honeycomb", 0.5, "CWE-200"),
    ("signoz-token", r"\bSIGNOZ_INGESTION_KEY\s*[:=]\s*['\"]([A-Za-z0-9_-]{40,})['\"]", "signoz", 0.85, "CWE-798"),
    ("uptrace-dsn", r"\bUPTRACE_DSN\s*[:=]\s*['\"](https?://[A-Za-z0-9_-]+@[\w.-]+/\d+)", "uptrace", 0.85, "CWE-798"),
    ("logtail-token", r"\bLOGTAIL_TOKEN\s*[:=]\s*['\"]([A-Za-z0-9_-]{32,})['\"]", "logtail", 0.85, "CWE-798"),
    ("betterstack-token", r"\bBETTERSTACK_SOURCE_TOKEN\s*[:=]\s*['\"]([A-Za-z0-9_-]{32,})['\"]", "betterstack", 0.85, "CWE-798"),
    # === More AI / LLM ===
    ("openai-azure", r"\bAZURE_OPENAI_API_KEY\s*[:=]\s*['\"]([A-Za-z0-9]{32})['\"]", "azure_openai", 0.95, "CWE-798"),
    ("openai-project-key", r"\bsk-proj-[A-Za-z0-9_-]{40,}", "openai", 0.95, "CWE-798"),
    ("openai-svc-key", r"\bsk-svcacct-[A-Za-z0-9_-]{40,}", "openai", 0.95, "CWE-798"),
    ("openai-org-key", r"\borganization-[A-Za-z0-9]{24}", "openai", 0.7, "CWE-200"),
    ("anthropic-staging", r"\bsk-ant-staging-[A-Za-z0-9_-]{40,}", "anthropic", 0.95, "CWE-798"),
    ("anthropic-test", r"\bsk-ant-test-[A-Za-z0-9_-]{40,}", "anthropic", 0.85, "CWE-798"),
    ("mistral-key", r"\bMISTRAL_API_KEY\s*[:=]\s*['\"]([A-Za-z0-9_-]{32,})['\"]", "mistral", 0.9, "CWE-798"),
    ("cohere-key", r"\bCOHERE_API_KEY\s*[:=]\s*['\"]([A-Za-z0-9_-]{40,})['\"]", "cohere", 0.9, "CWE-798"),
    ("groq-key", r"\bgsk_[A-Za-z0-9_-]{40,}", "groq", 0.9, "CWE-798"),
    ("replicate-token", r"\bREPLICATE_API_TOKEN\s*[:=]\s*['\"](r8_[A-Za-z0-9_-]{37})['\"]", "replicate", 0.95, "CWE-798"),
    ("together-key", r"\bTOGETHER_API_KEY\s*[:=]\s*['\"]([a-f0-9]{64})['\"]", "together", 0.9, "CWE-798"),
    ("perplexity-key", r"\bPERPLEXITY_API_KEY\s*[:=]\s*['\"](pplx-[A-Za-z0-9_-]{48,})['\"]", "perplexity", 0.9, "CWE-798"),
    ("deepinfra-key", r"\bDEEPINFRA_API_TOKEN\s*[:=]\s*['\"]([A-Za-z0-9_-]{40,})['\"]", "deepinfra", 0.85, "CWE-798"),
    ("fal-ai-key", r"\bFAL_KEY\s*[:=]\s*['\"]([a-f0-9-]{36}:[A-Za-z0-9_-]{40,})['\"]", "fal", 0.9, "CWE-798"),
    ("runway-token", r"\bRUNWAYML_API_SECRET_KEY\s*[:=]\s*['\"]([A-Za-z0-9_\-]{40,})['\"]", "runway", 0.9, "CWE-798"),
    ("pinecone-key", r"\bPINECONE_API_KEY\s*[:=]\s*['\"](pcsk_[A-Za-z0-9_]{40,})['\"]", "pinecone", 0.95, "CWE-798"),
    ("weaviate-key", r"\bWEAVIATE_API_KEY\s*[:=]\s*['\"]([A-Za-z0-9_-]{40,})['\"]", "weaviate", 0.85, "CWE-798"),
    ("qdrant-key", r"\bQDRANT_API_KEY\s*[:=]\s*['\"]([A-Za-z0-9_-]{32,})['\"]", "qdrant", 0.85, "CWE-798"),
    ("milvus-token", r"\bMILVUS_TOKEN\s*[:=]\s*['\"]([A-Za-z0-9_:.-]{20,})['\"]", "milvus", 0.8, "CWE-798"),
    ("chroma-token", r"\bCHROMA_API_TOKEN\s*[:=]\s*['\"]([A-Za-z0-9_-]{32,})['\"]", "chroma", 0.85, "CWE-798"),
    ("langchain-key", r"\bLANGCHAIN_API_KEY\s*[:=]\s*['\"](lc__[A-Za-z0-9_-]{40,})['\"]", "langchain", 0.9, "CWE-798"),
    ("langsmith-key", r"\bLANGSMITH_API_KEY\s*[:=]\s*['\"](lsv2_[A-Za-z0-9_-]{40,})['\"]", "langsmith", 0.9, "CWE-798"),
    # === More project management / collaboration ===
    ("monday-token", r"\bMONDAY_API_TOKEN\s*[:=]\s*['\"]([A-Za-z0-9_-]{40,})['\"]", "monday", 0.85, "CWE-798"),
    ("clickup-token", r"\bCLICKUP_API_TOKEN\s*[:=]\s*['\"](pk_[A-Za-z0-9_]{40,})['\"]", "clickup", 0.9, "CWE-798"),
    ("airtable-pat", r"\bAIRTABLE_API_KEY\s*[:=]\s*['\"](pat[A-Za-z0-9.]{40,})['\"]", "airtable", 0.95, "CWE-798"),
    ("smartsheet-token", r"\bSMARTSHEET_ACCESS_TOKEN\s*[:=]\s*['\"]([A-Za-z0-9_-]{40,})['\"]", "smartsheet", 0.85, "CWE-798"),
    ("shortcut-token", r"\bSHORTCUT_API_TOKEN\s*[:=]\s*['\"]([A-Fa-f0-9-]{36})['\"]", "shortcut", 0.85, "CWE-798"),
    ("trello-token", r"\bTRELLO_(?:API_KEY|API_TOKEN)\s*[:=]\s*['\"]([A-Za-z0-9]{32,})['\"]", "trello", 0.85, "CWE-798"),
    ("basecamp-token", r"\bBASECAMP_(?:ACCESS|API)_TOKEN\s*[:=]\s*['\"]([A-Za-z0-9_-]{40,})['\"]", "basecamp", 0.85, "CWE-798"),
    ("clubhouse-token", r"\bCLUBHOUSE_API_TOKEN\s*[:=]\s*['\"]([A-Fa-f0-9-]{36})['\"]", "clubhouse", 0.85, "CWE-798"),
    # === More infrastructure ===
    ("planetscale-token", r"\bPLANETSCALE_(?:ORG|DB)_TOKEN\s*[:=]\s*['\"](pscale_tkn_[A-Za-z0-9_\-]{40,})['\"]", "planetscale", 0.95, "CWE-798"),
    ("render-token", r"\bRENDER_API_KEY\s*[:=]\s*['\"](rnd_[A-Za-z0-9_]{24,})['\"]", "render", 0.9, "CWE-798"),
    ("fly-token", r"\bFLY_API_TOKEN\s*[:=]\s*['\"](FlyV1_[A-Za-z0-9_\-]{40,})['\"]", "fly", 0.95, "CWE-798"),
    ("railway-token", r"\bRAILWAY_TOKEN\s*[:=]\s*['\"]([A-Za-z0-9-]{36})['\"]", "railway", 0.85, "CWE-798"),
    ("koyeb-token", r"\bKOYEB_API_TOKEN\s*[:=]\s*['\"]([A-Za-z0-9_-]{40,})['\"]", "koyeb", 0.85, "CWE-798"),
    ("aptible-token", r"\bAPTIBLE_API_TOKEN\s*[:=]\s*['\"]([A-Za-z0-9_-]{40,})['\"]", "aptible", 0.85, "CWE-798"),
    ("northflank-token", r"\bNORTHFLANK_API_TOKEN\s*[:=]\s*['\"]([A-Za-z0-9_-]{40,})['\"]", "northflank", 0.85, "CWE-798"),
    ("zeabur-token", r"\bZEABUR_API_KEY\s*[:=]\s*['\"]([A-Za-z0-9_-]{40,})['\"]", "zeabur", 0.85, "CWE-798"),
    ("cleavr-token", r"\bCLEAVR_API_KEY\s*[:=]\s*['\"]([A-Za-z0-9_-]{40,})['\"]", "cleavr", 0.8, "CWE-798"),
    # === Misc SaaS ===
    ("twilio-verify", r"\bVA[a-z0-9]{32}", "twilio", 0.7, "CWE-200"),
    ("algolia-admin-key", r"\bALGOLIA_ADMIN_KEY\s*[:=]\s*['\"]([A-Za-z0-9]{32})['\"]", "algolia", 0.95, "CWE-798"),
    ("algolia-search-key", r"\bALGOLIA_SEARCH_KEY\s*[:=]\s*['\"]([A-Za-z0-9]{32})['\"]", "algolia", 0.7, "CWE-798"),
    ("elastic-cloud-token", r"\bELASTIC_CLOUD_API_KEY\s*[:=]\s*['\"]([A-Za-z0-9_-]{40,})['\"]", "elastic", 0.9, "CWE-798"),
    ("meilisearch-key", r"\bMEILI_MASTER_KEY\s*[:=]\s*['\"]([A-Za-z0-9_-]{32,})['\"]", "meilisearch", 0.95, "CWE-798"),
    ("typesense-key", r"\bTYPESENSE_API_KEY\s*[:=]\s*['\"]([A-Za-z0-9_\-]{32,})['\"]", "typesense", 0.9, "CWE-798"),
    ("search-io-key", r"\bSEARCHIO_API_KEY\s*[:=]\s*['\"]([A-Za-z0-9_-]{40,})['\"]", "searchio", 0.85, "CWE-798"),
    ("postman-key", r"\bPOSTMAN_API_KEY\s*[:=]\s*['\"](PMAK-[A-Za-z0-9-]{24,})['\"]", "postman", 0.9, "CWE-798"),
    ("insomnia-key", r"\bINSOMNIA_API_KEY\s*[:=]\s*['\"]([A-Za-z0-9_-]{32,})['\"]", "insomnia", 0.8, "CWE-798"),
    ("hoppscotch-key", r"\bHOPPSCOTCH_TOKEN\s*[:=]\s*['\"]([A-Za-z0-9_-]{32,})['\"]", "hoppscotch", 0.8, "CWE-798"),
    ("twilio-messaging", r"\bMG[a-z0-9]{32}", "twilio", 0.6, "CWE-200"),
    ("github-actions-token", r"\bGITHUB_TOKEN\s*[:=]\s*['\"](ghs_[A-Za-z0-9]{36})['\"]", "github", 0.9, "CWE-798"),
    ("gitlab-ci-token", r"\bCI_JOB_TOKEN\s*[:=]\s*['\"](glcb-[A-Za-z0-9_-]{20,})['\"]", "gitlab", 0.9, "CWE-798"),
    ("bitbucket-pipeline-token", r"\bBITBUCKET_ACCESS_TOKEN\s*[:=]\s*['\"]([A-Za-z0-9_-]{40,})['\"]", "bitbucket", 0.9, "CWE-798"),
    ("sonar-token", r"\bSONAR_TOKEN\s*[:=]\s*['\"](squ_[A-Za-z0-9_]{40,})['\"]", "sonar", 0.95, "CWE-798"),
    ("deepsource-key", r"\bDEEPSOURCE_DSN\s*[:=]\s*['\"](https?://[A-Za-z0-9]+@[\w.-]+)", "deepsource", 0.9, "CWE-798"),
    ("codecov-token", r"\bCODECOV_TOKEN\s*[:=]\s*['\"]([A-Za-z0-9_-]{32,})['\"]", "codecov", 0.85, "CWE-798"),
    ("coveralls-token", r"\bCOVERALLS_REPO_TOKEN\s*[:=]\s*['\"]([A-Za-z0-9_-]{32,})['\"]", "coveralls", 0.85, "CWE-798"),
    ("codacy-token", r"\bCODACY_PROJECT_TOKEN\s*[:=]\s*['\"]([A-Za-z0-9_-]{32,})['\"]", "codacy", 0.85, "CWE-798"),
    ("codeclimate-key", r"\bCC_TEST_REPORTER_ID\s*[:=]\s*['\"]([A-Za-z0-9_-]{32,})['\"]", "codeclimate", 0.85, "CWE-798"),
]


@dataclass
class SecretDetection:
    """A detected secret."""
    file: str
    line: int
    secret_type: str  # 'aws' | 'github' | 'stripe' | 'generic_entropy' | etc.
    value_preview: str  # first 4 + last 4 chars
    confidence: float
    verified: bool = False  # True if we confirmed it's still active


def shannon_entropy(s: str) -> float:
    """Compute Shannon entropy of a string. Higher = more random = more likely a secret."""
    if not s:
        return 0.0
    from collections import Counter
    counts = Counter(s)
    n = len(s)
    entropy = 0.0
    for count in counts.values():
        p = count / n
        entropy -= p * math.log2(p)
    return entropy


def detect_secrets_entropy(text: str, file: str) -> List[SecretDetection]:
    """Detect secrets using Shannon entropy. No external tool required.

    This is a fallback when TruffleHog isn't installed. It catches:
      - Known prefix secrets (AWS, Stripe, GitHub, etc.)
      - High-entropy strings (random tokens)
      - v4.34: 98 additional regex-based patterns (cloud, SaaS, DB URLs, private keys, etc.)
    """
    detections: List[SecretDetection] = []
    for i, line in enumerate(text.splitlines(), 1):
        # v4.34: Run the expanded regex patterns FIRST (they're more specific)
        seen_spans: List[Tuple[int, int]] = []
        for rule_suffix, pattern, secret_type, confidence, _cwe in SECRET_PATTERNS_V434:
            for m in re.finditer(pattern, line):
                # Skip overlapping matches
                start, end = m.span()
                if any(s <= start < e or s < end <= e for s, e in seen_spans):
                    continue
                seen_spans.append((start, end))
                value = m.group(0)
                # For patterns with a capture group, mask the captured secret
                if m.groups():
                    secret_value = m.group(1)
                else:
                    secret_value = value
                detections.append(SecretDetection(
                    file=file, line=i, secret_type=secret_type,
                    value_preview=_mask(secret_value) if len(secret_value) > 8 else "***",
                    confidence=confidence,
                ))

        # check for known prefixes
        for prefix in SECRET_PREFIXES:
            idx = line.find(prefix)
            while idx >= 0:
                # extract the secret (up to 80 chars)
                end = min(idx + 80, len(line))
                while end < len(line) and line[end] not in ' "\')\n;}<>':
                    end += 1
                value = line[idx:end]
                if len(value) >= MIN_SECRET_LENGTH:
                    # Skip if already caught by a v4.34 pattern
                    if any(s <= idx < e for s, e in seen_spans):
                        idx = line.find(prefix, idx + 1)
                        continue
                    secret_type = _classify_prefix(prefix)
                    detections.append(SecretDetection(
                        file=file, line=i, secret_type=secret_type,
                        value_preview=_mask(value),
                        confidence=0.9,
                    ))
                idx = line.find(prefix, idx + 1)

        # check for high-entropy strings (potential custom secrets)
        # match quoted strings of length >= 20
        for match in re.finditer(r'["\']([A-Za-z0-9+/=_-]{20,})["\']', line):
            value = match.group(1)
            entropy = shannon_entropy(value)
            if entropy >= ENTROPY_THRESHOLD:
                # check it's not a known prefix (already caught above)
                if not any(value.startswith(p) for p in SECRET_PREFIXES):
                    # Skip if already caught by a v4.34 pattern
                    if any(s <= match.start() < e for s, e in seen_spans):
                        continue
                    detections.append(SecretDetection(
                        file=file, line=i, secret_type="generic_entropy",
                        value_preview=_mask(value),
                        confidence=0.7,
                    ))

    return detections


def _classify_prefix(prefix: str) -> str:
    if prefix.startswith("AK") or prefix in ("AGPA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA"):
        return "aws"
    if prefix.startswith("sk"):
        return "stripe"
    if prefix.startswith("gh"):
        return "github"
    if prefix == "glpat-":
        return "gitlab"
    if prefix.startswith("xox"):
        return "slack"
    if prefix == "AIza":
        return "google"
    if prefix == "eyJ":
        return "jwt"
    return "unknown"


def _mask(value: str) -> str:
    """Mask a secret, showing only first 4 and last 4 chars."""
    if len(value) <= 8:
        return "***"
    return f"{value[:4]}...{value[-4:]}"


def run_trufflehog(repo_root: Path, files: List[Path]) -> List[Finding]:
    """Run TruffleHog on the given files. Returns findings."""
    if not shutil.which("trufflehog"):
        return []

    findings: List[Finding] = []
    for file_path in files:
        try:
            proc = subprocess.run(
                ["trufflehog", "filesystem", "--json", "--no-update",
                 str(file_path)],
                capture_output=True, text=True, check=False, timeout=30,
                cwd=str(repo_root),
            )
            for line in proc.stdout.splitlines():
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    if data.get("Verified") is True or data.get("Raw"):
                        detector = data.get("DetectorName", "unknown")
                        findings.append(Finding(
                            layer=LayerID.L0_FAST,
                            rule_id=f"L0.trufflehog.{detector}",
                            message=f"Secret detected (verified={data.get('Verified', False)}): {detector}",
                            file=data.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("path", ""),
                            start_line=data.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("line", 0),
                            severity=Severity.CRITICAL if data.get("Verified") else Severity.HIGH,
                            confidence=0.95 if data.get("Verified") else 0.8,
                            blast_radius=BlastRadius.SYSTEM, exploitability=0.95,
                            cwe="CWE-798",
                            fix_suggestion=f"Revoke and rotate the {detector} immediately; use environment variables",
                            raw=data,
                        ))
                except json.JSONDecodeError:
                    continue
        except subprocess.TimeoutExpired:
            continue
    return findings


def scan_git_history(repo_root: Path, max_commits: int = 1000) -> List[Finding]:
    """Scan git history for leaked secrets.

    This is the GitGuardian-equivalent feature: scan EVERY commit, not just
    the current diff. Catches secrets leaked years ago that are still in
    git history.

    Args:
        repo_root: path to the git repo
        max_commits: cap on commits to scan (prevents runaway scans on huge repos)

    Returns:
        List of secret findings across history.
    """
    findings: List[Finding] = []

    # Get all commits
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo_root), "log", "--pretty=format:%H", "-n", str(max_commits)],
            capture_output=True, text=True, check=False, timeout=30,
        )
        commits = proc.stdout.strip().splitlines()
    except Exception:
        return []

    # For each commit, get the diff and scan for secrets
    seen_secrets: Set[str] = set()  # dedupe by file+line+preview

    for commit in commits[:max_commits]:
        try:
            diff_proc = subprocess.run(
                ["git", "-C", str(repo_root), "show", commit, "--no-color", "--no-patch"],
                capture_output=True, text=True, check=False, timeout=10,
            )
            # get the commit's added lines
            diff_proc = subprocess.run(
                ["git", "-C", str(repo_root), "diff", f"{commit}~1", commit, "--no-color"]
                if commit != commits[-1] else
                ["git", "-C", str(repo_root), "show", commit, "--no-color"],
                capture_output=True, text=True, check=False, timeout=30,
            )
            diff = diff_proc.stdout
        except Exception:
            continue

        # Parse the diff for added lines (starting with +, not ++)
        current_file = ""
        current_line = 0
        for line in diff.splitlines():
            if line.startswith("+++ b/"):
                current_file = line[6:]
                current_line = 0
            elif line.startswith("+") and not line.startswith("+++"):
                current_line += 1
                # scan this added line for secrets
                detections = detect_secrets_entropy(line[1:], current_file)
                for d in detections:
                    dedupe_key = f"{d.file}:{d.line}:{d.value_preview}"
                    if dedupe_key in seen_secrets:
                        continue
                    seen_secrets.add(dedupe_key)
                    findings.append(Finding(
                        layer=LayerID.L0_FAST,
                        rule_id=f"L0.history_secret.{d.secret_type}",
                        message=f"Secret in git history ({d.secret_type}): {d.value_preview} — found in commit {commit[:8]}",
                        file=d.file, start_line=d.line,
                        severity=Severity.CRITICAL, confidence=d.confidence,
                        blast_radius=BlastRadius.SYSTEM, exploitability=0.95,
                        cwe="CWE-798",
                        fix_suggestion="Rotate the secret immediately. Use BFG or git-filter-repo to scrub history.",
                        raw={"commit": commit, "secret_type": d.secret_type,
                             "preview": d.value_preview},
                    ))

    return findings


def detect_secrets_advanced(repo_root: Path,
                             files: List[Path],
                             scan_history: bool = False) -> List[Finding]:
    """End-to-end secret detection: TruffleHog + entropy fallback + history.

    Args:
        repo_root: path to repo
        files: changed files in the diff
        scan_history: if True, scan all git history (slow but comprehensive)
    """
    findings: List[Finding] = []

    # Files to skip (high false positive rate)
    SKIP_FILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml",
                  "composer.lock", "Gemfile.lock", "Cargo.lock", "poetry.lock",
                  "go.sum", "result.json", "result.sarif", "report.html"}

    # 1. Try TruffleHog first (best detection)
    trufflehog_findings = run_trufflehog(repo_root, files)
    findings.extend(trufflehog_findings)

    # 2. Entropy fallback for files TruffleHog didn't cover
    trufflehog_files = {f.file for f in trufflehog_findings}
    for file_path in files:
        # Skip lock files and generated files
        if file_path.name in SKIP_FILES:
            continue
        rel = str(file_path.relative_to(repo_root)) if file_path.is_relative_to(repo_root) else str(file_path)
        if rel in trufflehog_files:
            continue
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
            detections = detect_secrets_entropy(text, rel)
            for d in detections:
                findings.append(Finding(
                    layer=LayerID.L0_FAST,
                    rule_id=f"L0.entropy_secret.{d.secret_type}",
                    message=f"Possible secret ({d.secret_type}, entropy-based): {d.value_preview}",
                    file=d.file, start_line=d.line,
                    severity=Severity.HIGH if d.confidence >= 0.85 else Severity.MEDIUM,
                    confidence=d.confidence,
                    blast_radius=BlastRadius.SYSTEM, exploitability=0.9,
                    cwe="CWE-798",
                    fix_suggestion="Move to environment variable or secret manager",
                    raw={"secret_type": d.secret_type, "preview": d.value_preview},
                ))
        except Exception:
            continue

    # 3. Historical scan (opt-in, slow)
    if scan_history:
        findings.extend(scan_git_history(repo_root))

    return findings
