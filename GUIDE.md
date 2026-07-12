# STCA Pipeline — Complete User Guide

> **Static + Test + Constraint Analysis** — a deterministic-first, type-2 fuzzy aggregated bug detection pipeline that runs on any laptop, offline, across 7+ programming languages.

This guide covers everything: installation, configuration, daily usage, CI/CD integration, advanced features, troubleshooting, and internals. Read it top-to-bottom for a full understanding, or jump to the section you need using the table of contents.

---

## Table of Contents

1. [What STCA Does](#1-what-stca-does)
2. [Installation](#2-installation)
3. [Quick Start (5 Minutes)](#3-quick-start-5-minutes)
4. [Core Concepts](#4-core-concepts)
5. [The `check` Command — Your Daily Driver](#5-the-check-command--your-daily-driver)
6. [Strictness Levels](#6-strictness-levels)
7. [Reports and Dashboards](#7-reports-and-dashboards)
8. [Configuration (.stca.yaml)](#8-configuration-stcayaml)
9. [Baseline Mode (Only New Issues)](#9-baseline-mode-only-new-issues)
10. [Auto-Fix](#10-auto-fix)
11. [Pre-commit Hook Integration](#11-pre-commit-hook-integration)
12. [CI/CD Integration (GitHub Actions)](#12-cicd-integration-github-actions)
13. [LLM Tie-Breaker (Optional)](#13-llm-tie-breaker-optional)
14. [Language Coverage](#14-language-coverage)
15. [Fuzzing (L4 Layer)](#15-fuzzing-l4-layer)
16. [Scanner Health Tracking](#16-scanner-health-tracking)
17. [Advanced Commands Reference](#17-advanced-commands-reference)
18. [Troubleshooting](#18-troubleshooting)
19. [How It Works Internally](#19-how-it-works-internally)
20. [Glossary](#20-glossary)

---

## 1. What STCA Does

STCA is a **multi-layer static analysis pipeline** for finding bugs, security vulnerabilities, and code quality issues. It runs on a git diff (for pre-commit/PR review) or the full repo (for periodic audits), aggregates findings from 8+ analysis layers, and uses a type-2 fuzzy inference system to decide whether each finding should block, warn, or pass.

### Key characteristics

| Feature | Description |
|---------|-------------|
| **Deterministic-first** | No random ML — all rules are deterministic. The only "AI" is the optional LLM tie-breaker. |
| **Type-2 fuzzy aggregation** | Findings are scored with interval-valued fuzzy logic (IT2-FIS), not crisp thresholds. This handles uncertainty gracefully. |
| **Offline** | Works without internet (except OSV.dev CVE lookups, which are cached). |
| **Cross-platform** | Windows, macOS, Linux. No compiler toolchain required. |
| **Multi-language** | Python, JavaScript/TypeScript, Go, Java, C/C++, Rust, IaC (Terraform/Dockerfile/K8s). |
| **8 analysis layers** | L0 (fast hooks) through L7 (simulation), plus supply chain, dependencies, behavioral, IaC. |
| **73+ command-line tools** | Not just `check` — there are dedicated commands for taint analysis, CPG queries, nullness, fuzzing, symbolic execution, and more. |

### What it finds

- **Security vulnerabilities**: SQL injection, XSS, path traversal, hardcoded secrets, crypto misuse, auth bypasses, IDOR, SSRF
- **Correctness bugs**: null dereferences, typestate violations, contract violations, unhandled exceptions
- **Code quality**: complexity, duplication, dead code, missing docs, architecture violations
- **Supply chain issues**: dependency CVEs, typosquats, abandoned packages, EOL versions, license issues
- **Infrastructure misconfigurations**: public S3 buckets, privileged containers, plaintext secrets in Dockerfiles
- **Concurrency bugs**: race conditions, deadlocks, async issues
- **Runtime crashes** (Python only): via coverage-guided fuzzing

---

## 2. Installation

### Prerequisites

- **Python 3.9+** (3.12+ recommended for faster fuzzing via `sys.monitoring`)
- **Git** (STCA analyzes git diffs)
- **pip** and **venv**

### Step 1: Extract and install

```bash
# Extract the tarball
tar -xzf stca-pipeline-v3.2.tar.gz
cd stca-pipeline

# Create a virtual environment
python -m venv .venv

# Activate it
source .venv/bin/activate        # Linux/macOS
# .venv\Scripts\activate         # Windows PowerShell

# Install STCA in editable mode
pip install -e .
```

### Step 2: Install optional extras (pick what you need)

```bash
pip install -e ".[llm]"            # Ollama LLM tie-breaker client
pip install -e ".[property]"       # Hypothesis property tests (L1)
pip install -e ".[mutation]"       # mutmut mutation testing (L2)
pip install -e ".[supply-chain]"   # pip-audit for Python CVEs (L0b)
pip install -e ".[fuzz]"           # atheris fuzzing (L4, Linux only)
pip install -e ".[all-tools]"      # everything except atheris
pip install -e ".[dev]"            # pytest + pytest-cov (for running tests)
```

**Note on atheris (L4 fuzzing)**: atheris only works on Linux (requires libFuzzer C++ library). On Windows/macOS, STCA automatically uses its built-in pure-Python coverage-guided fuzzer instead — same algorithm, slightly slower. See [§15. Fuzzing](#15-fuzzing-l4-layer).

### Step 3: Verify the install

```bash
stca --version                     # should print: stca, version 0.1.0
stca --help                        # list all commands
stca doctor                        # check what tools are available
python -m pytest tests/            # run the test suite (should all pass)
```

### Step 4: Install external tools (optional, recommended)

STCA can auto-install external analysis tools (gitleaks, semgrep, osv-scanner, etc.):

```bash
stca install-tools                 # install all tools
stca install-tools --layer L0      # only L0 tools (semgrep, gitleaks, ruff)
stca install-tools --layer L0b     # only supply chain tools
stca doctor                        # verify what's installed
```

Tools are installed to `~/.stca/bin/` (added to PATH automatically). Binary downloads are SHA256-verified.

---

## 3. Quick Start (5 Minutes)

### A. Initialize a repo

```bash
cd /path/to/your/repo
stca init                          # creates .stca.yaml config
```

### B. Run your first scan

```bash
# Full-repo scan (scans ALL source files)
stca check --repo . --full

# Or scan just the git diff (faster, for pre-commit)
stca check --repo . --base main
```

You'll see output like:

```
╔══════════════════════════════════════════════════════════════════════════╗
║                    ✗  STCA — Final Decision: BLOCK                       ║
╚══════════════════════════════════════════════════════════════════════════╝

Findings:                          47  Duration:    12.3s
By severity:  critical=8  high=12  medium=15  low=10  info=2  LLM invoked:  no

Full report:  stca report  (opens HTML dashboard in browser)
Reports dir:  .stca-reports/  (report.html, result.json, result.sarif)
```

### C. View the dashboard

```bash
stca dashboard --repo .            # generates .stca-reports/dashboard.html
# Open it in your browser:
# Linux:   xdg-open .stca-reports/dashboard.html
# macOS:   open .stca-reports/dashboard.html
# Windows: start .stca-reports\dashboard.html
```

### D. Get details on a specific finding

```bash
# JSON output with full finding details
stca check --repo . --full --json | python -m json.tool | head -50

# Or look at the SARIF report (VS Code SARIF Viewer compatible)
cat .stca-reports/result.sarif | python -m json.tool | head -30
```

---

## 4. Core Concepts

### Layers

STCA runs findings through 8 analysis layers, each inspired by a different OSS tool:

| Layer | Name | Inspired by | What it does |
|-------|------|-------------|--------------|
| **L0** | Fast Hooks | Semgrep + bundled rule packs | Multi-language pattern matching (88+ rules) |
| **L0b** | Supply Chain | pip-audit, osv-scanner | Dependency CVEs, typosquats, EOL versions |
| **L0c** | Dependencies | pip-licenses, npm outdated | Outdated packages, license compliance |
| **L0d** | Behavioral | CodeScene | Churn, hotspots, commit risk |
| **L0e** | IaC | Checkov, KICS | Terraform/Dockerfile/K8s misconfigurations |
| **L0f** | Commit Risk | git analysis | Secret leaks in commit history |
| **L1** | Property Tests | Hypothesis | Property-based testing |
| **L2** | Mutation | mutmut | Mutation testing (kill mutants) |
| **L3** | Invariants | boogie, Dafny | Invariant verification |
| **L4** | Fuzz | atheris, libFuzzer | Coverage-guided fuzzing (Python only) |
| **L5** | Policy | OPA/Rego | Policy-as-code enforcement |
| **L6** | Symbolic | Z3, Kani | Symbolic execution + model checking (Rust) |
| **L7** | Simulation | stress testing | Concurrency simulation |

### The Brain (IT2-FIS Aggregator)

Each finding gets a **decision** from the type-2 fuzzy inference system:

| Decision | Meaning | Exit code |
|----------|---------|-----------|
| `PASS` | Not a real issue, or very low confidence | 0 |
| `WARN` | Likely a real issue, but not blocking | 0 |
| `BLOCK` | Definitely a real issue — blocks the commit | 1 |
| `UNCERTAIN` | FIS can't decide — triggers LLM tie-breaker (if enabled) | 0 |

The FIS takes 4 inputs per finding:
- **Severity** (critical/high/medium/low/info → 0-1 score)
- **Confidence** (the layer's self-reported confidence, 0-1)
- **Source reliability** (historical precision/recall of the layer, 0-1)
- **Corroboration** (did other layers find the same issue? 0-1)

### Strictness Levels

PHPStan-inspired 9-level system. Higher levels = more layers + more severities:

| Level | What's added |
|-------|-------------|
| 1 | Critical only (fastest) |
| 2 | + High severity |
| 3 | + Supply chain (CVEs) |
| 4 | + Code quality (behavioral, commit risk) |
| 5 | + IaC + secrets (default) |
| 6 | + Taint analysis (CPG cross-file) |
| 7 | + Typestate + metamorphic |
| 8 | + Symbolic + mutation + fuzzing |
| 9 | Everything, strict (WARN treated as BLOCK) |

---

## 5. The `check` Command — Your Daily Driver

`stca check` is the main command. Here's every flag explained:

### Basic usage

```bash
# Full-repo scan (scans ALL source files, not just diff)
stca check --repo /path/to/repo --full

# Diff scan (compare against a base branch — for PR review)
stca check --repo /path/to/repo --base main

# Staged changes only (for pre-commit hook)
stca check --repo /path/to/repo --staged
```

### Output format flags

```bash
--quiet              # Just print the final decision: "block", "warn", or "pass"
--json               # Full JSON output (for CI integration, custom tooling)
--detailed           # Show full findings table + critical findings tree in terminal
                     # (default is minimal output — see §7 for details)
```

### Strictness control

```bash
--strictness 1       # Only critical findings (fastest, fewest FPs)
--strictness 5       # Default — IaC + secrets
--strictness 9       # Everything, strict (WARN treated as BLOCK)
```

### Baseline mode

```bash
--baseline           # Only flag NEW issues (not in the baseline)
                     # First run establishes the baseline; subsequent runs
                     # only report issues that weren't there before
```

### Scanner health (v3.1+)

```bash
--strict-scanners    # Exit code 3 if any scanner failed during the run
                     # (surfaces previously-silent failures as a CI gate)
```

### Verbose logging

```bash
-v, --verbose        # Enable DEBUG-level logging
                     # Shows optional-parser failures, per-file scan errors,
                     # and other low-level diagnostics
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | PASS or WARN (commit allowed) |
| 1 | BLOCK (findings block the commit) |
| 2 | Not a git repo / config error |
| 3 | Scanner errors (--strict-scanners gate failed) |

### Examples

```bash
# Quick pre-commit check (staged files, level 5, minimal output)
stca check --repo . --staged --strictness 5 --quiet

# Full audit for a release (everything, strict, JSON for CI)
stca check --repo . --full --strictness 9 --json > release-audit.json

# PR review (diff against main, show all findings)
stca check --repo . --base main --detailed

# CI gate (block on scanner failures too)
stca check --repo . --base origin/main --strict-scanners
```

---

## 6. Strictness Levels

### Show current level

```bash
stca strictness --repo .
```

### Set the level

```bash
# Sets it in .stca.yaml (persists across runs)
stca strictness --repo . --level 7

# Or override per-run
stca check --repo . --full --strictness 7
```

### All 9 levels

```
Level  Name                         Layers   Description
1      Critical Only                3        Only CRITICAL findings block. Good for first-time.
2      Critical + High              4        Adds HIGH severity findings.
3      + Supply Chain               5        Adds dependency CVEs and dependency health.
4      + Code Quality               7        Adds behavioral analysis and commit risk.
5      + IaC + Secrets              9        Adds IaC scanning and advanced secret detection.
6      + Taint Analysis             9        Adds CPG cross-file taint tracking and Pysa.
7      + Typestate + Metamorphic    10       Adds typestate, metamorphic, and differential tests.
8      + Symbolic + Mutation        12       Adds symbolic verification and mutation testing.
9      Everything, Strict           13       All layers, all rules, WARN treated as BLOCK.
```

### Choosing a level

| Use case | Recommended level |
|----------|-------------------|
| First time on a legacy codebase | 1 (overwhelmed otherwise) |
| Pre-commit hook (fast feedback) | 3 or 4 (fast, catches real bugs) |
| Default development | 5 (good balance) |
| PR review | 5 or 6 |
| Pre-release audit | 8 or 9 (thorough) |
| CI gate (block merges) | 5 with `--strict-scanners` |

---

## 7. Reports and Dashboards

Every `stca check` run generates 3 reports in `<repo>/.stca-reports/`:

### A. HTML Dashboard (`report.html`)

Self-contained HTML page with:
- Color-coded header showing the final decision
- Summary cards: findings count, by-severity, LLM invoked, scanner errors
- Scanner Health section (yellow banner when scanners fail)
- Layer Timings table
- Findings table with severity badges, layer, decision, file:line, message, confidence, FIS reasoning

```bash
# Generate after a check
stca check --repo . --full
# The HTML report is at .stca-reports/report.html

# Or generate a richer dashboard with charts and filterable table
stca dashboard --repo .
# Generates .stca-reports/dashboard.html

# Open in browser:
# Linux:   xdg-open .stca-reports/dashboard.html
# macOS:   open .stca-reports/dashboard.html
# Windows: start .stca-reports\dashboard.html
```

### B. JSON Report (`result.json`)

Structured JSON for CI integration and custom tooling:

```bash
stca check --repo . --full --json > report.json

# Key fields:
# - findings[]           : every issue found
# - decisions[]          : FIS decision per finding
# - scanner_health[]     : scanner failures (v3.1+)
# - scanner_error_count  : number of failed scanners
# - layer_timings        : how long each layer took
# - final_decision       : "block" | "warn" | "pass"
```

### C. SARIF Report (`result.sarif`)

SARIF 2.1.0 — the industry standard for static analysis. Compatible with:
- **GitHub Code Scanning** (upload via `github/codeql-action/upload-sarif`)
- **VS Code SARIF Viewer** extension
- **Azure DevOps**

```bash
stca check --repo . --full
# SARIF is at .stca-reports/result.sarif

# Upload to GitHub:
# - uses: github/codeql-action/upload-sarif@v3
#   with:
#     sarif_file: .stca-reports/result.sarif
```

When scanners fail, SARIF includes:
- `executionSuccessful: false`
- Each failure as a `toolExecutionNotification` with exception details

### Terminal output modes

| Flag | What you see |
|------|-------------|
| *(default)* | Minimal: decision header + summary + scanner errors + pointers to reports (~7 lines) |
| `--detailed` | Full: findings table + critical findings tree + layer timings + scanner health table |
| `--quiet` | Just the decision word: `block`, `warn`, or `pass` |
| `--json` | Full JSON to stdout (no TUI) |
| `-v` / `--verbose` | DEBUG logging to stderr (in addition to normal output) |

---

## 8. Configuration (.stca.yaml)

### Initialize

```bash
stca init --repo .                  # creates .stca.yaml with defaults
stca init --repo . --force          # overwrite existing config
```

### Full config reference

```yaml
# .stca.yaml — STCA Pipeline configuration

layers:
  L0_fast:       { enabled: true,  timeout_seconds: 10 }
  L1_property:   { enabled: true,  timeout_seconds: 30 }
  L2_mutation:   { enabled: false, timeout_seconds: 60 }
  L3_invariants: { enabled: true,  timeout_seconds: 5 }
  L4_fuzz:       { enabled: false, timeout_seconds: 60 }
  L5_policy:     { enabled: true,  timeout_seconds: 15 }
  L6_symbolic:   { enabled: false, timeout_seconds: 120 }
  L7_simulation: { enabled: false, timeout_seconds: 300 }

# Paths that are "critical" — L6 symbolic verification and L7 simulation
# only run on these paths (they're slow).
critical_paths:
  - "**/auth/**"
  - "**/crypto/**"
  - "**/payment/**"
  - "**/pii/**"
  - "app.py"

# Paths with concurrency code — L7 simulation runs on these.
concurrency_paths:
  - "**/concurrency/**"
  - "**/async/**"
  - "**/worker/**"

# FIS decision thresholds
block_on: ["block"]
warn_on: ["warn"]

# LLM tie-breaker (optional — see §13)
llm:
  enabled: false
  provider: ollama
  model: qwen3-coder-1.5b
  endpoint: http://localhost:11434
  prm_threshold: 0.6
  only_on_uncertain: true       # only invoke LLM for UNCERTAIN findings

# External tool paths (auto-detected if on PATH)
tools: {}

# Stats file (tracks layer precision/recall over time)
stats_file: ".stca-stats.json"

# Report output directory
report_dir: ".stca-reports"
```

### Enabling/disabling layers

Edit `.stca.yaml` or use the strictness level system. For example, to enable L4 fuzzing:

```yaml
layers:
  L4_fuzz: { enabled: true, timeout_seconds: 60 }
```

Or use strictness level 8+ (which enables L4 automatically):

```bash
stca strictness --repo . --level 8
```

### Custom critical paths

If you have security-critical code outside the defaults:

```yaml
critical_paths:
  - "**/auth/**"
  - "**/crypto/**"
  - "src/security/*.py"          # custom
  - "internal/admin/**/*.go"     # custom
```

---

## 9. Baseline Mode (Only New Issues)

For legacy codebases with many existing issues, baseline mode lets you only flag **new** issues:

### First run (establishes baseline)

```bash
stca check --repo . --full
# This run establishes the baseline in .stca-baseline.json
# All current findings are recorded as "known"
```

### Subsequent runs (only new issues)

```bash
stca check --repo . --full --baseline
# Only findings NOT in the baseline are reported
# Known issues are suppressed
```

### Managing the baseline

```bash
stca baseline --repo . show           # show current baseline
stca baseline --repo . add <fingerprint>   # add a finding to baseline
stca baseline --repo . remove <fingerprint>  # remove a finding from baseline
stca baseline --repo . clear          # clear the baseline
```

### Use cases

- **Legacy codebase adoption**: Establish baseline, then fix new issues as they're introduced
- **Incremental improvement**: See only what YOUR commits introduce
- **PR review**: Only flag issues in the diff (use `--base main` instead)

---

## 10. Auto-Fix

STCA can auto-fix some findings (bare except, mutable defaults, etc.):

### Stage fixes for review (default)

```bash
stca check --repo . --full           # generate findings
stca fix --repo .                    # stage fixes in .stca-fixes/
# Review the patches:
ls .stca-fixes/
# Apply the ones you want:
git apply .stca-fixes/001_*.patch
```

### Apply directly to source files

```bash
stca fix --repo . --apply            # apply all fixes directly
stca fix --repo . --finding-id <fingerprint>  # fix one specific finding
```

### What gets auto-fixed

| Rule | Fix |
|------|-----|
| Bare `except:` | `except Exception:` |
| Mutable default arguments | `def foo(x=None):` → `if x is None: x = []` |
| `eval()`/`exec()` | `ast.literal_eval()` (where safe) |
| Some formatting issues | ruff auto-fixes |

**Always review auto-fixes before committing.** STCA stages them in `.stca-fixes/` by default for this reason.

---

## 11. Pre-commit Hook Integration

### Option A: pre-commit framework

Create `.pre-commit-config.yaml` in your repo:

```yaml
repos:
  - repo: local
    hooks:
      - id: stca
        name: STCA Pipeline
        entry: stca pre-commit
        language: system
        pass_filenames: false
        stages: [commit]
```

Install:
```bash
pip install pre-commit
pre-commit install
```

Now every `git commit` runs STCA on staged files. If STCA returns exit code 1 (BLOCK), the commit is blocked.

### Option B: plain git hook

Create `.git/hooks/pre-commit`:

```bash
#!/bin/sh
stca check --repo . --staged --strictness 5 --quiet
exit $?
```

Make it executable:
```bash
chmod +x .git/hooks/pre-commit
```

### Option C: STCA's built-in pre-commit command

```bash
stca pre-commit --repo . --files "file1.py,file2.py"
```

This is what the pre-commit framework calls internally.

---

## 12. CI/CD Integration (GitHub Actions)

### Basic workflow

```yaml
# .github/workflows/stca.yml
name: STCA Scan
on: [pull_request]

jobs:
  stca:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # need full history for diff

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install STCA
        run: |
          pip install -e .
          pip install -e ".[supply-chain]"

      - name: Run STCA
        run: |
          stca check --repo . --base origin/main --json > stca-report.json
          # Exit code: 0=pass, 1=block, 3=scanner errors
          exit $?

      - name: Upload SARIF to GitHub Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: .stca-reports/result.sarif

      - name: Upload JSON report artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: stca-report
          path: stca-report.json
```

### Strict CI gate (block on scanner errors too)

```yaml
- name: Run STCA (strict)
  run: |
    stca check --repo . --base origin/main --strict-scanners --strictness 6
    # Exit 1 = findings block, Exit 3 = scanner errors block
```

### Using the STCA GitHub Action

STCA includes a ready-made action at `.github/actions/stca-action/`:

```yaml
- uses: ./.github/actions/stca-action
  with:
    args: 'check --base origin/main --strict-scanners'
```

---

## 13. LLM Tie-Breaker (Optional)

For UNCERTAIN findings (where the FIS can't decide), STCA can call a local LLM via Ollama to make the final call.

### Setup

```bash
# 1. Install Ollama (https://ollama.ai)
# 2. Pull a model
ollama pull qwen3-coder-1.5b

# 3. Enable in .stca.yaml:
cat >> .stca.yaml << 'EOF'
llm:
  enabled: true
  provider: ollama
  model: qwen3-coder-1.5b
  endpoint: http://localhost:11434
  prm_threshold: 0.6
  only_on_uncertain: true
EOF

# 4. Run with LLM tie-breaking
stca check --repo . --full
# The TUI will show "LLM invoked: yes" if any finding needed tie-breaking
```

### How it works

1. FIS produces an UNCERTAIN decision for a finding
2. STCA sends the finding + surrounding code context to the LLM
3. LLM proposes a hypothesis ("this function crashes on None input")
4. STCA **verifies** the hypothesis by executing it (LLM-as-oracle with verified reasoning)
5. Only confirmed bugs are reported

### Process Reward Model (PRM)

STCA uses a Process Reward Model to score the LLM's reasoning quality. Only reasoning with PRM score > `prm_threshold` (default 0.6) is trusted.

### Privacy

All LLM calls go to your local Ollama instance — no data leaves your machine.

---

## 14. Language Coverage

STCA analyzes 7+ programming languages. Different layers cover different languages:

| Language | L0 Patterns | Taint Tracking | CPG Queries | Fuzzing (L4) | Symbolic (L6) | IaC (L0e) |
|----------|:-----------:|:--------------:|:-----------:|:------------:|:-------------:|:---------:|
| **Python** | ✅ | ✅ | ✅ | ✅ | — | — |
| **JavaScript/TS** | ✅ | ✅ | ✅ | — | — | — |
| **Go** | ✅ | — | — | — | — | — |
| **Java** | ✅ | — | — | — | — | — |
| **C/C++ | ✅ | — | ✅ | — | — | — |
| **Rust** | — | — | — | — | ✅ (Kani) | — |
| **Terraform** | — | — | — | — | — | ✅ |
| **Dockerfile** | — | — | — | — | — | ✅ |
| **K8s YAML** | — | — | — | — | — | ✅ |

### What "L0 Patterns" means per language

- **Python**: 88+ Semgrep rules + custom pattern matchers (eval, exec, os.system, crypto misuse, SQL injection, etc.)
- **JavaScript/TS**: XSS, prototype pollution, injection, React security (JSX auth), 12 multi-line pattern matchers
- **Go**: crypto, auth, concurrency patterns
- **Java**: SpotBugs-ported rules (injection, null deref, resource leaks)
- **C/C++ | Flawfinder-inspired: dangerous functions (strcpy, sprintf, system, gets)

### Why fuzzing is Python-only

Fuzzing requires runtime execution. Python is interpreted, so STCA can `import` the target module and call its functions directly. Compiled languages (Go, Java, C/C++) would require their toolchains + build systems + language-specific harness generation, which would break STCA's "works on any laptop, offline" design.

For Rust, STCA uses **Kani** (L6) instead of fuzzing — Kani mathematically *proves* absence of certain bugs (overflow, panic, contract violations), which is more powerful than fuzzing.

---

## 15. Fuzzing (L4 Layer)

### What it does

The L4 fuzz layer:
1. Picks changed Python functions from the git diff
2. Generates a fuzz harness (imports the function, calls it with `FuzzedDataProvider` inputs)
3. Runs the harness for ~10 seconds, generating thousands of random inputs
4. Reports any crash (unhandled exception) as a CRITICAL finding (`L4.fuzz.crash`, CWE-20)

### Backends (3-tier fallback)

| Backend | Platform | Algorithm | Speed |
|---------|----------|-----------|-------|
| **atheris** | Linux only | libFuzzer (C++ instrumentation) | ~1-5M iter/sec |
| **coverage-python** | All platforms | `sys.monitoring` BRANCH events + corpus mutation | ~50-100K iter/sec |
| **random-python** | All platforms | Random mutation (legacy fallback) | ~50K iter/sec |

STCA auto-detects the best available backend. On Windows/macOS, it uses `coverage-python` (the built-in pure-Python fuzzer).

### Enabling fuzzing

```bash
# Option 1: Use strictness level 8+ (enables L4 automatically)
stca check --repo . --full --strictness 8

# Option 2: Enable L4 in .stca.yaml
stca strictness --repo . --level 8
# Or manually edit .stca.yaml:
# L4_fuzz: { enabled: true, timeout_seconds: 60 }
```

### What it finds

```python
# This function has a bug: crashes on empty input
def process(data):
    return data[0].upper()  # IndexError if data is empty

# Static analysis might miss this — the bug only triggers at runtime.
# Fuzzing finds it in seconds.
```

The fuzzer finds:
- **Surface crashes**: empty input, None, type confusion
- **Deep bugs**: requires specific input structure (via dictionary mutation with 60+ tokens like `ADMIN`, `../`, `' OR 1=1--`)
- **Boundary bugs**: off-by-one, exact-length requirements

### Custom fuzz harnesses

STCA auto-generates a naive harness, but you can provide a custom one:

```python
# tests/fuzz/process_fuzz.py
import sys
from stca.fuzz_coverage import fuzz_coverage, FuzzedDataProvider
from app import process

def test_one_input(data):
    fdp = FuzzedDataProvider(data)
    s = fdp.consume_unicode_no_surrogates(fdp.remaining_bytes() or 1)
    try:
        # Call with a string
        process(s)
    except (TypeError, ValueError):
        pass  # expected — not a bug
    except Exception:
        raise  # unexpected — that's the bug

if __name__ == '__main__':
    duration = int(sys.argv[1]) if len(sys.argv) > 1 else 10
    crash = fuzz_coverage(test_one_input, duration_seconds=duration)
    if crash:
        print(f"CRASH:{crash}", file=sys.stderr)
        sys.exit(1)
    sys.exit(0)
```

Place it at `tests/fuzz/<function_name>_fuzz.py` and STCA will use it instead of auto-generating.

### Fuzzer stats

The fuzzer reports stats via the `L4.fuzz.backend` INFO finding:
- Iterations run
- Corpus size
- Coverage branches tracked
- Backend used (`sys.monitoring` or `sys.settrace`)

### Limitations

- **Python only** (see [§14](#14-language-coverage))
- **No C-level memory bugs**: Can't detect use-after-free, buffer overflow in C extensions (atheris with ASan can)
- **Slower than atheris**: ~50-100K iter/sec vs atheris's 1-5M iter/sec
- **10-second default duration**: Increase via `L4_fuzz.timeout_seconds` in config

---

## 16. Scanner Health Tracking

### The problem it solves

Previously, if a scanner failed (e.g., missing import, parse error, network issue), the failure was silently swallowed. You'd get fewer findings without knowing why.

### How it works (v3.1+)

Every scanner failure is now:
1. **Logged** (WARNING level)
2. **Tracked** in `PipelineResult.scanner_health`
3. **Surfaced** in the TUI, JSON, SARIF, and HTML reports
4. **Gatable** via `--strict-scanners` (exit code 3)

### Where to see it

| Surface | What you see |
|---------|-------------|
| **TUI** (default) | Yellow banner: "⚠ N scanner(s) failed" |
| **TUI** (`--detailed`) | Full Scanner Health table with error types and messages |
| **JSON** | `scanner_health[]` array + `scanner_error_count` |
| **SARIF** | `executionSuccessful: false` + `toolExecutionNotifications[]` |
| **HTML** | Yellow warning banner + Scanner Health section |

### CI gate

```bash
stca check --repo . --full --strict-scanners
# Exit 3 if any scanner failed — surfaces previously-silent failures as a build breaker
```

### Debug logging

```bash
stca check --repo . --full -v
# Shows DEBUG-level diagnostics: optional-parser failures, per-file scan errors
```

---

## 17. Advanced Commands Reference

STCA has 73+ commands. Here are the most useful ones beyond `check`:

### Analysis commands

```bash
stca taint --repo .                # Interprocedural taint tracking (Python)
stca cpg --repo .                  # Code Property Graph queries (Joern-style)
stca nullness --repo .             # Sound nullness analysis (NilAway-inspired)
stca typestate --repo .            # State machine violation detection
stca symbolic --repo .             # Z3 symbolic execution + abstract interpretation
stca metamorphic --repo .          # Oracle-free bug detection
stca differential --repo .         # Refactor verification (old vs new)
stca concurrency --repo .          # Async/concurrency bug detection
stca crypto --repo .               # Cryptographic correctness audit
stca code-quality --repo .         # 111+ multi-language quality rules
stca duplicates --repo .           # Find duplicated code blocks
stca deadcode --repo .             # Runtime dead code analysis
stca toxicity --repo .             # Code toxicity (nocuous/codehawk-inspired)
stca consistency --repo .          # Codebase consistency (credo-inspired)
stca architecture --repo .         # Architecture enforcement (rev-dep-inspired)
stca contracts --repo .            # Design-by-contract analysis (deal-inspired)
stca doc-audit --repo .            # Documentation audit (Valknut-inspired)
stca ffi-check --repo .            # Cross-language FFI boundary analysis
```

### Security commands

```bash
stca iac --repo .                  # Terraform/Dockerfile/K8s scanner (71 rules)
stca pii --repo .                  # PII detection (pii-shield-inspired)
stca malicious --repo .            # Malicious package patterns (aura-inspired)
stca missing-patches --repo .      # Missing security patches (Vanir-inspired)
stca modern --repo .               # Modern attack surfaces (LLM, GraphQL, etc.)
stca history-scan --repo .         # Scan git history for leaked secrets
stca pysa --repo .                 # Pysa (Meta OSS) taint analysis
stca maven-cve --repo .            # Scan pom.xml for Maven CVEs
stca supply-chain --repo .         # Dependency CVEs, typosquats, EOL, licenses
```

### Management commands

```bash
stca init --repo .                 # Create .stca.yaml config
stca install-tools                 # Auto-install gitleaks, semgrep, etc.
stca doctor                        # Check what tools are available
stca baseline --repo . show        # Manage the issue baseline
stca audit --repo . show           # Tamper-evident audit log
stca issue --repo . list           # Issue store (CodeChecker-inspired)
stca hotspot --repo . list         # Security hotspots (SonarQube-style)
stca cache --repo . clear          # Function-level result cache
stca strictness --repo .           # Show/set strictness level
stca profile --repo .              # Configuration profiles
stca rules --repo .                # Manage rule packs (Semgrep + Rego)
stca suppressions --repo .         # Inline suppressions
stca feedback --repo .             # Track precision/recall
stca tuning                        # FIS auto-tuning
```

### Utility commands

```bash
stca sbom --repo .                 # Generate SBOM (CycloneDX/SPDX)
stca dashboard --repo .            # Generate HTML dashboard
stca fix --repo .                  # Apply auto-fixes
stca pre-commit --repo .           # Run as pre-commit hook
stca watch --repo .                # Watch and re-scan on save
stca lsp                           # Language server (VS Code/Neovim integration)
stca bootstrap                     # One-time setup (invariant inference, etc.)
stca optimize --repo .             # Parallel scan with file-level cache
stca trace --repo .                # Trace a finding's lifecycle
stca rca --repo .                  # Root cause analysis (Vitrage-inspired)
stca impact --repo .               # Impact analysis (gossiphs-inspired)
stca similar --repo .              # Find similar code snippets
stca source-discovery --repo .     # Discover taint sources
stca llm-verify --repo .           # LLM-as-oracle with verified reasoning
stca gnn --repo .                  # GNN-on-CPG scoring
```

### Update commands

```bash
stca update-cves                   # Update CVE database from OSV.dev
stca rule-lint                     # Lint custom rule files
```

---

## 18. Troubleshooting

### "Not a git repo"

```
Error: Not a git repo: /path/to/repo
```

**Cause**: STCA needs a git repo (it analyzes diffs by default).
**Fix**: Either `git init` the directory, or use `--full` for a full-repo scan.

### "atheris not installed" (L4 fuzzing)

**Cause**: atheris only works on Linux. On Windows/macOS, STCA automatically uses its built-in pure-Python fuzzer.
**Fix**: No action needed — STCA handles this automatically. The `L4.fuzz.backend` INFO finding tells you which backend is active.

### Too many findings (overwhelming)

**Fix 1**: Use a lower strictness level:
```bash
stca check --repo . --full --strictness 1   # critical only
```

**Fix 2**: Use baseline mode (only new issues):
```bash
stca check --repo . --full --baseline
```

**Fix 3**: Filter by severity in the JSON output:
```bash
stca check --repo . --full --json | python -c "
import json, sys
data = json.load(sys.stdin)
critical = [f for f in data['findings'] if f['severity'] == 'critical']
print(f'{len(critical)} critical findings:')
for f in critical:
    print(f'  {f[\"rule_id\"]} at {f[\"file\"]}:{f[\"start_line\"]}')
"
```

### Scanner failures (previously silent)

**Symptom**: Yellow banner in TUI: "⚠ N scanner(s) failed"
**Cause**: A scanner encountered an error (missing import, parse error, network issue).
**Diagnosis**:
```bash
stca check --repo . --full --detailed -v
# The -v flag shows DEBUG-level diagnostics
# The --detailed flag shows the full Scanner Health table
```
**Fix**: Read the error message in the Scanner Health table. Common causes:
- Missing optional dependency → `pip install -e ".[layer-name]"`
- Malformed source file → fix the file
- Network issue (OSV.dev) → check internet connection or use cached data

### Scan is slow

**Fix 1**: Use diff mode instead of full-repo:
```bash
stca check --repo . --base main    # only scan the diff
```

**Fix 2**: Use a lower strictness level:
```bash
stca check --repo . --full --strictness 3   # skips L4-L7
```

**Fix 3**: Use the file-level cache:
```bash
stca optimize --repo .             # parallel scan with caching
```

**Fix 4**: Disable slow layers in `.stca.yaml`:
```yaml
layers:
  L6_symbolic: { enabled: false, timeout_seconds: 120 }
  L7_simulation: { enabled: false, timeout_seconds: 300 }
```

### Too many false positives

**Fix 1**: Use baseline mode to suppress known issues:
```bash
stca check --repo . --full --baseline
```

**Fix 2**: Use the feedback loop to train the FP learner:
```bash
stca feedback --repo . mark-fp <fingerprint>   # mark as false positive
stca feedback --repo . stats                   # see precision/recall
```

**Fix 3**: Suppress inline:
```python
# stca-ignore-next-line
eval(user_input)  # STCA won't flag this
```

**Fix 4**: Use the precision engine:
```bash
stca precision --repo .           # rule mining, FP learning, calibration
```

### Config not being picked up

**Cause**: STCA looks for `.stca.yaml` in the repo root.
**Fix**:
```bash
stca init --repo . --force        # recreate with defaults
# Edit .stca.yaml, then verify:
stca strictness --repo .          # should show your level
```

### Reports not being generated

**Cause**: Reports go to `<repo>/.stca-reports/`.
**Fix**:
```bash
ls .stca-reports/                 # should have report.html, result.json, result.sarif
stca dashboard --repo .           # generate dashboard.html
```

### LLM tie-breaker not working

**Cause**: Ollama not running or model not pulled.
**Fix**:
```bash
ollama list                       # verify model is available
ollama serve                      # start Ollama server
# Test the endpoint:
curl http://localhost:11434/api/generate -d '{"model":"qwen3-coder-1.5b","prompt":"test"}'
```

---

## 19. How It Works Internally

### Pipeline flow

```
git diff (or full repo)
   │
   ▼
[tree-sitter diff slicer] — Python, JS/TS, Go, Java, C, C++
   │
   ├─► L0  Fast hooks + multi-language linters + bundled Semgrep rule packs (88 rules)
   ├─► L0  CPG-based cross-file taint tracking
   ├─► L0  Typestate analysis (state machine violations)
   ├─► L0  Nullness analysis (NilAway-inspired)
   ├─► L0  Modern attack surface detection (LLM, GraphQL, SSRF, etc.)
   ├─► L0  Code quality (111+ rules)
   ├─► L0  Interprocedural taint tracking
   ├─► L0  JS pattern scanner (12 multi-line matchers)
   ├─► L0  JS CPG taint tracking (cross-file XSS/injection)
   ├─► L0  Missing security patches (Vanir-inspired)
   ├─► L0  Malicious package patterns (aura-inspired)
   ├─► L0  Flawfinder (C/C++ dangerous functions)
   ├─► L0  Design-by-contract verification (deal-inspired)
   ├─► L0  PII detection (pii-shield-inspired)
   ├─► L0  Architecture enforcement (rev-dep-inspired)
   ├─► L0  Documentation audit (Valknut-inspired)
   ├─► L0  HTML/config scanner (CSP, security headers, .env secrets)
   ├─► L0  Counterfactual mutation FP filtering
   ├─► L0  Tree-sitter AST analysis
   ├─► L0b Supply chain (CVEs, typosquats, EOL, licenses)
   ├─► L0c Dependencies (outdated, deprecated)
   ├─► L0d Behavioral (churn, hotspots, commit risk)
   ├─► L0e IaC (Terraform, Dockerfile, K8s — 71 rules)
   ├─► L0f Commit risk (secret leaks in history)
   ├─► L1  Property tests (Hypothesis)
   ├─► L2  Mutation testing (mutmut)
   ├─► L3  Invariant verification
   ├─► L4  Directed fuzzing (atheris or pure-Python, Python only)
   ├─► L5  Policy enforcement (OPA/Rego)
   ├─► L6  Symbolic verification (Z3, Kani for Rust)
   ├─► L7  Concurrency simulation
   │
   ▼
[Counterfactual mutation FP filter] — mutates code, re-runs detector
   │
   ▼
[Precision pipeline] — FP learner + confidence calibrator + corroboration
   │
   ▼
[IT2-FIS aggregator] — type-2 fuzzy inference system
   │  inputs: severity, confidence, source reliability, corroboration
   │  output: BLOCK / WARN / PASS / UNCERTAIN
   ▼
[Optional LLM tie-breaker] — for UNCERTAIN findings only
   │  LLM proposes hypothesis → STCA verifies by execution
   ▼
[Issue store] — tamper-evident, tracks new vs recurring issues
   │
   ▼
[Reports] — TUI + JSON + SARIF + HTML
```

### The IT2-FIS aggregator

Each finding gets 4 inputs scored 0-1:
- **Severity**: critical=0.95, high=0.75, medium=0.50, low=0.30, info=0.10
- **Confidence**: the layer's self-reported confidence
- **Source reliability**: historical precision/recall of the layer
- **Corroboration**: did other layers find the same issue?

The FIS applies fuzzy rules like:
- "If severity is high AND confidence is certain → at least warn"
- "If severity is high AND confidence is indirect → warn"
- "If severity is low AND confidence is speculative → pass"

The output is an **interval** [lower, upper] (type-2 fuzzy), and the midpoint determines the decision:
- midpoint < 0.3 → PASS
- 0.3 ≤ midpoint < 0.6 → WARN
- midpoint ≥ 0.6 → BLOCK
- If upper - lower > 0.4 → UNCERTAIN (triggers LLM tie-breaker)

### Scanner health tracking

Every scanner failure is:
1. Logged via Python's `logging` module (WARNING level)
2. Appended to `Orchestrator._scanner_health` list
3. Copied to `PipelineResult.scanner_health` at the end of the run
4. Surfaced in TUI/JSON/SARIF/HTML reports

This ensures previously-silent failures are visible.

---

## 20. Glossary

| Term | Definition |
|------|-----------|
| **IT2-FIS** | Interval Type-2 Fuzzy Inference System — the aggregator that scores findings |
| **CPG** | Code Property Graph — merges AST + CFG + PDG into one graph (Joern-style) |
| **Taint tracking** | Following data from source (user input) to sink (eval, SQL, etc.) |
| **Typestate** | State machine analysis — e.g., file must be opened before reading |
| **Metamorphic testing** | Oracle-free testing — e.g., `sort(sort(x)) == sort(x)` |
| **Differential testing** | Comparing old vs new function behavior after a refactor |
| **PRM** | Process Reward Model — scores LLM reasoning quality |
| **SBOM** | Software Bill of Materials — list of all dependencies |
| **SARIF** | Static Analysis Results Interchange Format — industry standard for static analysis output |
| **Strictness level** | PHPStan-inspired 1-9 scale controlling how many layers run |
| **Baseline** | Known-issues list — baseline mode only flags NEW issues |
| **Scanner health** | Tracking of scanner failures (v3.1+) so they're not silently swallowed |
| **Counterfactual mutation** | FP filtering — mutates the code, re-runs detector, if finding disappears it was a TP |
| **Corroboration** | Whether multiple layers found the same issue (boosts confidence) |
| **Blast radius** | How wide an impact the bug has: function, module, or system |
| **FuzzedDataProvider** | API for consuming bytes as typed values (string, int, float, etc.) — atheris-compatible |
| **Coverage-guided** | Fuzzer tracks which lines/branches execute, steers mutation toward uncovered code |
| **Dictionary mutation** | Fuzzer inserts known crash-triggering tokens (ADMIN, ../, ' OR 1=1--, etc.) |

---

## Quick Reference Card

```bash
# === Daily workflow ===
stca check --repo . --full                          # full scan (default minimal output)
stca check --repo . --base main                     # diff scan (PR review)
stca check --repo . --staged                        # staged changes (pre-commit)
stca check --repo . --full --detailed               # full findings in terminal
stca check --repo . --full --json > report.json     # JSON for CI
stca check --repo . --full --quiet                  # just the decision

# === Strictness ===
stca strictness --repo .                            # show current level
stca strictness --repo . --level 7                  # set level
stca check --repo . --full --strictness 9           # override per-run

# === Baseline ===
stca check --repo . --full                          # establish baseline
stca check --repo . --full --baseline               # only new issues

# === Reports ===
stca dashboard --repo .                             # HTML dashboard
cat .stca-reports/result.json | python -m json.tool # view JSON
# .stca-reports/result.sarif                        # for VS Code / GitHub

# === Scanner health ===
stca check --repo . --full --strict-scanners        # exit 3 on scanner errors
stca check --repo . --full -v                       # DEBUG logging

# === Auto-fix ===
stca fix --repo .                                   # stage fixes for review
stca fix --repo . --apply                           # apply directly

# === Setup ===
stca init --repo .                                  # create .stca.yaml
stca install-tools                                  # install gitleaks, semgrep, etc.
stca doctor                                         # check what's installed

# === LLM tie-breaker ===
ollama pull qwen3-coder-1.5b                        # pull model
# Set llm.enabled: true in .stca.yaml
stca check --repo . --full                          # LLM invoked for UNCERTAIN findings
```

---

**STCA Pipeline v3.2** — 235 tests passing, 73+ commands, 8 analysis layers, cross-platform. For questions, run `stca <command> --help` on any command.
