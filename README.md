# STCA Pipeline — Static + Test + Constraint Analysis

> **v4.43** — A deterministic-first, type-2 fuzzy aggregated bug detection pipeline with **1,995 rules across 39 packs covering 24 languages**, **107 auto-fix patterns**, **275 secret detection patterns**, **9 unique differentiators**, and **77 CLI commands**. Free, offline, and production-ready.

## Quick Start

```bash
# Install
pip install -e .

# Verify installation
stca doctor

# Scan a git diff
stca check

# Scan the full repo
stca check --full

# Get JSON output
stca check --full --json

# Run quality gate (SonarQube-style)
stca gate --full --preset strict

# Apply auto-fixes
stca fix --apply
```

## What Makes STCA Unique

STCA has **9 capabilities no competitor offers**:

| # | Feature | What It Does |
|---|---------|-------------|
| 1 | **IT2-FIS Brain** | Type-2 fuzzy inference system with 50 rules. Produces confidence *intervals* (not point estimates). Aggregates severity, confidence, blast radius, exploitability, and source-layer reliability into BLOCK/WARN/PASS/UNCERTAIN decisions. |
| 2 | **LLM-Verify** | LLM proposes hypotheses ("function crashes on None input"); STCA verifies by *execution*. Only confirmed bugs are reported. PRM-gated (process reward model scores the LLM's reasoning). |
| 3 | **Counterfactual Mutation** | Mutates the code (removes lines, injects guards) and re-runs detectors. If the finding disappears → true positive (boost confidence). If it persists → false positive (demote). |
| 4 | **Metamorphic Testing** | Oracle-free bug detection: `sort(sort(x)) == sort(x)`, `hash(x) == hash(x)`. Catches semantic bugs no test oracle can. |
| 5 | **Knowledge Graph** | Builds a codebase structure graph (1,400+ nodes for a typical project). `stca impact --changed file.py` shows blast radius (which functions are affected by your change). |
| 6 | **Rule Auto-Mining** | `stca mine` scans git history for bug-fix commits and auto-generates Semgrep rules from the diff. Every bug you've ever fixed becomes a permanent rule. |
| 7 | **Spec Mining** | `stca spec` mines API usage patterns from your codebase (e.g., "open() is always followed by close()") and flags deviations. Adaptive — learns from your code, not from generic rules. |
| 8 | **--uncertain Flag** | `stca check --uncertain` shows only 30-70% confidence findings — the ones worth human review. No competitor has this. |
| 9 | **9-Level Strictness** | PHPStan-inspired strictness levels (1-9). Level 1 = only critical findings; Level 9 = everything including style issues. |

## Rule Coverage

| Category | Count | Details |
|----------|-------|---------|
| **YAML pack rules** | 1,995 | 39 packs across 24 languages |
| **Secret patterns** | 275 | AWS, Stripe, GitHub, Slack, OpenAI, Anthropic, GCP, Azure, +200 more |
| **Auto-fix patterns** | 107 | Python, JS, Java, Go, C/C++, Rust, PHP, Ruby, C#, Kotlin, SQL, Bash, Dart, Swift, Scala |
| **CPG queries** | 6 | Taint flows, unused variables, auth patterns, complexity, def-use chains, cross-function taint |
| **Taint sinks** | 28 | Cross-file source→sink patterns |
| **Typestate protocols** | 5 | File, connection, payment, session, transaction |

## Supported Languages (24)

Python, JavaScript, TypeScript, Go, Java, Rust, C, C++, PHP, Ruby, C#, Swift, Scala, Kotlin, SQL, Bash, Dart, Lua, R, Haskell, Elixir, Objective-C, Groovy, Julia, Perl, COBOL

## CLI Commands (77)

### Core
```bash
stca check [--full] [--json] [--sarif --output file] [--strictness N] [--uncertain]
stca gate [--full] [--preset strict|balanced|permissive|custom] [--max-critical N] [--max-high N]
stca fix [--apply] [--finding-id ID]
stca init / install-tools / doctor
```

### IDE Integration
```bash
stca lsp                    # Start LSP server (VS Code / JetBrains / Neovim)
stca watch                  # Incremental scanning with sub-second feedback
stca playground             # Web UI for testing regex rules (localhost:8765)
```

### Analysis
```bash
stca cpg --query taint|unused|auth|complexity|def_use|cross_func
stca typestate             # State machine violations
stca metamorphic           # Oracle-free bug detection
stca differential          # Refactor verification
stca llm-verify            # LLM proposes, STCA verifies by execution
stca impact --changed file.py  # Blast radius analysis
stca spec                  # Spec mining (adaptive API pattern learning)
stca mine                  # Rule auto-mining from git history
```

### Rules
```bash
stca rules list             # List all 39 built-in packs
stca rules show <pack>      # Show rules in a pack
stca rules pull <pack>      # Pull external pack
stca rules submit --pack my-rules.yml --name my-pack --language python  # Submit community rules
```

### CI/CD
```bash
stca bot --pr 42 --token $GITHUB_TOKEN  # PR comment bot (inline review comments)
stca check --sarif --output stca.sarif   # SARIF for GitHub Code Scanning
stca gate --preset strict                 # Quality gate (exit 0=pass, 1=fail)
```

### Quality
```bash
stca strictness --level N   # Set strictness (1-9)
stca code-quality           # Multi-language code quality
stca config-scan            # Scan config files for secrets
stca duplicates             # Code duplication detection
stca deadcode               # Dead code analysis
stca hotspot                # Security hotspot detection
```

## IDE Extensions

### VS Code
```bash
code --install-extension editor/vscode-stca/stca-0.2.0.vsix
```
- Real-time diagnostics via LSP
- Hover shows rule details + fix suggestions
- Code actions: "Apply STCA fix" (quickfix)
- 6 commands: CheckRepo, CheckFile, ApplyFix, ShowUncertain, Gate, Restart
- 17 language activations

### JetBrains (IntelliJ, PyCharm, WebStorm, etc.)
```bash
cd editor/intellij-stca && ./gradlew buildPlugin
# Install: Settings > Plugins > Install from Disk > build/distributions/*.zip
```
- LSP support via IntelliJ 2023.1+ platform
- 7 actions, settings panel, tool window, status bar widget
- CI builds automatically via `.github/workflows/build-jetbrains.yml`

## Architecture

```
git diff / --full
   │
   ├─► L0  Fast hooks (1,995 YAML rules + 275 secret patterns + 107 autofix)
   ├─► L0  CPG cross-file taint tracking + def-use chains
   ├─► L0  Typestate analysis (5 protocols)
   ├─► L0  Spec mining (adaptive API pattern learning)
   ├─► L0b Supply chain (pip-audit, npm audit, osv-scanner, cargo audit, govulncheck)
   ├─► L0e IaC scanning (Dockerfile, K8s, Terraform, CloudFormation, GitHub Actions)
   ├─► L0f Commit risk (size, time, message, author, reverts)
   ├─► L1  Property tests (Hypothesis) + Metamorphic tests + Differential tests
   ├─► L2  Mutation testing (mutmut)
   ├─► L3  Invariant checks (Daikon-style)
   ├─► L4  Directed greybox fuzz (Atheris)
   ├─► L5  Policy-as-code (OPA/Rego)
   ├─► L6  Symbolic verification (Kani for Rust)
   ├─► L7  Deterministic simulation
   ├─► L8  Auto-Fix (107 patterns across 15 languages)
   │
   ▼
┌─────────────────────────────────────────────────────┐
│  IT2-FIS Aggregation Brain (50 fuzzy rules)         │
│  + Bayesian second opinion (BBN with CPTs)          │
│  + Counterfactual mutation verification             │
│  + LLM-as-oracle (PRM-gated, execution-verified)    │
│  Output: BLOCK / WARN / PASS / UNCERTAIN            │
│  + Confidence intervals (not point estimates)       │
└─────────────────────────────────────────────────────┘
   │
   ▼
SARIF 2.1.0 + Rich TUI + HTML + JSON + CycloneDX SBOM + SPDX SBOM
```

## Quality Gates (SonarQube-style)

```bash
# Presets
stca gate --full --preset strict       # 0 critical, 0 high, 5/1k LOC
stca gate --full --preset balanced     # 0 critical, 5 high, 10/1k LOC (DEFAULT)
stca gate --full --preset permissive   # 5 critical, 20 high, 20/1k LOC
stca gate --full --preset custom --max-critical 0 --max-high 10

# Exit codes: 0=pass, 1=fail, 2=error, 3=scanner failure
```

## Monorepo Support

```yaml
# .stca.yaml
workspaces:
  - "apps/*"
  - "packages/*"
workspace_exclude:
  - "**/node_modules/**"
```

```bash
stca monorepo --list     # List resolved workspaces
stca monorepo --scan     # Scan each workspace, report findings
stca monorepo --add 'services/*'
```

## GitHub Actions Integration

```yaml
# .github/workflows/stca.yml
- name: Install STCA
  run: pip install --user .
- name: Run STCA
  run: stca check --sarif --output stca.sarif --strictness 5
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: stca.sarif
```

```yaml
# .github/workflows/stca-bot.yml — PR comment bot
- name: Run STCA PR Bot
  run: stca bot --token ${{ secrets.GITHUB_TOKEN }}
```

## Competitive Position

| Axis | STCA v4.43 | Semgrep | SonarQube | CodeQL |
|------|-----------|---------|-----------|--------|
| Total rules | ~2,700 | 3,000+ | 5,000+ | 1,500+ |
| Languages | 24 | 30+ | 30+ | 6 (deep) |
| Auto-fix | 107 | ~50 | ~200 | ❌ |
| Secrets | 275 | 200+ | enterprise | ❌ |
| FIS aggregation | ✅ | ❌ | ❌ | ❌ |
| LLM-verify | ✅ | ❌ | ❌ | ❌ |
| Rule mining | ✅ | ❌ | ❌ | ❌ |
| Spec mining | ✅ | ❌ | ❌ | ❌ |
| Free + offline | ✅ | ✅ CE | ⚠️ limits | ✅ |
| IDE plugins | VS Code + JetBrains | ✅ | SonarLint | ❌ |

## Test Suite

- **717 tests passed**, 35 skipped (tree-sitter grammars), 0 failed
- 291 smoke tests across v4.33-v4.43
- E2E tests for: SARIF, cross-file taint, max-files override, Docker healthcheck, LSP hover/code actions, spec mining, def-use chains, fast_regex, rules submit, PR bot, playground, monorepo

## License

MIT.
