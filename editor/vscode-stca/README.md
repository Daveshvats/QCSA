# STCA — VS Code Extension

Real-time squiggles from STCA (Static + Test + Constraint Analysis) in your editor.

## Installation

### From source (development)

1. Install STCA:
   ```bash
   pip install stca-pipeline
   ```

2. Build and run the extension:
   ```bash
   cd editor/vscode-stca
   npm install
   npm run compile
   ```
   Open the folder in VS Code and press `F5` to launch an Extension Development Host.

### From Marketplace (when published)

1. Open the Extensions panel in VS Code (`Ctrl+Shift+X` / `Cmd+Shift+X`)
2. Search for "STCA Pipeline"
3. Click Install

## Features

### Real-time diagnostics
STCA runs on every save and surfaces findings as squiggles in your editor:
- **Critical/High**: red squiggle
- **Medium**: yellow squiggle
- **Low**: blue info

Each diagnostic shows:
- Rule ID (e.g., `L0.sast.mini:py-eval`)
- Message describing the issue
- CWE reference

### Commands
- `STCA: Run full check on repo` — runs `stca check --full` and streams output
- `STCA: Check current file` — re-analyzes the active file immediately
- `STCA: Apply auto-fix for current finding` — runs `stca fix --apply` for the finding on the current line
- `STCA: Show uncertain findings (30-70% confidence)` — toggles showing only the findings worth human review
- `STCA: Restart LSP server` — restarts the underlying STCA LSP process

### Configuration
- `stca.enabled` — turn diagnostics on/off (default: `true`)
- `stca.pythonPath` — path to Python that has `stca` installed (default: `python`)
- `stca.strictness` — 1-9, higher = more findings (default: `5`)
- `stca.debounceMs` — debounce interval for save-triggered analysis (default: `500`)
- `stca.showUncertainOnly` — only show 30-70% confidence findings (default: `false`)

## Languages Supported
Python, JavaScript, TypeScript, Go, Java, Rust, C, C++, PHP, Ruby, C#, Swift, Scala.

## How it works

The extension spawns `stca lsp --repo <root>` as a subprocess. The STCA LSP server
speaks LSP 3.17 over stdio and pushes `textDocument/publishDiagnostics` notifications
back to the editor.

For v4.34, the extension also has a fallback path that runs `stca check --full --json`
on each save (more reliable than the LSP server which is still maturing).

## License
MIT
