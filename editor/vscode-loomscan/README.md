# LoomScan — VS Code Extension

Real-time squiggles from LoomScan (Static + Test + Constraint Analysis) in your editor.

## Installation

### From source (development)

1. Install LoomScan:
   ```bash
   pip install loomscan
   ```

2. Build and run the extension:
   ```bash
   cd editor/vscode-loomscan
   npm install
   npm run compile
   ```
   Open the folder in VS Code and press `F5` to launch an Extension Development Host.

### From Marketplace (when published)

1. Open the Extensions panel in VS Code (`Ctrl+Shift+X` / `Cmd+Shift+X`)
2. Search for "LoomScan"
3. Click Install

## Features

### Real-time diagnostics
LoomScan runs on every save and surfaces findings as squiggles in your editor:
- **Critical/High**: red squiggle
- **Medium**: yellow squiggle
- **Low**: blue info

Each diagnostic shows:
- Rule ID (e.g., `L0.sast.mini:py-eval`)
- Message describing the issue
- CWE reference

### Commands
- `LoomScan: Run full check on repo` — runs `loomscan check --full` and streams output
- `LoomScan: Check current file` — re-analyzes the active file immediately
- `LoomScan: Apply auto-fix for current finding` — runs `loomscan fix --apply` for the finding on the current line
- `LoomScan: Show uncertain findings (30-70% confidence)` — toggles showing only the findings worth human review
- `LoomScan: Restart LSP server` — restarts the underlying LoomScan LSP process

### Configuration
- `loomscan.enabled` — turn diagnostics on/off (default: `true`)
- `loomscan.pythonPath` — path to Python that has `loomscan` installed (default: `python`)
- `loomscan.strictness` — 1-9, higher = more findings (default: `5`)
- `loomscan.debounceMs` — debounce interval for save-triggered analysis (default: `500`)
- `loomscan.showUncertainOnly` — only show 30-70% confidence findings (default: `false`)

## Languages Supported
Python, JavaScript, TypeScript, Go, Java, Rust, C, C++, PHP, Ruby, C#, Swift, Scala.

## How it works

The extension spawns `loomscan lsp --repo <root>` as a subprocess. The LoomScan LSP server
speaks LSP 3.17 over stdio and pushes `textDocument/publishDiagnostics` notifications
back to the editor.

For v4.34, the extension also has a fallback path that runs `loomscan check --full --json`
on each save (more reliable than the LSP server which is still maturing).

## License
MIT
