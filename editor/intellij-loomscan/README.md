# LoomScan — IntelliJ / JetBrains Extension

Real-time squiggles, quality gates, auto-fix, and rule mining for 20+ languages. Connects to the LoomScan LSP server.

## Supported IDEs

- IntelliJ IDEA (Community + Ultimate) 2023.1+
- PyCharm (Community + Professional) 2023.1+
- WebStorm 2023.1+
- GoLand 2023.1+
- RubyMine 2023.1+
- PhpStorm 2023.1+
- CLion 2023.1+
- Android Studio 2023.1+
- Rider 2023.1+

## Installation

### From source (development)

1. Install LoomScan:
   ```bash
   pip install loomscan
   ```

2. Build and run the extension:
   ```bash
   cd editor/intellij-loomscan
   ./gradlew buildPlugin
   ```
   The plugin zip will be at `build/distributions/loomscan-intellij-0.1.0.zip`.

3. Install in IntelliJ:
   - File > Settings > Plugins > ⚙️ > Install Plugin from Disk
   - Select the zip file
   - Restart IntelliJ

### From JetBrains Marketplace (when published)

1. Open Settings > Plugins
2. Search for "LoomScan"
3. Click Install

## Features

### Real-time diagnostics
Uses IntelliJ's built-in LSP support (2023.1+) to talk to the `loomscan lsp` server. Diagnostics appear as squiggles in your editor.

### Commands (Tools menu > LoomScan)
- **Run Full Check on Repo** — runs `loomscan check --full` and streams output to the LoomScan tool window
- **Check Current File** — re-analyzes the active file
- **Apply Auto-fix** — runs `loomscan fix --apply` for a specific finding fingerprint
- **Toggle Uncertain Findings (30-70%)** — only show findings worth human review
- **Run Quality Gate** — runs `loomscan gate` with the configured preset (strict/balanced/permissive/custom)
- **Mine Rules from Git History** — auto-derives Semgrep rules from bug-fix commits
- **Restart LSP Server** — restarts the underlying LoomScan LSP process

### Settings (Settings > Tools > LoomScan)
- `stcaEnabled` — turn diagnostics on/off (default: `true`)
- `pythonPath` — path to Python that has `loomscan` installed (default: `python`)
- `strictness` — 1-9, higher = more findings (default: `5`)
- `debounceMs` — debounce interval for save-triggered analysis (default: `500`)
- `showUncertainOnly` — only show 30-70% confidence findings (default: `false`)
- `useLsp` — use LSP server (true) or fall back to CLI (false) (default: `true`)
- `gatePreset` — strict/balanced/permissive/custom (default: `balanced`)
- `gateMaxCritical` / `gateMaxHigh` — used only when preset=custom

### Tool Window
Window > Tool Windows > LoomScan — shows:
- **Output** tab: streamed stdout/stderr from `loomscan check`/`gate`/`mine`
- **Findings** tab: clickable list of current findings

### Status Bar Widget
Shows the current LoomScan status (idle/scanning/findings count).

## Languages Supported
Python, JavaScript, TypeScript, Go, Java, Rust, C, C++, PHP, Ruby, C#, Swift, Scala, Kotlin, SQL, Bash, Dart, Lua, R, Haskell, Elixir (20 languages).

## How it works

The extension uses IntelliJ's `platform.lsp.serverSupport` extension point (available since 2023.1). IntelliJ handles the LSP protocol, file watching, and diagnostic rendering. The extension just spawns `loomscan lsp --repo <project_root>` as a subprocess and tells IntelliJ which files to feed it.

For older IntelliJ versions or when `useLsp=false`, the extension falls back to an `ExternalAnnotator` that runs `loomscan check --full --json` on each save.

## Architecture

```
editor/intellij-loomscan/
├── build.gradle.kts              # Gradle build config
├── loomscan.json                     # Plugin metadata
├── src/main/
│   ├── kotlin/com/loomscan/pipeline/
│   │   ├── lsp/                  # LSP server support
│   │   │   └── StcaLspServerSupport.kt
│   │   ├── action/               # 7 actions (CheckRepo, Gate, Mine, etc.)
│   │   │   └── StcaActions.kt
│   │   ├── settings/             # Settings state + UI
│   │   │   ├── StcaSettingsService.kt
│   │   │   └── StcaSettingsConfigurable.kt
│   │   ├── ui/                   # Tool window + status bar
│   │   │   ├── StcaToolWindowFactory.kt
│   │   │   ├── StcaOutputPanel.kt
│   │   │   ├── StcaFindingsPanel.kt
│   │   │   └── StcaStatusBarWidget.kt
│   │   ├── annotator/            # Fallback annotator (CLI mode)
│   │   │   └── StcaAnnotator.kt
│   │   ├── inspection/           # Batch-mode inspection
│   │   │   └── StcaInspection.kt
│   │   ├── icons/                # SVG icons
│   │   │   └── StcaIcons.kt
│   │   └── service/              # Project-level state
│   │       └── StcaService.kt
│   └── resources/
│       ├── META-INF/plugin.xml   # Plugin descriptor
│       └── icons/                # SVG icon files
```

## License
MIT
