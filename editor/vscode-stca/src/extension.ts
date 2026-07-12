'use strict';

import * as vscode from 'vscode';
import * as path from 'path';
import * as cp from 'child_process';
import { LanguageClient, LanguageClientOptions, ServerOptions, TransportKind } from 'vscode-languageclient/node';

let stcaClient: StcaLspClient | undefined;

export function activate(context: vscode.ExtensionContext) {
    console.log('STCA extension activating...');

    stcaClient = new StcaLspClient(context);
    stcaClient.start();

    // Commands
    context.subscriptions.push(
        vscode.commands.registerCommand('stca.checkRepo', () => stcaClient?.runRepoCheck()),
        vscode.commands.registerCommand('stca.checkFile', () => stcaClient?.runFileCheck()),
        vscode.commands.registerCommand('stca.applyFix', () => stcaClient?.applyFix()),
        vscode.commands.registerCommand('stca.showUncertain', () => stcaClient?.showUncertain()),
        vscode.commands.registerCommand('stca.gate', () => stcaClient?.runGate()),
        vscode.commands.registerCommand('stca.restart', async () => {
            await stcaClient?.dispose();
            stcaClient = new StcaLspClient(context);
            await stcaClient.start();
            vscode.window.showInformationMessage('STCA LSP server restarted.');
        }),
    );

    // Watch config changes
    context.subscriptions.push(
        vscode.workspace.onDidChangeConfiguration(e => {
            if (e.affectsConfiguration('stca')) {
                vscode.window.showInformationMessage('STCA: configuration changed — restart the server to apply.', 'Restart').then(choice => {
                    if (choice === 'Restart') {
                        vscode.commands.executeCommand('stca.restart');
                    }
                });
            }
        })
    );
}

export async function deactivate(): Promise<void> {
    if (stcaClient) {
        await stcaClient.dispose();
    }
}

/**
 * STCA LSP client — uses vscode-languageclient to talk to `stca lsp` over stdio.
 *
 * v4.36: Replaced the stubbed handleLspMessage() with the official
 * vscode-languageclient library. Real diagnostics now flow via LSP
 * textDocument/publishDiagnostics notifications.
 *
 * Fallback: if the LSP server fails to start (e.g., stca not installed),
 * the extension falls back to running `stca check --full --json` on each save.
 */
class StcaLspClient {
    private languageClient: LanguageClient | undefined;
    private diagnostics: vscode.DiagnosticCollection;
    private outputChannel: vscode.OutputChannel;
    private statusBarItem: vscode.StatusBarItem;
    private debounceTimer: ReturnType<typeof setTimeout> | undefined;
    private fallbackMode: boolean = false;

    constructor(private context: vscode.ExtensionContext) {
        this.diagnostics = vscode.languages.createDiagnosticCollection('stca');
        this.outputChannel = vscode.window.createOutputChannel('STCA');
        this.statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50);
        this.statusBarItem.text = 'STCA: starting...';
        this.statusBarItem.show();
    }

    async start(): Promise<void> {
        const config = vscode.workspace.getConfiguration('stca');
        if (!config.get<boolean>('enabled', true)) {
            this.statusBarItem.text = 'STCA: disabled';
            return;
        }

        if (config.get<boolean>('useLsp', true)) {
            try {
                await this.startLspServer();
                return;
            } catch (e: any) {
                this.outputChannel.appendLine(`LSP server failed to start: ${e.message}. Falling back to CLI mode.`);
                this.fallbackMode = true;
            }
        } else {
            this.fallbackMode = true;
        }

        if (this.fallbackMode) {
            this.startFallbackMode();
        }
    }

    private async startLspServer(): Promise<void> {
        const config = vscode.workspace.getConfiguration('stca');
        const pythonPath = config.get<string>('pythonPath', 'python');
        const repoRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || process.cwd();

        // Spawn `python -c "from stca.cli import main; main()" lsp --repo <root>`
        // (LSP over stdio via the STCA LSP server)
        const serverOptions: ServerOptions = {
            run: {
                command: pythonPath,
                args: ['-c', 'from stca.cli import main; main()', 'lsp', '--repo', repoRoot],
                transport: TransportKind.stdio,
            },
            debug: {
                command: pythonPath,
                args: ['-c', 'from stca.cli import main; main()', 'lsp', '--repo', repoRoot],
                transport: TransportKind.stdio,
            },
        };

        const clientOptions: LanguageClientOptions = {
            documentSelector: [
                { scheme: 'file', language: 'python' },
                { scheme: 'file', language: 'javascript' },
                { scheme: 'file', language: 'typescript' },
                { scheme: 'file', language: 'go' },
                { scheme: 'file', language: 'java' },
                { scheme: 'file', language: 'rust' },
                { scheme: 'file', language: 'c' },
                { scheme: 'file', language: 'cpp' },
                { scheme: 'file', language: 'php' },
                { scheme: 'file', language: 'ruby' },
                { scheme: 'file', language: 'csharp' },
                { scheme: 'file', language: 'swift' },
                { scheme: 'file', language: 'scala' },
                { scheme: 'file', language: 'kotlin' },
                { scheme: 'file', language: 'sql' },
                { scheme: 'file', language: 'shell' },
                { scheme: 'file', language: 'dart' },
            ],
            synchronize: {
                fileEvents: vscode.workspace.createFileSystemWatcher('**/*'),
            },
            outputChannel: this.outputChannel,
        };

        this.languageClient = new LanguageClient(
            'stca',
            'STCA Pipeline',
            serverOptions,
            clientOptions,
        );

        await this.languageClient.start();
        this.statusBarItem.text = 'STCA: ready (LSP)';
    }

    private startFallbackMode(): void {
        this.statusBarItem.text = 'STCA: ready (CLI fallback)';

        // Subscribe to document save events
        this.context.subscriptions.push(
            vscode.workspace.onDidSaveTextDocument((doc) => this.onDocumentSave(doc))
        );

        // Initial analysis of all open files
        vscode.workspace.textDocuments.forEach(doc => this.analyzeFile(doc));
    }

    async dispose(): Promise<void> {
        if (this.languageClient) {
            await this.languageClient.stop();
            this.languageClient = undefined;
        }
        this.diagnostics.dispose();
        this.outputChannel.dispose();
        this.statusBarItem.dispose();
    }

    private onDocumentSave(doc: vscode.TextDocument) {
        if (this.debounceTimer) {
            clearTimeout(this.debounceTimer);
        }
        const config = vscode.workspace.getConfiguration('stca');
        const debounceMs = config.get<number>('debounceMs', 500);
        this.debounceTimer = setTimeout(() => {
            this.analyzeFile(doc);
        }, debounceMs);
    }

    private analyzeFile(doc: vscode.TextDocument) {
        const config = vscode.workspace.getConfiguration('stca');
        const pythonPath = config.get<string>('pythonPath', 'python');
        const strictness = config.get<number>('strictness', 5);
        const repoRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || path.dirname(doc.uri.fsPath);

        const args = ['-c', 'from stca.cli import main; main()', 'check', '--full',
                      '--strictness', String(strictness), '--json'];

        try {
            const result = cp.spawnSync(pythonPath, args, {
                cwd: repoRoot,
                encoding: 'utf-8',
                timeout: 30000,
            });

            if (result.status !== 0 && result.status !== 1) {
                this.statusBarItem.text = `STCA: error (exit ${result.status})`;
                this.outputChannel.append(`STCA error: ${result.stderr}`);
                return;
            }

            try {
                const data = JSON.parse(result.stdout);
                this.renderDiagnostics(doc, data.findings || []);
                this.statusBarItem.text = `STCA: ${data.findings?.length || 0} findings`;
            } catch (e: any) {
                this.outputChannel.append(`STCA JSON parse error: ${e.message}\n${result.stdout.slice(0, 500)}`);
            }
        } catch (e: any) {
            this.outputChannel.append(`STCA spawn error: ${e.message}`);
        }
    }

    private renderDiagnostics(doc: vscode.TextDocument, findings: any[]) {
        const config = vscode.workspace.getConfiguration('stca');
        const showUncertainOnly = config.get<boolean>('showUncertainOnly', false);

        const filtered = showUncertainOnly
            ? findings.filter(f => f.confidence >= 0.3 && f.confidence <= 0.7)
            : findings;

        // Filter to findings in the current file
        const fileFindings = filtered.filter(f => {
            const fPath = vscode.Uri.file(f.file).fsPath;
            return fPath === doc.uri.fsPath;
        });

        const diags: vscode.Diagnostic[] = fileFindings.map(f => {
            const line = Math.max(0, (f.start_line || 1) - 1);
            const range = new vscode.Range(line, 0, line, 80);
            const severity = this.severityToVscode(f.severity);
            const diag = new vscode.Diagnostic(
                range,
                `[STCA ${f.rule_id}] ${f.message}`,
                severity,
            );
            diag.source = 'stca';
            diag.code = f.rule_id;
            return diag;
        });

        this.diagnostics.set(doc.uri, diags);
    }

    private severityToVscode(sev: string): vscode.DiagnosticSeverity {
        switch ((sev || '').toLowerCase()) {
            case 'critical':
            case 'high':
                return vscode.DiagnosticSeverity.Error;
            case 'medium':
                return vscode.DiagnosticSeverity.Warning;
            case 'low':
                return vscode.DiagnosticSeverity.Information;
            default:
                return vscode.DiagnosticSeverity.Hint;
        }
    }

    // Command handlers

    async runRepoCheck() {
        const config = vscode.workspace.getConfiguration('stca');
        const pythonPath = config.get<string>('pythonPath', 'python');
        const strictness = config.get<number>('strictness', 5);
        const repoRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
        if (!repoRoot) {
            vscode.window.showWarningMessage('STCA: open a folder to run a repo check.');
            return;
        }

        this.outputChannel.show();
        this.outputChannel.appendLine(`Running STCA check on ${repoRoot}...`);
        this.statusBarItem.text = 'STCA: running...';

        const proc = cp.spawn(pythonPath, ['-c', 'from stca.cli import main; main()',
                                            'check', '--full', '--strictness', String(strictness)],
                              { cwd: repoRoot });

        proc.stdout?.on('data', (d) => this.outputChannel.append(d.toString()));
        proc.stderr?.on('data', (d) => this.outputChannel.append(`[stderr] ${d}`));

        proc.on('exit', (code) => {
            this.outputChannel.appendLine(`STCA check finished (exit ${code}).`);
            this.statusBarItem.text = `STCA: done (exit ${code})`;
        });
    }

    async runFileCheck() {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showWarningMessage('STCA: open a file first.');
            return;
        }
        if (this.fallbackMode) {
            this.analyzeFile(editor.document);
        } else {
            vscode.window.showInformationMessage('STCA: LSP mode — diagnostics are already pushed in real-time.');
        }
    }

    async applyFix() {
        const editor = vscode.window.activeTextEditor;
        if (!editor) return;
        const diags = this.diagnostics.get(editor.document.uri) || [];
        const currentLine = editor.selection.active.line;
        const matching = diags.filter(d => d.range.start.line === currentLine);
        if (matching.length === 0) {
            vscode.window.showInformationMessage('STCA: no fix available on this line.');
            return;
        }
        const diag = matching[0];
        const choice = await vscode.window.showInformationMessage(
            `STCA: applying fix for ${diag.code}...`,
            'Apply',
            'Cancel',
        );
        if (choice !== 'Apply') return;

        const config = vscode.workspace.getConfiguration('stca');
        const pythonPath = config.get<string>('pythonPath', 'python');
        const repoRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
        const proc = cp.spawn(pythonPath, ['-c', 'from stca.cli import main; main()',
                                              'fix', '--apply', '--finding-id', String(diag.code)],
                             { cwd: repoRoot });
        proc.on('exit', (code) => {
            vscode.window.showInformationMessage(`STCA fix applied (exit ${code}). Reload the file to see changes.`);
        });
    }

    async showUncertain() {
        const config = vscode.workspace.getConfiguration('stca');
        await config.update('showUncertainOnly', !config.get<boolean>('showUncertainOnly', false),
                            vscode.ConfigurationTarget.Workspace);
        const newState = config.get<boolean>('showUncertainOnly', false);
        vscode.window.showInformationMessage(
            `STCA: ${newState ? 'showing only uncertain (30-70%) findings' : 'showing all findings'}`
        );
        if (this.fallbackMode) {
            vscode.workspace.textDocuments.forEach(doc => this.analyzeFile(doc));
        }
    }

    async runGate() {
        const config = vscode.workspace.getConfiguration('stca');
        const pythonPath = config.get<string>('pythonPath', 'python');
        const repoRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
        if (!repoRoot) {
            vscode.window.showWarningMessage('STCA: open a folder to run the gate.');
            return;
        }

        const preset = config.get<string>('gatePreset', 'balanced');
        const args: string[] = ['-c', 'from stca.cli import main; main()', 'gate', '--full'];
        if (preset === 'strict') {
            args.push('--max-critical', '0', '--max-high', '0', '--max-density', '5.0');
        } else if (preset === 'balanced') {
            args.push('--max-critical', '0', '--max-high', '5', '--max-density', '10.0');
        } else if (preset === 'permissive') {
            args.push('--max-critical', '5', '--max-high', '20', '--max-density', '20.0');
        } else {
            // custom — use stca.gateMaxCritical / stca.gateMaxHigh
            const maxCrit = config.get<number>('gateMaxCritical', 0);
            const maxHigh = config.get<number>('gateMaxHigh', 0);
            args.push('--max-critical', String(maxCrit), '--max-high', String(maxHigh));
        }

        this.outputChannel.show();
        this.outputChannel.appendLine(`Running STCA quality gate (preset: ${preset})...`);
        this.statusBarItem.text = 'STCA: gate running...';

        const proc = cp.spawn(pythonPath, args, { cwd: repoRoot });
        proc.stdout?.on('data', (d) => this.outputChannel.append(d.toString()));
        proc.stderr?.on('data', (d) => this.outputChannel.append(`[stderr] ${d}`));

        proc.on('exit', (code) => {
            this.outputChannel.appendLine(`STCA gate finished (exit ${code}).`);
            this.statusBarItem.text = `STCA: gate ${code === 0 ? 'passed' : 'failed'}`;
            if (code === 0) {
                vscode.window.showInformationMessage('STCA: quality gate PASSED');
            } else {
                vscode.window.showErrorMessage('STCA: quality gate FAILED — see output for details');
            }
        });
    }
}
