package com.loomscan.pipeline.lsp

import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.VirtualFile
import com.intellij.platform.lsp.api.LspServerSupportProvider
import com.intellij.platform.lsp.api.ProjectLspServerManager

/**
 * LSP server support for LoomScan.
 *
 * This connects IntelliJ's built-in LSP support (IntelliJ 2023.1+) to the
 * `loomscan lsp` server. IntelliJ handles the LSP protocol, file watching, and
 * diagnostic rendering; we just spawn the server and tell IntelliJ which
 * files to feed it.
 *
 * v4.37: Mirror of the VS Code extension's LSP integration.
 */
class LoomScanLspServerSupport : LspServerSupportProvider() {

    override fun fileOpened(project: Project, file: VirtualFile, serverManager: ProjectLspServerManager) {
        if (!isLoomScanSupportedFile(file)) return
        serverManager.startServerIfNeeded(file)
    }

    override fun createServerDescriptor(project: Project, ideaLspServerManager: ProjectLspServerManager): LspServerDescriptor? {
        val settings = com.loomscan.pipeline.settings.LoomScanSettingsService.getInstance()
        if (!settings.state.stcaEnabled) return null

        val pythonPath = settings.state.pythonPath.ifEmpty { "python" }
        val projectRoot = project.basePath ?: return null

        return object : LspServerDescriptor(project, "LoomScan") {
            override fun getLanguageId(file: VirtualFile): String {
                return languageIdForFile(file) ?: super.getLanguageId(file)
            }

            override fun createCommandLine(): com.intellij.execution.configurations.GeneralCommandLine {
                return com.intellij.execution.configurations.GeneralCommandLine(
                    pythonPath,
                    "-c",
                    "from loomscan.cli import main; main()",
                    "lsp",
                    "--repo",
                    projectRoot
                ).withWorkDirectory(projectRoot)
            }

            override fun getFilePath(file: VirtualFile): String {
                return file.path.removePrefix("$projectRoot/")
            }

            override fun isSupportedFile(file: VirtualFile): Boolean {
                return isLoomScanSupportedFile(file)
            }
        }
    }

    companion object {
        private val SUPPORTED_EXTENSIONS = setOf(
            "py", "js", "jsx", "ts", "tsx", "go", "java", "rs",
            "c", "cpp", "cc", "h", "hpp", "php", "phtml", "rb",
            "cs", "swift", "scala", "kt", "kts", "sql", "sh", "bash",
            "zsh", "ksh", "dart", "lua", "r", "R", "hs", "lhs", "ex", "exs"
        )

        fun isLoomScanSupportedFile(file: VirtualFile): Boolean {
            val ext = file.extension?.lowercase() ?: return false
            return ext in SUPPORTED_EXTENSIONS
        }

        fun languageIdForFile(file: VirtualFile): String? {
            val ext = file.extension?.lowercase() ?: return null
            return when (ext) {
                "py" -> "python"
                "js", "jsx" -> "javascript"
                "ts", "tsx" -> "typescript"
                "go" -> "go"
                "java" -> "java"
                "rs" -> "rust"
                "c", "h" -> "c"
                "cpp", "cc", "hpp" -> "cpp"
                "php", "phtml" -> "php"
                "rb" -> "ruby"
                "cs" -> "csharp"
                "swift" -> "swift"
                "scala" -> "scala"
                "kt", "kts" -> "kotlin"
                "sql" -> "sql"
                "sh", "bash", "zsh", "ksh" -> "shell"
                "dart" -> "dart"
                "lua" -> "lua"
                "r" -> "r"
                "hs", "lhs" -> "haskell"
                "ex", "exs" -> "elixir"
                else -> null
            }
        }
    }
}
