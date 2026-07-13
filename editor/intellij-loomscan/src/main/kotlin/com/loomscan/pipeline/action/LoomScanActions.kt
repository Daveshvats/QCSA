package com.loomscan.pipeline.action

import com.intellij.notification.NotificationGroupManager
import com.intellij.notification.NotificationType
import com.intellij.openapi.actionSystem.AnAction
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.diagnostic.logger
import com.intellij.openapi.project.Project
import com.intellij.openapi.ui.Messages
import com.loomscan.pipeline.settings.LoomScanSettingsService
import java.io.BufferedReader
import java.io.InputStreamReader

private val LOG = logger<LoomScanBaseAction>()

/**
 * Base class for LoomScan actions — handles Python path resolution, command spawning,
 * and output streaming to the LoomScan tool window.
 */
abstract class LoomScanBaseAction : AnAction() {

    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return
        val settings = LoomScanSettingsService.getInstance().state
        if (!settings.stcaEnabled) {
            notify(project, "LoomScan is disabled in settings.", NotificationType.WARNING)
            return
        }
        runLoomScanCommand(project, settings.pythonPath, buildArgs(project, settings))
    }

    /** Subclasses override to build the CLI args. */
    abstract fun buildArgs(project: Project, settings: com.loomscan.pipeline.settings.LoomScanSettingsState): List<String>

    /** Subclasses can override to handle output differently. */
    protected open fun onOutput(project: Project, line: String) {
        LOG.info("[loomscan] $line")
    }

    protected fun runLoomScanCommand(project: Project, pythonPath: String, args: List<String>) {
        val projectRoot = project.basePath ?: return
        val fullArgs = listOf(pythonPath, "-c", "from loomscan.cli import main; main()") + args
        ApplicationManager.getApplication().executeOnPooledThread {
            try {
                val pb = ProcessBuilder(fullArgs)
                pb.directory(java.io.File(projectRoot))
                pb.redirectErrorStream(true)
                val process = pb.start()
                val reader = BufferedReader(InputStreamReader(process.inputStream))
                var line: String?
                while (reader.readLine().also { line = it } != null) {
                    val l = line ?: continue
                    ApplicationManager.getApplication().invokeLater {
                        onOutput(project, l)
                    }
                }
                val exitCode = process.waitFor()
                ApplicationManager.getApplication().invokeLater {
                    onExit(project, exitCode)
                }
            } catch (e: Exception) {
                LOG.warn("LoomScan command failed", e)
                ApplicationManager.getApplication().invokeLater {
                    notify(project, "LoomScan failed: ${e.message}", NotificationType.ERROR)
                }
            }
        }
    }

    protected open fun onExit(project: Project, exitCode: Int) {
        if (exitCode != 0 && exitCode != 1) {
            notify(project, "LoomScan exited with code $exitCode", NotificationType.WARNING)
        }
    }

    protected fun notify(project: Project, message: String, type: NotificationType) {
        NotificationGroupManager.getInstance()
            .getNotificationGroup("LoomScan")
            .createNotification(message, type)
            .notify(project)
    }
}

/** loomscan check --full --strictness N */
class CheckRepoAction : LoomScanBaseAction() {
    override fun buildArgs(project: Project, settings: com.loomscan.pipeline.settings.LoomScanSettingsState) =
        listOf("check", "--full", "--strictness", settings.strictness.toString())
}

/** loomscan check --full --json (re-analyze, return JSON) */
class CheckFileAction : LoomScanBaseAction() {
    override fun buildArgs(project: Project, settings: com.loomscan.pipeline.settings.LoomScanSettingsState) =
        listOf("check", "--full", "--strictness", settings.strictness.toString(), "--json")
}

/** loomscan fix --apply --finding-id <id> */
class ApplyFixAction : LoomScanBaseAction() {
    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return
        val id = Messages.showInputDialog(
            project,
            "Finding ID (fingerprint):",
            "LoomScan Apply Fix",
            Messages.getQuestionIcon()
        ) ?: return
        if (id.isBlank()) return
        val settings = LoomScanSettingsService.getInstance().state
        runLoomScanCommand(project, settings.pythonPath, listOf("fix", "--apply", "--finding-id", id))
    }

    override fun buildArgs(project: Project, settings: com.loomscan.pipeline.settings.LoomScanSettingsState) =
        emptyList<String>()  // handled in actionPerformed override
}

/** Toggle showUncertainOnly setting. */
class ShowUncertainAction : AnAction() {
    override fun actionPerformed(e: AnActionEvent) {
        val state = LoomScanSettingsService.getInstance().state
        state.showUncertainOnly = !state.showUncertainOnly
        val project = e.project ?: return
        NotificationGroupManager.getInstance()
            .getNotificationGroup("LoomScan")
            .createNotification(
                "LoomScan: ${if (state.showUncertainOnly) "showing only uncertain (30-70%) findings" else "showing all findings"}",
                NotificationType.INFORMATION
            )
            .notify(project)
    }
}

/** loomscan gate --full --preset <preset> */
class GateAction : LoomScanBaseAction() {
    override fun buildArgs(project: Project, settings: com.loomscan.pipeline.settings.LoomScanSettingsState): List<String> {
        val args = mutableListOf("gate", "--full", "--preset", settings.gatePreset)
        if (settings.gatePreset == "custom") {
            args.add("--max-critical")
            args.add(settings.gateMaxCritical.toString())
            args.add("--max-high")
            args.add(settings.gateMaxHigh.toString())
        }
        return args
    }

    override fun onExit(project: Project, exitCode: Int) {
        when (exitCode) {
            0 -> notify(project, "LoomScan: quality gate PASSED", NotificationType.INFORMATION)
            1 -> notify(project, "LoomScan: quality gate FAILED — see tool window for details", NotificationType.ERROR)
            else -> notify(project, "LoomScan: gate exited with code $exitCode", NotificationType.WARNING)
        }
    }
}

/** loomscan mine --max-commits 500 */
class MineAction : LoomScanBaseAction() {
    override fun buildArgs(project: Project, settings: com.loomscan.pipeline.settings.LoomScanSettingsState) =
        listOf("mine", "--max-commits", "500")

    override fun onExit(project: Project, exitCode: Int) {
        if (exitCode == 0) {
            notify(project, "LoomScan: rule mining complete — see .loomscan-rules/mined/", NotificationType.INFORMATION)
        }
    }
}

/** Restart the LSP server. */
class RestartAction : AnAction() {
    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return
        // Note: IntelliJ 2023.1+ LSP restart is handled by the platform;
        // we notify the user to re-open files.
        NotificationGroupManager.getInstance()
            .getNotificationGroup("LoomScan")
            .createNotification(
                "LoomScan: LSP server restart requested — re-open files to trigger.",
                NotificationType.INFORMATION
            )
            .notify(project)
    }
}
