package com.stca.pipeline.action

import com.intellij.notification.NotificationGroupManager
import com.intellij.notification.NotificationType
import com.intellij.openapi.actionSystem.AnAction
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.diagnostic.logger
import com.intellij.openapi.project.Project
import com.intellij.openapi.ui.Messages
import com.stca.pipeline.settings.StcaSettingsService
import java.io.BufferedReader
import java.io.InputStreamReader

private val LOG = logger<StcaBaseAction>()

/**
 * Base class for STCA actions — handles Python path resolution, command spawning,
 * and output streaming to the STCA tool window.
 */
abstract class StcaBaseAction : AnAction() {

    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return
        val settings = StcaSettingsService.getInstance().state
        if (!settings.stcaEnabled) {
            notify(project, "STCA is disabled in settings.", NotificationType.WARNING)
            return
        }
        runStcaCommand(project, settings.pythonPath, buildArgs(project, settings))
    }

    /** Subclasses override to build the CLI args. */
    abstract fun buildArgs(project: Project, settings: com.stca.pipeline.settings.StcaSettingsState): List<String>

    /** Subclasses can override to handle output differently. */
    protected open fun onOutput(project: Project, line: String) {
        LOG.info("[stca] $line")
    }

    protected fun runStcaCommand(project: Project, pythonPath: String, args: List<String>) {
        val projectRoot = project.basePath ?: return
        val fullArgs = listOf(pythonPath, "-c", "from stca.cli import main; main()") + args
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
                LOG.warn("STCA command failed", e)
                ApplicationManager.getApplication().invokeLater {
                    notify(project, "STCA failed: ${e.message}", NotificationType.ERROR)
                }
            }
        }
    }

    protected open fun onExit(project: Project, exitCode: Int) {
        if (exitCode != 0 && exitCode != 1) {
            notify(project, "STCA exited with code $exitCode", NotificationType.WARNING)
        }
    }

    protected fun notify(project: Project, message: String, type: NotificationType) {
        NotificationGroupManager.getInstance()
            .getNotificationGroup("STCA")
            .createNotification(message, type)
            .notify(project)
    }
}

/** stca check --full --strictness N */
class CheckRepoAction : StcaBaseAction() {
    override fun buildArgs(project: Project, settings: com.stca.pipeline.settings.StcaSettingsState) =
        listOf("check", "--full", "--strictness", settings.strictness.toString())
}

/** stca check --full --json (re-analyze, return JSON) */
class CheckFileAction : StcaBaseAction() {
    override fun buildArgs(project: Project, settings: com.stca.pipeline.settings.StcaSettingsState) =
        listOf("check", "--full", "--strictness", settings.strictness.toString(), "--json")
}

/** stca fix --apply --finding-id <id> */
class ApplyFixAction : StcaBaseAction() {
    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return
        val id = Messages.showInputDialog(
            project,
            "Finding ID (fingerprint):",
            "STCA Apply Fix",
            Messages.getQuestionIcon()
        ) ?: return
        if (id.isBlank()) return
        val settings = StcaSettingsService.getInstance().state
        runStcaCommand(project, settings.pythonPath, listOf("fix", "--apply", "--finding-id", id))
    }

    override fun buildArgs(project: Project, settings: com.stca.pipeline.settings.StcaSettingsState) =
        emptyList<String>()  // handled in actionPerformed override
}

/** Toggle showUncertainOnly setting. */
class ShowUncertainAction : AnAction() {
    override fun actionPerformed(e: AnActionEvent) {
        val state = StcaSettingsService.getInstance().state
        state.showUncertainOnly = !state.showUncertainOnly
        val project = e.project ?: return
        NotificationGroupManager.getInstance()
            .getNotificationGroup("STCA")
            .createNotification(
                "STCA: ${if (state.showUncertainOnly) "showing only uncertain (30-70%) findings" else "showing all findings"}",
                NotificationType.INFORMATION
            )
            .notify(project)
    }
}

/** stca gate --full --preset <preset> */
class GateAction : StcaBaseAction() {
    override fun buildArgs(project: Project, settings: com.stca.pipeline.settings.StcaSettingsState): List<String> {
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
            0 -> notify(project, "STCA: quality gate PASSED", NotificationType.INFORMATION)
            1 -> notify(project, "STCA: quality gate FAILED — see tool window for details", NotificationType.ERROR)
            else -> notify(project, "STCA: gate exited with code $exitCode", NotificationType.WARNING)
        }
    }
}

/** stca mine --max-commits 500 */
class MineAction : StcaBaseAction() {
    override fun buildArgs(project: Project, settings: com.stca.pipeline.settings.StcaSettingsState) =
        listOf("mine", "--max-commits", "500")

    override fun onExit(project: Project, exitCode: Int) {
        if (exitCode == 0) {
            notify(project, "STCA: rule mining complete — see .stca-rules/mined/", NotificationType.INFORMATION)
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
            .getNotificationGroup("STCA")
            .createNotification(
                "STCA: LSP server restart requested — re-open files to trigger.",
                NotificationType.INFORMATION
            )
            .notify(project)
    }
}
