package com.loomscan.pipeline.ui

import com.intellij.openapi.project.Project
import com.intellij.openapi.wm.ToolWindow
import com.intellij.openapi.wm.ToolWindowFactory
import com.intellij.ui.content.ContentFactory

/**
 * Tool window for LoomScan output (check results, gate results, mined rules).
 *
 * Shows the output of `loomscan check`, `loomscan gate`, and `loomscan mine` commands.
 */
class LoomScanToolWindowFactory : ToolWindowFactory {

    override fun createToolWindowContent(project: Project, toolWindow: ToolWindow) {
        val panel = LoomScanOutputPanel(project)
        val content = ContentFactory.getInstance().createContent(panel, "Output", false)
        toolWindow.contentManager.addContent(content)

        // Second tab for findings list
        val findingsPanel = LoomScanFindingsPanel(project)
        val findingsContent = ContentFactory.getInstance().createContent(findingsPanel, "Findings", false)
        toolWindow.contentManager.addContent(findingsContent)
    }

    override fun shouldBeAvailable(project: Project): Boolean = true
}
