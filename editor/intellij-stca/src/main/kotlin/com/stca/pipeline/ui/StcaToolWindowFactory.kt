package com.stca.pipeline.ui

import com.intellij.openapi.project.Project
import com.intellij.openapi.wm.ToolWindow
import com.intellij.openapi.wm.ToolWindowFactory
import com.intellij.ui.content.ContentFactory

/**
 * Tool window for STCA output (check results, gate results, mined rules).
 *
 * Shows the output of `stca check`, `stca gate`, and `stca mine` commands.
 */
class StcaToolWindowFactory : ToolWindowFactory {

    override fun createToolWindowContent(project: Project, toolWindow: ToolWindow) {
        val panel = StcaOutputPanel(project)
        val content = ContentFactory.getInstance().createContent(panel, "Output", false)
        toolWindow.contentManager.addContent(content)

        // Second tab for findings list
        val findingsPanel = StcaFindingsPanel(project)
        val findingsContent = ContentFactory.getInstance().createContent(findingsPanel, "Findings", false)
        toolWindow.contentManager.addContent(findingsContent)
    }

    override fun shouldBeAvailable(project: Project): Boolean = true
}
