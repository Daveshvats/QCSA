package com.loomscan.pipeline.ui

import com.intellij.openapi.project.Project
import com.intellij.ui.components.JBTextArea
import com.intellij.ui.components.JBScrollPane
import java.awt.BorderLayout
import javax.swing.JPanel

/**
 * Read-only text panel showing streamed LoomScan command output.
 *
 * Actions (CheckRepo, Gate, Mine) write their stdout/stderr here.
 */
class LoomScanOutputPanel(private val project: Project) : JPanel(BorderLayout()) {

    private val textArea = JBTextArea().apply {
        isEditable = false
        lineWrap = true
        wrapStyleWord = true
        text = "LoomScan — output will appear here.\n"
    }

    init {
        add(JBScrollPane(textArea), BorderLayout.CENTER)
    }

    fun append(text: String) {
        textArea.append(text + "\n")
    }

    fun clear() {
        textArea.text = ""
    }
}
