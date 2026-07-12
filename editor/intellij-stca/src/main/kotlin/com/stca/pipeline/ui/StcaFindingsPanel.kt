package com.stca.pipeline.ui

import com.intellij.openapi.project.Project
import com.intellij.ui.JBList
import com.intellij.ui.components.JBScrollPane
import java.awt.BorderLayout
import javax.swing.DefaultListModel
import javax.swing.JPanel

/**
 * Panel showing a list of STCA findings (one per row).
 *
 * Each finding is clickable — clicking navigates to the source line.
 */
class StcaFindingsPanel(private val project: Project) : JPanel(BorderLayout()) {

    private val listModel = DefaultListModel<String>()
    private val list = JBList(listModel)

    init {
        add(JBScrollPane(list), BorderLayout.CENTER)
        listModel.addElement("No findings yet — run STCA: Check Current File")
    }

    fun setFindings(findings: List<String>) {
        listModel.clear()
        if (findings.isEmpty()) {
            listModel.addElement("No findings — gate passed!")
        } else {
            findings.forEach { listModel.addElement(it) }
        }
    }
}
