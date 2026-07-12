package com.stca.pipeline.ui

import com.intellij.openapi.project.Project
import com.intellij.openapi.wm.StatusBar
import com.intellij.openapi.wm.StatusBarWidget
import com.intellij.openapi.wm.StatusBarWidgetFactory

class StcaStatusBarWidgetFactory : StatusBarWidgetFactory {
    override fun getId(): String = "StcaStatusBar"
    override fun getDisplayName(): String = "STCA"
    override fun isAvailable(project: Project): Boolean = true
    override fun createWidget(project: Project): StatusBarWidget = StcaStatusBarWidget(project)
    override fun disposeWidget(widget: StatusBarWidget) {}
    override fun canBeEnabledOn(statusBar: StatusBar): Boolean = true
}

class StcaStatusBarWidget(private val project: Project) : StatusBarWidget, StatusBarWidget.TextPresentation {
    private var text = "STCA: idle"

    override fun ID(): String = "StcaStatusBar"

    override fun getPresentation(): StatusBarWidget.WidgetPresentation = this

    override fun install(statusBar: StatusBar) {}

    override fun dispose() {}

    override fun getText(): String = text

    fun setStatus(text: String) {
        this.text = text
    }
}
