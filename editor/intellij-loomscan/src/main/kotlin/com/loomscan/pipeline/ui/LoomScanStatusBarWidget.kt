package com.loomscan.pipeline.ui

import com.intellij.openapi.project.Project
import com.intellij.openapi.wm.StatusBar
import com.intellij.openapi.wm.StatusBarWidget
import com.intellij.openapi.wm.StatusBarWidgetFactory

class LoomScanStatusBarWidgetFactory : StatusBarWidgetFactory {
    override fun getId(): String = "LoomScanStatusBar"
    override fun getDisplayName(): String = "LoomScan"
    override fun isAvailable(project: Project): Boolean = true
    override fun createWidget(project: Project): StatusBarWidget = LoomScanStatusBarWidget(project)
    override fun disposeWidget(widget: StatusBarWidget) {}
    override fun canBeEnabledOn(statusBar: StatusBar): Boolean = true
}

class LoomScanStatusBarWidget(private val project: Project) : StatusBarWidget, StatusBarWidget.TextPresentation {
    private var text = "LoomScan: idle"

    override fun ID(): String = "LoomScanStatusBar"

    override fun getPresentation(): StatusBarWidget.WidgetPresentation = this

    override fun install(statusBar: StatusBar) {}

    override fun dispose() {}

    override fun getText(): String = text

    fun setStatus(text: String) {
        this.text = text
    }
}
