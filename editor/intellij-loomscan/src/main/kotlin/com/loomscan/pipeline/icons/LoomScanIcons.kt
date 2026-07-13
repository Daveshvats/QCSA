package com.loomscan.pipeline.icons

import com.intellij.openapi.util.IconLoader
import javax.swing.Icon

/**
 * LoomScan icons used in tool window, status bar, and actions.
 */
object LoomScanIcons {
    @JvmField
    val LoomScan: Icon = IconLoader.getIcon("/icons/loomscan.svg", LoomScanIcons::class.java)

    @JvmField
    val GATE: Icon = IconLoader.getIcon("/icons/gate.svg", LoomScanIcons::class.java)

    @JvmField
    val MINE: Icon = IconLoader.getIcon("/icons/mine.svg", LoomScanIcons::class.java)
}
