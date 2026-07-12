package com.stca.pipeline.icons

import com.intellij.openapi.util.IconLoader
import javax.swing.Icon

/**
 * STCA icons used in tool window, status bar, and actions.
 */
object StcaIcons {
    @JvmField
    val STCA: Icon = IconLoader.getIcon("/icons/stca.svg", StcaIcons::class.java)

    @JvmField
    val GATE: Icon = IconLoader.getIcon("/icons/gate.svg", StcaIcons::class.java)

    @JvmField
    val MINE: Icon = IconLoader.getIcon("/icons/mine.svg", StcaIcons::class.java)
}
