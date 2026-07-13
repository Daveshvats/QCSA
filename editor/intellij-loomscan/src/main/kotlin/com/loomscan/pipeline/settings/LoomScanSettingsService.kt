package com.loomscan.pipeline.settings

import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.components.PersistentStateComponent
import com.intellij.openapi.components.State
import com.intellij.openapi.components.Storage

/**
 * Persistent LoomScan settings state.
 *
 * Mirrors the VS Code extension's configuration options.
 */
@State(name = "LoomScanSettings", storages = [Storage("loomscan.xml")])
data class LoomScanSettingsState(
    var stcaEnabled: Boolean = true,
    var pythonPath: String = "python",
    var strictness: Int = 5,
    var debounceMs: Int = 500,
    var showUncertainOnly: Boolean = false,
    var useLsp: Boolean = true,
    var gatePreset: String = "balanced",
    var gateMaxCritical: Int = 0,
    var gateMaxHigh: Int = 0
)

/**
 * Application-level service holding LoomScan settings.
 */
class LoomScanSettingsService : PersistentStateComponent<LoomScanSettingsState> {

    private var state = LoomScanSettingsState()

    override fun getState(): LoomScanSettingsState = state

    override fun loadState(state: LoomScanSettingsState) {
        this.state = state
    }

    companion object {
        fun getInstance(): LoomScanSettingsService {
            return ApplicationManager.getApplication().getService(LoomScanSettingsService::class.java)
        }
    }
}
