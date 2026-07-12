package com.stca.pipeline.settings

import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.components.PersistentStateComponent
import com.intellij.openapi.components.State
import com.intellij.openapi.components.Storage

/**
 * Persistent STCA settings state.
 *
 * Mirrors the VS Code extension's configuration options.
 */
@State(name = "StcaSettings", storages = [Storage("stca.xml")])
data class StcaSettingsState(
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
 * Application-level service holding STCA settings.
 */
class StcaSettingsService : PersistentStateComponent<StcaSettingsState> {

    private var state = StcaSettingsState()

    override fun getState(): StcaSettingsState = state

    override fun loadState(state: StcaSettingsState) {
        this.state = state
    }

    companion object {
        fun getInstance(): StcaSettingsService {
            return ApplicationManager.getApplication().getService(StcaSettingsService::class.java)
        }
    }
}
