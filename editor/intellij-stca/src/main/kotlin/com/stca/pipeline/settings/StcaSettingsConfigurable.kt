package com.stca.pipeline.settings

import com.intellij.openapi.options.Configurable
import com.intellij.openapi.ui.ComboBox
import com.intellij.ui.components.JBCheckBox
import com.intellij.ui.components.JBTextField
import com.intellij.ui.components.JBLabel
import com.intellij.util.ui.FormBuilder
import javax.swing.JComponent
import javax.swing.JPanel

/**
 * Settings UI: Settings > Tools > STCA Pipeline.
 *
 * Mirrors the VS Code extension's configuration panel.
 */
class StcaSettingsConfigurable : Configurable {

    private val enabledCheckbox = JBCheckBox("Enable STCA real-time diagnostics")
    private val pythonPathField = JBTextField("python", 30)
    private val strictnessField = JBTextField("5", 5)
    private val debounceField = JBTextField("500", 8)
    private val showUncertainCheckbox = JBCheckBox("Show only uncertain findings (30-70% confidence)")
    private val useLspCheckbox = JBCheckBox("Use LSP server (true) or fall back to CLI (false)")
    private val gatePresetCombo = ComboBox(arrayOf("strict", "balanced", "permissive", "custom"))
    private val gateMaxCriticalField = JBTextField("0", 5)
    private val gateMaxHighField = JBTextField("0", 5)

    private var panel: JPanel? = null

    override fun getDisplayName(): String = "STCA Pipeline"

    override fun createComponent(): JComponent? {
        panel = FormBuilder.createFormBuilder()
            .addComponent(enabledCheckbox)
            .addLabeledComponent(JBLabel("Python path:"), pythonPathField)
            .addLabeledComponent(JBLabel("Strictness (1-9):"), strictnessField)
            .addLabeledComponent(JBLabel("Debounce (ms):"), debounceField)
            .addComponent(showUncertainCheckbox)
            .addComponent(useLspCheckbox)
            .addLabeledComponent(JBLabel("Quality gate preset:"), gatePresetCombo)
            .addLabeledComponent(JBLabel("Max critical (custom preset):"), gateMaxCriticalField)
            .addLabeledComponent(JBLabel("Max high (custom preset):"), gateMaxHighField)
            .addComponentFillVertically(JPanel(), 0)
            .panel
        return panel
    }

    override fun isModified(): Boolean {
        val state = StcaSettingsService.getInstance().state
        return enabledCheckbox.isSelected != state.stcaEnabled ||
                pythonPathField.text != state.pythonPath ||
                strictnessField.text.toIntOrNull() != state.strictness ||
                debounceField.text.toIntOrNull() != state.debounceMs ||
                showUncertainCheckbox.isSelected != state.showUncertainOnly ||
                useLspCheckbox.isSelected != state.useLsp ||
                gatePresetCombo.selectedItem as String != state.gatePreset ||
                gateMaxCriticalField.text.toIntOrNull() != state.gateMaxCritical ||
                gateMaxHighField.text.toIntOrNull() != state.gateMaxHigh
    }

    override fun applyConfiguration() {
        val state = StcaSettingsService.getInstance().state
        state.stcaEnabled = enabledCheckbox.isSelected
        state.pythonPath = pythonPathField.text
        state.strictness = strictnessField.text.toIntOrNull() ?: 5
        state.debounceMs = debounceField.text.toIntOrNull() ?: 500
        state.showUncertainOnly = showUncertainCheckbox.isSelected
        state.useLsp = useLspCheckbox.isSelected
        state.gatePreset = gatePresetCombo.selectedItem as String
        state.gateMaxCritical = gateMaxCriticalField.text.toIntOrNull() ?: 0
        state.gateMaxHigh = gateMaxHighField.text.toIntOrNull() ?: 0
    }

    override fun reset() {
        val state = StcaSettingsService.getInstance().state
        enabledCheckbox.isSelected = state.stcaEnabled
        pythonPathField.text = state.pythonPath
        strictnessField.text = state.strictness.toString()
        debounceField.text = state.debounceMs.toString()
        showUncertainCheckbox.isSelected = state.showUncertainOnly
        useLspCheckbox.isSelected = state.useLsp
        gatePresetCombo.selectedItem = state.gatePreset
        gateMaxCriticalField.text = state.gateMaxCritical.toString()
        gateMaxHighField.text = state.gateMaxHigh.toString()
    }
}
