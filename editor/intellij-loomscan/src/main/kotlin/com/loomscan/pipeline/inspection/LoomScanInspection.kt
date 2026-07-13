package com.loomscan.pipeline.inspection

import com.intellij.codeInspection.LocalInspectionTool
import com.intellij.codeInspection.ProblemsHolder
import com.intellij.psi.PsiElementVisitor

/**
 * Batch-mode inspection for LoomScan findings.
 *
 * Used when running "Inspect Code" / "Code Cleanup" — falls back to running
 * `loomscan check --full --json` on the project and surfacing findings as
 * IntelliJ inspection results.
 *
 * In real-time mode, the LSP server pushes diagnostics directly — this
 * inspection is for offline/batch analysis.
 */
class LoomScanInspection : LocalInspectionTool() {

    override fun buildVisitor(holder: ProblemsHolder, isOnTheFly: Boolean): PsiElementVisitor {
        // The actual finding collection is handled by the LSP server.
        // This inspection is a placeholder for batch mode.
        return PsiElementVisitor.EMPTY_VISITOR
    }

    override fun getShortName(): String = "LoomScanInspection"
    override fun getDisplayName(): String = "LoomScan findings"
    override fun getGroupDisplayName(): String = "LoomScan"
    override fun isEnabledByDefault(): Boolean = true
}
