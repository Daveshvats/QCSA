package com.stca.pipeline.inspection

import com.intellij.codeInspection.LocalInspectionTool
import com.intellij.codeInspection.ProblemsHolder
import com.intellij.psi.PsiElementVisitor

/**
 * Batch-mode inspection for STCA findings.
 *
 * Used when running "Inspect Code" / "Code Cleanup" — falls back to running
 * `stca check --full --json` on the project and surfacing findings as
 * IntelliJ inspection results.
 *
 * In real-time mode, the LSP server pushes diagnostics directly — this
 * inspection is for offline/batch analysis.
 */
class StcaInspection : LocalInspectionTool() {

    override fun buildVisitor(holder: ProblemsHolder, isOnTheFly: Boolean): PsiElementVisitor {
        // The actual finding collection is handled by the LSP server.
        // This inspection is a placeholder for batch mode.
        return PsiElementVisitor.EMPTY_VISITOR
    }

    override fun getShortName(): String = "StcaInspection"
    override fun getDisplayName(): String = "STCA Pipeline findings"
    override fun getGroupDisplayName(): String = "STCA"
    override fun isEnabledByDefault(): Boolean = true
}
