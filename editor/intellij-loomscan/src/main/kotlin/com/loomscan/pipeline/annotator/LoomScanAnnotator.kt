package com.loomscan.pipeline.annotator

import com.intellij.lang.annotation.AnnotationHolder
import com.intellij.lang.annotation.ExternalAnnotator
import com.intellij.openapi.util.TextRange
import com.intellij.psi.PsiFile

/**
 * External annotator that surfaces LoomScan findings as squiggles.
 *
 * v4.37: In LSP mode, the LSP server pushes diagnostics directly via
 * IntelliJ's LSP support — this annotator is only used as a fallback
 * when useLsp=false in settings (CLI mode).
 */
class LoomScanAnnotator : ExternalAnnotator<List<Finding>, List<Finding>>() {

    data class Finding(
        val ruleId: String,
        val message: String,
        val severity: String,
        val line: Int,
        val file: String
    )

    override fun collectInformation(file: PsiFile): List<Finding>? {
        // Run `loomscan check --full --json` and parse findings
        // (Implementation would go here — for v4.37 this is a stub)
        return emptyList()
    }

    override fun doAnnotate(collectedInfo: List<Finding>?): List<Finding> {
        return collectedInfo ?: emptyList()
    }

    override fun apply(file: PsiFile, annotationResult: List<Finding>, holder: AnnotationHolder) {
        for (finding in annotationResult) {
            val line = maxOf(0, finding.line - 1)
            val startOffset = file.textRange.startOffset
            val lineStart = file.viewProvider.document.getLineStartOffset(line)
            val lineEnd = file.viewProvider.document.getLineEndOffset(line)
            val range = TextRange(lineStart, lineEnd)
            holder.newAnnotation(
                when (finding.severity.lowercase()) {
                    "critical", "high" -> com.intellij.lang.annotation.HighlightSeverity.ERROR
                    "medium" -> com.intellij.lang.annotation.HighlightSeverity.WARNING
                    else -> com.intellij.lang.annotation.HighlightSeverity.WEAK_WARNING
                },
                "[LoomScan ${finding.ruleId}] ${finding.message}"
            ).range(range).create()
        }
    }
}
