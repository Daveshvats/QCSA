package com.stca.pipeline.service

import com.intellij.openapi.project.Project

/**
 * Project-level service for STCA state (current findings, last scan time, etc.).
 *
 * Holds in-memory state that survives file edits but not project reload.
 */
interface StcaService {
    val project: Project
    fun getLastScanTime(): Long
    fun getFindings(): List<StcaFinding>
    fun setFindings(findings: List<StcaFinding>)
    fun clear()
}

data class StcaFinding(
    val ruleId: String,
    val message: String,
    val severity: String,
    val file: String,
    val line: Int,
    val confidence: Double
)

class StcaServiceImpl(override val project: Project) : StcaService {
    @Volatile private var lastScanTime: Long = 0
    @Volatile private var findings: List<StcaFinding> = emptyList()

    override fun getLastScanTime(): Long = lastScanTime
    override fun getFindings(): List<StcaFinding> = findings

    @Synchronized
    override fun setFindings(findings: List<StcaFinding>) {
        this.findings = findings
        this.lastScanTime = System.currentTimeMillis()
    }

    @Synchronized
    override fun clear() {
        findings = emptyList()
        lastScanTime = 0
    }
}
