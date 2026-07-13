package com.loomscan.pipeline.service

import com.intellij.openapi.project.Project

/**
 * Project-level service for LoomScan state (current findings, last scan time, etc.).
 *
 * Holds in-memory state that survives file edits but not project reload.
 */
interface LoomScanService {
    val project: Project
    fun getLastScanTime(): Long
    fun getFindings(): List<LoomScanFinding>
    fun setFindings(findings: List<LoomScanFinding>)
    fun clear()
}

data class LoomScanFinding(
    val ruleId: String,
    val message: String,
    val severity: String,
    val file: String,
    val line: Int,
    val confidence: Double
)

class LoomScanServiceImpl(override val project: Project) : LoomScanService {
    @Volatile private var lastScanTime: Long = 0
    @Volatile private var findings: List<LoomScanFinding> = emptyList()

    override fun getLastScanTime(): Long = lastScanTime
    override fun getFindings(): List<LoomScanFinding> = findings

    @Synchronized
    override fun setFindings(findings: List<LoomScanFinding>) {
        this.findings = findings
        this.lastScanTime = System.currentTimeMillis()
    }

    @Synchronized
    override fun clear() {
        findings = emptyList()
        lastScanTime = 0
    }
}
