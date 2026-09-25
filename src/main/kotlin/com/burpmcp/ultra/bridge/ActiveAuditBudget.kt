package com.burpmcp.ultra.bridge

/**
 * Pure budget helpers for [ScannerBridge.registerScanCheck]'s activeAudit loop (C6).
 *
 * Caps unbounded caller-supplied payload lists and total wall-clock time so a custom
 * scan check cannot hammer a target indefinitely. Testable without Montoya.
 */
internal object ActiveAuditBudget {
    const val MAX_ACTIVE_PAYLOADS_PER_INSERTION_POINT = 100
    const val MAX_ELAPSED_MS = 30_000L

    /**
     * Returns the payloads that may be attempted (hard cap), preserving order.
     * A 200-item list yields exactly [MAX_ACTIVE_PAYLOADS_PER_INSERTION_POINT] items.
     */
    fun cappedPayloads(payloads: List<String>): List<String> =
        payloads.take(MAX_ACTIVE_PAYLOADS_PER_INSERTION_POINT)

    /**
     * Whether the loop should stop before attempting [payloadIndex] (0-based) given
     * [elapsedMs] since the loop started. Returns a reason string or null to continue.
     */
    fun truncateReason(payloadIndex: Int, elapsedMs: Long): String? = when {
        payloadIndex >= MAX_ACTIVE_PAYLOADS_PER_INSERTION_POINT -> "max_payloads"
        elapsedMs > MAX_ELAPSED_MS -> "time_budget"
        else -> null
    }
}
