package com.burpmcp.ultra.core

/**
 * Result of a live (no-reload) transport rebind, surfaced to the Server-tab UI so it can report
 * success/exposure/downgrade and refresh the displayed endpoint URLs.
 */
data class RebindOutcome(
    val effectiveHost: String,
    val exposed: Boolean,
    val downgraded: Boolean,
    val boundOk: Boolean,
    val message: String?
)
