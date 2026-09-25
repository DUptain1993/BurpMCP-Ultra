package com.burpmcp.ultra.bridge

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class ActiveAuditBudgetTest {

    @Test
    fun `200-payload list is capped at 100`() {
        val payloads = (1..200).map { "p$it" }
        val capped = ActiveAuditBudget.cappedPayloads(payloads)
        assertEquals(ActiveAuditBudget.MAX_ACTIVE_PAYLOADS_PER_INSERTION_POINT, capped.size)
        assertEquals(100, capped.size)
        assertEquals("p1", capped.first())
        assertEquals("p100", capped.last())
    }

    @Test
    fun `under-cap list is unchanged`() {
        val payloads = listOf("a", "b", "c")
        assertEquals(payloads, ActiveAuditBudget.cappedPayloads(payloads))
    }

    @Test
    fun `time budget triggers truncate after 30s`() {
        assertNull(ActiveAuditBudget.truncateReason(0, 0))
        assertNull(ActiveAuditBudget.truncateReason(50, 29_999))
        assertEquals("time_budget", ActiveAuditBudget.truncateReason(50, 30_001))
    }

    @Test
    fun `max_payloads reason at index 100`() {
        assertNull(ActiveAuditBudget.truncateReason(99, 0))
        assertEquals("max_payloads", ActiveAuditBudget.truncateReason(100, 0))
    }
}
