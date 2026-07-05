package com.burpmcp.ultra.state

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Issue #8: "Delete Saved History" must actually empty the in-memory deque the table renders from. */
class StateManagerActivityTest {

    private fun entry(id: Long) =
        McpActivityEntry(id, "t", "2026-07-05T00:00:00Z", 1, "GET", "https://x/$id", "x.com", 200, false, "{}", "ok")

    @Test fun `clearMcpActivity empties the deque`() {
        val sm = StateManager()
        sm.mcpActivity.add(entry(1))
        sm.mcpActivity.add(entry(2))
        assertTrue(sm.mcpActivity.isNotEmpty())

        sm.clearMcpActivity()

        assertEquals(0, sm.mcpActivity.size, "the activity deque must be empty after clear")
    }
}
