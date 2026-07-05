package com.burpmcp.ultra.transport

import com.burpmcp.ultra.state.McpActivityEntry
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ActivityStoreTest {

    private fun entry(id: Long, tool: String = "t", args: String = "{}") =
        McpActivityEntry(id, tool, "2026-06-25T09:00:00Z", 12, "GET", "https://x/$id", "x.com", 200, false, args, "ok")

    @Test fun `round-trips an entry and nulls requestResponse after restore`() {
        val (back, proj) = ActivityStore.parseEntry(ActivityStore.buildEntry(entry(7, "cors_probe"), "ProjA"))!!
        assertEquals(7L, back.id)
        assertEquals("cors_probe", back.toolName)
        assertEquals(200, back.statusCode)
        assertEquals("ok", back.resultSummary)
        assertNull(back.requestResponse)
        assertEquals("ProjA", proj)
    }

    @Test fun `selectForProject filters by project, keeps last max, newest-first`() {
        // append order (oldest-first) 1..5; project A holds odd ids 1,3,5
        val parsed = (1L..5L).map { entry(it) to (if (it % 2 == 0L) "B" else "A") }
        assertEquals(listOf(5L, 3L), ActivityStore.selectForProject(parsed, "A", 2).map { it.id })
        assertEquals(listOf(5L, 3L, 1L), ActivityStore.selectForProject(parsed, "A", 10).map { it.id })
        assertTrue(ActivityStore.selectForProject(parsed, "Other", 5).isEmpty())
    }

    @Test fun `toEventData reparses the args object and carries the fields`() {
        val ev = ActivityStore.toEventData(entry(1, "http_send_request", "{\"url\":\"https://a\"}"))
        assertEquals("http_send_request", ev["tool_name"]!!.jsonPrimitive.content)
        assertEquals("https://a", ev["arguments"]!!.jsonObject["url"]!!.jsonPrimitive.content)
        assertEquals(200, ev["status_code"]!!.jsonPrimitive.content.toInt())
    }

    @Test fun `parseEntry tolerates malformed lines`() {
        assertNull(ActivityStore.parseEntry("not json {"))
        assertNull(ActivityStore.parseEntry(""))
    }

    // --- issue #8: clear/flush the saved store (multi-project safe) ---

    @Test fun `rebuildLines deletes a project keeping others`() {
        val parsed = listOf(entry(1) to "A", entry(2) to "B", entry(3) to "A")
        val back = ActivityStore.rebuildLines(parsed, "A", emptyList()).mapNotNull { ActivityStore.parseEntry(it) }
        assertEquals(listOf(2L), back.map { it.first.id }, "only project B should remain")
        assertTrue(back.all { it.second == "B" })
    }

    @Test fun `rebuildLines replaces a project's entries and keeps others`() {
        val parsed = listOf(entry(1) to "A", entry(2) to "B")
        val back = ActivityStore.rebuildLines(parsed, "A", listOf(entry(9), entry(10))).mapNotNull { ActivityStore.parseEntry(it) }
        assertEquals(listOf(2L, 9L, 10L), back.map { it.first.id }, "B kept, A replaced with 9,10")
        assertEquals("A", back.first { it.first.id == 9L }.second)
    }

    @Test fun `rebuildLines yields empty when the only project is deleted`() {
        val parsed = listOf(entry(1) to "A", entry(2) to "A")
        assertEquals(emptyList(), ActivityStore.rebuildLines(parsed, "A", emptyList()))
    }

    @Test fun `append no-ops when persistence is disabled`() {
        val prev = ActivityStore.enabled
        try {
            ActivityStore.enabled = false
            val before = if (java.io.File(ActivityStore.path()).exists()) java.io.File(ActivityStore.path()).length() else 0L
            ActivityStore.append(entry(999), "DisabledProj")
            val after = if (java.io.File(ActivityStore.path()).exists()) java.io.File(ActivityStore.path()).length() else 0L
            assertEquals(before, after, "no bytes should be written while persistence is disabled")
        } finally {
            ActivityStore.enabled = prev
        }
    }
}
