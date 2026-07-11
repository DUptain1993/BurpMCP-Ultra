package com.burpmcp.ultra.events

import com.burpmcp.ultra.tools.events.EventsTools
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Regression coverage for the negative / oversized `max_events` handling on
 * the event bus and the events_get / events_get_by_type tool boundary
 * (bugs #10 and #11): a hostile max_events must never leak Kotlin's internal
 * IllegalArgumentException from Iterable.take().
 */
class EventsBufferBoundsTest {

    private val emptyData: JsonObject = buildJsonObject {}

    private fun seed(bus: EventBus, count: Int, type: String = "proxy.request") {
        repeat(count) { bus.emit(type, emptyData) }
    }

    // --- EventBus.getEvents ------------------------------------------------

    @Test fun `getEvents with negative maxEvents returns empty list, no exception`() {
        val bus = EventBus(maxBufferSize = 100)
        seed(bus, 5)
        assertTrue(bus.getEvents(sinceId = 0, maxEvents = -1).isEmpty())
        assertTrue(bus.getEvents(sinceId = 0, maxEvents = Int.MIN_VALUE).isEmpty())
    }

    @Test fun `getEvents clamps oversized maxEvents to buffer contents`() {
        val bus = EventBus(maxBufferSize = 100)
        seed(bus, 5)
        // Asking for far more than exist (and more than maxBufferSize) must not throw.
        assertEquals(5, bus.getEvents(sinceId = 0, maxEvents = Int.MAX_VALUE).size)
    }

    @Test fun `getEvents zero maxEvents returns empty`() {
        val bus = EventBus(maxBufferSize = 100)
        seed(bus, 5)
        assertTrue(bus.getEvents(sinceId = 0, maxEvents = 0).isEmpty())
    }

    @Test fun `getEvents honours a valid positive limit and sinceId cursor`() {
        val bus = EventBus(maxBufferSize = 100)
        seed(bus, 10)
        val page = bus.getEvents(sinceId = 0, maxEvents = 3)
        assertEquals(3, page.size)
        // ids are monotonically increasing starting at 1
        assertEquals(listOf(1L, 2L, 3L), page.map { it.id })
        // cursor advances past the first three
        assertEquals(listOf(4L, 5L, 6L), bus.getEvents(sinceId = 3, maxEvents = 3).map { it.id })
    }

    // --- EventBus.getEventsByType ------------------------------------------

    @Test fun `getEventsByType with negative maxEvents returns empty list, no exception`() {
        val bus = EventBus(maxBufferSize = 100)
        seed(bus, 5, type = "scanner.issue")
        assertTrue(bus.getEventsByType(listOf("scanner.issue"), sinceId = 0, maxEvents = -7).isEmpty())
    }

    @Test fun `getEventsByType clamps oversized maxEvents and filters by type`() {
        val bus = EventBus(maxBufferSize = 100)
        seed(bus, 3, type = "scanner.issue")
        seed(bus, 4, type = "proxy.request")
        val issues = bus.getEventsByType(listOf("scanner.issue"), sinceId = 0, maxEvents = Int.MAX_VALUE)
        assertEquals(3, issues.size)
        assertTrue(issues.all { it.type == "scanner.issue" })
    }

    // --- Tool boundary: EventsTools.validateMaxEvents ----------------------

    @Test fun `validateMaxEvents returns explicit error for negative input`() {
        val result = EventsTools.validateMaxEvents(-1)
        assertTrue(result != null, "negative max_events must produce an error result")
        assertEquals(true, result.isError)
        val text = (result.content.first() as TextContent).text
        assertTrue(text!!.contains("max_events must be >= 0"), "error body was: $text")
    }

    @Test fun `validateMaxEvents accepts zero and positive input`() {
        assertNull(EventsTools.validateMaxEvents(0))
        assertNull(EventsTools.validateMaxEvents(200))
        assertNull(EventsTools.validateMaxEvents(Int.MAX_VALUE))
    }
}
