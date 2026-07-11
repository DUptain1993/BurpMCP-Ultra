package com.burpmcp.ultra.bridge

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Unit tests for the pure, Montoya-free logic in [OrganizerBridge].
 *
 * These cover the regressions in the `organizer_get_items` read path:
 *  - a `url_prefix` filter that used to return 0 for every item (because URL
 *    extraction threw and was swallowed to `false`), and
 *  - a negative `max_results` that used to leak the raw [IllegalArgumentException]
 *    thrown by [List.take].
 *
 * The item-reading path itself needs a live Montoya `OrganizerItem`, so it is not
 * exercised here; the defensive per-field reads are validated by construction in
 * the bridge (each accessor is wrapped in `runCatching`).
 */
class OrganizerBridgeTest {

    @Test
    fun `url filter matches a contained substring case-insensitively`() {
        assertTrue(OrganizerBridge.matchesUrlFilter("https://example.com/api/v1", "example.com"))
        assertTrue(OrganizerBridge.matchesUrlFilter("https://EXAMPLE.com/api/v1", "example.com"))
        assertTrue(OrganizerBridge.matchesUrlFilter("https://host/API/v1", "api/v1"))
    }

    @Test
    fun `url filter does not match when the substring is absent`() {
        assertFalse(OrganizerBridge.matchesUrlFilter("https://example.com/api", "other.com"))
    }

    @Test
    fun `url filter treats a null or empty filter as match-all and a null url as no-match`() {
        assertTrue(OrganizerBridge.matchesUrlFilter("https://example.com", null))
        assertTrue(OrganizerBridge.matchesUrlFilter("https://example.com", ""))
        // A null URL (unreadable item) must never match a real filter — this is
        // exactly the case that previously made every item drop out of the filter.
        assertFalse(OrganizerBridge.matchesUrlFilter(null, "example.com"))
        // ...but a null URL with a match-all filter is still counted.
        assertTrue(OrganizerBridge.matchesUrlFilter(null, null))
    }

    @Test
    fun `effective return count clamps to available items and never goes negative`() {
        assertEquals(3, OrganizerBridge.effectiveReturnCount(available = 3, maxResults = 100))
        assertEquals(2, OrganizerBridge.effectiveReturnCount(available = 5, maxResults = 2))
        assertEquals(0, OrganizerBridge.effectiveReturnCount(available = 5, maxResults = 0))
        // Negative limits collapse to zero rather than throwing (mirrors the
        // guard that getItems applies before ever calling List.take).
        assertEquals(0, OrganizerBridge.effectiveReturnCount(available = 5, maxResults = -3))
    }
}
