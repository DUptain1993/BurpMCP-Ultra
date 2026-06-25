package com.burpmcp.ultra.safety

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class BoundedHttpTest {

    @Test fun `returns the value when the block finishes in time`() {
        assertEquals(42, BoundedHttp.runBounded(2000) { 42 })
    }

    @Test fun `returns null when the block exceeds the timeout`() {
        assertNull(BoundedHttp.runBounded(50) { Thread.sleep(1500); 1 })
    }

    @Test fun `returns null when the block throws`() {
        assertNull(BoundedHttp.runBounded(2000) { throw RuntimeException("boom") })
    }

    @Test fun `non-positive timeout runs inline and swallows errors`() {
        assertEquals(7, BoundedHttp.runBounded(0) { 7 })
        assertNull(BoundedHttp.runBounded(0) { throw RuntimeException() })
    }
}
