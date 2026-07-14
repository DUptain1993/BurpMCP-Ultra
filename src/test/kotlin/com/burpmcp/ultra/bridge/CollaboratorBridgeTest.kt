package com.burpmcp.ultra.bridge

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Unit tests for [CollaboratorBridge.sanitizeCustomData] — the pure guard that
 * fits a caller-supplied Collaborator label to Montoya's constraint of at most
 * 16 ASCII-alphanumeric characters.
 *
 * Regression coverage for the live crash:
 *   java.lang.IllegalArgumentException: Length of custom data must not exceed
 *   16 alphanumeric characters
 * which `collaborator_generate_payload` leaked when the label was too long or
 * contained non-alphanumeric characters.
 */
class CollaboratorBridgeTest {

    private fun sani(s: String) = CollaboratorBridge.sanitizeCustomData(s)

    @Test fun `short alphanumeric label passes through unchanged`() {
        val r = sani("idor7f3a")
        assertEquals("idor7f3a", r.effective)
        assertFalse(r.adjusted)
        assertNull(r.note)
    }

    @Test fun `exactly 16 alphanumeric chars is kept whole`() {
        val v = "abcd1234efgh5678" // 16 chars
        val r = sani(v)
        assertEquals(v, r.effective)
        assertFalse(r.adjusted)
    }

    @Test fun `over-length label is truncated to 16 and flagged`() {
        val r = sani("idorcanarytest2026extra") // >16 alnum
        assertEquals(16, r.effective.length)
        assertEquals("idorcanarytest20", r.effective)
        assertTrue(r.adjusted)
        assertNotNull(r.note)
        assertTrue(r.note!!.contains("truncated"), r.note!!)
    }

    @Test fun `non-alphanumeric characters are stripped`() {
        val r = sani("idor-canary_7f") // dashes/underscores removed
        assertEquals("idorcanary7f", r.effective)
        assertTrue(r.adjusted)
        assertTrue(r.note!!.contains("non-alphanumeric"), r.note!!)
    }

    @Test fun `strip and truncate combine`() {
        // 20 alnum after stripping punctuation → truncated to 16
        val r = sani("idor-canary-test-2026-extra-label")
        assertEquals(16, r.effective.length)
        assertTrue(r.effective.all { it.isLetterOrDigit() })
        assertTrue(r.adjusted)
        assertTrue(r.note!!.contains("removed") && r.note!!.contains("truncated"), r.note!!)
    }

    @Test fun `all-non-alphanumeric input yields empty effective for caller rejection`() {
        val r = sani("---___...")
        assertEquals("", r.effective)
        // the bridge maps an empty effective to a clean actionable error
    }

    @Test fun `unicode letters and spaces are dropped as non-ascii-alphanumeric`() {
        val r = sani("café test 7") // é and spaces dropped → "caftest7"
        assertEquals("caftest7", r.effective)
        assertTrue(r.adjusted)
    }

    @Test fun `the limit constant matches Montoya's documented maximum`() {
        assertEquals(16, CollaboratorBridge.MAX_CUSTOM_DATA)
    }
}
