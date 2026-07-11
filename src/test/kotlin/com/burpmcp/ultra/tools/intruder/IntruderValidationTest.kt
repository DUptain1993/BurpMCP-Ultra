package com.burpmcp.ultra.tools.intruder

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/**
 * Unit tests for [IntruderValidation], the pure position-pair and regex validators used by
 * the Intruder tool handlers. No live Montoya API is required.
 *
 * BUG #16: malformed `[start, end]` position pairs must be rejected with a clean, consistent
 *          [IllegalArgumentException] — both too-few (previously a leaked
 *          IndexOutOfBoundsException) and too-many (previously silently truncated) elements.
 * BUG #33: an invalid `regex_replace` pattern must be rejected eagerly at registration time.
 */
class IntruderValidationTest {

    private fun arr(vararg ints: Int): JsonArray = buildJsonArray {
        for (i in ints) add(JsonPrimitive(i))
    }

    // ---- BUG #16: position pair arity ----

    @Test
    fun `valid two-element pair parses to start and end`() {
        val pair = IntruderValidation.parsePositionArray(arr(3, 7))
        assertEquals(3, pair.first)
        assertEquals(7, pair.second)
    }

    @Test
    fun `equal start and end is accepted (zero-width point)`() {
        val pair = IntruderValidation.parsePositionArray(arr(5, 5))
        assertEquals(5 to 5, pair)
    }

    @Test
    fun `too few elements is rejected with descriptive arity message`() {
        val e = assertFailsWith<IllegalArgumentException> {
            IntruderValidation.parsePositionArray(arr(3))
        }
        val msg = e.message ?: ""
        assertEquals("each position must be a [start,end] pair (got 1 element(s))", msg)
        // No leaked JDK bounds text.
        assertNull(Regex("(?i)index").find(msg)?.value)
    }

    @Test
    fun `empty array is rejected with descriptive arity message`() {
        val e = assertFailsWith<IllegalArgumentException> {
            IntruderValidation.parsePositionArray(arr())
        }
        assertEquals("each position must be a [start,end] pair (got 0 element(s))", e.message)
    }

    @Test
    fun `too many elements is rejected the same way as too few (not truncated)`() {
        val e = assertFailsWith<IllegalArgumentException> {
            IntruderValidation.parsePositionArray(arr(1, 2, 3))
        }
        assertEquals("each position must be a [start,end] pair (got 3 element(s))", e.message)
    }

    @Test
    fun `non-integer start is rejected cleanly`() {
        val bad = buildJsonArray { add(JsonPrimitive("x")); add(JsonPrimitive(5)) }
        val e = assertFailsWith<IllegalArgumentException> {
            IntruderValidation.parsePositionArray(bad)
        }
        assertEquals("position start must be an integer", e.message)
    }

    @Test
    fun `end before start is rejected`() {
        val e = assertFailsWith<IllegalArgumentException> {
            IntruderValidation.parsePositionArray(arr(9, 2))
        }
        assertEquals("position end (2) must be >= start (9)", e.message)
    }

    // ---- BUG #33: regex_replace eager validation ----

    @Test
    fun `valid regex pattern passes validation with no error`() {
        assertNull(IntruderValidation.regexError(mapOf("regex_pattern" to "[a-z]+")))
    }

    @Test
    fun `invalid regex pattern is rejected at registration time`() {
        val err = IntruderValidation.regexError(mapOf("regex_pattern" to "[unterminated"))
        assertNotNull(err, "an uncompilable pattern must be rejected")
        val text = err["error"]?.jsonPrimitive?.content ?: ""
        assertEquals(true, text.startsWith("Invalid regex_pattern:"))
    }

    @Test
    fun `missing regex pattern is rejected`() {
        val err = IntruderValidation.regexError(emptyMap())
        assertNotNull(err)
        assertEquals(
            "regex_replace requires a non-empty regex_pattern",
            err["error"]?.jsonPrimitive?.content
        )
    }

    @Test
    fun `blank regex pattern is rejected`() {
        val err = IntruderValidation.regexError(mapOf("regex_pattern" to ""))
        assertNotNull(err)
        assertEquals(
            "regex_replace requires a non-empty regex_pattern",
            err["error"]?.jsonPrimitive?.content
        )
    }
}
