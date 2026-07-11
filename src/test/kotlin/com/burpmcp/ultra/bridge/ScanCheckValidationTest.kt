package com.burpmcp.ultra.bridge

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Unit tests for [ScanCheckValidation], the pure emptiness guard shared by
 * ScanCheckBridge.createActive (steps) and createPassive (conditions).
 *
 * Regression coverage for BUG #31: a zero-step active check (or zero-condition
 * passive check) must be rejected at registration time rather than deployed as
 * a check that can never fire.
 */
class ScanCheckValidationTest {

    private fun cond(location: String): JsonObject = buildJsonObject {
        put("location", location)
        put("pattern", "x")
        put("condition_type", "contains")
    }

    @Test
    fun `empty steps list is rejected with a clear error`() {
        val err = ScanCheckValidation.nonEmptyError(emptyList(), "steps", "step")
        assertNotNull(err, "empty steps must produce an error object")
        assertEquals(
            "Parameter 'steps' must contain at least one step object",
            err["error"]?.jsonPrimitive?.content
        )
    }

    @Test
    fun `empty conditions list is rejected with a clear error`() {
        val err = ScanCheckValidation.nonEmptyError(emptyList(), "conditions", "condition")
        assertNotNull(err, "empty conditions must produce an error object")
        assertEquals(
            "Parameter 'conditions' must contain at least one condition object",
            err["error"]?.jsonPrimitive?.content
        )
    }

    @Test
    fun `non-empty list passes validation (no error)`() {
        assertNull(ScanCheckValidation.nonEmptyError(listOf(cond("response_body")), "conditions", "condition"))
        assertNull(ScanCheckValidation.nonEmptyError(listOf(cond("status_code"), cond("response_body")), "steps", "step"))
    }

    @Test
    fun `error object is not mistaken for a deployed result`() {
        val err = ScanCheckValidation.nonEmptyError(emptyList(), "steps", "step")
        assertNotNull(err)
        // A deployed check reports status="deployed"; the rejection must not.
        assertTrue(err["status"] == null, "rejection must not carry a deployed status")
    }
}
