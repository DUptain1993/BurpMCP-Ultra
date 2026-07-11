package com.burpmcp.ultra.bridge

import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Unit tests for the pure BCheck DSL logic in [BCheckBridge] (companion object).
 *
 * Regression coverage for BUG #32: bcheck_create emitted invalid BCheck DSL and
 * skipped input validation. Concretely:
 *   - unknown severity/confidence/type/match_condition were emitted verbatim,
 *     producing an un-importable or degenerate check,
 *   - the insertion_point branch emitted `run for each` over a define list under
 *     `given insertion point then`, which the v2-beta grammar does not support,
 *   - the `else` fallback turned an unknown type into a `matches ""` passive
 *     check that fires on every response,
 *   - `matches ""` could be emitted for active checks with no match pattern.
 *
 * These tests exercise only the pure static functions, so no live Burp is needed.
 */
class BCheckBridgeTest {

    // ---- input validation (BUG #32 A) -------------------------------------

    @Test
    fun `valid enum inputs pass validation`() {
        assertNull(BCheckBridge.validateInputs("passive_response", "high", "firm", "matches"))
        assertNull(BCheckBridge.validateInputs("insertion_point", "information", "tentative", null))
        // case/whitespace insensitive (delegated to EnumValidation)
        assertNull(BCheckBridge.validateInputs("  Passive_Request ", "LOW", "Certain", " IS "))
    }

    @Test
    fun `invalid severity is rejected with a clean error naming the value`() {
        val e = BCheckBridge.validateInputs("passive_response", "critical", "firm", "matches")
        assertNotNull(e, "invalid severity must produce an error object")
        val msg = e!!["error"]!!.jsonPrimitive.content
        assertTrue(msg.contains("critical"), msg)
        assertTrue(msg.contains("severity"), msg)
        // an error object must never look like a deployed result
        assertNull(e["status"])
    }

    @Test
    fun `invalid confidence is rejected`() {
        val e = BCheckBridge.validateInputs("passive_response", "high", "very-sure", "matches")
        assertNotNull(e)
        assertTrue(e!!["error"]!!.jsonPrimitive.content.contains("confidence"))
    }

    @Test
    fun `invalid type is rejected`() {
        val e = BCheckBridge.validateInputs("sql_injection", "high", "firm", "matches")
        assertNotNull(e)
        assertTrue(e!!["error"]!!.jsonPrimitive.content.contains("type"))
    }

    @Test
    fun `invalid match_condition is rejected but null is allowed`() {
        assertNotNull(BCheckBridge.validateInputs("passive_response", "high", "firm", "equals"))
        // match_condition is optional
        assertNull(BCheckBridge.validateInputs("passive_response", "high", "firm", null))
    }

    // ---- unknown type never becomes a degenerate check (BUG #32 B) --------

    @Test
    fun `emitScript throws on an unsupported type instead of emitting matches empty`() {
        val ex = assertFailsWith<IllegalArgumentException> {
            BCheckBridge.emitScript(
                name = "x", description = "d", author = "a", tags = "t",
                type = "totally_unknown",
                matchPattern = null, matchLocation = null, matchCondition = null,
                payloads = null, responseMatchPattern = null, collaboratorPayloadType = null,
                severity = "high", confidence = "firm", issueDetail = null, issueRemediation = null
            )
        }
        assertTrue(ex.message!!.contains("Unsupported BCheck type"), ex.message)
    }

    // ---- insertion_point emits valid v2-beta DSL (BUG #32 C) --------------

    @Test
    fun `insertion_point emits one send-payload per payload with no run-for-each`() {
        val script = BCheckBridge.emitScript(
            name = "SSTI", description = "d", author = "a", tags = "ssti",
            type = "insertion_point",
            matchPattern = null, matchLocation = null, matchCondition = null,
            payloads = listOf("\${7*7}", "\${9*9}"),
            responseMatchPattern = "49|81",
            collaboratorPayloadType = null,
            severity = "high", confidence = "firm",
            issueDetail = "SSTI", issueRemediation = "fix"
        )
        assertTrue(script.contains("given insertion point then"), script)
        // The broken construct must be gone.
        assertFalse(script.contains("run for each"), "insertion_point must not use run for each: $script")
        // One distinct send payload per payload, each with its own detection block.
        assertTrue(script.contains("send payload called p1:"), script)
        assertTrue(script.contains("send payload called p2:"), script)
        assertTrue(script.contains("if {p1.response.body} matches"), script)
        assertTrue(script.contains("if {p2.response.body} matches"), script)
        assertEquals(2, Regex("send payload called p\\d+:").findAll(script).count())
        // Never a degenerate empty match.
        assertFalse(script.contains("matches \"\""), "must not emit matches \"\": $script")
    }

    @Test
    fun `insertion_point with a single match pattern still emits a valid block`() {
        val script = BCheckBridge.emitScript(
            name = "err", description = "d", author = "a", tags = "t",
            type = "insertion_point",
            matchPattern = "'", matchLocation = null, matchCondition = null,
            payloads = null,
            responseMatchPattern = "SQL syntax",
            collaboratorPayloadType = null,
            severity = "medium", confidence = "tentative",
            issueDetail = null, issueRemediation = null
        )
        assertTrue(script.contains("send payload called p1:"), script)
        assertTrue(script.contains("replacing: `'`"), script)
        assertTrue(script.contains("if {p1.response.body} matches \"SQL syntax\""), script)
        assertFalse(script.contains("run for each"), script)
    }

    // ---- create() guards empty match for active checks (BUG #32 C) -------
    // (emitScript falls back defensively; create() enforces the hard guard.
    //  Here we assert the emitter never produces the degenerate pattern.)

    @Test
    fun `insertion_point never emits matches empty even with no patterns`() {
        val script = BCheckBridge.emitScript(
            name = "x", description = "d", author = "a", tags = "t",
            type = "insertion_point",
            matchPattern = null, matchLocation = null, matchCondition = null,
            payloads = null, responseMatchPattern = null, collaboratorPayloadType = null,
            severity = "low", confidence = "tentative", issueDetail = null, issueRemediation = null
        )
        assertFalse(script.contains("matches \"\""), script)
    }

    // ---- condition remapping: contains -> matches(escaped) ---------------

    @Test
    fun `contains condition is translated to an escaped matches regex`() {
        val (op, pat) = BCheckBridge.normalizeCondition("contains", "a.b(c)")
        assertEquals("matches", op)
        // metacharacters escaped so they are treated literally
        assertEquals("a\\.b\\(c\\)", pat)
    }

    @Test
    fun `is condition passes through unchanged`() {
        val (op, pat) = BCheckBridge.normalizeCondition("is", "200")
        assertEquals("is", op)
        assertEquals("200", pat)
    }

    @Test
    fun `matches and unknown default to matches with the raw pattern`() {
        assertEquals("matches" to "x+", BCheckBridge.normalizeCondition("matches", "x+"))
        assertEquals("matches" to "x+", BCheckBridge.normalizeCondition(null, "x+"))
    }

    @Test
    fun `passive_response contains emits a matches operator not the raw contains keyword`() {
        val script = BCheckBridge.emitScript(
            name = "n", description = "d", author = "a", tags = "t",
            type = "passive_response",
            matchPattern = "secret.value", matchLocation = "response_body",
            matchCondition = "contains",
            payloads = null, responseMatchPattern = null, collaboratorPayloadType = null,
            severity = "high", confidence = "firm", issueDetail = null, issueRemediation = null
        )
        // The invalid `contains` operator must never appear in the emitted DSL.
        assertFalse(Regex("\\bcontains\\b").containsMatchIn(script), script)
        assertTrue(script.contains("{latest.response.body} matches \"secret\\.value\""), script)
    }

    // ---- path_level define list stays grammar-valid (BUG #32 D) ----------

    @Test
    fun `path_level define list quotes and escapes each value`() {
        val script = BCheckBridge.emitScript(
            name = "bak", description = "d", author = "a", tags = "t",
            type = "path_level",
            matchPattern = null, matchLocation = null, matchCondition = null,
            payloads = listOf(".bak", "quote\"here"),
            responseMatchPattern = null, collaboratorPayloadType = null,
            severity = "medium", confidence = "tentative", issueDetail = null, issueRemediation = null
        )
        // Every list entry is individually quoted; the stray quote is neutralised
        // so it cannot terminate the list literal.
        assertTrue(script.contains("test_extensions = \".bak\", \"quote\\\"here\""), script)
        // The define list is consumed by a matching run-for-each binding.
        assertTrue(script.contains("run for each:"), script)
        assertTrue(script.contains("test_extensions as ext"), script)
    }

    // ---- collaborator interaction type is normalised ---------------------

    @Test
    fun `collaborator normalises interaction type to dns or http`() {
        val http = BCheckBridge.emitScript(
            name = "ssrf", description = "d", author = "a", tags = "t",
            type = "collaborator",
            matchPattern = null, matchLocation = "Referer", matchCondition = null,
            payloads = null, responseMatchPattern = null, collaboratorPayloadType = "HTTP",
            severity = "high", confidence = "firm", issueDetail = null, issueRemediation = null
        )
        assertTrue(http.contains("if http interactions then"), http)

        val bogus = BCheckBridge.emitScript(
            name = "ssrf", description = "d", author = "a", tags = "t",
            type = "collaborator",
            matchPattern = null, matchLocation = "Referer", matchCondition = null,
            payloads = null, responseMatchPattern = null, collaboratorPayloadType = "smtp",
            severity = "high", confidence = "firm", issueDetail = null, issueRemediation = null
        )
        // Unknown callback types fall back to dns rather than emitting `smtp interactions`.
        assertTrue(bogus.contains("if dns interactions then"), bogus)
    }

    // ---- metadata is always well-formed ----------------------------------

    @Test
    fun `emitScript always writes the required metadata header`() {
        val script = BCheckBridge.emitScript(
            name = "n", description = "d", author = "a", tags = "one, two",
            type = "passive_response",
            matchPattern = "x", matchLocation = null, matchCondition = null,
            payloads = null, responseMatchPattern = null, collaboratorPayloadType = null,
            severity = "high", confidence = "firm", issueDetail = null, issueRemediation = null
        )
        assertTrue(script.startsWith("metadata:"), script)
        assertTrue(script.contains("language: v2-beta"), script)
        assertTrue(script.contains("tags: \"one\", \"two\""), script)
    }
}
