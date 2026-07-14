package com.burpmcp.ultra.bridge

import com.burpmcp.ultra.bridge.IdorHunt.IdFormat
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.assertFalse

/**
 * Unit tests for the pure IDOR-hunting engine [IdorHunt]. Exercises the four
 * Burp-independent capabilities that back the `idor_hunt` MCP tool:
 * format recognition, transformation generation, request-ref location, and the
 * canary/signature verdict (the horizontal-IDOR confirmation auth_diff lacks).
 */
class IdorHuntTest {

    // ---- 1. format recognition -------------------------------------------

    @Test fun `classifies plain sequential integers`() {
        assertEquals(IdFormat.INT, IdorHunt.classify("1002").format)
        assertEquals(IdFormat.INT, IdorHunt.classify("42").format)
        assertEquals(IdFormat.INT, IdorHunt.classify("-1").format)
    }

    @Test fun `classifies UUID versions by the version nibble`() {
        assertEquals(IdFormat.UUID_V1, IdorHunt.classify("2c1b0e3a-7f6a-11e9-8f9e-2a86e4085a59").format)
        assertEquals(IdFormat.UUID_V4, IdorHunt.classify("f47ac10b-58cc-4372-a567-0e02b2c3d479").format)
        assertEquals(IdFormat.UUID_V7, IdorHunt.classify("018f6b3c-7e1a-7c2a-b3d4-1a2b3c4d5e6f").format)
    }

    @Test fun `classifies MongoDB ObjectID and hashes by length`() {
        assertEquals(IdFormat.OBJECTID, IdorHunt.classify("507f1f77bcf86cd799439011").format)
        assertEquals(IdFormat.HASH_MD5, IdorHunt.classify("c4ca4238a0b923820dcc509a6f75849b").format)
        assertEquals(IdFormat.HASH_SHA1, IdorHunt.classify("356a192b7913b04c54574d18c28d46e6395428ab").format)
        assertEquals(IdFormat.HASH_SHA256, IdorHunt.classify("6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b").format)
    }

    @Test fun `classifies snowflake-scale ids distinctly from small ints`() {
        assertEquals(IdFormat.SNOWFLAKE, IdorHunt.classify("175928847299117063").format)
        assertEquals(IdFormat.INT, IdorHunt.classify("1002").format)
    }

    @Test fun `classifies gid and base64 node ids and decodes them`() {
        val gid = IdorHunt.classify("gid://User/1001")
        assertEquals(IdFormat.GID, gid.format)
        assertEquals("1001", gid.decoded)

        val b64 = IdorHunt.classify("VXNlcjoxMDAx") // base64("User:1001")
        assertEquals(IdFormat.GID, b64.format)
        assertEquals("User:1001", b64.decoded)
    }

    @Test fun `classifies plain base64 opaque refs`() {
        val c = IdorHunt.classify("MTIz") // base64("123")
        assertEquals(IdFormat.BASE64, c.format)
        assertEquals("123", c.decoded)
    }

    @Test fun `unknown and empty inputs are low confidence`() {
        assertEquals(IdFormat.UNKNOWN, IdorHunt.classify("").format)
        assertEquals(0, IdorHunt.classify("").confidence)
        assertEquals(IdFormat.UNKNOWN, IdorHunt.classify("!!not-an-id!!").format)
    }

    // ---- 2. transformation generation ------------------------------------

    @Test fun `integer mutations include neighbors boundaries and encodings and are bounded`() {
        val muts = IdorHunt.mutations("1002")
        val values = muts.map { it.value }.toSet()
        assertTrue("1001" in values, "must include n-1")
        assertTrue("1003" in values, "must include n+1")
        assertTrue("0" in values, "must include boundary 0")
        assertTrue("2147483648" in values, "must include int32 overflow")
        assertTrue(muts.any { it.technique == "base64-encode" }, "must include a base64 transform")
        assertTrue(muts.any { it.technique == "null-byte-append" }, "must include a null-byte transform")
        assertTrue(muts.size <= 64, "must respect the max bound")
        // no dupes, never the original
        assertEquals(values.size, muts.size)
        assertFalse("1002" in values, "must never emit the original value")
    }

    @Test fun `uuid mutations include nil max and tail bump`() {
        val muts = IdorHunt.mutations("f47ac10b-58cc-4372-a567-0e02b2c3d479")
        val values = muts.map { it.value }.toSet()
        assertTrue("00000000-0000-0000-0000-000000000000" in values, "nil uuid")
        assertTrue("ffffffff-ffff-ffff-ffff-ffffffffffff" in values, "max uuid")
        assertTrue(muts.any { it.technique == "uuid-tail-decrement" }, "tail decrement")
        assertTrue(values.all { it != "f47ac10b-58cc-4372-a567-0e02b2c3d479" })
    }

    @Test fun `gid mutations decode modify and re-encode the numeric tail`() {
        val muts = IdorHunt.mutations("VXNlcjoxMDAx") // User:1001
        val decodedTails = muts.filter { it.technique == "decode-modify-reencode" }
            .map { IdorHunt.classify(it.value).decoded }
        assertTrue(decodedTails.contains("User:1000") || decodedTails.contains("User:1002"),
            "should produce User:1000/User:1002 re-encoded, got $decodedTails")
    }

    @Test fun `objectid mutations bump the trailing counter`() {
        val muts = IdorHunt.mutations("507f1f77bcf86cd799439011")
        assertTrue(muts.any { it.value == "507f1f77bcf86cd799439012" }, "counter+1")
        assertTrue(muts.any { it.value == "507f1f77bcf86cd799439010" }, "counter-1")
    }

    // ---- 3. request-ref location -----------------------------------------

    @Test fun `locates numeric id in the url path`() {
        val req = "GET /api/v1/users/1002/profile HTTP/1.1\r\nHost: x.com\r\n\r\n"
        val refs = IdorHunt.locateRefs(req)
        assertTrue(refs.any { it.location == "path" && it.value == "1002" }, "should find path id 1002: $refs")
    }

    @Test fun `locates id-ish query params and skips auth headers`() {
        val req = "GET /api/orders?order_id=5567&sort=asc HTTP/1.1\r\n" +
            "Host: x.com\r\nAuthorization: Bearer secrettoken\r\nX-User-Id: 42\r\n\r\n"
        val refs = IdorHunt.locateRefs(req)
        assertTrue(refs.any { it.location == "query" && it.name == "order_id" && it.value == "5567" }, "query id: $refs")
        assertTrue(refs.any { it.location == "header" && it.name == "X-User-Id" && it.value == "42" }, "header id: $refs")
        assertFalse(refs.any { it.value.contains("secrettoken") }, "must not surface the Authorization token as a ref")
        assertFalse(refs.any { it.name == "sort" }, "sort=asc is not an id")
    }

    @Test fun `locates id fields in a json body`() {
        val req = "POST /api/transfer HTTP/1.1\r\nHost: x.com\r\nContent-Type: application/json\r\n\r\n" +
            "{\"account_id\":\"9001\",\"amount\":50,\"note\":\"hi\"}"
        val refs = IdorHunt.locateRefs(req)
        assertTrue(refs.any { it.location == "body-json" && it.name == "account_id" && it.value == "9001" }, "json id: $refs")
        assertFalse(refs.any { it.name == "note" }, "note is not an id")
    }

    @Test fun `locates id-bearing cookies`() {
        val req = "GET /dashboard HTTP/1.1\r\nHost: x.com\r\nCookie: session=abc; user_id=7\r\n\r\n"
        val refs = IdorHunt.locateRefs(req)
        assertTrue(refs.any { it.location == "cookie" && it.name == "user_id" && it.value == "7" }, "cookie id: $refs")
    }

    // ---- 3b. location-scoped id swap -------------------------------------

    @Test fun `applySwap rewrites only the located path segment`() {
        val req = "GET /api/users/1002/orders/1002 HTTP/1.1\r\nHost: x.com\r\n\r\n"
        val ref = IdorHunt.locateRefs(req).first { it.location == "path" }
        val swapped = IdorHunt.applySwap(req, ref, "1003")
        // both /1002 path segments become /1003; the Host and version are untouched
        assertTrue(swapped.contains("/api/users/1003/orders/1003"), swapped)
        assertTrue(swapped.contains("HTTP/1.1"), "must not corrupt the version token: $swapped")
        assertTrue(swapped.contains("Host: x.com"))
    }

    @Test fun `applySwap rewrites a json body field without touching same-valued others`() {
        val req = "POST /t HTTP/1.1\r\nHost: x.com\r\n\r\n{\"account_id\":\"9001\",\"amount\":9001}"
        val ref = IdorHunt.locateRefs(req).first { it.name == "account_id" }
        val swapped = IdorHunt.applySwap(req, ref, "9002")
        assertTrue(swapped.contains("\"account_id\":\"9002\""), swapped)
        assertTrue(swapped.contains("\"amount\":9001"), "the amount field must be untouched: $swapped")
    }

    @Test fun `applySwap rewrites a cookie value only`() {
        val req = "GET /d HTTP/1.1\r\nHost: x.com\r\nCookie: session=abc; user_id=7\r\n\r\n"
        val ref = IdorHunt.locateRefs(req).first { it.location == "cookie" }
        val swapped = IdorHunt.applySwap(req, ref, "8")
        assertTrue(swapped.contains("user_id=8"), swapped)
        assertTrue(swapped.contains("session=abc"), "session cookie untouched")
    }

    // ---- 4. canary / signature verdict -----------------------------------

    @Test fun `confirms horizontal idor when reader sees the owner canary and not its own`() {
        val probes = listOf(
            IdorHunt.CanaryProbe("alice", "bob", "1002", 200, "{\"ssn\":\"BOB-CANARY-9f\"}", "BOB-CANARY-9f", "ALICE-CANARY-1a")
        )
        val f = IdorHunt.assessCanary(probes)
        assertEquals(1, f.size)
        assertEquals("critical", f[0].severity)
        assertEquals("confirmed_horizontal_idor", f[0].id)
        assertEquals("critical", IdorHunt.topSeverity(f))
    }

    @Test fun `filters own-data-reflection false positive`() {
        val probes = listOf(
            IdorHunt.CanaryProbe("alice", "bob", "1002", 200, "{\"ssn\":\"ALICE-CANARY-1a\"}", "BOB-CANARY-9f", "ALICE-CANARY-1a")
        )
        val f = IdorHunt.assessCanary(probes)
        assertEquals("own_data_reflection_fp", f[0].id)
        assertEquals("info", f[0].severity)
    }

    @Test fun `properly denied cross reads produce no finding`() {
        val probes = listOf(
            IdorHunt.CanaryProbe("alice", "bob", "1002", 403, "Forbidden", "BOB-CANARY-9f", "ALICE-CANARY-1a")
        )
        assertTrue(IdorHunt.assessCanary(probes).isEmpty(), "a 403 cross-read is correct behavior")
    }

    @Test fun `2xx without a canary is a candidate not a confirmation`() {
        val probes = listOf(
            IdorHunt.CanaryProbe("alice", "bob", "1002", 200, "{\"data\":\"...\"}", null, null)
        )
        val f = IdorHunt.assessCanary(probes)
        assertEquals("candidate_needs_canary", f[0].id)
        assertEquals("high", f[0].severity)
    }

    @Test fun `same-identity baseline reads are ignored`() {
        val probes = listOf(
            IdorHunt.CanaryProbe("alice", "alice", "1001", 200, "own", "A", "A")
        )
        assertTrue(IdorHunt.assessCanary(probes).isEmpty())
    }
}
