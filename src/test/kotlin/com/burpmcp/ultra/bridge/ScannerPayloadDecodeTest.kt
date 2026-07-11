package com.burpmcp.ultra.bridge

import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Unit tests for [ScannerBridge.decodeMessagePayload] / [ScannerBridge.looksLikeBase64].
 *
 * BUG #19: scanner_create_issue's schema documents `request`/`response` as plain
 * HTTP messages, but the bridge previously ran Base64.decode() on them
 * unconditionally, so a caller who followed the schema and passed plain HTTP got
 * a confusing "Illegal base64 character" failure. The decoder now accepts plain
 * HTTP text (the documented form) and only treats input as base64 when it is
 * unambiguously base64.
 */
class ScannerPayloadDecodeTest {

    private fun asString(bytes: ByteArray) = String(bytes, Charsets.ISO_8859_1)

    @Test
    fun `plain HTTP request with CRLF is preserved byte-accurately`() {
        val http = "GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n"
        val decoded = ScannerBridge.decodeMessagePayload(http)
        assertEquals(http, asString(decoded))
    }

    @Test
    fun `plain HTTP request with bare LF is normalized to CRLF`() {
        val http = "GET /a HTTP/1.1\nHost: example.com\n\n"
        val expected = "GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n"
        val decoded = ScannerBridge.decodeMessagePayload(http)
        assertEquals(expected, asString(decoded))
    }

    @Test
    fun `plain HTTP with body containing high bytes survives round-trip under charset`() {
        // A byte 0xFF placed in the body must round-trip exactly (ISO-8859-1).
        val http = "POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 1\r\n\r\nÿ"
        val decoded = ScannerBridge.decodeMessagePayload(http)
        assertEquals(http.length, decoded.size)
        assertEquals(0xFF.toByte(), decoded.last())
    }

    @Test
    fun `unambiguous base64 is decoded for backward compatibility`() {
        val original = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        val b64 = Base64.getEncoder().encodeToString(original.toByteArray(Charsets.ISO_8859_1))
        // The encoded form contains no spaces/CRLF, so it is treated as base64.
        assertTrue(ScannerBridge.looksLikeBase64(b64))
        val decoded = ScannerBridge.decodeMessagePayload(b64)
        assertEquals(original, asString(decoded))
    }

    @Test
    fun `a real HTTP message is never mistaken for base64`() {
        // Contains spaces and CRLF, both outside the base64 alphabet.
        assertFalse(ScannerBridge.looksLikeBase64("GET /a HTTP/1.1\r\nHost: h\r\n\r\n"))
    }

    @Test
    fun `base64-alphabet word without padding but wrong length is treated as plain text`() {
        // "GET" is 3 chars (length % 4 != 0), so it is NOT valid base64 framing;
        // it must be preserved as plain text rather than throwing.
        val decoded = ScannerBridge.decodeMessagePayload("GET")
        assertEquals("GET", asString(decoded))
    }

    @Test
    fun `looksLikeBase64 rejects strings with whitespace and stray characters`() {
        assertFalse(ScannerBridge.looksLikeBase64("has space"))
        assertFalse(ScannerBridge.looksLikeBase64("line\nbreak"))
        assertFalse(ScannerBridge.looksLikeBase64("with-dash1"))
        assertFalse(ScannerBridge.looksLikeBase64(""))
    }

    @Test
    fun `looksLikeBase64 accepts padded base64 and rejects mid-string padding`() {
        assertTrue(ScannerBridge.looksLikeBase64("YWJjZA=="))
        assertFalse(ScannerBridge.looksLikeBase64("YW==YWJj"))
    }
}
