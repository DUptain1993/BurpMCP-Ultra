package com.burpmcp.ultra.bridge

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.assertFalse

class HttpWireEncodingTest {

    @Test
    fun `Content-Length uses UTF-8 byte count for multi-byte body`() {
        val body = "café ☃" // é = 2 bytes UTF-8; ☃ = 3 bytes UTF-8
        val utf8Len = body.toByteArray(Charsets.UTF_8).size
        val latin1Len = body.toByteArray(Charsets.ISO_8859_1).size
        assertTrue(utf8Len > latin1Len, "UTF-8 must be longer than Latin-1 for this body")

        val raw = HttpWireEncoding.constructRawHttpRequest(
            url = "https://example.com/x",
            method = "POST",
            headers = emptyMap(),
            body = body,
            host = "example.com",
            port = 443,
            tls = true
        )

        val clLine = raw.lineSequence().first { it.startsWith("Content-Length:", ignoreCase = true) }
        val declared = clLine.substringAfter(":").trim().toInt()
        assertEquals(utf8Len, declared)
        assertFalse(declared == latin1Len, "must not use Latin-1 sizing")
        assertEquals(HttpWireEncoding.bodyByteLength(body), declared)
    }

    @Test
    fun `fixContentLength rewrites wrong CL to UTF-8 length`() {
        val body = "café ☃"
        val utf8Len = body.toByteArray(Charsets.UTF_8).size
        val wrong = "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\n\r\n$body"
        val fixed = HttpWireEncoding.fixContentLength(wrong)
        val clLine = fixed.lineSequence().first { it.startsWith("Content-Length:", ignoreCase = true) }
        assertEquals(utf8Len, clLine.substringAfter(":").trim().toInt())
    }
}
