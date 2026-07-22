package com.burpmcp.ultra.safety

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Issue #7: a raw CR/LF in an LLM-supplied method/url/header reaches the HTTP/2 :path (or splits a
 * header), so Burp "kettles" the request and the server rejects it (RST_STREAM). [stripControl] is
 * the fix (remove it before sending); [scan] reports what was cleaned. Neither touches raw_request /
 * raw bytes, so intentional CRLF (smuggling research) still works.
 */
class RequestHygieneTest {

    // --- scan(): advisory detection ---

    @Test fun `clean inputs produce no warnings`() {
        assertEquals(emptyList(), RequestHygiene.scan("GET", "https://example.com/api?q=1", mapOf("Accept" to "*/*")))
    }

    @Test fun `null inputs produce no warnings`() {
        assertEquals(emptyList(), RequestHygiene.scan(null, null, null))
    }

    @Test fun `a newline in a header value is flagged and names the header`() {
        val w = RequestHygiene.scan("GET", "https://example.com/", mapOf("X-From-LLM" to "value\nstray"))
        assertEquals(1, w.size)
        assertTrue(w[0].contains("X-From-LLM"), "should name the offending header: ${w[0]}")
    }

    @Test fun `a carriage return in a header value is flagged`() {
        assertEquals(1, RequestHygiene.scan("GET", "https://example.com/", mapOf("X" to "a\r\nInjected: 1")).size)
    }

    @Test fun `a newline in the url is flagged`() {
        assertEquals(1, RequestHygiene.scan("GET", "https://example.com/real/path\n", null).size)
    }

    @Test fun `a newline in the method is flagged`() {
        assertEquals(1, RequestHygiene.scan("GET\r\n", "https://example.com/", null).size)
    }

    @Test fun `a control char in a header name is flagged`() {
        assertTrue(RequestHygiene.scan("GET", "https://example.com/", mapOf("Bad\nName" to "v")).isNotEmpty())
    }

    @Test fun `a tab is not treated as a line break`() {
        assertEquals(emptyList(), RequestHygiene.scan("GET", "https://example.com/", mapOf("X" to "a\tb")))
    }

    // --- stripControl(): the actual fix ---

    @Test fun `stripControl removes a trailing newline from a url`() {
        assertEquals("https://example.com/api/search", RequestHygiene.stripControl("https://example.com/api/search\n"))
    }

    @Test fun `stripControl removes embedded CR and LF`() {
        assertEquals("/a/b", RequestHygiene.stripControl("/a\r\n/b"))
        assertEquals("GET", RequestHygiene.stripControl("GET\r\n"))
    }

    @Test fun `stripControl keeps tabs, spaces and normal characters`() {
        assertEquals("a\tb c", RequestHygiene.stripControl("a\tb c"))
        assertEquals("/path?q=1&r=2", RequestHygiene.stripControl("/path?q=1&r=2"))
    }

    @Test fun `stripControl removes other C0 control chars but keeps tab`() {
        assertEquals("xy", RequestHygiene.stripControl("x\u000By"))  // vertical tab
        assertEquals("ab", RequestHygiene.stripControl("a\u0007b"))  // BEL
        assertEquals("cd", RequestHygiene.stripControl("c\u0000d"))  // NUL
        assertEquals("a\tb", RequestHygiene.stripControl("a\tb"))    // tab kept
    }

    @Test fun `stripControl is a no-op on clean input`() {
        val clean = "https://example.com/normal/path"
        assertEquals(clean, RequestHygiene.stripControl(clean))
    }

    // --- normalizeCrlf(): the request-line "kettled :path" fix ---

    @Test fun `normalizeCrlf converts a bare-LF request to CRLF so the request line delimits`() {
        // Regression for the live "kettled" report: a bare-LF WebSocket-upgrade request
        // added to Repeater folded the whole message into the HTTP/2 :path pseudo-header.
        val bareLf = "GET /chat HTTP/1.1\nHost: x.com\nUpgrade: websocket\n\n"
        val fixed = RequestHygiene.normalizeCrlf(bareLf)
        assertTrue(fixed.startsWith("GET /chat HTTP/1.1\r\n"), "request line must be CRLF-delimited: $fixed")
        assertFalse(fixed.contains(Regex("(?<!\r)\n")), "no bare LF may remain: $fixed")
    }

    @Test fun `normalizeCrlf leaves an already-CRLF request byte-identical`() {
        val crlf = "POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\nabc"
        assertEquals(crlf, RequestHygiene.normalizeCrlf(crlf))
    }

    @Test fun `normalizeCrlf canonicalizes escaped JSON-transport line endings`() {
        assertEquals("A\r\nB\r\nC", RequestHygiene.normalizeCrlf("A\\r\\nB\\nC"))
    }

    // --- adjustedOffset(): keeps Intruder positions aligned after LF→CRLF expansion ---

    @Test fun `adjustedOffset is identity on an already-CRLF request`() {
        val crlf = "GET / HTTP/1.1\r\nHost: x\r\n\r\n"
        assertEquals(10, RequestHygiene.adjustedOffset(crlf, 10))
    }

    @Test fun `adjustedOffset shifts by the count of bare LFs before the offset`() {
        val bareLf = "AB\nCD\nEF" // one LF before index 4, two before index 6
        assertEquals(0, RequestHygiene.adjustedOffset(bareLf, 0))
        assertEquals(5, RequestHygiene.adjustedOffset(bareLf, 4))
        assertEquals(8, RequestHygiene.adjustedOffset(bareLf, 6))
    }

    @Test fun `adjustedOffset clamps out-of-range offsets`() {
        val s = "abc\ndef"
        assertEquals(RequestHygiene.normalizeCrlf(s).length, RequestHygiene.adjustedOffset(s, 999))
        assertEquals(0, RequestHygiene.adjustedOffset(s, -5))
    }
}
