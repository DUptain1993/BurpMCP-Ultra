package com.burpmcp.ultra.safety

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Advisory hygiene for http_send_request inputs (GitHub issue #7): a raw CR/LF in the method, url,
 * or a header value is what makes Burp flag a request as "kettled" (unrepresentable in HTTP/1), or
 * silently retargets a request to "/". The scan surfaces a human-readable warning so the agent can
 * self-correct; it never blocks (a security tool may send CRLF for smuggling research on purpose).
 */
class RequestHygieneTest {

    @Test fun `clean inputs produce no warnings`() {
        assertEquals(emptyList(), RequestHygiene.scan("GET", "https://example.com/api?q=1", mapOf("Accept" to "*/*")))
    }

    @Test fun `null inputs produce no warnings`() {
        assertEquals(emptyList(), RequestHygiene.scan(null, null, null))
    }

    @Test fun `a newline in a header value is flagged as kettling`() {
        val w = RequestHygiene.scan("GET", "https://example.com/", mapOf("X-From-LLM" to "value\nstray"))
        assertEquals(1, w.size)
        assertTrue(w[0].contains("kettled"), "should explain the Burp 'kettled' consequence: ${w[0]}")
        assertTrue(w[0].contains("X-From-LLM"), "should name the offending header: ${w[0]}")
    }

    @Test fun `a carriage return in a header value is also flagged`() {
        assertEquals(1, RequestHygiene.scan("GET", "https://example.com/", mapOf("X" to "a\r\nInjected: 1")).size)
    }

    @Test fun `a newline in the url is flagged as a path fallback`() {
        val w = RequestHygiene.scan("GET", "https://example.com/real/path\n", null)
        assertEquals(1, w.size)
        assertTrue(w[0].contains("\"/\""), "should warn the request falls back to path \"/\": ${w[0]}")
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
}
