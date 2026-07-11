package com.burpmcp.ultra.bridge

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Unit tests for the pure, Burp-independent helpers in [AnalysisBridge].
 *
 * These cover the regressions fixed for:
 *  - BUG #3  analyze_request: missing CRLF normalization (LF-delimited headers dropped)
 *  - BUG #4  analyze_insertion_points: query string appended to final path segment
 *  - BUG #5/#6 empty-input parser exception leakage (via describeException)
 *  - BUG #18 auth_diff: bare-null / raw JVM exception leakage
 *
 * The full bridge cannot be instantiated here (the Montoya API is compileOnly),
 * so we exercise the extracted pure logic directly through the internal companion.
 */
class AnalysisBridgeHelpersTest {

    // ---- BUG #3: CRLF normalization -----------------------------------

    @Test
    fun `bare LF delimiters are upgraded to CRLF so headers are not dropped`() {
        val raw = "GET / HTTP/1.1\nHost: example.com\nAccept: */*\n\n"
        val normalized = AnalysisBridge.normalizeCrlfMessage(raw)
        assertEquals("GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n", normalized)
        assertFalse(normalized.contains(Regex("(?<!\r)\n")), "no bare LF should remain")
    }

    @Test
    fun `escaped newline sequences from JSON transport are decoded then normalized`() {
        val raw = "GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n"
        val normalized = AnalysisBridge.normalizeCrlfMessage(raw)
        assertEquals("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", normalized)
    }

    @Test
    fun `already-CRLF messages are left unchanged (idempotent)`() {
        val raw = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        assertEquals(raw, AnalysisBridge.normalizeCrlfMessage(raw))
    }

    @Test
    fun `escaped backslash-n mixed with real CRLF does not double-convert`() {
        val raw = "GET / HTTP/1.1\r\nHost: example.com\\n\r\n\r\n"
        val normalized = AnalysisBridge.normalizeCrlfMessage(raw)
        assertFalse(normalized.contains(Regex("(?<!\r)\n")), "no bare LF should remain")
        assertFalse(normalized.contains("\r\r"), "no doubled CR should be produced")
    }

    // ---- BUG #4: path segment query-string stripping ------------------

    @Test
    fun `path segments strip the query string from the final segment`() {
        val segments = AnalysisBridge.pathSegments("/product/category/e?id=42&q=x")
        assertEquals(listOf("product", "category", "e"), segments)
    }

    @Test
    fun `path segments strip a fragment as well`() {
        val segments = AnalysisBridge.pathSegments("/a/b/c#frag")
        assertEquals(listOf("a", "b", "c"), segments)
    }

    @Test
    fun `path with no query is unaffected and drops empty segments`() {
        val segments = AnalysisBridge.pathSegments("/product//e/")
        assertEquals(listOf("product", "e"), segments)
    }

    @Test
    fun `root path yields no segments`() {
        assertTrue(AnalysisBridge.pathSegments("/").isEmpty())
        assertTrue(AnalysisBridge.pathSegments("/?only=query").isEmpty())
    }

    // ---- BUG #5 / #6 / #18: safe exception description ----------------

    @Test
    fun `null-message exception is described by its class name not the string null`() {
        val e = StringIndexOutOfBoundsException() // message is null
        val described = AnalysisBridge.describeException(e)
        assertEquals("StringIndexOutOfBoundsException", described)
        assertFalse(described.equals("null", ignoreCase = true))
    }

    @Test
    fun `blank-message exception falls back to the class name`() {
        val e = RuntimeException("   ")
        assertEquals("RuntimeException", AnalysisBridge.describeException(e))
    }

    @Test
    fun `present message is preserved verbatim`() {
        val e = IllegalArgumentException("fromIndex(1) > toIndex(0)")
        assertEquals("fromIndex(1) > toIndex(0)", AnalysisBridge.describeException(e))
    }

    // kotlin.test.assertFalse is imported transitively; local shim for clarity.
    private fun assertFalse(condition: Boolean, message: String? = null) =
        kotlin.test.assertFalse(condition, message)
}
