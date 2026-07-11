package com.burpmcp.ultra.bridge

import kotlin.test.Test
import kotlin.test.assertEquals

class HttpKeywordCountTest {

    @Test
    fun `case-sensitive count distinguishes case`() {
        val text = "Error error ERROR error"
        val counts = HttpKeywordCount.countCaseSensitive(text, listOf("error", "Error", "ERROR"))
        assertEquals(2, counts["error"])
        assertEquals(1, counts["Error"])
        assertEquals(1, counts["ERROR"])
    }

    @Test
    fun `case-sensitive count is zero when only other cases present`() {
        // The whole point of the fix: "admin" must NOT match "ADMIN" in case-sensitive mode.
        val counts = HttpKeywordCount.countCaseSensitive("Welcome ADMIN panel", listOf("admin"))
        assertEquals(0, counts["admin"])
    }

    @Test
    fun `empty keyword counts as zero`() {
        val counts = HttpKeywordCount.countCaseSensitive("anything", listOf(""))
        assertEquals(0, counts[""])
    }

    @Test
    fun `counts are non-overlapping`() {
        assertEquals(2, HttpKeywordCount.countOccurrences("aaaa", "aa"))
    }

    @Test
    fun `preserves input order of keywords`() {
        val counts = HttpKeywordCount.countCaseSensitive("b a c", listOf("c", "a", "b"))
        assertEquals(listOf("c", "a", "b"), counts.keys.toList())
    }

    @Test
    fun `multiple occurrences across a raw response are counted`() {
        val raw = "HTTP/1.1 200 OK\r\nX-Flag: token\r\n\r\ntoken=abc; token=def"
        assertEquals(3, HttpKeywordCount.countOccurrences(raw, "token"))
    }
}
