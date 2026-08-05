package com.burpmcp.ultra.core

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * GitHub issue #12 (@th0t3p): `proxy_history` with `include_response=true` embedded a binary body
 * verbatim, and a single binary asset (a webfont) made an entire ~4 MB, 50-item batch unparseable
 * client-side with `json.JSONDecodeError: Unterminated string`.
 *
 * The decisive mechanism is an **unpaired surrogate**: it has no UTF-8 encoding, so it corrupts the
 * encoded stream. It can be present in the decoded bytes, or manufactured by truncating a valid
 * string right between the two halves of a pair. These tests pin both, and pin that ordinary text
 * (including control characters, which a conformant JSON encoder escapes perfectly well) is still
 * passed through untouched.
 */
class BodyTextTest {

    private val HI = '\uD83D'   // high surrogate of U+1F600
    private val LO = '\uDE00'   // low  surrogate of U+1F600
    private val EMOJI = "$HI$LO"

    // ---- binary detection --------------------------------------------------

    @Test fun `a NUL byte marks content as binary`() {
        assertTrue(BodyText.isProbablyBinary("PK\u0003\u0004\u0000 rest of a zip"))
    }

    @Test fun `a control-char-dense body is binary`() {
        val fontish = buildString { repeat(200) { append('\u0001').append('\u0002').append("Aa") } }
        assertTrue(BodyText.isProbablyBinary(fontish))
    }

    @Test fun `ordinary HTTP text is not binary`() {
        val html = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>hi</body></html>"
        assertFalse(BodyText.isProbablyBinary(html))
        assertFalse(BodyText.isProbablyBinary(""))
    }

    @Test fun `binary mime types are recognised regardless of content`() {
        assertTrue(BodyText.isBinaryMime("IMAGE_PNG"))
        assertTrue(BodyText.isBinaryMime("FONT_WOFF2"))
        assertTrue(BodyText.isBinaryMime("APPLICATION_PDF"))
        assertFalse(BodyText.isBinaryMime("HTML"))
        assertFalse(BodyText.isBinaryMime("JSON"))
        assertFalse(BodyText.isBinaryMime(null))
    }

    // ---- lone surrogates: the actual corruption ----------------------------

    @Test fun `a lone high surrogate is replaced so the result is UTF-8 encodable`() {
        val broken = "abc$HI" + "def"
        val fixed = BodyText.stripLoneSurrogates(broken)
        assertFalse(fixed.any { it.isHighSurrogate() || it.isLowSurrogate() }, fixed)
        // The real invariant: it can now be encoded, which the original could not.
        assertEquals(broken.length, fixed.length)
        fixed.toByteArray(Charsets.UTF_8)  // must not throw / must round-trip
        assertEquals(fixed, String(fixed.toByteArray(Charsets.UTF_8), Charsets.UTF_8))
    }

    @Test fun `a lone low surrogate is replaced`() {
        val fixed = BodyText.stripLoneSurrogates("abc$LO")
        assertEquals(fixed, String(fixed.toByteArray(Charsets.UTF_8), Charsets.UTF_8))
    }

    @Test fun `a valid surrogate PAIR is preserved untouched`() {
        val ok = "hello $EMOJI world"
        assertEquals(ok, BodyText.stripLoneSurrogates(ok))
        assertEquals(ok, String(ok.toByteArray(Charsets.UTF_8), Charsets.UTF_8))
    }

    @Test fun `clean text is returned as the same instance-equal value`() {
        val s = "nothing to fix here"
        assertEquals(s, BodyText.stripLoneSurrogates(s))
    }

    // ---- truncation must not manufacture a lone surrogate ------------------

    @Test fun `truncation never splits a surrogate pair`() {
        // "abc" + emoji : cutting at 4 would land between the pair's two halves.
        val s = "abc$EMOJI"
        val cut = BodyText.truncate(s, 4)
        assertEquals("abc", cut, "must back off to before the pair, not split it")
        assertFalse(cut.any { it.isHighSurrogate() || it.isLowSurrogate() })
        assertEquals(cut, String(cut.toByteArray(Charsets.UTF_8), Charsets.UTF_8))
    }

    @Test fun `truncation keeps a pair that fits entirely`() {
        assertEquals("abc$EMOJI", BodyText.truncate("abc$EMOJI!", 5))
    }

    @Test fun `truncation is a no-op when under the cap`() {
        assertEquals("short", BodyText.truncate("short", 100))
    }

    // ---- render(): the end-to-end contract ---------------------------------

    @Test fun `a binary body is replaced by a placeholder naming size and mime`() {
        val r = BodyText.render("PK\u0003\u0004\u0000binary", mimeHint = "FONT_WOFF2", label = "response body")
        assertTrue(r.binary)
        assertFalse(r.truncated)
        assertTrue(r.text.startsWith("[binary response body omitted:"), r.text)
        assertTrue(r.text.contains("FONT_WOFF2"), r.text)
        assertTrue(r.text.contains("${r.originalLength} bytes"), r.text)
    }

    @Test fun `a binary MIME wins even when the bytes look texty`() {
        val r = BodyText.render("AElig Agrave acute", mimeHint = "FONT_WOFF")
        assertTrue(r.binary, "the reported font case: glyph names look like text but the body is not")
    }

    @Test fun `a text body passes through unchanged`() {
        val html = "HTTP/1.1 200 OK\r\n\r\n<html>ok</html>"
        val r = BodyText.render(html, mimeHint = "HTML")
        assertFalse(r.binary); assertFalse(r.truncated)
        assertEquals(html, r.text)
    }

    @Test fun `a long text body is truncated with a note and stays encodable`() {
        val long = "x".repeat(500) + EMOJI + "y".repeat(500)
        val r = BodyText.render(long, maxLength = 501, mimeHint = "HTML")
        assertTrue(r.truncated)
        assertFalse(r.binary)
        assertTrue(r.text.contains("truncated, full length: ${long.length}"), r.text)
        // Nothing unencodable survived the cut.
        assertEquals(r.text, String(r.text.toByteArray(Charsets.UTF_8), Charsets.UTF_8))
    }

    @Test fun `a null or non-positive max falls back to the default cap`() {
        val long = "x".repeat(BodyText.DEFAULT_MAX_LENGTH + 10)
        assertTrue(BodyText.render(long, maxLength = null, mimeHint = "HTML").truncated)
        assertTrue(BodyText.render(long, maxLength = 0, mimeHint = "HTML").truncated)
    }

    @Test fun `control characters in text are kept — a JSON encoder escapes them fine`() {
        // Regression guard against over-correcting: \t\r\n are normal in HTTP text.
        val text = "HTTP/1.1 200 OK\r\n\tX: 1\r\n\r\nbody"
        val r = BodyText.render(text, mimeHint = "HTML")
        assertFalse(r.binary)
        assertEquals(text, r.text)
    }
}
