package com.burpmcp.ultra.core

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Guards the pure validation helpers extracted from [com.burpmcp.ultra.bridge.ProxyBridge]:
 *
 *  - [StatusCodeRange]: `proxy_history`'s `status_code_range` used to split the range inside
 *    the per-item filter and only honour a two-part "min-max" string; every other shape
 *    silently dropped the filter (BUG #8).
 *  - [HighlightColorName]: `proxy_annotate` trusted Montoya's `highlightColor()` factory,
 *    which returns NONE for unknown names, so a bogus colour silently cleared the highlight
 *    while reporting success (BUG #30).
 */
class ProxyBridgeValidationTest {

    // ---- StatusCodeRange (BUG #8) ---------------------------------------

    @Test fun `null range means no filter`() =
        assertTrue(StatusCodeRange.parse(null) is StatusCodeRange.Result.None)

    @Test fun `closed range parses inclusively`() {
        val r = StatusCodeRange.parse("200-299")
        assertTrue(r is StatusCodeRange.Result.Ok)
        val range = (r as StatusCodeRange.Result.Ok).range
        assertEquals(200, range.min)
        assertEquals(299, range.max)
        assertTrue(range.contains(200))
        assertTrue(range.contains(299))
        assertFalse(range.contains(199))
        assertFalse(range.contains(300))
    }

    @Test fun `open upper bound defaults to 999`() {
        val r = StatusCodeRange.parse("400-") as StatusCodeRange.Result.Ok
        assertEquals(400, r.range.min)
        assertEquals(999, r.range.max)
        assertTrue(r.range.contains(500))
        assertFalse(r.range.contains(399))
    }

    @Test fun `open lower bound defaults to 0`() {
        val r = StatusCodeRange.parse("-299") as StatusCodeRange.Result.Ok
        assertEquals(0, r.range.min)
        assertEquals(299, r.range.max)
        assertTrue(r.range.contains(0))
        assertTrue(r.range.contains(299))
        assertFalse(r.range.contains(300))
    }

    @Test fun `bare single code is treated as exact match, not a silent pass`() {
        // Regression for BUG #8: "404" used to fall through the size==2 guard and
        // silently drop the filter; it must now match only 404.
        val r = StatusCodeRange.parse("404") as StatusCodeRange.Result.Ok
        assertEquals(404, r.range.min)
        assertEquals(404, r.range.max)
        assertTrue(r.range.contains(404))
        assertFalse(r.range.contains(403))
        assertFalse(r.range.contains(405))
    }

    @Test fun `whitespace around bounds is tolerated`() {
        val r = StatusCodeRange.parse(" 200 - 299 ") as StatusCodeRange.Result.Ok
        assertEquals(200, r.range.min)
        assertEquals(299, r.range.max)
    }

    @Test fun `min greater than max is an error, not a silent pass`() {
        val r = StatusCodeRange.parse("500-200")
        assertTrue(r is StatusCodeRange.Result.Invalid)
        assertTrue((r as StatusCodeRange.Result.Invalid).message.contains("min"))
    }

    @Test fun `three-part range is rejected instead of silently dropped`() {
        // The core regression: "1-2-3" used to no-op silently.
        assertTrue(StatusCodeRange.parse("1-2-3") is StatusCodeRange.Result.Invalid)
    }

    @Test fun `non-numeric bounds are rejected`() {
        assertTrue(StatusCodeRange.parse("abc") is StatusCodeRange.Result.Invalid)
        assertTrue(StatusCodeRange.parse("200-xyz") is StatusCodeRange.Result.Invalid)
        assertTrue(StatusCodeRange.parse("xyz-200") is StatusCodeRange.Result.Invalid)
    }

    @Test fun `empty and dash-only strings are rejected`() {
        assertTrue(StatusCodeRange.parse("") is StatusCodeRange.Result.Invalid)
        assertTrue(StatusCodeRange.parse("   ") is StatusCodeRange.Result.Invalid)
        assertTrue(StatusCodeRange.parse("-") is StatusCodeRange.Result.Invalid)
    }

    // ---- HighlightColorName (BUG #30) -----------------------------------

    @Test fun `known colors are valid and canonicalised to uppercase`() {
        assertTrue(HighlightColorName.isValid("red"))
        assertEquals("RED", HighlightColorName.canonical("red"))
        assertEquals("BLUE", HighlightColorName.canonical("  Blue "))
        assertEquals("MAGENTA", HighlightColorName.canonical("MAGENTA"))
        assertEquals("GRAY", HighlightColorName.canonical("gray"))
    }

    @Test fun `NONE is an accepted explicit clear`() {
        assertTrue(HighlightColorName.isValid("none"))
        assertEquals("NONE", HighlightColorName.canonical("none"))
    }

    @Test fun `unknown color is rejected, never silently accepted`() {
        // Regression for BUG #30: "purple" used to resolve to NONE (silent clear) and
        // report success. It must now be rejected outright.
        assertFalse(HighlightColorName.isValid("purple"))
        assertNull(HighlightColorName.canonical("purple"))
        assertFalse(HighlightColorName.isValid("bright-red"))
        assertNull(HighlightColorName.canonical(""))
        assertFalse(HighlightColorName.isValid(null))
        assertNull(HighlightColorName.canonical(null))
    }

    @Test fun `valid values hint lists the real colors and does not offer NONE as a color`() {
        val hint = HighlightColorName.validValues()
        assertTrue(hint.contains("RED"))
        assertTrue(hint.contains("MAGENTA"))
        assertTrue(hint.contains("NONE"))
    }
}
