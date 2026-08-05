package com.burpmcp.ultra.core

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Pins the URL -> (host, port, TLS) derivation that gives custom-issue evidence its `HttpService`.
 *
 * Without a service the evidence request has no host for Montoya to resolve, and filing the issue
 * into the site map throws a `NullPointerException` inside Burp — the bug fixed by PR #13
 * (@aconstantinou-cmd). The derivation now lives in one place, so these cases cover both
 * `sitemap_add_issue` and `scanner_create_issue`.
 */
class ServicePartsTest {

    @Test fun `https defaults to port 443 with TLS`() {
        val p = ServiceParts.fromUrl("https://example.com/x")
        assertEquals(ServiceParts.Parts("example.com", 443, true), p)
    }

    @Test fun `http defaults to port 80 without TLS`() {
        assertEquals(ServiceParts.Parts("example.com", 80, false), ServiceParts.fromUrl("http://example.com/x"))
    }

    @Test fun `scheme comparison is case-insensitive`() {
        // "HTTP://" must not be mistaken for TLS just because it isn't lowercase "http".
        assertEquals(ServiceParts.Parts("example.com", 80, false), ServiceParts.fromUrl("HTTP://example.com/x"))
    }

    @Test fun `an explicit port always wins over the scheme default`() {
        assertEquals(ServiceParts.Parts("example.com", 8080, false), ServiceParts.fromUrl("http://example.com:8080/x"))
        assertEquals(ServiceParts.Parts("example.com", 8443, true), ServiceParts.fromUrl("https://example.com:8443/x"))
    }

    @Test fun `userinfo is not mistaken for the host`() {
        assertEquals("example.com", ServiceParts.fromUrl("https://user:pw@example.com/x").host)
    }

    @Test fun `ip literals are preserved`() {
        assertEquals("192.168.1.5", ServiceParts.fromUrl("https://192.168.1.5/x").host)
        // IPv6 keeps the bracketed form java.net.URI reports; it is passed through unchanged.
        assertEquals(ServiceParts.Parts("[::1]", 8080, false), ServiceParts.fromUrl("http://[::1]:8080/x"))
    }

    @Test fun `a query string and fragment do not affect the service`() {
        assertEquals(ServiceParts.Parts("example.com", 443, true), ServiceParts.fromUrl("https://example.com/a?b=1#c"))
    }

    // ---- failures are actionable, never a raw URISyntaxException or NPE ----

    @Test fun `a url with no scheme fails with an actionable message`() {
        val e = assertFailsWith<IllegalArgumentException> { ServiceParts.fromUrl("example.com/no-scheme") }
        assertTrue(e.message!!.contains("host"), e.message!!)
        assertTrue(e.message!!.contains("example.com/no-scheme"), e.message!!)
    }

    @Test fun `a malformed url is reported cleanly, not as a URISyntaxException`() {
        val e = assertFailsWith<IllegalArgumentException> { ServiceParts.fromUrl("http://exa mple.com/") }
        assertTrue(e.message!!.contains("Could not parse"), e.message!!)
    }

    @Test fun `an empty url fails cleanly`() {
        assertFailsWith<IllegalArgumentException> { ServiceParts.fromUrl("") }
    }

    @Test fun `the label names which input was bad`() {
        val e = assertFailsWith<IllegalArgumentException> { ServiceParts.fromUrl("", what = "issue url") }
        assertTrue(e.message!!.contains("issue url"), e.message!!)
    }
}
