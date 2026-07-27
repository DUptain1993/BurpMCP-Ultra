package com.burpmcp.ultra.transport

import java.net.URI
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * GitHub issue #11 — "headers中的Authorization多此一举" (the Authorization header is an
 * unnecessary extra step): MCP clients that cannot set custom headers had NO working
 * configuration.
 *
 * The documented `?token=` alternative silently half-worked: it authenticated the SSE GET, but
 * the SDK advertises its back-channel as the relative reference `?sessionId=...`, and per
 * RFC 3986 §5.3 a reference containing only a query REPLACES the base query while KEEPING the
 * base path. So the token vanished on the POST and every message 401'd (verified live).
 *
 * A token carried in the PATH survives that resolution, which is why [SecurityConfig.pathToken]
 * exists and why the transports also mount at `/{token}`. These tests pin both the extraction
 * and the URL-resolution invariant the fix depends on.
 */
class PathTokenAuthTest {

    // ---- the resolution invariant that makes the fix work --------------------

    /** Mirrors how an MCP client resolves the advertised endpoint against its base URL. */
    private fun resolvedPost(base: String) = URI(base).resolve("?sessionId=X").toString()

    @Test fun `a query token is DROPPED on the back-channel POST (the bug)`() {
        val resolved = resolvedPost("http://127.0.0.1:9876/?token=SECRET")
        assertTrue("SECRET" !in resolved, "RFC 3986 replaces the query, so ?token= cannot survive: $resolved")
        assertEquals("http://127.0.0.1:9876/?sessionId=X", resolved)
    }

    @Test fun `a path token SURVIVES on the back-channel POST (the fix)`() {
        val resolved = resolvedPost("http://127.0.0.1:9876/SECRET/")
        assertTrue("SECRET" in resolved, "the base path must be preserved: $resolved")
        assertEquals("http://127.0.0.1:9876/SECRET/?sessionId=X", resolved)
    }

    /**
     * Why [ConnectionInfo.sseUrlWithPathToken] always emits a TRAILING SLASH.
     *
     * Java's [URI.resolve] is RFC 2396-based and treats a query-only reference as having an empty
     * path, so it resolves against the base's PARENT and drops `/SECRET` entirely — while
     * RFC 3986 implementations (Python, JS `new URL`, Go) keep it. A Java-based MCP client
     * (e.g. an mcp-proxy) would therefore POST to `/` with no token and 401.
     *
     * The trailing-slash form is the one URL that works under BOTH resolvers, so it is the only
     * form we ever advertise — and the session-bound back-channel fallback covers the rest.
     */
    @Test fun `without a trailing slash a Java client drops the path — hence we always emit one`() {
        assertEquals("http://127.0.0.1:9876/?sessionId=X", resolvedPost("http://127.0.0.1:9876/SECRET"))
        // The advertised form is immune:
        assertEquals("http://127.0.0.1:9876/SECRET/?sessionId=X", resolvedPost("http://127.0.0.1:9876/SECRET/"))
    }

    // ---- pathToken() extraction ---------------------------------------------

    @Test fun `extracts the first path segment as the token`() {
        assertEquals("abc123", SecurityConfig.pathToken("/abc123"))
        assertEquals("abc123", SecurityConfig.pathToken("/abc123/"))
        assertEquals("abc123", SecurityConfig.pathToken("/abc123/anything/else"))
    }

    @Test fun `returns null for the root path so other carriers still apply`() {
        assertNull(SecurityConfig.pathToken("/"))
        assertNull(SecurityConfig.pathToken(""))
    }

    @Test fun `handles a real url-safe base64 token verbatim`() {
        // Tokens are Base64-URL without padding: [A-Za-z0-9_-]. None of those are path separators,
        // so the token round-trips unescaped.
        val token = "EXAMPLE_fake_token_for_tests_only_0123456789"
        assertEquals(token, SecurityConfig.pathToken("/$token/"))
        assertEquals(token, ConnectionInfoPathHelper.tokenFromUrl("http://127.0.0.1:9876/$token/"))
    }

    @Test fun `a wrong path segment yields a non-matching token, not a bypass`() {
        // Extraction is deliberately naive; authorization is the constant-time comparison that
        // follows. Anything that is not the token simply fails that comparison.
        assertEquals("favicon.ico", SecurityConfig.pathToken("/favicon.ico"))
        assertEquals("api", SecurityConfig.pathToken("/api/events"))
    }

    /** Tiny helper so the test can assert on a full URL the way a client would build it. */
    private object ConnectionInfoPathHelper {
        fun tokenFromUrl(url: String): String? = SecurityConfig.pathToken(URI(url).path)
    }
}
