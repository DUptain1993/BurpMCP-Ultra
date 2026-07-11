package com.burpmcp.ultra.bridge

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ApiImportBridgeTest {

    // --- BUG #21: path-join normalization (no double slashes) ---

    @Test
    fun `root basePath joined with slashed path yields single-slash endpoint`() {
        assertEquals("/blog", ApiImportBridge.joinPaths("/", "/blog"))
    }

    @Test
    fun `non-root basePath joined with slashed path preserves both segments`() {
        assertEquals("/api/blog", ApiImportBridge.joinPaths("/api", "/blog"))
    }

    @Test
    fun `trailing-slash basePath (from servers url) collapses the boundary slash`() {
        assertEquals("/api/blog", ApiImportBridge.joinPaths("/api/", "/blog"))
    }

    @Test
    fun `root basePath joined with root path yields a single slash`() {
        assertEquals("/", ApiImportBridge.joinPaths("/", "/"))
    }

    @Test
    fun `empty basePath still produces a rooted path`() {
        assertEquals("/blog", ApiImportBridge.joinPaths("", "/blog"))
    }

    @Test
    fun `path without leading slash is rooted onto basePath`() {
        assertEquals("/api/blog", ApiImportBridge.joinPaths("/api", "blog"))
    }

    @Test
    fun `no double slash ever appears at the join boundary`() {
        val cases = listOf(
            "/" to "/blog",
            "/api/" to "/blog",
            "/api" to "/blog",
            "" to "/blog"
        )
        for ((bp, p) in cases) {
            val joined = ApiImportBridge.joinPaths(bp, p)
            assertFalse(joined.contains("//"), "unexpected '//' in '$joined' for ('$bp','$p')")
        }
    }

    // --- BUG #21: base URL validation ---

    @Test
    fun `valid https url with dotted host is accepted`() {
        assertTrue(ApiImportBridge.validateBaseUrl("https://api.example.com"))
    }

    @Test
    fun `valid http url with path and port is accepted`() {
        assertTrue(ApiImportBridge.validateBaseUrl("http://api.example.com:8080/v1"))
    }

    @Test
    fun `localhost is accepted`() {
        assertTrue(ApiImportBridge.validateBaseUrl("http://localhost:3000"))
    }

    @Test
    fun `dotted ipv4 host is accepted`() {
        assertTrue(ApiImportBridge.validateBaseUrl("http://127.0.0.1:8000/api"))
    }

    @Test
    fun `missing scheme is rejected`() {
        assertFalse(ApiImportBridge.validateBaseUrl("api.example.com"))
    }

    @Test
    fun `non-http scheme is rejected`() {
        assertFalse(ApiImportBridge.validateBaseUrl("ftp://api.example.com"))
    }

    @Test
    fun `host containing a space is rejected`() {
        assertFalse(ApiImportBridge.validateBaseUrl("https://bad host.com"))
    }

    @Test
    fun `scheme with empty host is rejected`() {
        assertFalse(ApiImportBridge.validateBaseUrl("https://"))
    }

    @Test
    fun `bare single-label host without a dot is rejected`() {
        assertFalse(ApiImportBridge.validateBaseUrl("http://notahost"))
    }

    @Test
    fun `non-numeric port is rejected`() {
        assertFalse(ApiImportBridge.validateBaseUrl("http://api.example.com:notaport"))
    }
}
