package com.burpmcp.ultra.bridge

import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Unit tests for the pure validation and status-mapping helpers on
 * [WebSocketBridge]. These cover the fixes for:
 *
 *  - BUG #23: scheme rejection + Montoya creation-status mapping.
 *  - BUG #25: max_results / direction filter validation on websocket_get_messages.
 *
 * They exercise the pure companion functions only, so no live Burp / Montoya
 * API is required.
 */
class WebSocketBridgeValidationTest {

    // --- BUG #23: scheme validation -------------------------------------

    @Test
    fun `accepts ws wss http and https schemes`() {
        assertNull(WebSocketBridge.validateScheme("ws"))
        assertNull(WebSocketBridge.validateScheme("wss"))
        assertNull(WebSocketBridge.validateScheme("http"))
        assertNull(WebSocketBridge.validateScheme("https"))
    }

    @Test
    fun `scheme validation is case-insensitive`() {
        assertNull(WebSocketBridge.validateScheme("WSS"))
        assertNull(WebSocketBridge.validateScheme("Https"))
    }

    @Test
    fun `rejects non-websocket schemes with a clear message`() {
        val err = WebSocketBridge.validateScheme("ftp")
        assertNotNull(err)
        assertTrue(err.contains("Unsupported scheme"))
        assertTrue(err.contains("ftp"))
    }

    @Test
    fun `rejects a null or missing scheme`() {
        assertNotNull(WebSocketBridge.validateScheme(null))
    }

    // --- BUG #23: creation-status mapping -------------------------------

    @Test
    fun `unknown host maps to DNS failure`() {
        val msg = WebSocketBridge.describeCreationStatus("UNKNOWN_HOST", null)
        assertTrue(msg.contains("DNS"), msg)
    }

    @Test
    fun `non-upgrade response hints at scheme or port mismatch`() {
        val msg = WebSocketBridge.describeCreationStatus("NON_UPGRADE_RESPONSE", null)
        assertTrue(msg.contains("scheme/port mismatch"), msg)
    }

    @Test
    fun `connection failed maps to reachability message`() {
        val msg = WebSocketBridge.describeCreationStatus("CONNECTION_FAILED", null)
        assertTrue(msg.contains("Connection failed"), msg)
    }

    @Test
    fun `upgrade status code is appended when present`() {
        val msg = WebSocketBridge.describeCreationStatus("NON_UPGRADE_RESPONSE", 200)
        assertTrue(msg.contains("upgrade HTTP 200"), msg)
    }

    @Test
    fun `unknown status name falls back to generic reason including the name`() {
        val msg = WebSocketBridge.describeCreationStatus("SOMETHING_NEW", null)
        assertTrue(msg.contains("SOMETHING_NEW"), msg)
    }

    @Test
    fun `null status name yields a no-status reason`() {
        val msg = WebSocketBridge.describeCreationStatus(null, null)
        assertTrue(msg.contains("no status"), msg)
    }

    // --- BUG #25: direction filter validation --------------------------

    @Test
    fun `null direction is accepted as no filter`() {
        assertNull(WebSocketBridge.validateDirectionFilter(null))
    }

    @Test
    fun `known directions are accepted`() {
        assertNull(WebSocketBridge.validateDirectionFilter("client_to_server"))
        assertNull(WebSocketBridge.validateDirectionFilter("server_to_client"))
    }

    @Test
    fun `unknown direction is rejected with a clear message`() {
        val err = WebSocketBridge.validateDirectionFilter("sideways")
        assertNotNull(err)
        assertTrue(err.contains("Invalid direction"))
        assertTrue(err.contains("sideways"))
    }

    // --- BUG #25: max_results validation -------------------------------

    @Test
    fun `negative max_results is rejected before it can throw`() {
        val err = WebSocketBridge.validateMaxResults(-1)
        assertNotNull(err)
        assertTrue(err.contains("max_results"))
    }

    @Test
    fun `zero and positive max_results are accepted`() {
        assertNull(WebSocketBridge.validateMaxResults(0))
        assertNull(WebSocketBridge.validateMaxResults(100))
    }

    @Test
    fun `connect timeout constant is a sane positive bound`() {
        assertTrue(WebSocketBridge.CONNECT_TIMEOUT_MS in 1_000L..60_000L)
    }
}
