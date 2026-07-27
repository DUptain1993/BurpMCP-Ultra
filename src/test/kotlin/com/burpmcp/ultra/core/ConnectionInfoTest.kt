package com.burpmcp.ultra.core

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Guards the two connection invariants that broke clients in GitHub issue #1:
 * the endpoint is the root path "/" (not "/sse") and the config always carries a token.
 */
class ConnectionInfoTest {

    @Test fun `sse url is the root path, never slash-sse`() {
        assertTrue(ConnectionInfo.primarySseUrl.endsWith(":9876/"), ConnectionInfo.primarySseUrl)
        assertTrue(ConnectionInfo.secondarySseUrl.endsWith(":9877/"), ConnectionInfo.secondarySseUrl)
        assertFalse(ConnectionInfo.primarySseUrl.contains("/sse"))
        assertFalse(ConnectionInfo.secondarySseUrl.contains("/sse"))
    }

    @Test fun `client config uses root url and a bearer token`() {
        val c = ConnectionInfo.clientConfigJson("TOK123")
        assertTrue(c.contains("\"url\":\"http://127.0.0.1:9876/\""), c)
        assertFalse(c.contains("/sse"))
        assertTrue(c.contains("\"Authorization\":\"Bearer TOK123\""), c)
        assertTrue(c.contains("\"type\":\"sse\""))
    }

    @Test fun `null token yields the placeholder, never a token-less config`() {
        val c = ConnectionInfo.clientConfigJson(null)
        assertTrue(c.contains("Bearer ${ConnectionInfo.TOKEN_PLACEHOLDER}"), c)
        assertTrue(c.contains("Authorization"))
    }

    // ---- header-less clients (GitHub issue #11) ----------------------------

    @Test fun `path-token url embeds the token in the path, not the query`() {
        val u = ConnectionInfo.sseUrlWithPathToken("TOK123")
        assertTrue(u == "http://127.0.0.1:9876/TOK123/", u)
        // A query token would be dropped by the SDK's relative back-channel endpoint.
        assertFalse(u.contains("?token="), u)
    }

    @Test fun `path-token client config carries no headers block at all`() {
        val c = ConnectionInfo.clientConfigJsonPathToken("TOK123")
        assertTrue(c.contains("\"url\":\"http://127.0.0.1:9876/TOK123/\""), c)
        assertFalse(c.contains("headers"), "header-less clients must get a config with no headers: $c")
        assertFalse(c.contains("Authorization"), c)
        assertTrue(c.contains("\"type\":\"sse\""), c)
    }

    @Test fun `path-token config still never emits a token-less url`() {
        val c = ConnectionInfo.clientConfigJsonPathToken(null)
        assertTrue(c.contains(ConnectionInfo.TOKEN_PLACEHOLDER), c)
    }

    @Test fun `path-token url honours a custom host and port`() {
        assertTrue(
            ConnectionInfo.sseUrlWithPathToken("T", port = 9877, host = "192.168.1.8") ==
                "http://192.168.1.8:9877/T/"
        )
    }
}
