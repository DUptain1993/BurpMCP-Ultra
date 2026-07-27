package com.burpmcp.ultra.core

/**
 * Single source of truth for how MCP clients connect to BurpMCP-Ultra. Used by the
 * dashboard, the Server UI tab (and mirrored in the README/configs) so the connection
 * details can never drift again.
 *
 * Two invariants this guards, both of which previously broke clients (GitHub issue #1):
 *  1. The MCP SSE endpoint is the **root path `/`**, NOT `/sse`.
 *  2. A **token is required** on every request.
 *
 * The token may ride in an `Authorization: Bearer` header OR in the URL **path**
 * (`http://host:port/<token>/`). The path form exists for MCP clients that cannot set custom
 * headers (GitHub issue #11) — and it is the only URL-borne carrier that works, because the SDK
 * advertises its POST back-channel as the relative reference `?sessionId=...`, which per
 * RFC 3986 §5.3 replaces a `?token=` query but preserves the path.
 */
object ConnectionInfo {
    const val PRIMARY_PORT = 9876
    const val SECONDARY_PORT = 9877
    const val DASHBOARD_PORT = 9878

    /** Shown where the real token must NOT be embedded (e.g. browser-served HTML). */
    const val TOKEN_PLACEHOLDER = "PASTE_TOKEN_FROM_SERVER_TAB"

    /** The MCP SSE endpoint URL for [port] on [host] — the ROOT path `/`, never `/sse`. */
    fun sseUrl(port: Int, host: String = "127.0.0.1"): String = "http://$host:$port/"

    val primarySseUrl: String get() = sseUrl(PRIMARY_PORT)
    val secondarySseUrl: String get() = sseUrl(SECONDARY_PORT)
    val dashboardUrl: String get() = dashboardUrlForHost()

    // Host-aware variants — used once the bind host is configurable (issue #4) so every
    // displayed endpoint reflects the interface the servers actually bound to.
    fun primarySseUrlForHost(host: String): String = sseUrl(PRIMARY_PORT, host)
    fun secondarySseUrlForHost(host: String): String = sseUrl(SECONDARY_PORT, host)
    fun dashboardUrlForHost(host: String = "127.0.0.1"): String = "http://$host:$DASHBOARD_PORT"

    /**
     * A ready-to-paste MCP client config. Pass the real [token] ONLY for same-process
     * surfaces (the Swing Server tab). Pass `null` for anything browser-served so the
     * token is not embedded in HTML — the user then fills [TOKEN_PLACEHOLDER] from the
     * Server tab (this preserves the dashboard's HttpOnly-cookie token confidentiality).
     */
    fun clientConfigJson(token: String?, port: Int = PRIMARY_PORT, host: String = "127.0.0.1"): String {
        val bearer = token ?: TOKEN_PLACEHOLDER
        return """{"mcpServers":{"burp":{"type":"sse","url":"${sseUrl(port, host)}","headers":{"Authorization":"Bearer $bearer"}}}}"""
    }

    /**
     * The SSE endpoint with the token embedded in the **path** — for MCP clients that accept only a
     * URL and cannot set headers (GitHub issue #11).
     *
     * Note the token becomes part of the URL, so it can land in shell history or a client's config
     * file. Prefer [clientConfigJson] (header) when the client supports headers.
     */
    fun sseUrlWithPathToken(token: String, port: Int = PRIMARY_PORT, host: String = "127.0.0.1"): String =
        "http://$host:$port/$token/"

    /**
     * A ready-to-paste MCP client config for a **header-less** client: no `headers` block at all,
     * the token rides in the URL path. Same [token] handling contract as [clientConfigJson].
     */
    fun clientConfigJsonPathToken(token: String?, port: Int = PRIMARY_PORT, host: String = "127.0.0.1"): String {
        val t = token ?: TOKEN_PLACEHOLDER
        return """{"mcpServers":{"burp":{"type":"sse","url":"${sseUrlWithPathToken(t, port, host)}"}}}"""
    }
}
