package com.burpmcp.ultra.transport

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.plugins.cors.routing.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

/**
 * Localhost security hardening for the embedded Ktor servers.
 *
 * Binding to `127.0.0.1` is NOT a trust boundary: any web page the operator
 * visits can issue requests to localhost, and DNS rebinding can make those
 * responses cross-origin-readable. Three independent controls close that hole:
 *
 *  1. **Host-header allowlist** — defeats DNS rebinding. A rebound request
 *     carries `Host: attacker.com`, which is not on the allowlist and is rejected
 *     before any handler runs.
 *  2. **Origin lockdown** — rejects any cross-origin browser request outright
 *     (and CORS only ever advertises the loopback origins).
 *  3. **Per-session token** — only a caller holding the token (surfaced solely in the
 *     local Burp UI) may invoke anything. Accepted as an `Authorization: Bearer` header,
 *     an `mcp_token` cookie, a `?token=` query param, or the first PATH segment
 *     (`/<token>/` — the only carrier that survives the MCP SSE back-channel, issue #11).
 *
 * Removing any one of these re-opens the "malicious website drives your local
 * MCP server" chain, so all three are installed together.
 */
object SecurityConfig {
    /** Generates a fresh 256-bit URL-safe session token. */
    fun generateToken(): String {
        val bytes = ByteArray(32)
        SecureRandom().nextBytes(bytes)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }

    /**
     * Builds the (Host-header allowlist, CORS-origin allowlist) for every ([hosts] x [ports])
     * pair. Pure — the anti-DNS-rebinding invariant is that only these explicit hosts are ever
     * permitted, never `anyHost()`.
     */
    fun buildAllowlists(hosts: List<String>, ports: List<Int>): Pair<Set<String>, Set<String>> {
        val h = hosts.distinct()
        val allowedHosts = ports.flatMap { port -> h.map { host -> "$host:$port" } }.toSet()
        val allowedOrigins = ports.flatMap { port -> h.map { host -> "http://$host:$port" } }.toSet()
        return allowedHosts to allowedOrigins
    }

    /**
     * Extracts a token carried as the FIRST path segment (`http://host:port/<token>/`), the only
     * carrier that survives the MCP SSE back-channel (GitHub issue #11).
     *
     * The SDK advertises its POST endpoint as the relative reference `?sessionId=...`. Per
     * RFC 3986 §5.3 a reference containing only a query REPLACES the base query but KEEPS the
     * base path, so `?token=` is silently dropped on the POST (401) while a path-borne token is
     * preserved. Clients that cannot set an `Authorization` header therefore have no working
     * configuration unless the token can ride in the path.
     *
     * Returns null when the path has no segments (`/`), so the caller falls through to the
     * header / cookie / query carriers.
     */
    fun pathToken(path: String): String? =
        path.split('/').firstOrNull { it.isNotEmpty() }
}

/**
 * Installs Host validation + locked CORS + token auth on this [Application].
 *
 * @param token the per-session secret required on every request.
 * @param ports ports that, combined with [hosts], define the valid Host / Origin allowlist.
 * @param hosts the allowed bind hosts. Defaults to loopback; a non-loopback value is only ever
 *   passed after [BindHostPolicy] has confirmed the operator opted into network exposure.
 * @param tokenExemptPaths paths served WITHOUT a token (still Host/Origin-checked).
 *   Used only for the dashboard's `/` page, which injects the token into the
 *   served HTML so its own same-origin API calls can authenticate. A cross-origin
 *   attacker cannot read that page (same-origin policy) and cannot reach it via
 *   rebinding (Host check), so the token stays confidential.
 * @param isAuthenticatedSession accepts a **live MCP session id** as proof for a back-channel
 *   `POST ?sessionId=...`. The id is a 122-bit random UUID that the server discloses ONLY over an
 *   already token-authenticated SSE stream, so holding one is equivalent to holding the token —
 *   it is a capability derived from it, not a bypass. This keeps the POST working when a client's
 *   URL resolver drops the path-borne token (Java's RFC 2396 `URI.resolve` does exactly that for
 *   a base without a trailing slash — issue #11). Defaults to rejecting everything.
 */
fun Application.installLocalhostSecurity(
    token: String,
    ports: List<Int>,
    hosts: List<String> = listOf("127.0.0.1", "localhost"),
    tokenExemptPaths: Set<String> = emptySet(),
    isAuthenticatedSession: (String) -> Boolean = { false }
) {
    val (allowedHosts, allowedOrigins) = SecurityConfig.buildAllowlists(hosts, ports)

    install(CORS) {
        allowMethod(HttpMethod.Options)
        allowMethod(HttpMethod.Get)
        allowMethod(HttpMethod.Post)
        allowMethod(HttpMethod.Delete)
        allowHeader(HttpHeaders.Authorization)
        allowHeader(HttpHeaders.ContentType)
        allowNonSimpleContentTypes = true
        // Only the explicitly configured host:port origins are ever permitted — never anyHost().
        allowedHosts.forEach { hostPort -> allowHost(hostPort, schemes = listOf("http")) }
    }

    intercept(ApplicationCallPipeline.ApplicationPhase.Plugins) {
        // CORS preflight must pass through without auth so legitimate browsers work.
        if (call.request.httpMethod == HttpMethod.Options) return@intercept

        // 1. Host-header allowlist — primary anti-DNS-rebinding control.
        val host = call.request.headers[HttpHeaders.Host]
        if (host == null || host !in allowedHosts) {
            call.respondText(
                """{"error":"forbidden: invalid Host header"}""",
                ContentType.Application.Json,
                HttpStatusCode.Forbidden
            )
            return@intercept finish()
        }

        // 2. Origin lockdown — reject cross-origin browser requests outright.
        val origin = call.request.headers[HttpHeaders.Origin]
        if (origin != null && origin !in allowedOrigins) {
            call.respondText(
                """{"error":"forbidden: cross-origin request rejected"}""",
                ContentType.Application.Json,
                HttpStatusCode.Forbidden
            )
            return@intercept finish()
        }

        // 3. Token — required on everything except explicitly exempt paths.
        //    A back-channel POST may instead present a live session id (see the
        //    isAuthenticatedSession KDoc: a capability derived from an authenticated stream).
        val backChannelSession = call.request.queryParameters["sessionId"]
            ?.takeIf { call.request.httpMethod == HttpMethod.Post && isAuthenticatedSession(it) }

        if (backChannelSession == null && call.request.path() !in tokenExemptPaths) {
            val provided = call.request.headers[HttpHeaders.Authorization]
                ?.removePrefix("Bearer ")?.trim()
                ?: call.request.cookies["mcp_token"]
                ?: call.request.queryParameters["token"]
                // Path-borne token: the ONLY carrier that survives the MCP SSE back-channel,
                // for clients that cannot set headers (issue #11). See [SecurityConfig.pathToken].
                ?: SecurityConfig.pathToken(call.request.path())
            if (provided == null || !constantTimeEquals(provided, token)) {
                call.respondText(
                    """{"error":"unauthorized: missing or invalid token"}""",
                    ContentType.Application.Json,
                    HttpStatusCode.Unauthorized
                )
                return@intercept finish()
            }
        }
    }
}

/** Length-constant string comparison to avoid token timing side-channels. */
private fun constantTimeEquals(a: String, b: String): Boolean =
    MessageDigest.isEqual(a.toByteArray(Charsets.UTF_8), b.toByteArray(Charsets.UTF_8))
