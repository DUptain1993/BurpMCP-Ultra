package com.burpmcp.ultra.transport

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.cio.*
import io.ktor.server.engine.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.sse.*
import io.ktor.sse.ServerSentEvent
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * End-to-end regression tests for the transport auth interceptor, driven over raw sockets against
 * a real CIO server wired exactly like [McpServerManager] (same `installLocalhostSecurity`, same
 * `install(SSE)`, same GET-selected SSE mount + POST back-channel at `/` and `/{token}`).
 *
 * These pin a **critical bypass** found by an adversarial review of the issue-#11 change and
 * reproduced against the live extension:
 *
 *   OPTIONS / HTTP/1.1
 *   Host: evil.attacker.com          <- rebound host, zero credentials
 *   => HTTP/1.1 200 OK  +  "event: endpoint / data: ?sessionId=<live uuid>"
 *
 * Two independent defects combined: the interceptor short-circuited on `OPTIONS` *before* the
 * Host allowlist, Origin lockdown and token check; and Ktor's no-path `sse { }` overload registers
 * a handler with **no HttpMethod selector**, so the SSE endpoint answered every verb. On its own
 * the leaked session id was inert, but it became a full unauthenticated bypass the moment a
 * session id was accepted as an auth carrier — which is why it no longer is one.
 */
class SecurityInterceptorTest {

    private val token = "TESTTOKEN123"

    private fun freePort(): Int = ServerSocket(0).use { it.localPort }

    /** Stands up the real interceptor + the real route shape, then runs [block] against it. */
    private fun withServer(block: (Int) -> Unit) {
        val port = freePort()
        val server = embeddedServer(CIO, port = port, host = "127.0.0.1") {
            installLocalhostSecurity(token, listOf(port), listOf("127.0.0.1", "localhost"))
            install(SSE)
            install(IgnoreTrailingSlash)
            routing {
                // Mirrors McpServerManager: GET-selected SSE + POST back-channel.
                method(HttpMethod.Get) { sse { send(ServerSentEvent(event = "endpoint", data = "?sessionId=test-sid")) } }
                post { call.respondText("posted") }
                route("/{token}") {
                    method(HttpMethod.Get) { sse { send(ServerSentEvent(event = "endpoint", data = "?sessionId=test-sid")) } }
                    post { call.respondText("posted") }
                }
            }
        }
        server.start(wait = false)
        try {
            waitForBind(port)
            block(port)
        } finally {
            server.stop(0, 0)
        }
    }

    private fun waitForBind(port: Int) {
        repeat(60) {
            try {
                Socket().use { it.connect(InetSocketAddress("127.0.0.1", port), 200) }
                return
            } catch (_: Exception) { Thread.sleep(50) }
        }
        error("test server never bound on port $port")
    }

    /** Sends a raw request and returns whatever the server writes back (status line + any body). */
    private fun raw(port: Int, request: String, readMs: Int = 1500): String {
        Socket().use { s ->
            s.connect(InetSocketAddress("127.0.0.1", port), 2000)
            s.soTimeout = readMs
            s.getOutputStream().write(request.toByteArray())
            s.getOutputStream().flush()
            val buf = StringBuilder()
            try {
                val stream = s.getInputStream()
                val chunk = ByteArray(4096)
                while (buf.length < 4096) {
                    val n = stream.read(chunk)
                    if (n <= 0) break
                    buf.append(String(chunk, 0, n))
                }
            } catch (_: Exception) { /* read timeout on a held-open stream is expected */ }
            return buf.toString()
        }
    }

    private fun status(response: String): Int =
        Regex("^HTTP/1\\.1 (\\d{3})").find(response)?.groupValues?.get(1)?.toInt() ?: -1

    // ---- the critical bypass, closed ---------------------------------------

    @Test fun `OPTIONS with a rebound Host is rejected and mints no session`() {
        withServer { port ->
            val r = raw(port, "OPTIONS / HTTP/1.1\r\nHost: evil.attacker.com\r\nConnection: close\r\n\r\n")
            assertEquals(403, status(r), "a rebound Host must be refused for OPTIONS too: $r")
            assertFalse(r.contains("sessionId"), "no session id may ever be disclosed here: $r")
        }
    }

    @Test fun `a bare OPTIONS is not a preflight and still requires the token`() {
        withServer { port ->
            val r = raw(port, "OPTIONS / HTTP/1.1\r\nHost: 127.0.0.1:$port\r\nConnection: close\r\n\r\n")
            assertEquals(401, status(r), "OPTIONS without Access-Control-Request-Method is an ordinary request: $r")
            assertFalse(r.contains("sessionId"), r)
        }
    }

    @Test fun `an unauthenticated OPTIONS never opens an SSE stream`() {
        withServer { port ->
            for (target in listOf("/", "/anything", "/$token")) {
                val r = raw(port, "OPTIONS $target HTTP/1.1\r\nHost: evil.attacker.com\r\nConnection: close\r\n\r\n")
                assertFalse(r.contains("text/event-stream"), "OPTIONS $target opened a stream: $r")
                assertFalse(r.contains("sessionId"), "OPTIONS $target leaked a session id: $r")
            }
        }
    }

    /** A session id is evidence of nothing — it must never authenticate a back-channel POST. */
    @Test fun `a sessionId alone does not authenticate a POST`() {
        withServer { port ->
            val r = raw(port, "POST /?sessionId=test-sid HTTP/1.1\r\nHost: 127.0.0.1:$port\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
            assertEquals(401, status(r), "the token must still be required: $r")
        }
    }

    // ---- genuine CORS preflight still works --------------------------------

    @Test fun `a genuine preflight from an allowed origin passes the interceptor`() {
        withServer { port ->
            val r = raw(
                port,
                "OPTIONS / HTTP/1.1\r\nHost: 127.0.0.1:$port\r\n" +
                    "Origin: http://127.0.0.1:$port\r\nAccess-Control-Request-Method: POST\r\nConnection: close\r\n\r\n"
            )
            assertTrue(status(r) !in listOf(401, 403), "a real preflight carries no credentials by design: $r")
        }
    }

    @Test fun `a preflight from a foreign origin is still rejected`() {
        withServer { port ->
            val r = raw(
                port,
                "OPTIONS / HTTP/1.1\r\nHost: 127.0.0.1:$port\r\n" +
                    "Origin: http://evil.example\r\nAccess-Control-Request-Method: POST\r\nConnection: close\r\n\r\n"
            )
            assertEquals(403, status(r), "cross-origin must be refused: $r")
        }
    }

    // ---- the issue #11 happy path still works ------------------------------

    @Test fun `GET without a token is unauthorized`() {
        withServer { port ->
            val r = raw(port, "GET / HTTP/1.1\r\nHost: 127.0.0.1:$port\r\nConnection: close\r\n\r\n")
            assertEquals(401, status(r), r)
        }
    }

    @Test fun `GET with a path token opens the SSE stream`() {
        withServer { port ->
            val r = raw(port, "GET /$token/ HTTP/1.1\r\nHost: 127.0.0.1:$port\r\n\r\n")
            assertEquals(200, status(r), "the path-token carrier must still work (issue #11): $r")
            assertTrue(r.contains("text/event-stream"), r)
        }
    }

    @Test fun `GET with a bearer header still opens the SSE stream`() {
        withServer { port ->
            val r = raw(port, "GET / HTTP/1.1\r\nHost: 127.0.0.1:$port\r\nAuthorization: Bearer $token\r\n\r\n")
            assertEquals(200, status(r), r)
            assertTrue(r.contains("text/event-stream"), r)
        }
    }

    @Test fun `a wrong path token is rejected`() {
        withServer { port ->
            val r = raw(port, "GET /NOTTHETOKEN/ HTTP/1.1\r\nHost: 127.0.0.1:$port\r\nConnection: close\r\n\r\n")
            assertEquals(401, status(r), r)
        }
    }
}
