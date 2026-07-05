package com.burpmcp.ultra.transport

import burp.api.montoya.logging.Logging
import com.burpmcp.ultra.bridge.BridgeFactory
import com.burpmcp.ultra.core.BuildInfo
import com.burpmcp.ultra.events.EventBus
import com.burpmcp.ultra.state.StateManager
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.cio.*
import io.ktor.server.engine.*
import io.ktor.server.plugins.cors.routing.*
import io.ktor.server.sse.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.server.SseServerTransport
import io.modelcontextprotocol.kotlin.sdk.shared.Transport
import io.modelcontextprotocol.kotlin.sdk.shared.TransportSendOptions
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.JSONRPCMessage
import io.modelcontextprotocol.kotlin.sdk.types.ServerCapabilities
import kotlinx.coroutines.*
import java.util.concurrent.ConcurrentHashMap

/**
 * Manages the lifecycle of MCP server instances and their underlying
 * Ktor HTTP servers.
 *
 * Two SSE transports are exposed on separate ports so that multiple
 * MCP clients can connect independently:
 * - **Primary SSE** on [ssePort] (default 9876).
 * - **Secondary SSE** on [httpPort] (default 9877).
 *
 * Both are plain MCP SSE transports: the SSE stream is the ROOT path "/" (GET) and
 * the back-channel is "/?sessionId=..." (POST) — NOT "/sse". There is no "Streamable
 * HTTP" or "stdio" transport — those were previously advertised but never implemented.
 *
 * @param bridges All bridge instances for tool/resource registration.
 * @param eventBus Shared event bus for event-related tools/resources.
 * @param stateManager Shared state for stateful tools.
 * @param bindHost Interface address to bind the transport servers to. Defaults to loopback; a
 *   non-loopback value only ever reaches here after [BindHostPolicy] confirmed the operator
 *   opted into network exposure (GitHub issue #4).
 * @param ssePort TCP port for the primary SSE transport (default 9876).
 * @param httpPort TCP port for the secondary SSE transport (default 9877).
 * @param logging Burp Suite logging API for startup/error messages.
 */
class McpServerManager(
    private val bridges: BridgeFactory.Bridges,
    private val eventBus: EventBus,
    private val stateManager: StateManager,
    private val authToken: String,
    private var bindHost: String = "127.0.0.1",
    private val ssePort: Int = 9876,
    private val httpPort: Int = 9877,
    private val logging: Logging
) {
    private var sseServer: EmbeddedServer<CIOApplicationEngine, CIOApplicationEngine.Configuration>? = null
    private var httpServer: EmbeddedServer<CIOApplicationEngine, CIOApplicationEngine.Configuration>? = null
    private var scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    /**
     * Hard cap on a single SSE write. The failure mode is a client that stops draining the
     * stream (e.g. a long-running PostToolUse hook), wedging the per-session write forever
     * (docs/BUG-sse-backpressure-hang.md) — NOT slowness — so this is generous: it must clear a
     * normal large-result flush but still bound the hang. On expiry the session is torn down
     * (its coroutine cancelled) and a standard SSE client reconnects.
     */
    private val sendTimeoutMs: Long = 45_000L

    /**
     * Creates a fresh MCP [Server] instance with all tools and resources
     * registered. Each transport gets its own server instance so they
     * maintain independent session state.
     */
    fun createMcpServer(): Server {
        val server = Server(
            serverInfo = Implementation(
                name = "burpmcp-ultra",
                version = BuildInfo.VERSION
            ),
            options = ServerOptions(
                capabilities = ServerCapabilities(
                    tools = ServerCapabilities.Tools(listChanged = true),
                    resources = ServerCapabilities.Resources(
                        subscribe = true,
                        listChanged = true
                    )
                )
            )
        )

        // Register all tools and resources on this server instance
        ToolRegistry.registerAll(server, bridges, eventBus, stateManager)
        ResourceRegistry.registerAll(server, bridges, eventBus, stateManager)

        // Wrap all tools to emit tool.called events for dashboard + native UI visibility
        ToolCallTracker.wrapAll(server, eventBus, stateManager)

        return server
    }

    /**
     * Returns the REAL number of (tools, resources) actually registered, by
     * building a throwaway server and counting. Used for honest startup
     * reporting instead of a hardcoded count that drifts as tools change.
     */
    fun registeredCounts(): Pair<Int, Int> {
        val s = createMcpServer()
        return s.tools.size to s.resources.size
    }

    /**
     * Starts both transport servers asynchronously. Failures on one
     * transport do not prevent the other from starting.
     *
     * Each server is hardened via [installLocalhostSecurity] (Host-header allowlist + locked
     * CORS + per-session token), then mounts the MCP SSE transport with our OWN wiring —
     * equivalent to the SDK's `mcp()` helper, but giving us a handle to each per-session
     * [SseServerTransport] and the SSE GET coroutine's [Job], so [TimeoutSseTransport] can
     * bound `send()` and recover a back-pressured client instead of wedging forever. The SSE
     * stream is the ROOT path '/' (GET); the POST back-channel is keyed by a `sessionId` query
     * param — NOT '/sse'. Both require the auth token (Authorization: Bearer, an mcp_token
     * cookie, or a ?token= query param).
     */
    fun start() {
        startTransport("Primary SSE", ssePort) { sseServer = it }
        startTransport("Secondary SSE", httpPort) { httpServer = it }
    }

    /**
     * Launches one CIO transport on [port] and VERIFIES it actually bound.
     *
     * `start(wait = false)` returns before Ktor's CIO engine has bound the
     * socket, and a bind failure surfaces on the engine's own coroutines — not
     * the launching one — so a plain try/catch logs a false "started" while the
     * port never opens. That is the GitHub issue #2/#3 symptom: the UI shows
     * "running", 9876/9877 never listen, and there is no error. We therefore
     * actively probe the port and log a loud, actionable error if it didn't come
     * up (the usual cause is a JAR built with Java 22+).
     */
    private fun startTransport(
        label: String,
        port: Int,
        assign: (EmbeddedServer<CIOApplicationEngine, CIOApplicationEngine.Configuration>) -> Unit
    ) {
        scope.launch {
            try {
                val server = embeddedServer(CIO, port = port, host = bindHost) {
                    installLocalhostSecurity(authToken, listOf(port), allowedSecurityHosts())
                    // Hand-rolled equivalent of the SDK's `mcp(serverFactory())` so we OWN each
                    // per-session SseServerTransport AND the SSE GET coroutine's Job — the SDK's
                    // mcp() builds the transport internally and hands us no handle. Route shape is
                    // byte-identical: SSE GET at "/", POST back-channel at "/?sessionId=...".
                    // The wrapped transport bounds send() (TimeoutSseTransport); the raw transport
                    // is registered for the POST path. See docs/BUG-sse-backpressure-hang.md.
                    install(SSE)
                    val sessions = ConcurrentHashMap<String, SseServerTransport>()
                    routing {
                        sse {
                            val raw = SseServerTransport("", this)
                            val tx = TimeoutSseTransport(raw, coroutineContext.job, sendTimeoutMs, logging)
                            val mcpServer = createMcpServer()
                            sessions[raw.sessionId] = raw
                            mcpServer.onClose { sessions.remove(raw.sessionId) }
                            mcpServer.connect(tx)        // responses flow through the bounded send
                            awaitCancellation()          // keep the SSE stream open until torn down
                        }
                        post {
                            val sid = call.request.queryParameters["sessionId"]
                                ?: return@post call.respond(HttpStatusCode.BadRequest, "sessionId query parameter is not provided")
                            val raw = sessions[sid]
                                ?: return@post call.respond(HttpStatusCode.NotFound, "Session not found")
                            raw.handlePostMessage(call)  // routes onMessage -> server -> tx.send (bounded)
                        }
                    }
                }
                server.start(wait = false)
                assign(server)

                if (verifyListening(port)) {
                    logging.logToOutput("BurpMCP-Ultra: $label transport listening on http://$bindHost:$port (MCP SSE endpoint is the root path '/', not '/sse')")
                } else {
                    logging.logToError(
                        "BurpMCP-Ultra: $label transport reported start() but $bindHost:$port is NOT listening. " +
                            "This is the GitHub issue #2/#3 symptom — almost always a JAR built with Java 22+ " +
                            "(Kotlin/Ktor/MCP-SDK incompatibility). Rebuild with a JDK 17-21 (NOT Burp's bundled Java 25)."
                    )
                }
            } catch (e: Exception) {
                logging.logToError("BurpMCP-Ultra: Failed to start $label transport on $bindHost:$port: ${e.message}")
                logging.logToError("BurpMCP-Ultra: Stack trace: ${e.stackTraceToString()}")
            }
        }
    }

    /**
     * Probes the bound socket for up to ~3s to confirm the engine actually bound. A wildcard
     * bind (`0.0.0.0`/`::`) isn't connectable at that address, so [BindHostPolicy.probeHost]
     * redirects the probe to loopback — otherwise this false-negatives and logs a misleading error.
     */
    private suspend fun verifyListening(port: Int): Boolean {
        val probe = BindHostPolicy.probeHost(bindHost)
        repeat(15) {
            try {
                java.net.Socket().use { it.connect(java.net.InetSocketAddress(probe, port), 200) }
                return true
            } catch (_: Exception) {
                kotlinx.coroutines.delay(200)
            }
        }
        return false
    }

    /**
     * Hosts accepted by the Host-header + CORS allowlist. Always loopback; when bound to a
     * network interface (operator opted in) this machine's own addresses are added so real LAN
     * clients — whose `Host` header is the concrete IP, not the wildcard — pass the check.
     */
    private fun allowedSecurityHosts(): List<String> {
        val extra = if (BindHostPolicy.classify(bindHost) != BindHostPolicy.Kind.LOOPBACK) NetworkHosts.local() else emptyList()
        return (listOf(bindHost, "127.0.0.1", "localhost") + extra).distinct()
    }

    /**
     * Gracefully stops both transport servers and cancels the coroutine scope.
     * Called from the extension unload handler.
     */
    fun stop() {
        sseServer?.stop(gracePeriodMillis = 1000, timeoutMillis = 2000)
        httpServer?.stop(gracePeriodMillis = 1000, timeoutMillis = 2000)
        scope.cancel()
        logging.logToOutput("BurpMCP-Ultra: MCP servers stopped")
    }

    /**
     * Hot-rebinds both SSE transports to [newHost] WITHOUT an extension reload: a bound socket
     * cannot change address, so the listeners are stopped and reopened on the new interface. Runs
     * on the caller's thread (blocks up to a few seconds while sockets stop + rebind) — the UI
     * calls this OFF the EDT. [newHost] is the already-gated effective host (see [BindHostPolicy]).
     * Returns whether the primary port came back up. Any live MCP client is disconnected by this,
     * exactly as a reload would.
     */
    fun rebind(newHost: String): Boolean {
        sseServer?.stop(gracePeriodMillis = 500, timeoutMillis = 1500); sseServer = null
        httpServer?.stop(gracePeriodMillis = 500, timeoutMillis = 1500); httpServer = null
        scope.cancel()
        scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
        bindHost = newHost
        start()
        return blockingWaitListening(ssePort)
    }

    /** Blocking sibling of [verifyListening] for the rebind path (already off the EDT). */
    private fun blockingWaitListening(port: Int): Boolean {
        val probe = BindHostPolicy.probeHost(bindHost)
        repeat(15) {
            try {
                java.net.Socket().use { it.connect(java.net.InetSocketAddress(probe, port), 200) }
                return true
            } catch (_: Exception) {
                Thread.sleep(200)
            }
        }
        return false
    }
}

/**
 * Wraps an [SseServerTransport] and bounds its [send] with a hard timeout so a client that
 * stops draining the SSE stream cannot wedge the per-session write forever (the 57-min hang —
 * see docs/BUG-sse-backpressure-hang.md). On timeout we cancel the SSE GET coroutine's
 * [sessionJob]: this is the ONLY recovery that works, because the session's `close()` and the
 * SSE heartbeat both re-acquire the same per-session Mutex the wedged `send()` holds and would
 * deadlock behind it. Cancelling the Job cancels the shared response byte-channel, which resumes
 * the parked `flush()` with a cause, releasing the Mutex and unwinding the POST coroutine into a
 * recoverable error. All members except [send] delegate unchanged to [delegate].
 */
private class TimeoutSseTransport(
    private val delegate: SseServerTransport,
    private val sessionJob: Job,
    private val sendTimeoutMs: Long,
    private val logging: Logging
) : Transport by delegate {
    override suspend fun send(message: JSONRPCMessage, options: TransportSendOptions?) {
        runWithSendTimeout(sendTimeoutMs, sessionJob, onTimeout = {
            logging.logToError(
                "BurpMCP-Ultra: an SSE write stalled >${sendTimeoutMs}ms (client stopped reading the " +
                    "stream); tearing that session down to recover instead of wedging it — the client reconnects."
            )
        }) { delegate.send(message, options) }
    }
}

/**
 * Runs [block] under a [timeoutMs] deadline; on timeout invokes [onTimeout], cancels [sessionJob]
 * (the SSE GET coroutine), and re-throws. Cancelling that job cancels the shared response
 * byte-channel, which resumes the back-pressured flush() with a cause and releases the per-session
 * Mutex — the only sound recovery (close()/heartbeat would deadlock on that same Mutex). Extracted
 * from [TimeoutSseTransport.send] so the recovery TRIGGER is deterministically unit-testable
 * without needing to induce a real TCP-level write wedge.
 */
internal suspend fun <T> runWithSendTimeout(
    timeoutMs: Long,
    sessionJob: Job,
    onTimeout: () -> Unit,
    block: suspend () -> T
): T = try {
    withTimeout(timeoutMs) { block() }
} catch (t: TimeoutCancellationException) {
    onTimeout()
    sessionJob.cancel(CancellationException("SSE send back-pressure timeout after ${timeoutMs}ms"))
    throw t
}
