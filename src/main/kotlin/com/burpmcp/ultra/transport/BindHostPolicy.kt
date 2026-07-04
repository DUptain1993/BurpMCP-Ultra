package com.burpmcp.ultra.transport

import java.net.InetAddress

/**
 * Security policy for the configurable server bind host (GitHub issue #4, contributed as PR #6
 * by @Spark0618 and re-implemented here with an operator gate).
 *
 * BurpMCP-Ultra's entire threat model is **loopback-only**: the embedded servers expose 149
 * tools that drive the operator's Burp (SSRF-capable request engine, proxy history containing
 * captured credentials/cookies, scanner, collaborator) plus a dashboard API. Binding to a
 * network-reachable interface collapses that to "only the bearer token protects it". So a
 * non-loopback bind is treated as a privileged action and **requires an explicit operator
 * opt-in** (Burp pref `mcp_allow_remote_bind` / `-Dburpmcp.allowRemoteBind`); absent that, any
 * non-loopback request is refused and downgraded back to `127.0.0.1`. This mirrors the existing
 * `mcp_allow_destructive` gate pattern.
 *
 * Kept pure (no Ktor, no I/O beyond a local `InetAddress` classification) so the gate is
 * deterministically unit-tested.
 */
object BindHostPolicy {
    const val LOOPBACK = "127.0.0.1"

    enum class Kind {
        /** 127.0.0.0/8 or ::1 or a name that resolves to loopback (e.g. "localhost"). */
        LOOPBACK,
        /** 0.0.0.0 / :: — binds to every interface (the broadest exposure). */
        WILDCARD,
        /** A concrete, network-reachable address/hostname. */
        OTHER,
        /** Empty, whitespace-bearing, or unresolvable — never bound. */
        INVALID
    }

    /**
     * @param effectiveHost the host the servers should ACTUALLY bind to (already gated).
     * @param exposed true when [effectiveHost] is network-reachable (operator opted in).
     * @param downgraded true when the request was refused/invalid and forced back to loopback.
     * @param message operator-facing reason, present when [exposed] or [downgraded].
     */
    data class Decision(
        val effectiveHost: String,
        val exposed: Boolean,
        val downgraded: Boolean,
        val message: String?
    )

    /** Classifies a requested bind host without ever binding. Whitespace/empty ⇒ [Kind.INVALID]. */
    fun classify(host: String): Kind {
        val h = host.trim()
        if (h.isEmpty() || h.any { it.isWhitespace() }) return Kind.INVALID
        return try {
            val addr = InetAddress.getByName(h)
            when {
                addr.isAnyLocalAddress -> Kind.WILDCARD
                addr.isLoopbackAddress -> Kind.LOOPBACK
                else -> Kind.OTHER
            }
        } catch (_: Exception) {
            Kind.INVALID
        }
    }

    /** Applies the operator gate to a requested host, returning the host to actually bind to. */
    fun resolve(requested: String, allowRemoteBind: Boolean): Decision = when (classify(requested)) {
        Kind.LOOPBACK -> Decision(requested.trim(), exposed = false, downgraded = false, message = null)

        Kind.INVALID -> Decision(
            LOOPBACK, exposed = false, downgraded = true,
            message = "invalid bind host '$requested' — falling back to $LOOPBACK"
        )

        Kind.WILDCARD, Kind.OTHER ->
            if (allowRemoteBind) Decision(
                requested.trim(), exposed = true, downgraded = false,
                message = "binding to non-loopback interface '${requested.trim()}' — the MCP servers and " +
                    "dashboard are reachable from the network; only the bearer token protects them"
            ) else Decision(
                LOOPBACK, exposed = false, downgraded = true,
                message = "non-loopback bind '${requested.trim()}' requires an operator opt-in " +
                    "(set Burp pref mcp_allow_remote_bind=true or -Dburpmcp.allowRemoteBind=true) — " +
                    "falling back to $LOOPBACK"
            )
    }

    /**
     * The address to PROBE for liveness. A server bound to a wildcard (`0.0.0.0`/`::`) is not
     * directly connectable at that address, so probe loopback instead — otherwise the bind
     * verification false-negatives and logs the misleading "Java 22+" error. Concrete addresses
     * are probed as-is.
     */
    fun probeHost(bindHost: String): String =
        if (classify(bindHost) == Kind.WILDCARD) LOOPBACK else bindHost
}
