package com.burpmcp.ultra.transport

/**
 * Enumerates THIS machine's own interface addresses. Used ONLY when the operator has opted into
 * a non-loopback bind (see [BindHostPolicy]): the Host-header allowlist must then include the
 * concrete addresses a LAN client will actually send. A `0.0.0.0` bind, for example, is reached
 * at `192.168.x.y`, and the client's `Host` header is that IP — not `0.0.0.0` — so without this
 * the anti-rebinding Host check would reject every real remote client.
 *
 * This is still far tighter than `anyHost()`: only addresses belonging to this host are added.
 * Environment-dependent (hence not unit-tested); failures degrade to an empty list so the base
 * loopback allowlist still applies.
 */
object NetworkHosts {
    fun local(): List<String> = try {
        java.net.NetworkInterface.getNetworkInterfaces().asSequence()
            .filter { runCatching { it.isUp }.getOrDefault(false) }
            .flatMap { it.inetAddresses.asSequence() }
            .map { it.hostAddress?.substringBefore('%')?.trim() ?: "" }  // strip IPv6 zone id
            .filter { it.isNotBlank() }
            .toList()
    } catch (_: Exception) {
        emptyList()
    }
}
