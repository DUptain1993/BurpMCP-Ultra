package com.burpmcp.ultra.transport

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The SECURITY GATE for the configurable bind host (GitHub issue #4 / PR #6). The tool's
 * whole threat model is loopback-only; binding to a network interface exposes 149 Burp-driving
 * tools behind only a bearer token, so a non-loopback bind must require an explicit operator
 * opt-in. This pins that invariant — everything else in the feature is UI/wiring around it.
 */
class BindHostPolicyTest {

    @Test fun `loopback is allowed as-is and never marked exposed`() {
        val d = BindHostPolicy.resolve("127.0.0.1", allowRemoteBind = false)
        assertEquals("127.0.0.1", d.effectiveHost)
        assertFalse(d.exposed, "loopback is never a network exposure")
        assertFalse(d.downgraded, "loopback is honored, not downgraded")
    }

    @Test fun `localhost classifies as loopback`() {
        assertEquals(BindHostPolicy.Kind.LOOPBACK, BindHostPolicy.classify("localhost"))
    }

    @Test fun `wildcard without operator opt-in is refused and downgraded to loopback`() {
        val d = BindHostPolicy.resolve("0.0.0.0", allowRemoteBind = false)
        assertEquals("127.0.0.1", d.effectiveHost, "0.0.0.0 must NOT bind without opt-in")
        assertFalse(d.exposed)
        assertTrue(d.downgraded)
    }

    @Test fun `wildcard with operator opt-in binds and is marked exposed`() {
        val d = BindHostPolicy.resolve("0.0.0.0", allowRemoteBind = true)
        assertEquals("0.0.0.0", d.effectiveHost)
        assertTrue(d.exposed)
        assertFalse(d.downgraded)
    }

    @Test fun `concrete non-loopback address requires the operator opt-in`() {
        val blocked = BindHostPolicy.resolve("192.168.1.50", allowRemoteBind = false)
        assertEquals("127.0.0.1", blocked.effectiveHost)
        assertFalse(blocked.exposed)

        val allowed = BindHostPolicy.resolve("192.168.1.50", allowRemoteBind = true)
        assertEquals("192.168.1.50", allowed.effectiveHost)
        assertTrue(allowed.exposed)
    }

    @Test fun `invalid or blank host falls back to loopback even when opt-in is on`() {
        assertEquals("127.0.0.1", BindHostPolicy.resolve("", allowRemoteBind = true).effectiveHost)
        val spaced = BindHostPolicy.resolve("has space", allowRemoteBind = true)
        assertEquals("127.0.0.1", spaced.effectiveHost)
        assertTrue(spaced.downgraded)
    }

    @Test fun `probeHost redirects a wildcard bind to loopback but keeps concrete addresses`() {
        // A server bound to 0.0.0.0 is not directly connectable at 0.0.0.0 — probe loopback,
        // otherwise the liveness check false-negatives and logs the misleading "Java 22+" error.
        assertEquals("127.0.0.1", BindHostPolicy.probeHost("0.0.0.0"))
        assertEquals("192.168.1.50", BindHostPolicy.probeHost("192.168.1.50"))
        assertEquals("127.0.0.1", BindHostPolicy.probeHost("127.0.0.1"))
    }
}
