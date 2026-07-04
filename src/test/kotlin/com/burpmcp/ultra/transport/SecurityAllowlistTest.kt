package com.burpmcp.ultra.transport

import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * The Host-header + CORS-origin allowlist is the anti-DNS-rebinding control. When the bind host
 * becomes configurable it must be built from the explicit allowed-host list (not hardcoded
 * loopback), for every (host x port) pair. This pins that pure construction.
 */
class SecurityAllowlistTest {

    @Test fun `builds host and origin allowlists for each host x port`() {
        val (hosts, origins) = SecurityConfig.buildAllowlists(listOf("127.0.0.1", "localhost"), listOf(9876))
        assertEquals(setOf("127.0.0.1:9876", "localhost:9876"), hosts)
        assertEquals(setOf("http://127.0.0.1:9876", "http://localhost:9876"), origins)
    }

    @Test fun `dedupes repeated hosts`() {
        val (hosts, _) = SecurityConfig.buildAllowlists(listOf("127.0.0.1", "127.0.0.1"), listOf(9876))
        assertEquals(setOf("127.0.0.1:9876"), hosts)
    }

    @Test fun `covers every port for a concrete bind host`() {
        val (hosts, origins) = SecurityConfig.buildAllowlists(listOf("192.168.1.50"), listOf(9876, 9877))
        assertEquals(setOf("192.168.1.50:9876", "192.168.1.50:9877"), hosts)
        assertEquals(setOf("http://192.168.1.50:9876", "http://192.168.1.50:9877"), origins)
    }
}
