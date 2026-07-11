package com.burpmcp.ultra.bridge

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Unit tests for the pure schema builders/parsers in ConfigBridge. These
 * exercise the fixes for BUG #27 (match/replace schema), BUG #28 (proxy
 * listener schema), and BUG #29 (upstream proxy nesting) without needing a
 * live Burp/Montoya API — the builder helpers are pure companion functions,
 * so no ConfigBridge instance (and no MontoyaApi) is required.
 */
class ConfigBridgeSchemaTest {

    // ---- BUG #27: match/replace rule schema ----

    @Test
    fun `match replace rule uses Burp's real key names`() {
        val rule = ConfigBridge.buildMatchReplaceRule(
            type = "request_header",
            match = "^Foo: bar",
            replace = "Foo: baz",
            comment = "test",
            enabled = true
        )
        // Real Burp keys must be present.
        assertEquals("request_header", rule["rule_type"]?.jsonPrimitive?.content)
        assertEquals("^Foo: bar", rule["string_match"]?.jsonPrimitive?.content)
        assertEquals("Foo: baz", rule["string_replace"]?.jsonPrimitive?.content)
        assertEquals("test", rule["comment"]?.jsonPrimitive?.content)
        assertEquals(true, rule["enabled"]?.jsonPrimitive?.content?.toBoolean())
        assertEquals(false, rule["is_simple_match"]?.jsonPrimitive?.content?.toBoolean())

        // The old (wrong) keys must NOT be present — those are what made every
        // add silently fail.
        assertNull(rule["type"])
        assertNull(rule["match"])
        assertNull(rule["replace"])
        assertNull(rule["is_regex"])
    }

    @Test
    fun `match replace rule defaults null comment to empty string`() {
        val rule = ConfigBridge.buildMatchReplaceRule("response_body", "a", "b", null, false)
        assertEquals("", rule["comment"]?.jsonPrimitive?.content)
        assertEquals(false, rule["enabled"]?.jsonPrimitive?.content?.toBoolean())
    }

    // ---- BUG #28: proxy listener interface parsing ----

    @Test
    fun `parseListenerInterface accepts valid host and port`() {
        assertEquals("127.0.0.1" to 8081, ConfigBridge.parseListenerInterface("127.0.0.1:8081"))
        assertEquals("0.0.0.0" to 9000, ConfigBridge.parseListenerInterface("0.0.0.0:9000"))
        assertEquals("localhost" to 1, ConfigBridge.parseListenerInterface("localhost:1"))
        assertEquals("10.0.0.5" to 65535, ConfigBridge.parseListenerInterface("10.0.0.5:65535"))
    }

    @Test
    fun `parseListenerInterface rejects malformed input`() {
        assertNull(ConfigBridge.parseListenerInterface("not-a-valid-interface"))
        assertNull(ConfigBridge.parseListenerInterface("127.0.0.1"))
        assertNull(ConfigBridge.parseListenerInterface("127.0.0.1:"))
        assertNull(ConfigBridge.parseListenerInterface(":8080"))
        assertNull(ConfigBridge.parseListenerInterface("127.0.0.1:abc"))
        assertNull(ConfigBridge.parseListenerInterface("127.0.0.1:0"))
        assertNull(ConfigBridge.parseListenerInterface("127.0.0.1:70000"))
        assertNull(ConfigBridge.parseListenerInterface(""))
    }

    // ---- BUG #28: proxy listener schema ----

    @Test
    fun `buildProxyListener maps loopback host to loopback_only`() {
        val l = ConfigBridge.buildProxyListener("127.0.0.1", 8081, false, null, null, null)
        assertEquals(8081, l["listener_port"]?.jsonPrimitive?.int)
        assertEquals("loopback_only", l["listen_mode"]?.jsonPrimitive?.content)
        assertEquals("per_host", l["certificate_mode"]?.jsonPrimitive?.content)
        assertNull(l["bind_address"])
        // The invented key that broke every add must be gone.
        assertNull(l["listener_interface"])
        assertEquals(true, l["running"]?.jsonPrimitive?.content?.toBoolean())
        assertEquals(true, l["enable_http2"]?.jsonPrimitive?.content?.toBoolean())
    }

    @Test
    fun `buildProxyListener maps localhost to loopback_only`() {
        val l = ConfigBridge.buildProxyListener("localhost", 8080, false, null, null, null)
        assertEquals("loopback_only", l["listen_mode"]?.jsonPrimitive?.content)
    }

    @Test
    fun `buildProxyListener maps wildcard hosts to all_interfaces`() {
        for (h in listOf("0.0.0.0", "*", "")) {
            val l = ConfigBridge.buildProxyListener(h, 8080, false, null, null, null)
            assertEquals("all_interfaces", l["listen_mode"]?.jsonPrimitive?.content, "host=$h")
            assertNull(l["bind_address"], "host=$h")
        }
    }

    @Test
    fun `buildProxyListener maps a specific IP to specific_address with bind_address`() {
        val l = ConfigBridge.buildProxyListener("192.168.1.10", 8080, false, null, null, null)
        assertEquals("specific_address", l["listen_mode"]?.jsonPrimitive?.content)
        assertEquals("192.168.1.10", l["bind_address"]?.jsonPrimitive?.content)
    }

    @Test
    fun `buildProxyListener honours certificate mode and redirect fields`() {
        val l = ConfigBridge.buildProxyListener("127.0.0.1", 8080, true, "example.com", 443, "self_signed")
        assertEquals("self_signed", l["certificate_mode"]?.jsonPrimitive?.content)
        assertEquals("example.com", l["redirect_to_host"]?.jsonPrimitive?.content)
        assertEquals(443, l["redirect_to_port"]?.jsonPrimitive?.int)
        // Fabricated boolean redirect keys must be gone.
        assertNull(l["redirect_host"])
        assertNull(l["redirect_port"])
    }

    // ---- BUG #28: read-back matching on the real schema ----

    @Test
    fun `listenerMatches round-trips a built listener`() {
        val l = ConfigBridge.buildProxyListener("127.0.0.1", 8081, false, null, null, null)
        assertTrue(ConfigBridge.listenerMatches(l, "127.0.0.1", 8081))
        assertFalse(ConfigBridge.listenerMatches(l, "127.0.0.1", 9090))
    }

    @Test
    fun `listenerMatches round-trips a specific address listener`() {
        val l = ConfigBridge.buildProxyListener("192.168.1.10", 8080, false, null, null, null)
        assertTrue(ConfigBridge.listenerMatches(l, "192.168.1.10", 8080))
        assertFalse(ConfigBridge.listenerMatches(l, "10.0.0.1", 8080))
    }

    @Test
    fun `listenerMatches ignores a listener whose port differs`() {
        val other = buildJsonObject {
            put("listener_port", 9999)
            put("listen_mode", "loopback_only")
        }
        assertFalse(ConfigBridge.listenerMatches(other, "127.0.0.1", 8081))
    }

    // ---- BUG #29: upstream proxy server entry ----

    @Test
    fun `buildUpstreamServer emits the real server keys`() {
        val s = ConfigBridge.buildUpstreamServer("proxy.local", 3128, "socks5", null, null, null)
        assertEquals("proxy.local", s["proxy_host"]?.jsonPrimitive?.content)
        assertEquals(3128, s["proxy_port"]?.jsonPrimitive?.int)
        assertEquals("SOCKS5", s["proxy_type"]?.jsonPrimitive?.content)
        assertEquals("*", s["destination_host"]?.jsonPrimitive?.content)
        assertEquals(true, s["enabled"]?.jsonPrimitive?.content?.toBoolean())
        assertNull(s["authentication"])
    }

    @Test
    fun `buildUpstreamServer includes authentication when a user is supplied`() {
        val s = ConfigBridge.buildUpstreamServer("p", 8080, "http", "alice", "secret", "example.com")
        assertEquals("example.com", s["destination_host"]?.jsonPrimitive?.content)
        val auth = s["authentication"] as JsonObject
        assertEquals("alice", auth["username"]?.jsonPrimitive?.content)
        assertEquals("secret", auth["password"]?.jsonPrimitive?.content)
        assertEquals(true, auth["enabled"]?.jsonPrimitive?.content?.toBoolean())
    }

    @Test
    fun `upstream proxy config must be nested under project_options connections`() {
        // Mirror the exact structure setUpstreamProxy builds so the schema
        // nesting fix (BUG #29) is locked in: a flat {"upstream_proxy": ...}
        // root is silently ignored by Burp.
        val serverEntry = ConfigBridge.buildUpstreamServer("p", 8080, "http", null, null, null)
        val cfg = buildJsonObject {
            put("project_options", buildJsonObject {
                put("connections", buildJsonObject {
                    put("upstream_proxy", buildJsonObject {
                        put("servers", JsonArray(listOf(serverEntry)))
                    })
                })
            })
        }
        // Navigate the nested path the way Burp expects.
        val servers = cfg["project_options"]!!.let { it as JsonObject }["connections"]!!
            .let { it as JsonObject }["upstream_proxy"]!!
            .let { it as JsonObject }["servers"]!!
            .let { it as JsonArray }
        assertEquals(1, servers.size)
        assertEquals(8080, (servers[0] as JsonObject)["proxy_port"]?.jsonPrimitive?.intOrNull)
        // The old flat root key must not be where the config lives.
        assertNull(cfg["upstream_proxy"])
    }
}
