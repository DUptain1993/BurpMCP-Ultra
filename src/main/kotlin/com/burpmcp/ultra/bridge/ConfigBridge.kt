package com.burpmcp.ultra.bridge

import burp.api.montoya.MontoyaApi
import kotlinx.serialization.json.*

/**
 * Bridge providing convenient shortcuts for common Burp Suite configuration
 * operations. All config changes are performed by exporting the current
 * project options as JSON, modifying the relevant section, and re-importing.
 */
class ConfigBridge(private val api: MontoyaApi) {

    /**
     * Lists all proxy listeners from the current project configuration.
     */
    fun listProxyListeners(): JsonObject {
        return try {
            val configJson = api.burpSuite().exportProjectOptionsAsJson("proxy.request_listeners")
            val config = Json.parseToJsonElement(configJson)
            val listeners = config.jsonObject["proxy"]
                ?.jsonObject?.get("request_listeners")
                ?.jsonArray ?: JsonArray(emptyList())

            buildJsonObject {
                put("count", listeners.size)
                put("listeners", listeners)
            }
        } catch (e: Exception) {
            buildJsonObject {
                put("error", "Failed to list proxy listeners: ${e.message}")
            }
        }
    }

    /**
     * Adds a new proxy listener by modifying the project configuration.
     */
    fun addProxyListener(
        listenerInterface: String,
        tls: Boolean,
        redirectHost: String?,
        redirectPort: Int?,
        certificate: String?
    ): JsonObject {
        // Parse & validate "host:port" up front so callers get a clear
        // validation error rather than a confusing "unrecognized schema?".
        val parsed = parseListenerInterface(listenerInterface)
            ?: return buildJsonObject {
                put("error", "Invalid interface '$listenerInterface'. Expected 'host:port' " +
                    "with a port in 1-65535, e.g. '127.0.0.1:8081'.")
            }
        val (host, port) = parsed

        return try {
            val configJson = api.burpSuite().exportProjectOptionsAsJson("proxy.request_listeners")
            val config = Json.parseToJsonElement(configJson).jsonObject.toMutableMap()

            val proxyObj = config["proxy"]?.jsonObject?.toMutableMap()
                ?: mutableMapOf()
            val existingListeners = proxyObj["request_listeners"]
                ?.jsonArray?.toMutableList() ?: mutableListOf()

            // Build new listener entry using Burp's real request_listeners schema.
            val newListener = buildProxyListener(host, port, tls, redirectHost, redirectPort, certificate)

            val expectedCount = existingListeners.size + 1
            existingListeners.add(newListener)
            proxyObj["request_listeners"] = JsonArray(existingListeners)
            config["proxy"] = JsonObject(proxyObj)

            val modifiedConfig = JsonObject(config).toString()
            api.burpSuite().importProjectOptionsFromJson(modifiedConfig)

            // Read back the actual config: Burp silently ignores unrecognized
            // keys, so confirm the listener was really added before reporting
            // success.
            val afterListeners = currentProxyListeners()
            val present = afterListeners.any { listener -> listenerMatches(listener, host, port) }
            if (!present || afterListeners.size < expectedCount) {
                return buildJsonObject {
                    put("status", "failed")
                    put("error", "Burp did not accept the config change (unrecognized schema?)")
                }
            }

            buildJsonObject {
                put("status", "added")
                put("interface", listenerInterface)
                put("listener_port", port)
                put("tls", tls)
                put("total_listeners", afterListeners.size)
            }
        } catch (e: Exception) {
            buildJsonObject {
                put("error", "Failed to add proxy listener: ${e.message}")
            }
        }
    }

    /**
     * Removes a proxy listener matching the given interface string.
     */
    fun removeProxyListener(listenerInterface: String): JsonObject {
        val parsed = parseListenerInterface(listenerInterface)
            ?: return buildJsonObject {
                put("error", "Invalid interface '$listenerInterface'. Expected 'host:port' " +
                    "with a port in 1-65535, e.g. '127.0.0.1:8081'.")
            }
        val (host, port) = parsed

        return try {
            val configJson = api.burpSuite().exportProjectOptionsAsJson("proxy.request_listeners")
            val config = Json.parseToJsonElement(configJson).jsonObject.toMutableMap()

            val proxyObj = config["proxy"]?.jsonObject?.toMutableMap()
                ?: return buildJsonObject { put("error", "No proxy configuration found") }
            val existingListeners = proxyObj["request_listeners"]
                ?.jsonArray?.toMutableList() ?: mutableListOf()

            val sizeBefore = existingListeners.size
            existingListeners.removeAll { listener -> listenerMatches(listener, host, port) }

            if (existingListeners.size == sizeBefore) {
                return buildJsonObject {
                    put("error", "No listener found with interface: $listenerInterface")
                }
            }

            proxyObj["request_listeners"] = JsonArray(existingListeners)
            config["proxy"] = JsonObject(proxyObj)

            val modifiedConfig = JsonObject(config).toString()
            api.burpSuite().importProjectOptionsFromJson(modifiedConfig)

            // Read back the actual config and confirm the listener is gone;
            // Burp silently ignores unrecognized keys.
            val afterListeners = currentProxyListeners()
            val stillPresent = afterListeners.any { listener -> listenerMatches(listener, host, port) }
            if (stillPresent) {
                return buildJsonObject {
                    put("status", "failed")
                    put("error", "Burp did not accept the config change (unrecognized schema?)")
                }
            }

            buildJsonObject {
                put("status", "removed")
                put("interface", listenerInterface)
                put("remaining_listeners", afterListeners.size)
            }
        } catch (e: Exception) {
            buildJsonObject {
                put("error", "Failed to remove proxy listener: ${e.message}")
            }
        }
    }

    /**
     * Adds a match-and-replace rule to the proxy configuration.
     */
    fun addMatchReplaceRule(
        type: String,
        match: String,
        replace: String,
        comment: String?,
        enabled: Boolean
    ): JsonObject {
        return try {
            val configJson = api.burpSuite().exportProjectOptionsAsJson("proxy.match_replace_rules")
            val config = Json.parseToJsonElement(configJson).jsonObject.toMutableMap()

            val proxyObj = config["proxy"]?.jsonObject?.toMutableMap()
                ?: mutableMapOf()
            val existingRules = proxyObj["match_replace_rules"]
                ?.jsonArray?.toMutableList() ?: mutableListOf()

            val newRule = buildMatchReplaceRule(type, match, replace, comment, enabled)

            val expectedCount = existingRules.size + 1
            existingRules.add(newRule)
            proxyObj["match_replace_rules"] = JsonArray(existingRules)
            config["proxy"] = JsonObject(proxyObj)

            val modifiedConfig = JsonObject(config).toString()
            api.burpSuite().importProjectOptionsFromJson(modifiedConfig)

            // Read back the actual config: Burp silently ignores unrecognized
            // keys, so confirm the rule was really added before reporting
            // success.
            val afterRules = currentMatchReplaceRules()
            val present = afterRules.any { rule ->
                val r = rule.jsonObject
                r["string_match"]?.jsonPrimitive?.contentOrNull == match &&
                    r["string_replace"]?.jsonPrimitive?.contentOrNull == replace
            }
            if (!present || afterRules.size < expectedCount) {
                return buildJsonObject {
                    put("status", "failed")
                    put("error", "Burp did not accept the config change (unrecognized schema?)")
                }
            }

            buildJsonObject {
                put("status", "added")
                put("type", type)
                put("match", match)
                put("replace", replace)
                put("enabled", enabled)
                put("total_rules", afterRules.size)
            }
        } catch (e: Exception) {
            buildJsonObject {
                put("error", "Failed to add match/replace rule: ${e.message}")
            }
        }
    }

    /**
     * Lists all match-and-replace rules from the proxy configuration.
     */
    fun listMatchReplaceRules(): JsonObject {
        return try {
            val configJson = api.burpSuite().exportProjectOptionsAsJson("proxy.match_replace_rules")
            val config = Json.parseToJsonElement(configJson)
            val rules = config.jsonObject["proxy"]
                ?.jsonObject?.get("match_replace_rules")
                ?.jsonArray ?: JsonArray(emptyList())

            buildJsonObject {
                put("count", rules.size)
                put("rules", buildJsonArray {
                    rules.forEachIndexed { idx, rule ->
                        addJsonObject {
                            put("index", idx)
                            for ((key, value) in rule.jsonObject) {
                                put(key, value)
                            }
                        }
                    }
                })
            }
        } catch (e: Exception) {
            buildJsonObject {
                put("error", "Failed to list match/replace rules: ${e.message}")
            }
        }
    }

    /**
     * Removes a match-and-replace rule by its index.
     */
    fun removeMatchReplaceRule(index: Int): JsonObject {
        return try {
            val configJson = api.burpSuite().exportProjectOptionsAsJson("proxy.match_replace_rules")
            val config = Json.parseToJsonElement(configJson).jsonObject.toMutableMap()

            val proxyObj = config["proxy"]?.jsonObject?.toMutableMap()
                ?: return buildJsonObject { put("error", "No proxy configuration found") }
            val existingRules = proxyObj["match_replace_rules"]
                ?.jsonArray?.toMutableList() ?: mutableListOf()

            if (index < 0 || index >= existingRules.size) {
                return buildJsonObject {
                    put("error", "Invalid rule index: $index. Valid range: 0..${existingRules.size - 1}")
                }
            }

            val expectedCount = existingRules.size - 1
            val removed = existingRules.removeAt(index)
            proxyObj["match_replace_rules"] = JsonArray(existingRules)
            config["proxy"] = JsonObject(proxyObj)

            val modifiedConfig = JsonObject(config).toString()
            api.burpSuite().importProjectOptionsFromJson(modifiedConfig)

            // Read back the actual config and confirm the rule count dropped;
            // Burp silently ignores unrecognized keys.
            val afterRules = currentMatchReplaceRules()
            if (afterRules.size > expectedCount) {
                return buildJsonObject {
                    put("status", "failed")
                    put("error", "Burp did not accept the config change (unrecognized schema?)")
                }
            }

            buildJsonObject {
                put("status", "removed")
                put("removed_index", index)
                put("removed_rule", removed)
                put("remaining_rules", afterRules.size)
            }
        } catch (e: Exception) {
            buildJsonObject {
                put("error", "Failed to remove match/replace rule: ${e.message}")
            }
        }
    }

    /**
     * Configures an upstream proxy server.
     */
    fun setUpstreamProxy(
        host: String,
        port: Int,
        proxyType: String,
        authUser: String?,
        authPass: String?,
        destinationHost: String?
    ): JsonObject {
        return try {
            // Burp requires the upstream proxy nested under
            // project_options.connections.upstream_proxy — a flat
            // {"upstream_proxy": ...} root is silently ignored.
            val serverEntry = buildUpstreamServer(host, port, proxyType, authUser, authPass, destinationHost)
            val upstreamConfig = buildJsonObject {
                put("project_options", buildJsonObject {
                    put("connections", buildJsonObject {
                        put("upstream_proxy", buildJsonObject {
                            putJsonArray("servers") {
                                add(serverEntry)
                            }
                        })
                    })
                })
            }

            api.burpSuite().importProjectOptionsFromJson(upstreamConfig.toString())

            // Read back the actual config: Burp silently ignores unrecognized
            // keys, so confirm the upstream proxy server is really present
            // before reporting success.
            val afterServers = currentUpstreamProxyServers()
            val present = afterServers.any { server ->
                val s = server.jsonObject
                s["proxy_host"]?.jsonPrimitive?.contentOrNull == host &&
                    s["proxy_port"]?.jsonPrimitive?.intOrNull == port
            }
            if (!present) {
                return buildJsonObject {
                    put("status", "failed")
                    put("error", "Burp did not accept the config change (unrecognized schema?)")
                }
            }

            buildJsonObject {
                put("status", "configured")
                put("proxy_host", host)
                put("proxy_port", port)
                put("proxy_type", proxyType.uppercase())
                put("destination_host", destinationHost ?: "*")
                put("has_auth", authUser != null)
            }
        } catch (e: Exception) {
            buildJsonObject {
                put("error", "Failed to set upstream proxy: ${e.message}")
            }
        }
    }

    // ---------------------------------------------------------------
    // Read-back helpers (re-export config to verify changes took effect)
    // ---------------------------------------------------------------

    /**
     * Re-exports the current proxy request listeners from the live project
     * config. Returns an empty list if the section is absent.
     */
    private fun currentProxyListeners(): List<JsonElement> {
        val configJson = api.burpSuite().exportProjectOptionsAsJson("proxy.request_listeners")
        val config = Json.parseToJsonElement(configJson)
        return config.jsonObject["proxy"]
            ?.jsonObject?.get("request_listeners")
            ?.jsonArray ?: JsonArray(emptyList())
    }

    /**
     * Re-exports the current match-and-replace rules from the live project
     * config. Returns an empty list if the section is absent.
     */
    private fun currentMatchReplaceRules(): List<JsonElement> {
        val configJson = api.burpSuite().exportProjectOptionsAsJson("proxy.match_replace_rules")
        val config = Json.parseToJsonElement(configJson)
        return config.jsonObject["proxy"]
            ?.jsonObject?.get("match_replace_rules")
            ?.jsonArray ?: JsonArray(emptyList())
    }

    /**
     * Re-exports the current upstream proxy servers from the live project
     * config. Returns an empty list if the section is absent.
     */
    private fun currentUpstreamProxyServers(): List<JsonElement> {
        val configJson = api.burpSuite().exportProjectOptionsAsJson("project_options.connections.upstream_proxy")
        val config = Json.parseToJsonElement(configJson)
        // Tolerate both a flat "upstream_proxy" root and the nested
        // project_options.connections.upstream_proxy layout.
        val root = config.jsonObject
        val upstream = root["upstream_proxy"]?.jsonObject
            ?: root["project_options"]?.jsonObject
                ?.get("connections")?.jsonObject
                ?.get("upstream_proxy")?.jsonObject
        return upstream?.get("servers")?.jsonArray ?: JsonArray(emptyList())
    }

    // ---------------------------------------------------------------
    // Pure schema builders / parsers (unit-testable without live Burp)
    //
    // These live in a companion object so they can be exercised directly by
    // unit tests without constructing a ConfigBridge (which needs a live
    // MontoyaApi). The instance methods above call them by their short names.
    // ---------------------------------------------------------------

    companion object {

        /**
         * Builds a match-and-replace rule using Burp's real project-config
         * schema. Burp expects `rule_type`, `string_match`, `string_replace`,
         * and `is_simple_match` (true = literal, false = regex) — NOT the
         * invented `type`/`match`/`replace`/`is_regex` keys, which Burp
         * silently drops (BUG #27).
         */
        internal fun buildMatchReplaceRule(
            type: String,
            match: String,
            replace: String,
            comment: String?,
            enabled: Boolean
        ): JsonObject = buildJsonObject {
            put("rule_type", type)
            put("string_match", match)
            put("string_replace", replace)
            put("comment", comment ?: "")
            put("enabled", enabled)
            // We accept plain text or regex; treat every rule as a regex match
            // (is_simple_match = false) to preserve the previous is_regex=false
            // behaviour, where the literal string is used as the regex pattern.
            put("is_simple_match", false)
        }

        /**
         * Parses a "host:port" interface string into (host, port). Returns null
         * for malformed input (empty host, missing/invalid port, out-of-range
         * port). IPv6 literals are not supported by Burp's simple interface
         * field.
         */
        internal fun parseListenerInterface(iface: String): Pair<String, Int>? {
            val trimmed = iface.trim()
            val idx = trimmed.lastIndexOf(':')
            if (idx <= 0 || idx == trimmed.length - 1) return null
            val host = trimmed.substring(0, idx).trim()
            val portStr = trimmed.substring(idx + 1).trim()
            if (host.isEmpty()) return null
            val port = portStr.toIntOrNull() ?: return null
            if (port < 1 || port > 65535) return null
            return host to port
        }

        /**
         * Builds a proxy request listener entry using Burp's real
         * `proxy.request_listeners` schema (`listener_port`, `listen_mode`,
         * `bind_address`, ...) instead of the invented `listener_interface`
         * key (BUG #28).
         */
        internal fun buildProxyListener(
            host: String,
            port: Int,
            tls: Boolean,
            redirectHost: String?,
            redirectPort: Int?,
            certificate: String?
        ): JsonObject = buildJsonObject {
            put("listener_port", port)
            val loopback = host == "127.0.0.1" || host.equals("localhost", ignoreCase = true)
            val allIfaces = host == "0.0.0.0" || host == "*" || host.isEmpty()
            when {
                loopback -> put("listen_mode", "loopback_only")
                allIfaces -> put("listen_mode", "all_interfaces")
                else -> {
                    put("listen_mode", "specific_address")
                    put("bind_address", host)
                }
            }
            put("running", true)
            put("certificate_mode", certificate ?: "per_host")
            put("use_custom_tls_protocols", false)
            put("enable_http2", true)
            if (tls) {
                // TLS termination for this listener — matches Burp's exported flag.
                put("support_invisible_proxying", false)
            }
            if (redirectHost != null) {
                // Burp models fixed redirection under the listener's
                // invisible-proxy / redirect fields.
                put("redirect_to_host", redirectHost)
                put("redirect_to_port", redirectPort ?: 80)
            }
        }

        /**
         * True if the given exported listener JSON matches (host, port) using
         * Burp's real schema (`listener_port` + `listen_mode`/`bind_address`).
         */
        internal fun listenerMatches(listener: JsonElement, host: String, port: Int): Boolean {
            val obj = listener as? JsonObject ?: return false
            val lport = obj["listener_port"]?.jsonPrimitive?.intOrNull ?: return false
            if (lport != port) return false
            val loopback = host == "127.0.0.1" || host.equals("localhost", ignoreCase = true)
            val allIfaces = host == "0.0.0.0" || host == "*" || host.isEmpty()
            val mode = obj["listen_mode"]?.jsonPrimitive?.contentOrNull
            return when {
                loopback -> mode == null || mode == "loopback_only"
                allIfaces -> mode == null || mode == "all_interfaces"
                else -> obj["bind_address"]?.jsonPrimitive?.contentOrNull == host
            }
        }

        /**
         * Builds a single upstream proxy server entry. The caller nests this
         * under project_options.connections.upstream_proxy.servers (BUG #29).
         */
        internal fun buildUpstreamServer(
            host: String,
            port: Int,
            proxyType: String,
            authUser: String?,
            authPass: String?,
            destinationHost: String?
        ): JsonObject = buildJsonObject {
            put("proxy_host", host)
            put("proxy_port", port)
            put("proxy_type", proxyType.uppercase())
            put("destination_host", destinationHost ?: "*")
            put("enabled", true)
            if (authUser != null) {
                put("authentication", buildJsonObject {
                    put("enabled", true)
                    put("username", authUser)
                    put("password", authPass ?: "")
                })
            }
        }
    }
}
