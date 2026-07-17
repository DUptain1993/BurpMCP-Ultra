package com.burpmcp.ultra.agent

import burp.api.montoya.MontoyaApi

/**
 * Operator-only Venice AI settings, persisted via Burp's preferences store
 * (same mechanism as `mcp_scope_mode` / `mcp_bind_host`, see [com.burpmcp.ultra.safety.ScopeGate]).
 *
 * These keys are read/written ONLY from Swing UI code ([com.burpmcp.ultra.ui.BurpMcpUltraTab])
 * and [AgentRunner] construction — never registered as an MCP tool, so the
 * natural-language agent can never read or rewrite its own API key.
 */
object AgentConfig {
    const val DEFAULT_BASE_URL = "https://api.venice.ai/api/v1"
    const val DEFAULT_MAX_ITERATIONS = 25
    const val DEFAULT_TEMPERATURE = 0.2

    data class Settings(
        val apiKey: String,
        val baseUrl: String,
        val model: String,
        val maxIterations: Int,
        val temperature: Double
    ) {
        val isConfigured: Boolean get() = apiKey.isNotBlank() && model.isNotBlank()
    }

    fun load(api: MontoyaApi): Settings {
        val prefs = api.persistence().preferences()
        return Settings(
            apiKey = safeGetString(prefs, "venice_api_key") ?: "",
            baseUrl = safeGetString(prefs, "venice_base_url")?.trim()?.ifEmpty { null } ?: DEFAULT_BASE_URL,
            model = safeGetString(prefs, "venice_model") ?: "",
            maxIterations = safeGetInteger(prefs, "venice_max_iterations") ?: DEFAULT_MAX_ITERATIONS,
            temperature = safeGetString(prefs, "venice_temperature")?.toDoubleOrNull() ?: DEFAULT_TEMPERATURE
        )
    }

    fun save(api: MontoyaApi, settings: Settings) {
        val prefs = api.persistence().preferences()
        prefs.setString("venice_api_key", settings.apiKey)
        prefs.setString("venice_base_url", settings.baseUrl)
        prefs.setString("venice_model", settings.model)
        prefs.setInteger("venice_max_iterations", settings.maxIterations)
        prefs.setString("venice_temperature", settings.temperature.toString())
    }

    private fun safeGetString(prefs: burp.api.montoya.persistence.Preferences, key: String): String? =
        try { prefs.getString(key) } catch (_: Exception) { null }

    private fun safeGetInteger(prefs: burp.api.montoya.persistence.Preferences, key: String): Int? =
        try { prefs.getInteger(key) } catch (_: Exception) { null }
}
