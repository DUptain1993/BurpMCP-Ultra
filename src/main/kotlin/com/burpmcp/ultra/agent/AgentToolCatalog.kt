package com.burpmcp.ultra.agent

import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

/**
 * Converts the MCP tools already registered on a [Server] (see
 * [com.burpmcp.ultra.transport.ToolRegistry]) into the OpenAI-compatible `tools`
 * array Venice AI's function-calling API expects. Every tool's real [io.modelcontextprotocol.kotlin.sdk.types.ToolSchema]
 * (the same JSON Schema an external MCP client sees) is reused as-is — no
 * hand-duplicated schemas to drift out of sync.
 */
object AgentToolCatalog {

    fun build(server: Server): JsonArray = buildJsonArray {
        server.tools.values.forEach { registered ->
            val tool = registered.tool
            add(buildJsonObject {
                put("type", "function")
                putJsonObject("function") {
                    put("name", tool.name)
                    put("description", tool.description ?: "")
                    putJsonObject("parameters") {
                        put("type", "object")
                        put("properties", tool.inputSchema.properties ?: JsonObject(emptyMap()))
                        putJsonArray("required") {
                            tool.inputSchema.required?.forEach { add(it) }
                        }
                    }
                }
            })
        }
    }
}
