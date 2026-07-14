package com.burpmcp.ultra.tools.idor

import com.burpmcp.ultra.bridge.IdorHuntBridge
import com.burpmcp.ultra.core.asJsonObjectList
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

/** Registers the `idor_hunt` MCP tool — horizontal object-id IDOR with canary confirmation. */
object IdorTools {
    fun register(server: Server, bridge: IdorHuntBridge) {
        server.addTool(
            name = "idor_hunt",
            description = "Horizontal-IDOR / BOLA hunter with CANARY confirmation — the object-id-swap that auth_diff/access_control_sweep do not do. " +
                "Give a raw request that identity A makes to A's own object, plus 'identities' where each low-priv account declares its own 'object_id' " +
                "(a resource it owns) and 'canary' (a string that appears only in its own data). For every (reader, owner) pair the tool swaps the object " +
                "id to the owner's resource, replays under the reader's auth, and asserts the owner's canary appears in the reader's response — a CONFIRMED " +
                "cross-user read — while filtering the own-data-reflection false positive. It also runs the identity-diff (vertical/unauth) with the id held " +
                "constant, and can enumerate the id-transformation set (encodings, neighbours, type-juggling). Auto-detects the object id in path/query/body/" +
                "header/cookie, or pin it with id_value/id_location. Scope-gated (mcp_scope_mode) and bounded.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("request") { put("type", "string"); put("description", "Raw HTTP request A makes to A's own object") }
                    putJsonObject("host") { put("type", "string"); put("description", "Target hostname") }
                    putJsonObject("port") { put("type", "integer"); put("description", "Target port (default 443)") }
                    putJsonObject("use_tls") { put("type", "boolean"); put("description", "Use HTTPS (default: port==443)") }
                    putJsonObject("identities") {
                        put("type", "array"); putJsonObject("items") { put("type", "object") }
                        put("description", "[{name, header_name?, header_value?, object_id?, canary?}]; name none/unauth strips auth. object_id = a resource that identity owns; canary = a token only in that identity's own data (enables confirmed-grade verdicts).")
                    }
                    putJsonObject("id_value") { put("type", "string"); put("description", "Optional: the object-id value in 'request' to swap (else auto-detected)") }
                    putJsonObject("id_location") { put("type", "string"); put("description", "Optional: where the id is — path/query/header/cookie/body-json/body-form") }
                    putJsonObject("transforms") { put("type", "boolean"); put("description", "Also replay the id-transformation set (encodings/neighbours/type-juggle) under the primary identity") }
                    putJsonObject("enumerate") { put("type", "integer"); put("description", "Optional neighbour/transform replay count (0=off, capped at 25)") }
                },
                required = listOf("request", "host", "identities")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val req = args["request"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool err("Parameter 'request' (raw HTTP request string) is required")
                val host = args["host"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool err("Parameter 'host' is required")
                val port = args["port"]?.jsonPrimitive?.intOrNull ?: 443
                val useTls = args["use_tls"]?.jsonPrimitive?.booleanOrNull
                    ?: args["tls"]?.jsonPrimitive?.booleanOrNull ?: (port == 443)
                val identities = args["identities"].asJsonObjectList()
                    ?: return@addTool err("Parameter 'identities' (array of >=2 identity objects) is required")
                val idValue = args["id_value"]?.jsonPrimitive?.contentOrNull
                val idLocation = args["id_location"]?.jsonPrimitive?.contentOrNull
                val transforms = args["transforms"]?.jsonPrimitive?.booleanOrNull ?: false
                val enumerate = args["enumerate"]?.jsonPrimitive?.intOrNull ?: 0

                val result = bridge.hunt(req, host, port, useTls, identities, idLocation, idValue, transforms, enumerate)
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                err(e.message)
            }
        }
    }

    private fun err(msg: String?): CallToolResult =
        CallToolResult(content = listOf(TextContent(buildJsonObject { put("error", msg ?: "Unknown error") }.toString())), isError = true)
}
