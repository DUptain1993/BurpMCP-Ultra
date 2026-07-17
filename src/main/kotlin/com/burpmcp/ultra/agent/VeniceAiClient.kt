package com.burpmcp.ultra.agent

import kotlinx.serialization.json.*
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration

/**
 * Minimal client for Venice AI's OpenAI-compatible `/chat/completions` and `/models`
 * endpoints (https://docs.venice.ai). Deliberately built on the JDK's own
 * [HttpClient] rather than adding a Ktor client dependency, since the project's
 * Ktor version is already pinned tightly to what kotlin-sdk-server 0.8.3 requires
 * (see build.gradle.kts).
 *
 * Blocking by design — callers invoke this from a background thread/coroutine
 * (see [AgentRunner]), never from the Swing EDT.
 */
class VeniceAiClient(
    private val baseUrl: String,
    private val apiKey: String
) {
    private val http: HttpClient = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(20))
        .build()

    data class ToolCall(val id: String, val name: String, val argumentsJson: String)

    data class ChatResult(
        val content: String?,
        val toolCalls: List<ToolCall>,
        val error: String? = null
    )

    data class ModelInfo(val id: String, val supportsFunctionCalling: Boolean)

    /**
     * Sends one chat-completion turn. [messages] are pre-built OpenAI-shaped message
     * objects (system/user/assistant/tool roles) and [tools] is the OpenAI
     * function-calling tool array from [AgentToolCatalog]. Non-streaming: the whole
     * assistant turn (text and/or tool calls) comes back in a single response.
     */
    fun chat(
        model: String,
        messages: List<JsonObject>,
        tools: JsonArray,
        temperature: Double
    ): ChatResult {
        val requestBody = buildJsonObject {
            put("model", model)
            putJsonArray("messages") { messages.forEach { add(it) } }
            if (tools.isNotEmpty()) {
                put("tools", tools)
                put("tool_choice", "auto")
            }
            put("temperature", temperature)
            put("stream", false)
        }

        val httpResponse = try {
            http.send(
                HttpRequest.newBuilder()
                    .uri(URI.create("${trimmedBaseUrl()}/chat/completions"))
                    .header("Authorization", "Bearer $apiKey")
                    .header("Content-Type", "application/json")
                    .timeout(Duration.ofSeconds(120))
                    .POST(HttpRequest.BodyPublishers.ofString(requestBody.toString()))
                    .build(),
                HttpResponse.BodyHandlers.ofString()
            )
        } catch (e: Exception) {
            return ChatResult(null, emptyList(), "Venice AI request failed: ${e.message}")
        }

        if (httpResponse.statusCode() !in 200..299) {
            return ChatResult(
                null, emptyList(),
                "Venice AI returned HTTP ${httpResponse.statusCode()}: ${httpResponse.body().take(500)}"
            )
        }

        return try {
            parseChatResponse(httpResponse.body())
        } catch (e: Exception) {
            ChatResult(null, emptyList(), "Failed to parse Venice AI response: ${e.message}")
        }
    }

    /** `GET /models?type=text`, used by the settings UI to list tool-calling-capable models. */
    fun listModels(): Result<List<ModelInfo>> {
        return try {
            val httpResponse = http.send(
                HttpRequest.newBuilder()
                    .uri(URI.create("${trimmedBaseUrl()}/models?type=text"))
                    .header("Authorization", "Bearer $apiKey")
                    .timeout(Duration.ofSeconds(30))
                    .GET()
                    .build(),
                HttpResponse.BodyHandlers.ofString()
            )
            if (httpResponse.statusCode() !in 200..299) {
                return Result.failure(RuntimeException("HTTP ${httpResponse.statusCode()}: ${httpResponse.body().take(300)}"))
            }
            val root = Json.parseToJsonElement(httpResponse.body()).jsonObject
            val data = root["data"]?.jsonArray ?: JsonArray(emptyList())
            Result.success(data.mapNotNull { entry ->
                val obj = entry.jsonObject
                val id = obj["id"]?.jsonPrimitive?.contentOrNull ?: return@mapNotNull null
                val supportsFunctionCalling = obj["model_spec"]?.jsonObject
                    ?.get("capabilities")?.jsonObject
                    ?.get("supportsFunctionCalling")?.jsonPrimitive?.booleanOrNull ?: false
                ModelInfo(id, supportsFunctionCalling)
            })
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    private fun trimmedBaseUrl(): String = baseUrl.trimEnd('/')

    private fun parseChatResponse(bodyText: String): ChatResult {
        val root = Json.parseToJsonElement(bodyText).jsonObject
        val choices = root["choices"]?.jsonArray
            ?: return ChatResult(null, emptyList(), "Venice AI response had no 'choices': ${bodyText.take(300)}")
        val message = choices.firstOrNull()?.jsonObject?.get("message")?.jsonObject
            ?: return ChatResult(null, emptyList(), "Venice AI response had no message in the first choice")

        val content = message["content"]?.jsonPrimitive?.contentOrNull
        val toolCalls = message["tool_calls"]?.jsonArray?.mapNotNull { entry ->
            val obj = entry.jsonObject
            val id = obj["id"]?.jsonPrimitive?.contentOrNull ?: return@mapNotNull null
            val function = obj["function"]?.jsonObject ?: return@mapNotNull null
            val name = function["name"]?.jsonPrimitive?.contentOrNull ?: return@mapNotNull null
            val arguments = function["arguments"]?.jsonPrimitive?.contentOrNull ?: "{}"
            ToolCall(id, name, arguments)
        } ?: emptyList()

        return ChatResult(content, toolCalls)
    }
}
