package com.burpmcp.ultra.agent

import burp.api.montoya.logging.Logging
import io.modelcontextprotocol.kotlin.sdk.ExperimentalMcpApi
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.types.buildCallToolRequest
import kotlinx.coroutines.*
import kotlinx.serialization.json.*
import kotlin.coroutines.coroutineContext

/** Progress events emitted while a run is in flight, consumed by the AI Agent tab UI. */
sealed class AgentEvent {
    data class AssistantMessage(val text: String) : AgentEvent()
    data class ToolCallStarted(val name: String, val argumentsJson: String) : AgentEvent()
    data class ToolCallFinished(val name: String, val resultSummary: String, val isError: Boolean) : AgentEvent()
    data class Error(val message: String) : AgentEvent()
    data class Finished(val finalText: String) : AgentEvent()
    object Stopped : AgentEvent()
}

private val SYSTEM_PROMPT = """
    You are an autonomous web application security testing assistant embedded inside
    Burp Suite via BurpMCP-Ultra. You act on the operator's plain-language goal by calling
    the tools made available to you (proxy history, HTTP send/repeat, scanner, intruder,
    injection probes, access-control sweeps, JWT attacks, recon, GraphQL/CORS probing,
    collaborator, etc.) instead of asking the operator to run them manually.

    Rules:
    - Briefly state your plan before you start acting, and narrate significant findings as you go.
    - Every outbound request you make is still subject to Burp's target scope and the operator's
      destructive-action policy; if a tool call is blocked or denied, explain why and adjust your
      approach instead of retrying the same blocked call.
    - Record any confirmed vulnerability or notable finding with the findings_add tool as you
      discover it, so it persists in the operator's working memory even if the run is stopped early.
    - Only report a finding as confirmed when you have observed real tool output that supports it -
      never fabricate results.
    - When the goal is accomplished, or you are blocked and cannot make further progress, stop
      calling tools and give a concise final summary instead.
""".trimIndent()

/**
 * Drives a natural-language goal to completion by looping Venice AI chat-completion
 * calls (with the extension's own MCP tools exposed as OpenAI-style function-calling
 * tools, see [AgentToolCatalog]) against in-process invocations of the same tool
 * handlers an external MCP client would call. Every invocation goes through the
 * [Server]'s already-registered, already-audited, already-scope/policy-gated handler
 * (see [com.burpmcp.ultra.transport.ToolCallTracker], [com.burpmcp.ultra.safety.ScopeGate],
 * [com.burpmcp.ultra.safety.ActionPolicy]) — this loop adds no separate safety path.
 */
class AgentRunner(
    private val toolServer: Server,
    private val logging: Logging
) {
    private val toolCatalog: JsonArray by lazy { AgentToolCatalog.build(toolServer) }

    /**
     * Starts a run on a fresh coroutine and returns its [Job] so the caller (the AI Agent
     * tab's Stop button) can cancel it. [onEvent] fires on the coroutine's own thread —
     * callers must marshal UI updates back to the Swing EDT themselves.
     */
    fun start(
        settings: AgentConfig.Settings,
        goal: String,
        onEvent: (AgentEvent) -> Unit
    ): Job {
        val client = VeniceAiClient(settings.baseUrl, settings.apiKey)
        val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
        return scope.launch {
            try {
                runLoop(client, settings, goal, onEvent)
            } catch (e: CancellationException) {
                onEvent(AgentEvent.Stopped)
            } catch (e: Exception) {
                logging.logToError("BurpMCP-Ultra: AI agent run failed: ${e.message}")
                onEvent(AgentEvent.Error("Agent loop failed: ${e.message}"))
            }
        }
    }

    private suspend fun runLoop(
        client: VeniceAiClient,
        settings: AgentConfig.Settings,
        goal: String,
        onEvent: (AgentEvent) -> Unit
    ) {
        val messages = mutableListOf<JsonObject>()
        messages += chatMessage("system", SYSTEM_PROMPT)
        messages += chatMessage("user", goal)

        repeat(settings.maxIterations) {
            coroutineContext.ensureActive()

            val result = client.chat(settings.model, messages, toolCatalog, settings.temperature)

            if (result.error != null) {
                onEvent(AgentEvent.Error(result.error))
                return
            }

            if (result.toolCalls.isEmpty()) {
                val finalText = result.content?.takeIf { it.isNotBlank() }
                    ?: "(Venice AI returned no further tool calls and no summary text.)"
                onEvent(AgentEvent.Finished(finalText))
                return
            }

            if (!result.content.isNullOrBlank()) {
                onEvent(AgentEvent.AssistantMessage(result.content))
            }

            // Record the assistant's tool_calls turn before the tool results, as the
            // OpenAI/Venice chat-completion protocol requires.
            messages += buildJsonObject {
                put("role", "assistant")
                put("content", result.content ?: "")
                putJsonArray("tool_calls") {
                    result.toolCalls.forEach { call ->
                        add(buildJsonObject {
                            put("id", call.id)
                            put("type", "function")
                            putJsonObject("function") {
                                put("name", call.name)
                                put("arguments", call.argumentsJson)
                            }
                        })
                    }
                }
            }

            // Sequential, not parallel: several tools mutate shared Burp state (active
            // scanner tasks, intruder attacks), so concurrent calls risk cross-talk.
            for (call in result.toolCalls) {
                coroutineContext.ensureActive()
                onEvent(AgentEvent.ToolCallStarted(call.name, call.argumentsJson))
                val (resultText, isError) = invokeTool(call)
                onEvent(AgentEvent.ToolCallFinished(call.name, resultText, isError))
                messages += buildJsonObject {
                    put("role", "tool")
                    put("tool_call_id", call.id)
                    put("content", resultText)
                }
            }
        }

        onEvent(
            AgentEvent.Finished(
                "Stopped after reaching the ${settings.maxIterations}-iteration limit without a final " +
                    "answer. Raise Max Iterations in the AI Agent settings if the task genuinely needs more steps."
            )
        )
    }

    @OptIn(ExperimentalMcpApi::class)
    private suspend fun invokeTool(call: VeniceAiClient.ToolCall): Pair<String, Boolean> {
        val registered = toolServer.tools[call.name]
            ?: return "Unknown tool: ${call.name}" to true

        val argumentsObject = try {
            Json.parseToJsonElement(call.argumentsJson).jsonObject
        } catch (e: Exception) {
            return "Invalid JSON arguments for ${call.name}: ${e.message}" to true
        }

        val request = buildCallToolRequest {
            name = call.name
            arguments(argumentsObject)
        }

        return try {
            val callResult: CallToolResult = registered.handler.invoke(request)
            val text = callResult.content
                ?.filterIsInstance<TextContent>()
                ?.firstOrNull()
                ?.text
                ?: ""
            val truncated = if (text.length > 4000) text.take(4000) + "... (truncated)" else text
            truncated to (callResult.isError ?: false)
        } catch (e: Exception) {
            "Tool ${call.name} threw an exception: ${e.message}" to true
        }
    }

    private fun chatMessage(role: String, content: String): JsonObject = buildJsonObject {
        put("role", role)
        put("content", content)
    }
}
