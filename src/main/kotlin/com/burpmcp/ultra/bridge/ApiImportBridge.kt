package com.burpmcp.ultra.bridge

import burp.api.montoya.MontoyaApi
import com.burpmcp.ultra.safety.BoundedHttp
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.http.message.HttpRequestResponse
import com.burpmcp.ultra.openapi.OpenApiSchema
import com.burpmcp.ultra.state.StateManager
import kotlinx.serialization.json.*

class ApiImportBridge(
    private val api: MontoyaApi,
    private val stateManager: StateManager
) {
    private val scopeGate = com.burpmcp.ultra.safety.ScopeGate(api)
    /**
     * Parse an OpenAPI/Swagger spec and generate requests for all endpoints.
     * Adds them to Burp's sitemap and optionally to scope.
     *
     * @param specJson The OpenAPI/Swagger JSON spec as a string
     * @param baseUrl Override base URL (if not in spec or want to test different host)
     * @param authHeader Optional auth header to include in all generated requests
     * @param authValue Auth header value
     * @param addToScope Whether to add the base URL to Burp's target scope
     * @param addToSitemap Whether to add generated requests to the sitemap
     * @param sendRequests Whether to actually send the requests (adds responses to sitemap)
     */
    fun importOpenApi(
        specJson: String,
        baseUrl: String?,
        authHeader: String?,
        authValue: String?,
        addToScope: Boolean,
        addToSitemap: Boolean,
        sendRequests: Boolean
    ): JsonObject {
        return try {
            val spec = try {
                Json.parseToJsonElement(specJson).jsonObject
            } catch (e: Exception) {
                return buildJsonObject {
                    put("error", "Failed to parse spec as JSON: ${e.message}. Ensure the input is valid JSON (not YAML).")
                }
            }

            // Detect spec version
            val isOpenApi3 = spec.containsKey("openapi")
            val isSwagger2 = spec.containsKey("swagger")

            if (!isOpenApi3 && !isSwagger2) {
                return buildJsonObject {
                    put("error", "Unrecognized spec format: missing 'openapi' or 'swagger' key. Provide a valid OpenAPI 3.x or Swagger 2.0 JSON spec.")
                }
            }

            // Extract base URL
            val resolvedBaseUrl = baseUrl ?: extractBaseUrl(spec, isOpenApi3)
                ?: return buildJsonObject { put("error", "No base URL found in spec and none provided") }

            // Validate the base URL BEFORE any scope/sitemap mutation: require a
            // well-formed http(s) scheme and a syntactically valid host.
            if (!validateBaseUrl(resolvedBaseUrl)) {
                return buildJsonObject { put("error", "Invalid base URL: $resolvedBaseUrl") }
            }

            // Parse the base URL
            val urlParts = parseUrl(resolvedBaseUrl)
            val host = urlParts["host"] ?: return buildJsonObject { put("error", "Invalid base URL: $resolvedBaseUrl") }
            val port = urlParts["port"]?.toIntOrNull() ?: if (resolvedBaseUrl.startsWith("https")) 443 else 80
            val useTls = resolvedBaseUrl.startsWith("https")
            val basePath = urlParts["path"] ?: ""

            val service = HttpService.httpService(host, port, useTls)

            // Add to scope if requested
            if (addToScope) {
                try {
                    api.scope().includeInScope(resolvedBaseUrl)
                } catch (_: Exception) {}
            }

            // Extract paths and operations
            val refs = OpenApiSchema.buildRefs(spec)
            val paths = spec["paths"]?.jsonObject ?: JsonObject(emptyMap())
            val endpoints = mutableListOf<JsonObject>()
            var requestsSent = 0
            var addedToSitemap = 0
            var skippedOutOfScope = 0

            for ((path, pathItem) in paths) {
                val pathObj = pathItem.jsonObject

                for (method in listOf("get", "post", "put", "delete", "patch", "options", "head")) {
                    val operation = pathObj[method]?.jsonObject ?: continue

                    val operationId = operation["operationId"]?.jsonPrimitive?.contentOrNull ?: "$method $path"
                    val summary = operation["summary"]?.jsonPrimitive?.contentOrNull ?: ""
                    val description = operation["description"]?.jsonPrimitive?.contentOrNull ?: ""
                    val tags = operation["tags"]?.jsonArray?.mapNotNull { it.jsonPrimitive.contentOrNull } ?: emptyList()

                    // Extract parameters
                    val params = (operation["parameters"]?.jsonArray ?: JsonArray(emptyList())) +
                        (pathObj["parameters"]?.jsonArray ?: JsonArray(emptyList()))

                    val queryParams = mutableListOf<Pair<String, String>>()
                    val headerParams = mutableListOf<Pair<String, String>>()
                    val pathParams = mutableMapOf<String, String>()

                    for (param in params) {
                        val p = param.jsonObject
                        val name = p["name"]?.jsonPrimitive?.contentOrNull ?: continue
                        val location = p["in"]?.jsonPrimitive?.contentOrNull ?: continue
                        val required = p["required"]?.jsonPrimitive?.booleanOrNull ?: false
                        val example = extractExample(p) ?: generateSampleValue(name, p)

                        when (location) {
                            "query" -> queryParams.add(name to example)
                            "header" -> headerParams.add(name to example)
                            "path" -> pathParams[name] = example
                        }
                    }

                    // Build the URL path with path parameters substituted.
                    // Normalize the base-path/path boundary so a basePath of '/'
                    // (or a servers[].url ending in '/') does not yield '//blog'.
                    var fullPath = joinPaths(basePath, path)
                    for ((paramName, paramValue) in pathParams) {
                        fullPath = fullPath.replace("{$paramName}", paramValue)
                    }

                    // Add query parameters
                    if (queryParams.isNotEmpty()) {
                        fullPath += "?" + queryParams.joinToString("&") { "${it.first}=${it.second}" }
                    }

                    // Build request body for POST/PUT/PATCH
                    var body: String? = null
                    var contentType = "application/json"
                    if (method in listOf("post", "put", "patch")) {
                        val requestBody = operation["requestBody"]?.jsonObject
                        if (requestBody != null) {
                            val content = requestBody["content"]?.jsonObject
                            val jsonContent = content?.get("application/json")?.jsonObject
                            val formContent = content?.get("application/x-www-form-urlencoded")?.jsonObject

                            if (jsonContent != null) {
                                val schema = jsonContent["schema"]?.jsonObject
                                body = generateJsonBody(schema, refs)
                                contentType = "application/json"
                            } else if (formContent != null) {
                                val schema = formContent["schema"]?.jsonObject
                                body = generateFormBody(schema, refs)
                                contentType = "application/x-www-form-urlencoded"
                            }
                        }
                        // Swagger 2.0 body parameter
                        val bodyParam = params.firstOrNull {
                            it.jsonObject["in"]?.jsonPrimitive?.contentOrNull == "body"
                        }
                        if (body == null && bodyParam != null) {
                            val schema = bodyParam.jsonObject["schema"]?.jsonObject
                            body = generateJsonBody(schema, refs)
                        }
                    }

                    // Build the HTTP request
                    var httpRequest = HttpRequest.httpRequestFromUrl(
                        "${if (useTls) "https" else "http"}://$host:$port$fullPath"
                    ).withMethod(method.uppercase())

                    // Add headers
                    for ((hName, hValue) in headerParams) {
                        httpRequest = httpRequest.withHeader(hName, hValue)
                    }
                    if (authHeader != null && authValue != null) {
                        httpRequest = httpRequest.withHeader(authHeader, authValue)
                    }
                    if (body != null) {
                        httpRequest = httpRequest.withHeader("Content-Type", contentType).withBody(body)
                    }

                    // Send or just add to sitemap
                    if (sendRequests) {
                        if (scopeGate.deny(httpRequest.url()) != null) {
                            // Operator scope policy (mcp_scope_mode=enforce): don't send out-of-scope.
                            skippedOutOfScope++
                        } else try {
                            val result = BoundedHttp.send(api, httpRequest)
                            if (result != null) {
                                if (addToSitemap) {
                                    api.siteMap().add(result)
                                    addedToSitemap++
                                }
                                requestsSent++
                            }
                        } catch (_: Exception) {}
                    } else if (addToSitemap) {
                        try {
                            api.siteMap().add(
                                HttpRequestResponse.httpRequestResponse(httpRequest, HttpResponse.httpResponse())
                            )
                            addedToSitemap++
                        } catch (_: Exception) {}
                    }

                    endpoints.add(buildJsonObject {
                        put("method", method.uppercase())
                        put("path", fullPath)
                        put("operation_id", operationId)
                        put("summary", summary)
                        put("tags", buildJsonArray { tags.forEach { add(it) } })
                        put("query_params", queryParams.size)
                        put("has_body", body != null)
                        if (body != null) put("body_preview", body.take(200))
                    })
                }
            }

            buildJsonObject {
                put("spec_version", if (isOpenApi3) "OpenAPI 3.x" else if (isSwagger2) "Swagger 2.0" else "unknown")
                put("base_url", resolvedBaseUrl)
                put("total_endpoints", endpoints.size)
                put("requests_sent", requestsSent)
                put("skipped_out_of_scope", skippedOutOfScope)
                put("added_to_sitemap", addedToSitemap)
                put("added_to_scope", addToScope)
                put("endpoints", buildJsonArray { endpoints.forEach { add(it) } })
            }
        } catch (e: Exception) {
            buildJsonObject { put("error", "Failed to import OpenAPI spec: ${e.message}") }
        }
    }

    companion object {
        /**
         * Join a base path and an endpoint path, collapsing the boundary slash so a
         * basePath of "/" (or a servers[].url ending in "/") does not produce a
         * double-slash path. An empty result maps to "/".
         *
         *   joinPaths("/",     "/blog") == "/blog"
         *   joinPaths("/api",  "/blog") == "/api/blog"
         *   joinPaths("/api/", "/blog") == "/api/blog"
         *   joinPaths("/",     "/")     == "/"
         *   joinPaths("",      "/blog") == "/blog"
         *   joinPaths("/api",  "blog")  == "/api/blog"
         */
        internal fun joinPaths(basePath: String, path: String): String {
            val bp = basePath.trimEnd('/')
            val p = if (path.startsWith("/")) path else "/$path"
            val joined = bp + p
            return if (joined.isEmpty()) "/" else joined
        }

        /**
         * Validate a resolved base URL before any scope/sitemap mutation. Requires an
         * http/https scheme and a syntactically valid host (no spaces; must look like a
         * hostname/IP or "localhost"). Returns false for malformed input rather than
         * letting a bad host silently reach scope.
         */
        internal fun validateBaseUrl(url: String): Boolean {
            val lower = url.lowercase()
            if (!lower.startsWith("http://") && !lower.startsWith("https://")) return false
            val withoutScheme = url.removePrefix("https://").removePrefix("http://")
            if (withoutScheme.isEmpty()) return false

            val pathStart = withoutScheme.indexOf('/')
            val hostPort = if (pathStart >= 0) withoutScheme.substring(0, pathStart) else withoutScheme
            if (hostPort.isEmpty()) return false
            if (hostPort.any { it.isWhitespace() }) return false

            val host = if (hostPort.contains(':')) hostPort.substringBefore(':') else hostPort
            val portPart = if (hostPort.contains(':')) hostPort.substringAfter(':') else null
            if (host.isEmpty()) return false
            if (portPart != null && (portPart.isEmpty() || portPart.toIntOrNull() == null)) return false

            // Accept localhost, dotted hostnames/IPv4, or single-label hosts that
            // contain only valid hostname characters. Reject anything with spaces
            // or characters that can't appear in a host.
            if (host == "localhost") return true
            if (host.any { it.isWhitespace() }) return false
            val hostRegex = Regex("^[A-Za-z0-9._-]+$")
            if (!hostRegex.matches(host)) return false
            // Require a dot (FQDN / IPv4) OR a purely-numeric single label is rejected;
            // a bare single label like "notahost" without a dot is treated as invalid.
            return host.contains('.')
        }
    }

    private fun extractBaseUrl(spec: JsonObject, isOpenApi3: Boolean): String? {
        if (isOpenApi3) {
            val servers = spec["servers"]?.jsonArray
            return servers?.firstOrNull()?.jsonObject?.get("url")?.jsonPrimitive?.contentOrNull
        } else {
            // Swagger 2.0
            val host = spec["host"]?.jsonPrimitive?.contentOrNull ?: return null
            val basePath = spec["basePath"]?.jsonPrimitive?.contentOrNull ?: ""
            val schemes = spec["schemes"]?.jsonArray?.mapNotNull { it.jsonPrimitive.contentOrNull }
            val scheme = schemes?.firstOrNull { it == "https" } ?: schemes?.firstOrNull() ?: "https"
            return "$scheme://$host$basePath"
        }
    }

    private fun parseUrl(url: String): Map<String, String> {
        val result = mutableMapOf<String, String>()
        val withoutScheme = url.removePrefix("https://").removePrefix("http://")
        val pathStart = withoutScheme.indexOf('/')
        val hostPort = if (pathStart >= 0) withoutScheme.substring(0, pathStart) else withoutScheme
        val path = if (pathStart >= 0) withoutScheme.substring(pathStart) else ""

        if (hostPort.contains(':')) {
            result["host"] = hostPort.substringBefore(':')
            result["port"] = hostPort.substringAfter(':')
        } else {
            result["host"] = hostPort
        }
        result["path"] = path
        return result
    }

    private fun extractExample(param: JsonObject): String? {
        return param["example"]?.jsonPrimitive?.contentOrNull
            ?: param["schema"]?.jsonObject?.get("example")?.jsonPrimitive?.contentOrNull
            ?: param["schema"]?.jsonObject?.get("default")?.jsonPrimitive?.contentOrNull
    }

    private fun generateSampleValue(name: String, param: JsonObject): String {
        val schema = param["schema"]?.jsonObject
        val type = schema?.get("type")?.jsonPrimitive?.contentOrNull
            ?: param["type"]?.jsonPrimitive?.contentOrNull
        return when (type) {
            "integer", "number" -> "1"
            "boolean" -> "true"
            "array" -> "test"
            else -> "test"
        }
    }

    private fun generateJsonBody(schema: JsonObject?, refs: Map<String, JsonObject>): String {
        if (schema == null) return "{}"
        return try {
            OpenApiSchema.example(schema, refs).toString()
        } catch (_: Exception) { "{}" }
    }

    private fun generateFormBody(schema: JsonObject?, refs: Map<String, JsonObject>): String {
        if (schema == null) return ""
        val resolved = OpenApiSchema.deref(schema, refs)
        val properties = resolved["properties"]?.jsonObject ?: return ""
        return properties.entries.joinToString("&") { (name, propSchema) ->
            val value = (try { OpenApiSchema.example(propSchema.jsonObject, refs) } catch (_: Exception) { null }) as? JsonPrimitive
            "$name=${value?.contentOrNull ?: "test"}"
        }
    }
}
