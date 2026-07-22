package com.burpmcp.ultra.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpRequestResponse
import com.burpmcp.ultra.safety.RequestHygiene
import kotlinx.serialization.json.*

class OrganizerBridge(private val api: MontoyaApi) {

    /**
     * Sends a request (and optionally a response) to Burp Suite's Organizer
     * tool for bookmarking and note-taking.
     *
     * If [response] is provided, both request and response are sent as an
     * HttpRequestResponse pair. Otherwise only the request is sent.
     *
     * @param request Raw HTTP request string.
     * @param response Optional raw HTTP response string.
     * @param host Target hostname.
     * @param port Target port number.
     * @param useTls Whether the connection uses TLS.
     * @return JSON object confirming the item was sent to the Organizer.
     */
    fun send(
        request: String,
        response: String?,
        host: String,
        port: Int,
        useTls: Boolean
    ): JsonObject {
        val httpService = HttpService.httpService(host, port, useTls)
        val httpRequest = HttpRequest.httpRequest(httpService, RequestHygiene.normalizeCrlf(request))

        if (response != null) {
            val httpResponse = HttpResponse.httpResponse(response)
            val requestResponse = HttpRequestResponse.httpRequestResponse(httpRequest, httpResponse)
            api.organizer().sendToOrganizer(requestResponse)
        } else {
            api.organizer().sendToOrganizer(httpRequest)
        }

        return buildJsonObject {
            put("status", "sent_to_organizer")
            put("host", host)
            put("port", port)
            put("use_tls", useTls)
            put("has_response", response != null)
        }
    }

    /**
     * Retrieves items currently in the Organizer, with optional URL prefix
     * filtering and result limiting.
     *
     * The Montoya [burp.api.montoya.organizer.OrganizerItem] extends
     * [HttpRequestResponse], whose accessors ([HttpRequestResponse.url],
     * [HttpRequestResponse.httpService], ...) can throw or return `null`
     * depending on how the item was stored. Each field is therefore read
     * independently and defensively so that one unreadable accessor never
     * discards an otherwise-valid item (previously every item collapsed to
     * `{"error":"failed to read item details"}`).
     *
     * @param urlPrefix Optional substring to filter items by URL (case-insensitive).
     * @param maxResults Maximum number of items to return (default 100). Negative
     *   values are rejected with a clean error object rather than leaking the raw
     *   [IllegalArgumentException] thrown by [List.take].
     * @return JSON object containing the matching Organizer items.
     */
    fun getItems(urlPrefix: String?, maxResults: Int): JsonObject {
        if (maxResults < 0) {
            return buildJsonObject {
                put("error", "max_results must be non-negative (got $maxResults)")
            }
        }

        val allItems = api.organizer().items()

        val filtered = if (urlPrefix.isNullOrEmpty()) {
            allItems
        } else {
            allItems.filter { item -> matchesUrlFilter(safeUrl(item), urlPrefix) }
        }

        val limited = filtered.take(maxResults)

        return buildJsonObject {
            put("total_items", allItems.size)
            put("filtered_items", filtered.size)
            put("returned_items", limited.size)
            putJsonArray("items") {
                for (item in limited) {
                    addJsonObject {
                        // Read every field independently: a single failing accessor
                        // must not discard the whole item.
                        safeUrl(item)?.let { put("url", it) }
                        runCatching { item.request()?.method() }.getOrNull()?.let { put("method", it) }

                        val service = runCatching { item.httpService() }.getOrNull()
                        if (service != null) {
                            runCatching { service.host() }.getOrNull()?.let { put("host", it) }
                            runCatching { service.port() }.getOrNull()?.let { put("port", it) }
                            runCatching { service.secure() }.getOrNull()?.let { put("use_tls", it) }
                        }

                        val hasResponse = runCatching { item.hasResponse() }.getOrDefault(false)
                        if (hasResponse) {
                            val resp = runCatching { item.response() }.getOrNull()
                            if (resp != null) {
                                runCatching { resp.statusCode().toInt() }.getOrNull()?.let { put("status_code", it) }
                                runCatching { resp.body().length() }.getOrNull()?.let { put("response_length", it) }
                            }
                        }
                    }
                }
            }
        }
    }

    /**
     * Best-effort extraction of an item's URL. Returns `null` (instead of
     * throwing) when the underlying request has no associated service or the
     * accessor is otherwise unsupported for the stored item.
     */
    private fun safeUrl(item: HttpRequestResponse): String? =
        runCatching { item.url() }.getOrNull()
            ?: runCatching { item.request()?.url() }.getOrNull()

    companion object {
        /**
         * Case-insensitive substring match used for the `url_prefix` filter. A
         * `null` URL never matches; an empty/blank filter matches everything.
         * Pure — extracted so it can be unit-tested without a live Montoya API.
         */
        internal fun matchesUrlFilter(url: String?, filter: String?): Boolean {
            if (filter.isNullOrEmpty()) return true
            if (url == null) return false
            return url.contains(filter, ignoreCase = true)
        }

        /**
         * Clamps a caller-supplied result limit into a safe range. Negative
         * limits are invalid (callers should surface an error); this returns the
         * count actually applied by [List.take] for a given available size.
         * Pure — extracted for unit testing.
         */
        internal fun effectiveReturnCount(available: Int, maxResults: Int): Int {
            if (maxResults <= 0) return 0
            return minOf(available, maxResults)
        }
    }
}
