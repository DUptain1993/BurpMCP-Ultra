package com.burpmcp.ultra.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.HttpService
import com.burpmcp.ultra.safety.RequestHygiene
import kotlinx.serialization.json.*

class RepeaterBridge(private val api: MontoyaApi) {

    fun sendToRepeater(request: String, host: String, port: Int, useTls: Boolean, tabName: String?): JsonObject {
        val httpService = HttpService.httpService(host, port, useTls)
        // Normalize line endings so a bare-LF request doesn't fold into the HTTP/2
        // :path and land in Repeater "kettled" and unsendable (issue #7 request-line variant).
        val httpRequest = HttpRequest.httpRequest(httpService, RequestHygiene.normalizeCrlf(request))

        if (tabName != null) {
            api.repeater().sendToRepeater(httpRequest, tabName)
        } else {
            api.repeater().sendToRepeater(httpRequest)
        }

        return buildJsonObject {
            put("tab_name", tabName ?: "auto")
            put("status", "created")
            put("host", host)
            put("port", port)
            put("use_tls", useTls)
        }
    }
}
