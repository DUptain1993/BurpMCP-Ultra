package com.burpmcp.ultra.bridge

import java.net.URI
import java.nio.charset.Charset

/**
 * Pure wire-encoding helpers for Content-Length on structured HTTP requests (C7).
 *
 * Burp transmits request bodies as UTF-8; sizing with Latin-1 produced CL drift on
 * multi-byte bodies (the "status_code:0 ghost" class). [sendRawBytes] stays
 * ISO-8859-1 by design (byte-exact). Testable without Montoya.
 */
internal object HttpWireEncoding {
    val WIRE_CHARSET: Charset = Charsets.UTF_8

    fun bodyByteLength(body: String): Int = body.toByteArray(WIRE_CHARSET).size

    /**
     * Constructs a complete raw HTTP/1.1 request from structured parameters.
     * Auto-adds Host and Content-Length only if missing; CL uses [WIRE_CHARSET].
     */
    fun constructRawHttpRequest(
        url: String,
        method: String,
        headers: Map<String, String>,
        body: String?,
        host: String,
        port: Int,
        tls: Boolean
    ): String {
        val uri = try { URI(url) } catch (_: Exception) { null }
        val pathPart = uri?.rawPath?.ifEmpty { "/" } ?: "/"
        val queryPart = uri?.rawQuery?.let { "?$it" } ?: ""
        val requestTarget = "$pathPart$queryPart"

        val isDefaultPort = (tls && port == 443) || (!tls && port == 80)
        val hostHeader = if (isDefaultPort) host else "$host:$port"

        val sb = StringBuilder()
        sb.append("$method $requestTarget HTTP/1.1\r\n")

        val hasHost = headers.keys.any { it.equals("Host", ignoreCase = true) }
        if (!hasHost) sb.append("Host: $hostHeader\r\n")

        headers.forEach { (k, v) -> sb.append("$k: $v\r\n") }

        val hasContentLength = headers.keys.any { it.equals("Content-Length", ignoreCase = true) }
        val hasTransferEncoding = headers.keys.any { it.equals("Transfer-Encoding", ignoreCase = true) }
        if (body != null && !hasContentLength && !hasTransferEncoding) {
            sb.append("Content-Length: ${bodyByteLength(body)}\r\n")
        }

        sb.append("\r\n")
        if (body != null) sb.append(body)

        return sb.toString()
    }

    /**
     * Recomputes Content-Length to match the actual body size in [WIRE_CHARSET] bytes.
     * Returns the original request unchanged if there is no body section or no CL header.
     */
    fun fixContentLength(rawRequest: String): String {
        val boundary = rawRequest.indexOf("\r\n\r\n")
        if (boundary < 0) return rawRequest

        val headerSection = rawRequest.substring(0, boundary)
        val bodySection = rawRequest.substring(boundary + 4)

        val clRegex = Regex("(?im)^Content-Length:\\s*(\\d+)\\s*$")
        val clMatch = clRegex.find(headerSection) ?: return rawRequest

        val declaredLength = clMatch.groupValues[1].toIntOrNull() ?: return rawRequest
        val actualLength = bodyByteLength(bodySection)
        if (declaredLength == actualLength) return rawRequest

        val fixedHeader = clRegex.replaceFirst(headerSection, "Content-Length: $actualLength")
        return "$fixedHeader\r\n\r\n$bodySection"
    }
}
