package com.burpmcp.ultra.safety

/**
 * Input hygiene for `http_send_request`-style tools (GitHub issue #7).
 *
 * A raw CR/LF in a structured input (method, url, header) — commonly a stray newline emitted by an
 * LLM — reaches the HTTP/2 `:path` pseudo-header or splits a header, so Burp flags the request as
 * **"kettled"** and the server rejects it (`RST_STREAM` PROTOCOL_ERROR). [stripControl] removes those
 * control chars before the request is built (the actual fix), and [scan] reports what was cleaned so
 * the agent can self-correct.
 *
 * Only the STRUCTURED build path is sanitized; `raw_request` / `http_send_raw_bytes` stay verbatim so
 * intentional CRLF (request-smuggling / header-injection research) remains possible. Pure + tested.
 */
object RequestHygiene {

    /**
     * Removes raw CR/LF and other C0 control chars (tab excepted) from [s]. A stray newline in an
     * LLM-supplied url/method/header would otherwise land in the HTTP/2 `:path` or split a header and
     * get the request kettled / `RST_STREAM`'d. Keeps everything printable (code >= 32) plus tab.
     */
    fun stripControl(s: String): String {
        if (s.none { it != '\t' && it.code < 32 }) return s   // clean → no allocation
        return buildString(s.length) { for (ch in s) if (ch == '\t' || ch.code >= 32) append(ch) }
    }

    /** Advisory: reports raw CR/LF found (and removed by [stripControl]) so the agent notices. */
    fun scan(method: String?, url: String?, headers: Map<String, String>?): List<String> {
        val out = mutableListOf<String>()

        if (method != null && HeaderSafety.containsCrlf(method)) {
            out += "a raw CR/LF was removed from the request method before sending."
        }
        if (url != null && HeaderSafety.containsCrlf(url)) {
            out += "a raw newline was removed from the url before sending — it would otherwise reach " +
                "the HTTP/2 :path and get the request kettled/rejected. Percent-encode it (%0A) if intended."
        }
        headers?.forEach { (name, value) ->
            if (HeaderSafety.containsCrlf(name)) {
                out += "a raw CR/LF was removed from a request header name before sending."
            }
            if (HeaderSafety.containsCrlf(value)) {
                out += "a raw newline was removed from header \"$name\" before sending — it would " +
                    "otherwise kettle the request or split headers. Percent-encode it (%0A) if intended."
            }
        }
        return out
    }
}
