package com.burpmcp.ultra.safety

/**
 * Advisory input hygiene for `http_send_request`-style tools (GitHub issue #7).
 *
 * A raw CR/LF in the structured inputs an LLM fills is what makes Burp flag a request as
 * **"kettled"** (a header value — including the `:path` pseudo-header — that can't be represented in
 * HTTP/1), or silently retargets a request to `/` when the newline is in the URL (Java's `URI`
 * rejects it, so the builder falls back). LLMs frequently emit stray trailing/embedded newlines in
 * tool arguments, so this returns human-readable warnings that are surfaced in the tool result and
 * let the agent self-correct.
 *
 * It is **advisory only** — it never blocks. BurpMCP-Ultra is a security tool; sending CRLF on
 * purpose (request smuggling / header-injection research) is a legitimate use, so the decision stays
 * with the operator/agent. Pure + unit-tested. Uses [HeaderSafety.containsCrlf] for the primitive.
 */
object RequestHygiene {

    fun scan(method: String?, url: String?, headers: Map<String, String>?): List<String> {
        val out = mutableListOf<String>()

        if (method != null && HeaderSafety.containsCrlf(method)) {
            out += "method contains a raw CR/LF — the request line will be malformed."
        }
        if (url != null && HeaderSafety.containsCrlf(url)) {
            out += "url contains a raw newline (CR/LF); Burp's URL parser rejects it, so the request " +
                "would fall back to path \"/\" instead of the intended path — percent-encode it " +
                "(e.g. %0A) or remove the newline."
        }
        headers?.forEach { (name, value) ->
            if (HeaderSafety.containsCrlf(name)) {
                out += "a request header name contains a raw CR/LF — it will split the request."
            }
            if (HeaderSafety.containsCrlf(value)) {
                out += "header \"$name\" value contains a raw newline (CR/LF); Burp will flag the " +
                    "request as \"kettled\" (unrepresentable in HTTP/1) and it may split into extra " +
                    "headers — percent-encode or remove the newline."
            }
        }
        return out
    }
}
