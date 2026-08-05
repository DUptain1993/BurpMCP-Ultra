package com.burpmcp.ultra.transport

/**
 * Resolution and conflict diagnostics for the three listening ports.
 *
 * The ports used to be hardcoded, which made one failure mode unfixable and misdiagnosed:
 * **PortSwigger's own "MCP Server" extension also defaults to 9876**, so anyone running both
 * extensions has an unavoidable clash — and the only message they got blamed "a JAR built with
 * Java 22+", sending them down entirely the wrong path (the likely story behind GitHub issue #9).
 *
 * Ports are therefore operator-configurable on the same ladder as the bind host — JVM system
 * property (ops override), else a persisted Burp preference, else the default — and a bind onto an
 * occupied port now says what is actually wrong and how to fix it.
 */
object PortPolicy {

    const val DEFAULT_SSE = 9876
    const val DEFAULT_HTTP = 9877
    const val DEFAULT_DASHBOARD = 9878

    /** The port PortSwigger's official MCP Server extension listens on by default. */
    const val PORTSWIGGER_MCP_DEFAULT_PORT = 9876

    const val PREF_SSE_PORT = "mcp_sse_port"
    const val PREF_HTTP_PORT = "mcp_http_port"
    const val PREF_DASHBOARD_PORT = "mcp_dashboard_port"

    /**
     * Resolves a port from [systemProperty] (highest precedence), else [preference], else [default].
     *
     * Anything unparseable or outside 1..65535 is ignored in favour of the next source, so a typo
     * in a preference degrades to the default instead of failing the extension to start.
     */
    fun resolve(systemProperty: String?, preference: String?, default: Int): Int =
        parse(systemProperty) ?: parse(preference) ?: default

    private fun parse(raw: String?): Int? {
        val n = raw?.trim()?.toIntOrNull() ?: return null
        return if (n in 1..65535) n else null
    }

    /**
     * The message logged when [port] is already taken, naming the causes an operator can actually
     * act on. [prefKey] is the preference that changes this particular port.
     */
    fun conflictMessage(label: String, host: String, port: Int, prefKey: String): String {
        val causes = mutableListOf<String>()
        if (port == PORTSWIGGER_MCP_DEFAULT_PORT) {
            causes += "PortSwigger's own \"MCP Server\" extension listens on $PORTSWIGGER_MCP_DEFAULT_PORT by default — " +
                "if it is installed, disable one of the two extensions or move this one to a free port"
        }
        causes += "a previous BurpMCP-Ultra instance may still hold the socket — fully restart Burp (an extension reload is not always enough)"
        causes += "another application may own the port — check with: ss -ltnp | grep $port"

        return buildString {
            append("BurpMCP-Ultra: $label cannot start — $host:$port is ALREADY IN USE. ")
            append("This is NOT the Java-version problem; the port is simply taken. Likely causes: ")
            causes.forEachIndexed { i, c -> append("(${i + 1}) $c. ") }
            append("Change the port with the '$prefKey' preference and reload the extension.")
        }
    }
}
