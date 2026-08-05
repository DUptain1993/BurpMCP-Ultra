package com.burpmcp.ultra.core

import java.net.URI

/**
 * Pure derivation of the (host, port, TLS) triple an `HttpService` needs, from a target URL.
 *
 * Evidence attached to a custom issue must be built on a request that carries an `HttpService`:
 * a service-less request has no host for Montoya to resolve, and filing such an issue into the
 * site map throws a `NullPointerException` deep inside Burp (GitHub PR #13, reported and diagnosed
 * by **@aconstantinou-cmd**). Both `sitemap_add_issue` and `scanner_create_issue` therefore derive
 * the service from the issue's own `url`.
 *
 * That derivation lived twice — copy-pasted into each bridge, with the two copies disagreeing on
 * how a malformed URL was reported. It is centralised here so the rule is stated once, fails the
 * same way everywhere, and is unit-testable without a live Montoya API (which is `compileOnly`).
 */
object ServiceParts {

    /** @param host never blank; @param port already defaulted from the scheme when absent. */
    data class Parts(val host: String, val port: Int, val useTls: Boolean)

    /**
     * Parses [url] into the parts of an `HttpService`.
     *
     * Defaults follow the scheme: anything that is not explicitly `http` is treated as TLS (443),
     * plain `http` as 80. An explicit port always wins.
     *
     * @param what a short label for the value being parsed, used in error messages so the caller
     *   knows *which* input was bad.
     * @throws IllegalArgumentException with an actionable message when [url] is unparseable or
     *   carries no host — never a raw `URISyntaxException` or a `NullPointerException`.
     */
    fun fromUrl(url: String, what: String = "url"): Parts {
        val parsed = try {
            URI(url)
        } catch (e: Exception) {
            throw IllegalArgumentException(
                "Could not parse $what '$url' to derive host/port: ${e.message}. " +
                    "Provide an absolute URL such as https://example.com/path."
            )
        }
        val host = parsed.host
            ?: throw IllegalArgumentException(
                "Could not determine a host from $what '$url'. " +
                    "Provide an absolute URL including the scheme, such as https://example.com/path."
            )
        val useTls = !"http".equals(parsed.scheme, ignoreCase = true)
        val port = if (parsed.port != -1) parsed.port else if (useTls) 443 else 80
        return Parts(host, port, useTls)
    }
}
