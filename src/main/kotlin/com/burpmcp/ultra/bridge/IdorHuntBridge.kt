package com.burpmcp.ultra.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import com.burpmcp.ultra.bridge.AnalysisBridge.Companion.normalizeCrlfMessage
import com.burpmcp.ultra.safety.BoundedHttp
import com.burpmcp.ultra.safety.ScopeGate
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

/**
 * The `idor_hunt` engine's live layer. Orchestrates the pure [IdorHunt] logic
 * against real HTTP:
 *
 *  1. **Identity diff** (reused, id held constant) — delegates to the vetted,
 *     scope-gated [AnalysisBridge.authDiff] for vertical / unauthenticated
 *     access-control coverage.
 *  2. **Canary matrix** (the flagship, id varied) — for every (reader, owner)
 *     pair it swaps the object id to the owner's resource, replays under the
 *     reader's identity, and asserts the owner's canary appears in the reader's
 *     response (a CONFIRMED horizontal IDOR), filtering own-data-reflection FPs.
 *  3. **Transform enumeration** (opt-in) — replays the §2 id-transformation set
 *     (neighbours, encodings, type-juggling) under the primary identity and
 *     reports 2xx candidates.
 *
 * Every send goes through the same [ScopeGate] and [BoundedHttp] the rest of the
 * extension uses, so `mcp_scope_mode=enforce` gates it and no send can hang.
 */
class IdorHuntBridge(private val api: MontoyaApi) {

    private val scopeGate = ScopeGate(api)
    private val analysis = AnalysisBridge(api)

    /** Hard ceiling on transform replays so an opt-in enumeration can't turn into a flood. */
    private val transformCap = 25

    fun hunt(
        request: String,
        host: String,
        port: Int,
        useTls: Boolean,
        identities: List<JsonObject>,
        idLocation: String?,
        idValue: String?,
        transforms: Boolean,
        enumerate: Int
    ): JsonObject {
        if (request.isBlank()) return err("Empty request: provide a raw HTTP request that identity A makes to A's own object.")
        if (identities.size < 2) return err("Provide 'identities' (>=2): e.g. two low-priv peers A and B, each with 'object_id' (a resource they own) and 'canary' (a string only in their own data). A 'none'/'unauth' identity is also useful.")

        val url = (if (useTls) "https" else "http") + "://$host:$port/"
        scopeGate.deny(url)?.let { return it }

        val base = normalizeCrlfMessage(request)
        val service = HttpService.httpService(host, port, useTls)

        // 1. Locate the object reference to swap.
        val ref = resolveRef(base, idLocation, idValue)

        // 2. Identity-only diff (vertical / unauth; object id held constant) — reuse the audited engine.
        val identityDiff = analysis.authDiff(request, host, port, useTls, identities, null)

        // 3. Canary matrix (horizontal object-id swap).
        val owners = identities.filter { str(it, "object_id") != null }
        val probes = mutableListOf<IdorHunt.CanaryProbe>()
        val replays = buildJsonArray {
            if (ref != null && owners.isNotEmpty()) {
                for (reader in identities) {
                    val readerName = str(reader, "name") ?: "reader"
                    val readerCanary = str(reader, "canary")
                    for (owner in owners) {
                        val ownerName = str(owner, "name") ?: "owner"
                        if (readerName.equals(ownerName, true)) continue
                        val ownerId = str(owner, "object_id") ?: continue
                        val swapped = IdorHunt.applySwap(base, ref, ownerId)
                        val (status, body) = sendAs(swapped, service, reader)
                        probes.add(
                            IdorHunt.CanaryProbe(
                                reader = readerName, owner = ownerName, targetId = ownerId,
                                status = status, body = body,
                                ownerCanary = str(owner, "canary"), readerCanary = readerCanary
                            )
                        )
                        add(buildJsonObject {
                            put("reader", readerName); put("owner", ownerName)
                            put("target_id", ownerId); put("status", status)
                            put("body_length", body.length)
                            put("owner_canary_present", str(owner, "canary")?.let { body.contains(it) } ?: false)
                            put("body_preview", body.take(300))
                        })
                    }
                }
            }
        }
        val canaryFindings = IdorHunt.assessCanary(probes)

        // 4. Optional transform / neighbour enumeration under the primary identity.
        val transformProbes = if (ref != null && (transforms || enumerate > 0)) {
            val cls = IdorHunt.classify(ref.value)
            val muts = IdorHunt.mutations(ref.value, cls, maxOf(enumerate, if (transforms) transformCap else 0))
                .take(minOf(transformCap, if (enumerate > 0) enumerate else transformCap))
            val reader = identities.first()
            buildJsonArray {
                for (m in muts) {
                    val swapped = IdorHunt.applySwap(base, ref, m.value)
                    val (status, body) = sendAs(swapped, service, reader)
                    add(buildJsonObject {
                        put("technique", m.technique); put("value", m.value)
                        put("status", status); put("body_length", body.length)
                        put("candidate", status in 200..299)
                    })
                }
            }
        } else JsonArray(emptyList())

        return buildJsonObject {
            put("target", url)
            put("object_ref", ref?.let {
                buildJsonObject {
                    put("location", it.location); put("name", it.name)
                    put("value", it.value); put("format", it.format.name)
                    put("classification", IdorHunt.classify(it.value).note)
                }
            } ?: JsonNull)
            put("identities_tested", identities.size)
            put("owners_with_object_id", owners.size)
            put("top_severity", IdorHunt.topSeverity(canaryFindings))
            put("horizontal_findings", buildJsonArray {
                canaryFindings.forEach { f ->
                    add(buildJsonObject { put("severity", f.severity); put("id", f.id); put("detail", f.detail) })
                }
            })
            put("horizontal_replays", replays)
            put("transform_probes", transformProbes)
            put("identity_diff", identityDiff)
            put("note", "horizontal_findings come from swapping the object id across identities and asserting the owner's canary (CONFIRMED cross-user read); identity_diff is the vertical/unauth check with the id held constant. Supply each identity's own 'object_id' + 'canary' to reach confirmed-grade precision.")
        }
    }

    /** Choose the reference to swap: explicit value/location if given, else the strongest auto-detected ref. */
    private fun resolveRef(base: String, idLocation: String?, idValue: String?): IdorHunt.ObjectRef? {
        val refs = IdorHunt.locateRefs(base)
        if (idValue != null) {
            refs.firstOrNull { it.value == idValue && (idLocation == null || it.location.equals(idLocation, true)) }?.let { return it }
            // fall back to a synthetic ref if the caller pinned a value we didn't auto-detect
            val loc = idLocation ?: refs.firstOrNull { it.value == idValue }?.location ?: "path"
            return IdorHunt.ObjectRef(loc, refs.firstOrNull { it.value == idValue }?.name ?: "id", idValue, IdorHunt.classify(idValue).format)
        }
        if (idLocation != null) refs.firstOrNull { it.location.equals(idLocation, true) }?.let { return it }
        // strongest by format confidence
        return refs.maxByOrNull { IdorHunt.classify(it.value).confidence }
    }

    /** Build the request under one identity's auth (mirrors authDiff), send it bounded, return status+body. */
    private fun sendAs(rawRequest: String, service: HttpService, identity: JsonObject): Pair<Int, String> {
        return try {
            var req = HttpRequest.httpRequest(service, rawRequest)
            val name = str(identity, "name") ?: "unknown"
            val hn = str(identity, "header_name")
            val hv = str(identity, "header_value")
            if (hn != null && hv != null) {
                req = req.withRemovedHeader(hn).withHeader(hn, hv)
            } else if (name.equals("none", true) || name.equals("unauth", true) || name.equals("anonymous", true)) {
                req = req.withRemovedHeader("Authorization").withRemovedHeader("Cookie")
                    .withRemovedHeader("X-API-Key").withRemovedHeader("X-Auth-Token")
            }
            val result = BoundedHttp.send(api, req)
            val resp = result?.response()
            (resp?.statusCode()?.toInt() ?: 0) to (resp?.bodyToString() ?: "")
        } catch (e: Exception) {
            0 to "error: ${AnalysisBridge.describeException(e)}"
        }
    }

    private fun str(o: JsonObject, key: String): String? = o[key]?.jsonPrimitive?.contentOrNull

    private fun err(msg: String): JsonObject = buildJsonObject { put("error", msg) }
}
