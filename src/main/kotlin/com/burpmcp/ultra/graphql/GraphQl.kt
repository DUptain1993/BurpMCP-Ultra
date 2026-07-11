package com.burpmcp.ultra.graphql

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

/**
 * Pure GraphQL recon helpers: a compact introspection query, a summarizer for
 * the introspection response, and "Did you mean" field-suggestion extraction
 * (schema enumeration even when introspection is disabled).
 */
object GraphQl {

    /** Compact introspection query — enough to enumerate root query/mutation fields. */
    const val INTROSPECTION_QUERY =
        "query IntrospectionQuery { __schema { queryType { name } mutationType { name } " +
            "subscriptionType { name } types { name fields { name } } } }"

    private val didYouMean = Regex("""Did you mean ([^?]+)\??""")
    private val quoted = Regex(""""([^"]+)"""")

    /** Summarizes an introspection response (`{data:{__schema:...}}`) into root types + field names. */
    fun summarize(json: JsonObject): JsonObject {
        // `as? JsonObject` returns null for JsonNull (and any non-object), so error-only or
        // null-valued responses short-circuit cleanly instead of crashing on `.jsonObject`.
        val schema = (json["data"] as? JsonObject)?.get("__schema") as? JsonObject
            ?: return buildJsonObject { put("introspection_enabled", false) }

        val types = (schema["types"] as? JsonArray) ?: JsonArray(emptyList())
        fun fieldsOf(typeName: String?): List<String> {
            if (typeName == null) return emptyList()
            val t = types.firstOrNull {
                (it as? JsonObject)?.get("name")?.jsonPrimitive?.contentOrNull == typeName
            } as? JsonObject
            return (t?.get("fields") as? JsonArray)
                ?.mapNotNull { (it as? JsonObject)?.get("name")?.jsonPrimitive?.contentOrNull }
                ?: emptyList()
        }

        // Root types may legitimately be JSON null (schemas without a mutation/subscription root,
        // e.g. Rick and Morty / Countries). `as? JsonObject` filters JsonNull safely.
        val queryType = (schema["queryType"] as? JsonObject)?.get("name")?.jsonPrimitive?.contentOrNull
        val mutationType = (schema["mutationType"] as? JsonObject)?.get("name")?.jsonPrimitive?.contentOrNull
        val subscriptionType = (schema["subscriptionType"] as? JsonObject)?.get("name")?.jsonPrimitive?.contentOrNull

        return buildJsonObject {
            put("introspection_enabled", true)
            put("type_count", types.size)
            put("query_type", queryType)
            put("mutation_type", mutationType)
            if (subscriptionType != null) put("subscription_type", subscriptionType)
            put("query_fields", buildJsonArray { fieldsOf(queryType).forEach { add(it) } })
            put("mutation_fields", buildJsonArray { fieldsOf(mutationType).forEach { add(it) } })
        }
    }

    /** Extracts suggested field names from a "Did you mean ..." GraphQL error message (decoded). */
    fun extractSuggestions(decodedMessage: String): List<String> {
        val out = linkedSetOf<String>()
        didYouMean.findAll(decodedMessage).forEach { m ->
            quoted.findAll(m.groupValues[1]).forEach { out.add(it.groupValues[1]) }
        }
        return out.toList()
    }
}
