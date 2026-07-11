package com.burpmcp.ultra.graphql

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class GraphQlTest {

    private fun obj(s: String) = Json.parseToJsonElement(s).jsonObject

    @Test
    fun `summarize reports introspection disabled when no schema`() {
        val s = GraphQl.summarize(obj("""{"data":{}}"""))
        assertFalse(s["introspection_enabled"]!!.jsonPrimitive.boolean)
    }

    @Test
    fun `summarize extracts query and mutation fields`() {
        val intro = obj(
            """{"data":{"__schema":{
               "queryType":{"name":"Query"},
               "mutationType":{"name":"Mutation"},
               "types":[
                 {"name":"Query","fields":[{"name":"users"},{"name":"me"}]},
                 {"name":"Mutation","fields":[{"name":"login"},{"name":"deleteUser"}]}
               ]}}}"""
        )
        val s = GraphQl.summarize(intro)
        assertTrue(s["introspection_enabled"]!!.jsonPrimitive.boolean)
        assertEquals("Query", s["query_type"]?.jsonPrimitive?.contentOrNull)
        val qf = s["query_fields"]!!.jsonArray.map { it.jsonPrimitive.content }
        val mf = s["mutation_fields"]!!.jsonArray.map { it.jsonPrimitive.content }
        assertTrue("users" in qf && "me" in qf)
        assertTrue("login" in mf && "deleteUser" in mf)
    }

    @Test
    fun `summarize handles null mutation and subscription root types`() {
        // Rick and Morty / Countries shape: introspection enabled but no mutation/subscription root.
        val intro = obj(
            """{"data":{"__schema":{
               "queryType":{"name":"Query"},
               "mutationType":null,
               "subscriptionType":null,
               "types":[
                 {"name":"Query","fields":[{"name":"characters"},{"name":"episodes"}]}
               ]}}}"""
        )
        val s = GraphQl.summarize(intro)
        assertTrue(s["introspection_enabled"]!!.jsonPrimitive.boolean)
        assertEquals("Query", s["query_type"]?.jsonPrimitive?.contentOrNull)
        // Null mutation root must not crash and must yield no fields.
        assertTrue(s["mutation_type"] is kotlinx.serialization.json.JsonNull)
        assertTrue(s["mutation_fields"]!!.jsonArray.isEmpty())
        // Absent subscription is omitted from the summary entirely.
        assertFalse("subscription_type" in s)
        val qf = s["query_fields"]!!.jsonArray.map { it.jsonPrimitive.content }
        assertTrue("characters" in qf && "episodes" in qf)
    }

    @Test
    fun `summarize treats error-only response as introspection disabled`() {
        // Some endpoints return {"data":null,"errors":[...]}; data=null must not crash.
        val s = GraphQl.summarize(obj("""{"data":null,"errors":[{"message":"nope"}]}"""))
        assertFalse(s["introspection_enabled"]!!.jsonPrimitive.boolean)
    }

    @Test
    fun `extractSuggestions pulls did-you-mean field names`() {
        val msg = """Cannot query field "usr" on type "Query". Did you mean "users" or "user"?"""
        assertEquals(listOf("users", "user"), GraphQl.extractSuggestions(msg))
    }

    @Test
    fun `extractSuggestions returns empty when none`() {
        assertTrue(GraphQl.extractSuggestions("Syntax Error: Unexpected end of input").isEmpty())
    }
}
