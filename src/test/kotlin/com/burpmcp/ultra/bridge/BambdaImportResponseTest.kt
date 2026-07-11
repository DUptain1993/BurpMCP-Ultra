package com.burpmcp.ultra.bridge

import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Tests the pure outcome-mapping helper that BambdaBridge.importBambda uses.
 *
 * Regression for BUG #22: importBambda previously discarded Burp's
 * BambdaImportResult and always reported "imported", so a script that failed
 * to compile (LOADED_WITH_ERRORS) looked like a success.
 */
class BambdaImportResponseTest {

    @Test
    fun `clean load reports imported with no import_errors key`() {
        val r = BambdaBridge.buildImportResponse(
            loadedWithErrors = false,
            errors = emptyList(),
            scriptLength = 42
        )
        assertEquals("imported", r["status"]?.jsonPrimitive?.content)
        assertEquals(42, r["script_length"]?.jsonPrimitive?.content?.toInt())
        assertFalse(r.containsKey("import_errors"))
    }

    @Test
    fun `a failed compile reports imported_with_errors, not a false success`() {
        val r = BambdaBridge.buildImportResponse(
            loadedWithErrors = true,
            errors = listOf("line 1: cannot find symbol"),
            scriptLength = 10
        )
        assertEquals("imported_with_errors", r["status"]?.jsonPrimitive?.content)
        assertTrue(r.containsKey("import_errors"))
        val errs = r["import_errors"]!!.jsonArray
        assertEquals(1, errs.size)
        assertEquals("line 1: cannot find symbol", errs[0].jsonPrimitive.content)
    }

    @Test
    fun `all import errors are preserved in order`() {
        val r = BambdaBridge.buildImportResponse(
            loadedWithErrors = true,
            errors = listOf("err-a", "err-b", "err-c"),
            scriptLength = 5
        )
        val errs = r["import_errors"]!!.jsonArray
        assertEquals(listOf("err-a", "err-b", "err-c"), errs.map { it.jsonPrimitive.content })
    }

    @Test
    fun `a clean load that still carries diagnostics still stays imported`() {
        // status drives success; errors list is informational only.
        val r = BambdaBridge.buildImportResponse(
            loadedWithErrors = false,
            errors = listOf("warning: unused var"),
            scriptLength = 3
        )
        assertEquals("imported", r["status"]?.jsonPrimitive?.content)
        assertEquals(1, r["import_errors"]!!.jsonArray.size)
    }

    @Test
    fun `no error key is emitted for successful imports`() {
        val r = BambdaBridge.buildImportResponse(
            loadedWithErrors = false,
            errors = emptyList(),
            scriptLength = 1
        )
        assertNull(r["error"])
    }
}
