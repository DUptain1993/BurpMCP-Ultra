package com.burpmcp.ultra.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.bambda.BambdaImportResult
import kotlinx.serialization.json.*

/**
 * Bridge wrapping the Montoya Bambda API.
 *
 * Bambda expressions are Java-like lambda expressions that can be used
 * to customize Burp Suite's behavior (e.g., proxy history filters,
 * HTTP match-and-replace rules).
 */
class BambdaBridge(private val api: MontoyaApi) {

    /**
     * Imports a Bambda script into Burp Suite.
     *
     * The script is a Java lambda expression string that Burp Suite will
     * compile and execute in the appropriate context.
     *
     * Burp reports the outcome via [BambdaImportResult]; a script that fails
     * to compile is returned with status [BambdaImportResult.Status.LOADED_WITH_ERRORS]
     * rather than by throwing. Callers must consume that result — discarding it
     * makes a compile failure look like a success.
     *
     * @param script The Bambda script content (Java lambda expression).
     * @return JSON object confirming the import or reporting an error.
     */
    fun importBambda(script: String): JsonObject {
        return try {
            val result = api.bambda().importBambda(script)
            buildImportResponse(
                loadedWithErrors = result.status() == BambdaImportResult.Status.LOADED_WITH_ERRORS,
                errors = result.importErrors(),
                scriptLength = script.length
            )
        } catch (e: UnsupportedOperationException) {
            buildJsonObject {
                put("error", "Bambda API is not available in this version of Burp Suite")
                put("available", false)
            }
        } catch (e: Exception) {
            buildJsonObject {
                put("error", "Failed to import Bambda: ${e.message}")
                put("script_length", script.length)
            }
        }
    }

    companion object {
        /**
         * Pure mapping from a Bambda import outcome to the tool response JSON.
         *
         * Extracted so the success/error branching can be unit-tested without a
         * live Burp instance (the Montoya API is compileOnly here).
         *
         * @param loadedWithErrors true when Burp reported LOADED_WITH_ERRORS
         *   (the script was accepted but failed to compile cleanly).
         * @param errors compile/import diagnostics from Burp, if any.
         * @param scriptLength length of the submitted script.
         */
        internal fun buildImportResponse(
            loadedWithErrors: Boolean,
            errors: List<String>,
            scriptLength: Int
        ): JsonObject = buildJsonObject {
            put("status", if (loadedWithErrors) "imported_with_errors" else "imported")
            put("script_length", scriptLength)
            if (errors.isNotEmpty()) {
                put("import_errors", buildJsonArray { errors.forEach { add(it) } })
            }
        }
    }
}
