package com.burpmcp.ultra.core

/**
 * Pure decision logic for `proxy_history_search`: maps a `search_in` value to which
 * parts of a history item should be scanned. Extracted from [ProxyBridge.searchHistory]
 * so it is unit-testable without Montoya.
 *
 * The original code only recognised "request"/"response"/"both"; any other value
 * (notably `search_in="url"`) set both flags false, scanned nothing, and silently
 * returned 0 matches. This adds first-class **url** scanning and makes unknown/blank
 * values fall back to scanning everything rather than nothing.
 */
object ProxyHistorySearch {

    /** Which parts of a history item to scan for the pattern. */
    data class Targets(val url: Boolean, val request: Boolean, val response: Boolean)

    fun targets(searchIn: String?): Targets = when (searchIn?.trim()?.lowercase()) {
        "url" -> Targets(url = true, request = false, response = false)
        "request" -> Targets(url = false, request = true, response = false)
        "response" -> Targets(url = false, request = false, response = true)
        // "both" / "all" / null / blank / anything unrecognised -> scan everything,
        // never silently match nothing.
        else -> Targets(url = true, request = true, response = true)
    }
}

/**
 * Pure decision logic for `proxy_history`'s `status_code_range` filter. Extracted from
 * [com.burpmcp.ultra.bridge.ProxyBridge.getHistory] so it is unit-testable without Montoya.
 *
 * The original code split the range inside the per-item filter and only honoured a
 * two-part `"min-max"` string; **any** other shape (a bare `"200"`, a triple `"1-2-3"`,
 * garbage like `"abc"`) fell through the `if (parts.size == 2)` guard and silently
 * dropped the filter, returning items that did not match the caller's intent. This
 * validates the range **once, up front** and reports a clear error for malformed input
 * instead of silently no-op'ing.
 */
object StatusCodeRange {

    /** An inclusive, validated status-code range. */
    data class Range(val min: Int, val max: Int) {
        fun contains(code: Int): Boolean = code in min..max
    }

    /** Result of parsing a caller-supplied `status_code_range`. */
    sealed interface Result {
        /** Input was `null`: no range filter requested. */
        object None : Result
        /** Input was a well-formed 1- or 2-bound range. */
        data class Ok(val range: Range) : Result
        /** Input was present but malformed; [message] is caller-facing. */
        data class Invalid(val message: String) : Result
    }

    /**
     * Parses and validates a `status_code_range` string.
     *
     * Accepts:
     *  - `"200-299"` — closed range
     *  - `"200-"` — open upper bound (defaults to 999)
     *  - `"-299"` — open lower bound (defaults to 0)
     *  - `"200"` — a bare single code, treated as the exact range `200..200`
     *
     * Rejects (returns [Result.Invalid]) anything else: empty string, `min > max`,
     * non-numeric bounds, or more than two dash-separated parts.
     */
    fun parse(input: String?): Result {
        if (input == null) return Result.None
        val trimmed = input.trim()
        if (trimmed.isEmpty()) {
            return Result.Invalid(
                "Invalid status_code_range: ''. Use 'min-max' (e.g. 200-299), " +
                    "open-ended '200-' or '-299', or a single code '200'."
            )
        }
        val parts = trimmed.split("-")
        return when {
            parts.size == 2 -> {
                val minRaw = parts[0].trim()
                val maxRaw = parts[1].trim()
                // Reject "-" (both bounds blank) — it carries no filtering intent.
                if (minRaw.isEmpty() && maxRaw.isEmpty()) {
                    return Result.Invalid(
                        "Invalid status_code_range: '$input'. At least one bound is required, " +
                            "e.g. '200-299', '200-', or '-299'."
                    )
                }
                val min = if (minRaw.isEmpty()) 0 else minRaw.toIntOrNull()
                    ?: return Result.Invalid("Invalid status_code_range: '$input'. Lower bound '$minRaw' is not a number.")
                val max = if (maxRaw.isEmpty()) 999 else maxRaw.toIntOrNull()
                    ?: return Result.Invalid("Invalid status_code_range: '$input'. Upper bound '$maxRaw' is not a number.")
                if (min > max) {
                    Result.Invalid("Invalid status_code_range: min ($min) > max ($max)")
                } else {
                    Result.Ok(Range(min, max))
                }
            }
            // Bare single value "200" — treat as an exact match, not a silent pass.
            parts.size == 1 -> {
                val v = parts[0].trim().toIntOrNull()
                    ?: return Result.Invalid(
                        "Invalid status_code_range: '$input'. Use 'min-max' (e.g. 200-299), " +
                            "open-ended '200-' or '-299', or a single code '200'."
                    )
                Result.Ok(Range(v, v))
            }
            else -> Result.Invalid(
                "Invalid status_code_range: '$input'. Use 'min-max' (e.g. 200-299), " +
                    "open-ended '200-' or '-299', or a single code '200'."
            )
        }
    }
}

/**
 * Pure decision logic for `proxy_annotate`'s `highlight` argument. Extracted from
 * [com.burpmcp.ultra.bridge.ProxyBridge.annotateHistoryItem] so it is unit-testable
 * without Montoya.
 *
 * Montoya's `HighlightColor.highlightColor(name)` factory does NOT throw on an unknown
 * name — it returns `HighlightColor.NONE`. The original annotate code trusted that
 * factory, so a bogus colour (e.g. `"purple"`) resolved to `NONE`, `setHighlightColor(NONE)`
 * **cleared** any existing highlight, and the tool still reported `annotated: true` with the
 * bogus colour echoed back. This validates the name against the real colour constants first
 * so an invalid colour is a clean error instead of a silent clear + false success.
 */
object HighlightColorName {

    /** The colour constants a caller may actually set (all Montoya colours except NONE). */
    private val COLORS = setOf(
        "RED", "ORANGE", "YELLOW", "GREEN", "CYAN", "BLUE", "PINK", "MAGENTA", "GRAY"
    )

    /** All accepted names, including "NONE" which explicitly clears the highlight. */
    private val ACCEPTED = COLORS + "NONE"

    /** True when [name] is a recognised highlight colour (or the explicit "NONE" clear). */
    fun isValid(name: String?): Boolean {
        val n = name?.trim()?.uppercase() ?: return false
        return n in ACCEPTED
    }

    /** Normalises a valid name to its canonical uppercase constant, or null if invalid. */
    fun canonical(name: String?): String? {
        val n = name?.trim()?.uppercase() ?: return null
        return if (n in ACCEPTED) n else null
    }

    /** A caller-facing hint listing the valid colour names. */
    fun validValues(): String =
        (COLORS.sorted() + "NONE (clears the highlight)").joinToString(", ")
}
