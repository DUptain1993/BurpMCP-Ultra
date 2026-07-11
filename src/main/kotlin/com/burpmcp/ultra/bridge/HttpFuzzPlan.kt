package com.burpmcp.ultra.bridge

/**
 * Pure, Montoya-free planning logic for [HttpBridge.fuzz].
 *
 * Extracted so the injection-point resolution (FUZZ keyword, marker pairs, legacy
 * offset positions) and its validation can be unit-tested without a live Burp API.
 *
 * Fixes three defects that lived in the inline fuzz body:
 *  1. Custom multi-character markers were detected with a first-character-only heuristic
 *     (`count { it == marker[0] }`), so a marker like `[[` or `MARK` could silently fail
 *     to register any injection points (no-op).
 *  2. Reversed / out-of-bounds offset pairs (`start > end`, negatives, past end-of-string)
 *     produced corrupted requests or threw StringIndexOutOfBoundsException. They are now
 *     validated up front and rejected with an actionable message.
 *  3. Astral / multi-byte payloads: planning stays at the String level and the caller
 *     (HttpBridge) encodes the final request with an explicit UTF-8 charset so surrogate
 *     pairs survive — the old path handed the String straight to Montoya's String overload.
 */
internal object HttpFuzzPlan {

    /** A single request to send: the fully-substituted request text plus reporting metadata. */
    data class PlannedRequest(val request: String, val payload: String, val position: Int)

    /** Result of planning: either a list of requests to send (with the mode label) or an error. */
    sealed class Result {
        data class Ok(val mode: String, val requests: List<PlannedRequest>) : Result()
        data class Error(val message: String) : Result()
    }

    /**
     * Builds the list of concrete requests to send for a fuzz run.
     *
     * @param baseRequest CRLF-normalized base request text.
     * @param positions optional legacy [start,end) offset pairs (UTF-16 indices).
     * @param payloads payload strings to inject (already merged with any library set).
     * @param marker optional custom marker string; defaults to `§`.
     */
    fun plan(
        baseRequest: String,
        positions: List<Pair<Int, Int>>?,
        payloads: List<String>,
        marker: String?
    ): Result {
        // A blank marker would match everywhere and count infinitely; treat it as "use default".
        val effectiveMarker = marker?.takeIf { it.isNotEmpty() } ?: "§" // §
        val hasFuzzKeyword = baseRequest.contains("FUZZ")
        // Count occurrences of the WHOLE marker string, not just its first char, so multi-char
        // custom markers (e.g. "MARK", "[[") are detected correctly. Need >= 2 to form a pair.
        val markerCount = countOccurrences(baseRequest, effectiveMarker)
        val hasMarkerPairs = markerCount >= 2

        return when {
            // Mode 1: FUZZ keyword — replace every occurrence of "FUZZ" with each payload.
            hasFuzzKeyword && !hasMarkerPairs -> {
                Result.Ok(
                    "fuzz_keyword",
                    payloads.map { payload ->
                        PlannedRequest(baseRequest.replace("FUZZ", payload), payload, 0)
                    }
                )
            }

            // Mode 2: Marker pairs — find marker…marker pairs, replace each with payloads (sniper).
            hasMarkerPairs -> {
                val markerPositions = findMarkerPairs(baseRequest, effectiveMarker)
                if (markerPositions.isEmpty()) {
                    return Result.Error(
                        "Found marker '$effectiveMarker' but could not pair it into injection points. " +
                            "Wrap each value with an opening and closing marker, e.g. ${effectiveMarker}value${effectiveMarker}."
                    )
                }
                val out = ArrayList<PlannedRequest>(payloads.size * markerPositions.size)
                for (payload in payloads) {
                    for ((posIdx, pos) in markerPositions.withIndex()) {
                        val (start, end) = pos
                        out.add(
                            PlannedRequest(
                                baseRequest.substring(0, start) + payload + baseRequest.substring(end),
                                payload,
                                posIdx
                            )
                        )
                    }
                }
                Result.Ok("marker_pairs", out)
            }

            // Mode 3: Legacy offset-based positions.
            positions != null && positions.isNotEmpty() -> {
                validatePositions(positions, baseRequest.length)?.let { return Result.Error(it) }
                val out = ArrayList<PlannedRequest>(payloads.size * positions.size)
                for (payload in payloads) {
                    for ((posIdx, pos) in positions.withIndex()) {
                        val (start, end) = pos
                        out.add(
                            PlannedRequest(
                                baseRequest.substring(0, start) + payload + baseRequest.substring(end),
                                payload,
                                posIdx
                            )
                        )
                    }
                }
                Result.Ok("offset", out)
            }

            else -> Result.Error(
                "No injection points found. Use FUZZ keyword, ${effectiveMarker}marker${effectiveMarker} pairs, or a positions array."
            )
        }
    }

    /** Counts non-overlapping occurrences of [needle] in [haystack]. Empty needle yields 0. */
    fun countOccurrences(haystack: String, needle: String): Int {
        if (needle.isEmpty()) return 0
        var count = 0
        var idx = haystack.indexOf(needle)
        while (idx >= 0) {
            count++
            idx = haystack.indexOf(needle, idx + needle.length)
        }
        return count
    }

    /**
     * Finds [start, end) pairs delimiting each `marker…marker` region (end is exclusive and
     * includes the closing marker so the whole `§value§` span is replaced by the payload).
     */
    fun findMarkerPairs(baseRequest: String, marker: String): List<Pair<Int, Int>> {
        val positions = mutableListOf<Pair<Int, Int>>()
        var searchFrom = 0
        while (true) {
            val openIdx = baseRequest.indexOf(marker, searchFrom)
            if (openIdx < 0) break
            val closeIdx = baseRequest.indexOf(marker, openIdx + marker.length)
            if (closeIdx < 0) break
            positions.add(openIdx to (closeIdx + marker.length))
            searchFrom = closeIdx + marker.length
        }
        return positions
    }

    /**
     * Validates legacy offset pairs against [length]. Returns an error message describing the
     * first bad pair, or null when every pair is in-bounds and non-reversed.
     */
    fun validatePositions(positions: List<Pair<Int, Int>>, length: Int): String? {
        positions.forEachIndexed { i, (start, end) ->
            if (start < 0 || end < 0) {
                return "positions[$i] = [$start, $end] is invalid: offsets must be non-negative."
            }
            if (start > end) {
                return "positions[$i] = [$start, $end] is invalid: start ($start) must be <= end ($end). " +
                    "Offsets are [start, end) into the request string."
            }
            if (end > length) {
                return "positions[$i] = [$start, $end] is out of bounds: end ($end) exceeds request length ($length)."
            }
        }
        return null
    }
}
