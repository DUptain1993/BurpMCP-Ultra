package com.burpmcp.ultra.bridge

/**
 * Pure keyword-counting logic for [HttpBridge.analyzeKeywords].
 *
 * Montoya's keyword analyzer is case-INSENSITIVE only. When the caller asks for
 * case-sensitive matching we compute the counts ourselves with an exact, non-overlapping
 * substring scan so the documented `case_sensitive` contract actually works instead of
 * being silently ignored.
 */
internal object HttpKeywordCount {

    /**
     * Counts non-overlapping, case-SENSITIVE occurrences of each keyword in [text].
     *
     * Empty keywords count as 0 (an empty needle would otherwise "match" at every index).
     * Duplicate keywords in the input collapse to a single entry (last one wins, same key).
     *
     * @return ordered map of keyword -> occurrence count, preserving input order.
     */
    fun countCaseSensitive(text: String, keywords: List<String>): Map<String, Int> {
        val out = LinkedHashMap<String, Int>()
        for (kw in keywords) {
            out[kw] = if (kw.isEmpty()) 0 else countOccurrences(text, kw)
        }
        return out
    }

    /** Non-overlapping case-sensitive occurrence count of [needle] in [haystack]. */
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
}
