package com.burpmcp.ultra.core

/**
 * Makes an arbitrary HTTP/WebSocket body safe to embed in a JSON tool result (GitHub issue #12,
 * reported by **@th0t3p**).
 *
 * `proxy_history` with `include_response=true` used to put `response.toString()` straight into the
 * JSON. For a binary body (a webfont, image, archive…) that string is not text, and two things go
 * wrong once it reaches the wire:
 *
 *  - **Lone surrogates cannot be UTF-8 encoded.** A half of a surrogate pair — either present in the
 *    decoded bytes, or *created* by truncating at a fixed character count right between the two
 *    halves — has no valid UTF-8 form, so the encoder emits replacement/invalid bytes and the
 *    client's strict JSON parser dies with `Unterminated string`. Because one item's corruption
 *    breaks the surrounding array, **a single binary asset makes an entire ~4 MB, 50-item batch
 *    unparseable**. (Control characters are *not* the culprit — a conformant encoder escapes those
 *    as `\u00XX` and they round-trip fine.)
 *  - Binary bodies are large and useless as text, bloating every response.
 *
 * So a body is rendered as text only when it plausibly *is* text; otherwise it is replaced by a
 * short placeholder that states what was dropped. Everything that does get emitted is stripped of
 * lone surrogates and truncated on a safe boundary, so no unencodable sequence can ever reach the
 * serializer.
 */
object BodyText {

    /** Default cap on an emitted body, matching the previous `maxResponseLength` default. */
    const val DEFAULT_MAX_LENGTH = 200_000

    /** How much of a body is sampled when guessing whether it is binary. */
    private const val SAMPLE = 4096

    /** Share of control characters above which a body is considered binary (5%). */
    private const val CONTROL_RATIO_DENOMINATOR = 20

    /**
     * @param text what to emit (placeholder when [binary]).
     * @param binary the body was not text and was replaced by a placeholder.
     * @param truncated the emitted text is a prefix of the original.
     * @param originalLength length of the body before any placeholder/truncation.
     */
    data class Rendered(
        val text: String,
        val binary: Boolean,
        val truncated: Boolean,
        val originalLength: Int
    )

    /** MIME fragments that are binary regardless of content sampling. */
    private val BINARY_MIME_HINTS = listOf(
        "IMAGE", "FONT", "VIDEO", "SOUND", "AUDIO", "ZIP", "PDF", "OCTET", "APPLICATION_UNKNOWN"
    )

    /**
     * Heuristic: does [s] look like binary rather than text?
     *
     * A NUL byte is decisive — no real text body contains one. Otherwise the first [SAMPLE]
     * characters are scored on their share of C0 control characters (tab/newline/carriage-return
     * excluded, since those are ordinary in HTTP text).
     */
    fun isProbablyBinary(s: String): Boolean {
        if (s.isEmpty()) return false
        if (s.contains('\u0000')) return true
        val sample = if (s.length > SAMPLE) s.substring(0, SAMPLE) else s
        var controls = 0
        for (ch in sample) {
            if (ch.code < 0x20 && ch != '\t' && ch != '\n' && ch != '\r') controls++
        }
        return controls * CONTROL_RATIO_DENOMINATOR > sample.length
    }

    /** True when [mime] names a format whose body is binary by definition. */
    fun isBinaryMime(mime: String?): Boolean {
        if (mime.isNullOrBlank()) return false
        val m = mime.uppercase()
        return BINARY_MIME_HINTS.any { it in m }
    }

    /**
     * Replaces every unpaired surrogate with U+FFFD. An unpaired surrogate has no UTF-8 encoding,
     * so leaving one in place corrupts the encoded stream — which is the actual failure in #12.
     */
    fun stripLoneSurrogates(s: String): String {
        var needsWork = false
        var i = 0
        while (i < s.length) {
            val c = s[i]
            if (c.isHighSurrogate()) {
                if (i + 1 >= s.length || !s[i + 1].isLowSurrogate()) { needsWork = true; break }
                i += 2; continue
            }
            if (c.isLowSurrogate()) { needsWork = true; break }
            i++
        }
        if (!needsWork) return s

        val out = StringBuilder(s.length)
        var j = 0
        while (j < s.length) {
            val c = s[j]
            when {
                c.isHighSurrogate() && j + 1 < s.length && s[j + 1].isLowSurrogate() -> {
                    out.append(c).append(s[j + 1]); j += 2
                }
                c.isHighSurrogate() || c.isLowSurrogate() -> { out.append('\uFFFD'); j++ }
                else -> { out.append(c); j++ }
            }
        }
        return out.toString()
    }

    /**
     * Truncates to at most [max] characters **without splitting a surrogate pair** — the naive
     * `take(max)` can cut between the two halves and manufacture exactly the unencodable sequence
     * this class exists to prevent.
     */
    fun truncate(s: String, max: Int): String {
        if (max <= 0 || s.length <= max) return s
        val end = if (s[max - 1].isHighSurrogate()) max - 1 else max
        return s.substring(0, end)
    }

    /**
     * Renders [raw] for embedding in a JSON result.
     *
     * @param maxLength cap on the emitted text; null or <= 0 uses [DEFAULT_MAX_LENGTH].
     * @param mimeHint optional MIME name (e.g. Montoya's `MimeType.name`) used as an extra binary signal.
     * @param label what the body is, for the placeholder text.
     */
    fun render(
        raw: String,
        maxLength: Int? = null,
        mimeHint: String? = null,
        label: String = "content"
    ): Rendered {
        val originalLength = raw.length
        if (isBinaryMime(mimeHint) || isProbablyBinary(raw)) {
            val mimeSuffix = if (mimeHint.isNullOrBlank()) "" else ", mime_type: $mimeHint"
            return Rendered(
                text = "[binary $label omitted: $originalLength bytes$mimeSuffix]",
                binary = true,
                truncated = false,
                originalLength = originalLength
            )
        }

        val cleaned = stripLoneSurrogates(raw)
        val cap = if (maxLength == null || maxLength <= 0) DEFAULT_MAX_LENGTH else maxLength
        if (cleaned.length <= cap) {
            return Rendered(cleaned, binary = false, truncated = false, originalLength = originalLength)
        }
        val cut = truncate(cleaned, cap)
        return Rendered(
            text = cut + "... [truncated, full length: $originalLength]",
            binary = false,
            truncated = true,
            originalLength = originalLength
        )
    }
}
