package com.burpmcp.ultra.bridge

/**
 * Pure, Burp-independent IDOR-hunting logic, distilled from the combined
 * IDOR/BOLA/BFLA methodology (the lossless union of the system's idor-agent
 * knowledge base, the auth-authz skill, and the API/auth/business-logic agents).
 *
 * This is the engine behind the `idor_hunt` MCP tool. It is deliberately kept
 * free of the Montoya API (which is compileOnly and cannot be instantiated in
 * tests) so every classification / transformation / verdict rule is unit tested.
 * The [IdorHuntBridge] supplies the live HTTP replay around this core.
 *
 * What it adds over the existing identity-only [AuthDiffVerdict] engine — which
 * varies the *auth identity* while holding the object reference CONSTANT — is:
 *   1. object-reference DETECTION + format classification (§1/§2 of the methodology),
 *   2. object-id TRANSFORMATION generation (the §2 encoding/HPP/type-juggle cheat-sheet),
 *   3. the flagship HORIZONTAL object-id swap with CANARY confirmation and
 *      own-data-reflection false-positive filtering (§25) — turning a candidate
 *      into a CONFIRMED cross-user read.
 */
object IdorHunt {

    // ---------------------------------------------------------------------
    // 1. Object-reference format recognition (methodology §1 / §2.1)
    // ---------------------------------------------------------------------

    enum class IdFormat {
        INT, UUID_V1, UUID_V4, UUID_V7, UUID_OTHER, OBJECTID, SNOWFLAKE,
        HASH_MD5, HASH_SHA1, HASH_SHA256, BASE64, GID, SLUG, UNKNOWN
    }

    /** @param confidence 0..100; @param decoded the underlying value for opaque refs (base64/gid). */
    data class IdClassification(
        val format: IdFormat,
        val confidence: Int,
        val note: String,
        val decoded: String? = null
    )

    private val HEX = Regex("^[0-9a-fA-F]+$")
    private val UUID = Regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
    private val INT_RE = Regex("^-?\\d+$")
    private val BASE64_RE = Regex("^[A-Za-z0-9+/]{4,}={0,2}$")
    private val BASE64URL_RE = Regex("^[A-Za-z0-9_-]{4,}={0,2}$")
    private val GID_RE = Regex("^gid://[A-Za-z][A-Za-z0-9_]*/.+$")
    private val SLUG_RE = Regex("^[a-z0-9]+(?:[-_][a-z0-9]+)*$")

    /** Classify a single reference string into its most likely object-id format. */
    fun classify(raw: String): IdClassification {
        val v = raw.trim()
        if (v.isEmpty()) return IdClassification(IdFormat.UNKNOWN, 0, "empty value")

        // gid://Type/ID (Relay/GitHub-style global ids)
        if (GID_RE.matches(v)) return IdClassification(IdFormat.GID, 95, "GraphQL/Relay global id (gid://Type/ID)", v.substringAfterLast('/'))

        // UUID (version nibble is the first char of the 3rd group → index 14)
        if (UUID.matches(v)) {
            return when (v[14]) {
                '1' -> IdClassification(IdFormat.UUID_V1, 95, "UUID v1 — timestamp+MAC, predictable; harvest and window (guidtool/reset-tolkien)")
                '4' -> IdClassification(IdFormat.UUID_V4, 90, "UUID v4 — random; still harvest cross-endpoint refs and test nil/max")
                '7' -> IdClassification(IdFormat.UUID_V7, 92, "UUID v7 — unix-ms prefix, narrow the random tail")
                else -> IdClassification(IdFormat.UUID_OTHER, 80, "UUID v${v[14]} (v3/v5 namespace-hashed if 3/5)")
            }
        }

        // Pure hex: ObjectID (24) or hash (32/40/64). Check BEFORE int so hex-only digits aren't misread.
        if (HEX.matches(v)) {
            when (v.length) {
                24 -> return IdClassification(IdFormat.OBJECTID, 90, "MongoDB ObjectID — 4B ts | 5B machine | 3B counter; sweep ts+counter")
                32 -> return IdClassification(IdFormat.HASH_MD5, 75, "MD5-length hex — confirm own id then hash the input space (hashcat -m0)")
                40 -> return IdClassification(IdFormat.HASH_SHA1, 75, "SHA1-length hex — confirm own id then hash input space (hashcat -m100)")
                64 -> return IdClassification(IdFormat.HASH_SHA256, 75, "SHA256-length hex — confirm own id then hash input space (hashcat -m1400)")
            }
        }

        // Integer: distinguish plain auto-increment from Snowflake (very large).
        if (INT_RE.matches(v)) {
            val digits = v.trimStart('-').length
            val big = v.toLongOrNull()
            return if (digits >= 17 && big != null && big > 4_000_000_000_000_000L) {
                IdClassification(IdFormat.SNOWFLAKE, 70, "Snowflake-scale id — ts=(id>>22)+epoch; brute low 22 bits (worker+seq)")
            } else {
                IdClassification(IdFormat.INT, 90, "Sequential integer — enumerate ±1/±10/±100, boundaries, zero-pad")
            }
        }

        // Opaque base64 (standard or url-safe): decode-modify-re-encode candidate.
        if (BASE64_RE.matches(v) || BASE64URL_RE.matches(v)) {
            val decoded = tryDecodeBase64(v)
            if (decoded != null) {
                // base64('Type:ID') → treat as a Relay node id
                if (decoded.contains(':') && decoded.substringBefore(':').all { it.isLetterOrDigit() || it == '_' }) {
                    return IdClassification(IdFormat.GID, 80, "Base64 node id (decodes to '$decoded') — decode/inc/re-encode", decoded)
                }
                if (decoded.all { it.code in 32..126 }) {
                    return IdClassification(IdFormat.BASE64, 70, "Base64 opaque ref (decodes to '$decoded') — decode/modify/re-encode", decoded)
                }
            }
            return IdClassification(IdFormat.BASE64, 45, "Base64-shaped opaque ref — try decode/modify/re-encode")
        }

        // Predictable slug (usernames/titles): dictionary-enumerable.
        if (SLUG_RE.matches(v) && v.length <= 40) {
            return IdClassification(IdFormat.SLUG, 40, "Slug/keyword ref — dictionary-enumerate (admin/test/demo/me)")
        }

        return IdClassification(IdFormat.UNKNOWN, 10, "Unrecognized reference — try the generic encoding/HPP/type-juggle set")
    }

    private fun tryDecodeBase64(v: String): String? = try {
        val norm = v.replace('-', '+').replace('_', '/')
        val padded = norm.padEnd((norm.length + 3) / 4 * 4, '=')
        String(java.util.Base64.getDecoder().decode(padded), Charsets.UTF_8)
    } catch (_: Exception) { null }

    // ---------------------------------------------------------------------
    // 2. ID transformation generation (methodology §2 cheat-sheet)
    // ---------------------------------------------------------------------

    data class Mutation(val value: String, val technique: String)

    /**
     * Generate a bounded, de-duplicated transformation set for a reference,
     * tuned by its detected format. Covers the §2 library: numeric neighbours &
     * boundaries, encodings (base64/hex/url/double-url), type-juggling,
     * value-terminating tricks (null-byte, whitespace, extension), and
     * decode-modify-re-encode for opaque refs.
     */
    fun mutations(raw: String, cls: IdClassification = classify(raw), max: Int = 64): List<Mutation> {
        val v = raw.trim()
        val out = LinkedHashMap<String, Mutation>()
        fun add(value: String, technique: String) {
            if (value.isNotEmpty() && value != v && !out.containsKey(value)) out[value] = Mutation(value, technique)
        }

        when (cls.format) {
            IdFormat.INT, IdFormat.SNOWFLAKE -> {
                val n = v.toLongOrNull()
                if (n != null) {
                    listOf(n - 1, n + 1, n - 10, n + 10, n - 100, n + 100, n * 2).forEach { add(it.toString(), "numeric-neighbor") }
                    add("0", "boundary"); add("1", "boundary"); add("-1", "negative")
                    add("2147483647", "int32-max"); add("2147483648", "int32-overflow")
                    add("9223372036854775807", "int64-max")
                    add("0$v", "zero-pad"); add("00$v", "zero-pad"); add("$v.0", "float-coerce")
                    add("${v}e0", "scientific"); add("0x${n.toString(16)}", "hex-literal")
                }
            }
            IdFormat.UUID_V1, IdFormat.UUID_V4, IdFormat.UUID_V7, IdFormat.UUID_OTHER -> {
                add("00000000-0000-0000-0000-000000000000", "uuid-nil")
                add("ffffffff-ffff-ffff-ffff-ffffffffffff", "uuid-max")
                add("00000000-0000-0000-0000-000000000001", "uuid-one")
                // decrement / increment the last group
                bumpUuidTail(v, -1)?.let { add(it, "uuid-tail-decrement") }
                bumpUuidTail(v, +1)?.let { add(it, "uuid-tail-increment") }
            }
            IdFormat.OBJECTID -> {
                bumpHexTail(v, -1)?.let { add(it, "objectid-counter-decrement") }
                bumpHexTail(v, +1)?.let { add(it, "objectid-counter-increment") }
                add("000000000000000000000000", "objectid-nil")
            }
            IdFormat.GID, IdFormat.BASE64 -> {
                cls.decoded?.let { dec ->
                    // decode → mutate the numeric tail → re-encode
                    val tail = Regex("(\\d+)\\s*$").find(dec)
                    if (tail != null) {
                        val num = tail.groupValues[1].toLongOrNull()
                        if (num != null) {
                            listOf(num - 1, num + 1).forEach { newNum ->
                                val newDec = dec.substring(0, tail.range.first) + newNum
                                add(reencodeBase64(raw, newDec), "decode-modify-reencode")
                            }
                        }
                    }
                }
            }
            else -> {
                add("admin", "slug-dictionary"); add("me", "alias"); add("0", "boundary")
            }
        }

        // Generic transforms applicable to any reference (§2 encodings + terminators).
        add(base64(v), "base64-encode")
        add(v.let { java.net.URLEncoder.encode(it, "UTF-8") }, "url-encode")
        add(doubleUrlEncode(v), "double-url-encode")
        add("$v%00", "null-byte-append")
        add("$v ", "trailing-space")
        add(" $v", "leading-space")
        add("$v.json", "extension-append")
        add("$v/../$v", "path-traversal-noop")
        add("[\"$v\"]", "array-type-juggle")

        return out.values.take(max)
    }

    private fun base64(s: String) = java.util.Base64.getEncoder().encodeToString(s.toByteArray(Charsets.UTF_8))
    private fun doubleUrlEncode(s: String): String =
        java.net.URLEncoder.encode(java.net.URLEncoder.encode(s, "UTF-8"), "UTF-8")

    private fun reencodeBase64(original: String, newDecoded: String): String {
        val urlSafe = original.contains('-') || original.contains('_')
        val enc = if (urlSafe) java.util.Base64.getUrlEncoder() else java.util.Base64.getEncoder()
        var s = enc.encodeToString(newDecoded.toByteArray(Charsets.UTF_8))
        if (!original.endsWith("=")) s = s.trimEnd('=')
        return s
    }

    private fun bumpUuidTail(uuid: String, delta: Long): String? {
        val idx = uuid.lastIndexOf('-')
        if (idx < 0) return null
        val head = uuid.substring(0, idx + 1)
        val tail = uuid.substring(idx + 1)
        val n = tail.toBigIntegerOrNull(16) ?: return null
        val bumped = (n + delta.toBigInteger())
        if (bumped.signum() < 0) return null
        return head + bumped.toString(16).padStart(tail.length, '0').takeLast(tail.length)
    }

    private fun bumpHexTail(hex: String, delta: Long): String? {
        if (hex.length < 6) return null
        val head = hex.substring(0, hex.length - 6)
        val tail = hex.substring(hex.length - 6)
        val n = tail.toLongOrNull(16) ?: return null
        val bumped = n + delta
        if (bumped < 0) return null
        return head + bumped.toString(16).padStart(6, '0').takeLast(6)
    }

    private fun String.toBigIntegerOrNull(radix: Int): java.math.BigInteger? =
        try { java.math.BigInteger(this, radix) } catch (_: Exception) { null }

    // ---------------------------------------------------------------------
    // 3. Object-reference location in a raw HTTP request (methodology §0)
    // ---------------------------------------------------------------------

    data class ObjectRef(val location: String, val name: String, val value: String, val format: IdFormat)

    private val ID_PARAM_HINT = Regex(
        "(^|[_\\-.])(id|ids|uid|guid|uuid|user_?id|account_?id|owner_?id|org_?id|" +
            "member_?id|group_?id|doc(ument)?_?id|order_?id|invoice_?id|ticket_?id|" +
            "customer_?id|profile_?id|file_?id|object_?id|resource_?id|tenant_?id|" +
            "workspace_?id|team_?id|project_?id|number|ref|key|token|slug)$",
        RegexOption.IGNORE_CASE
    )
    private val AUTH_HEADERS = setOf("authorization", "cookie", "x-api-key", "x-auth-token")

    /**
     * Locate candidate object references across every injection location the
     * methodology says to test: path segments, query params, JSON/form body
     * fields, identity-style custom headers, and cookies. Auth-bearing headers
     * are skipped (those are the *identity*, not the object under test).
     */
    fun locateRefs(rawRequest: String): List<ObjectRef> {
        val refs = LinkedHashMap<String, ObjectRef>()
        fun add(loc: String, name: String, value: String) {
            val cls = classify(value)
            if (cls.format == IdFormat.UNKNOWN || cls.confidence < 40) return
            val k = "$loc|$name|$value"
            refs.putIfAbsent(k, ObjectRef(loc, name, value, cls.format))
        }

        val lines = rawRequest.replace("\r\n", "\n").split("\n")
        if (lines.isEmpty()) return emptyList()

        // Request line: METHOD PATH?QUERY HTTP/x
        val parts = lines[0].split(" ")
        if (parts.size >= 2) {
            val target = parts[1]
            val path = target.substringBefore("?").substringBefore("#")
            val query = target.substringAfter("?", "")
            // path segments that look like ids
            path.split("/").filter { it.isNotEmpty() }.forEach { seg ->
                val cls = classify(seg)
                if (cls.format != IdFormat.UNKNOWN && cls.confidence >= 60 &&
                    cls.format != IdFormat.SLUG) add("path", "segment", seg)
            }
            // query params
            if (query.isNotEmpty()) query.split("&").forEach { kv ->
                val name = kv.substringBefore("=")
                val value = kv.substringAfter("=", "")
                if (value.isNotEmpty() && (ID_PARAM_HINT.containsMatchIn(name) || looksLikeId(value))) add("query", name, value)
            }
        }

        // Headers + cookies
        var i = 1
        while (i < lines.size && lines[i].isNotBlank()) {
            val line = lines[i]; i++
            val name = line.substringBefore(":").trim()
            val value = line.substringAfter(":", "").trim()
            val lname = name.lowercase()
            if (lname == "cookie") {
                value.split(";").forEach { c ->
                    val cn = c.substringBefore("=").trim()
                    val cv = c.substringAfter("=", "").trim()
                    if (cv.isNotEmpty() && (ID_PARAM_HINT.containsMatchIn(cn) || looksLikeId(cv))) add("cookie", cn, cv)
                }
            } else if (lname !in AUTH_HEADERS && (ID_PARAM_HINT.containsMatchIn(name) || lname.startsWith("x-") && looksLikeId(value))) {
                if (value.isNotEmpty()) add("header", name, value)
            }
        }

        // Body (everything after the blank line): JSON id-ish fields or form params.
        val blank = lines.indexOfFirst { it.isBlank() }
        if (blank in 0 until lines.size - 1) {
            val body = lines.subList(blank + 1, lines.size).joinToString("\n").trim()
            if (body.startsWith("{") || body.startsWith("[")) {
                Regex("\"([A-Za-z0-9_]+)\"\\s*:\\s*\"?([^\",}\\]]+)\"?").findAll(body).forEach { m ->
                    val name = m.groupValues[1]; val value = m.groupValues[2].trim()
                    if (value.isNotEmpty() && (ID_PARAM_HINT.containsMatchIn(name) || looksLikeId(value))) add("body-json", name, value)
                }
            } else if (body.contains("=")) {
                body.split("&").forEach { kv ->
                    val name = kv.substringBefore("="); val value = kv.substringAfter("=", "")
                    if (value.isNotEmpty() && (ID_PARAM_HINT.containsMatchIn(name) || looksLikeId(value))) add("body-form", name, value)
                }
            }
        }

        return refs.values.toList()
    }

    private fun looksLikeId(v: String): Boolean {
        val c = classify(v)
        return c.confidence >= 60 && c.format in setOf(
            IdFormat.INT, IdFormat.SNOWFLAKE, IdFormat.UUID_V1, IdFormat.UUID_V4,
            IdFormat.UUID_V7, IdFormat.UUID_OTHER, IdFormat.OBJECTID, IdFormat.GID
        )
    }

    /**
     * Replace a located object reference's value with [newValue], scoped to the
     * ref's location so a short integer id can't collaterally rewrite unrelated
     * bytes elsewhere in the request. Used by the bridge to swap the object id
     * for a cross-identity replay while leaving the identity (auth) untouched.
     */
    fun applySwap(rawRequest: String, ref: ObjectRef, newValue: String): String {
        val old = ref.value
        val lineSep = if (rawRequest.contains("\r\n")) "\r\n" else "\n"
        val lines = rawRequest.split(lineSep).toMutableList()
        if (lines.isEmpty()) return rawRequest
        when (ref.location) {
            "path", "query" -> {
                val parts = lines[0].split(" ").toMutableList()
                if (parts.size >= 2) {
                    parts[1] = if (ref.location == "query")
                        parts[1].replace("${ref.name}=$old", "${ref.name}=$newValue")
                    else
                        parts[1].replace("/$old", "/$newValue")
                    lines[0] = parts.joinToString(" ")
                }
            }
            "header" -> for (i in 1 until lines.size) {
                if (lines[i].substringBefore(":").trim().equals(ref.name, true)) {
                    lines[i] = "${ref.name}: $newValue"; break
                }
            }
            "cookie" -> for (i in 1 until lines.size) {
                if (lines[i].substringBefore(":").trim().equals("cookie", true)) {
                    lines[i] = lines[i].replace("${ref.name}=$old", "${ref.name}=$newValue"); break
                }
            }
            "body-json" -> {
                val blank = lines.indexOfFirst { it.isBlank() }
                if (blank in 0 until lines.size) {
                    for (i in blank + 1 until lines.size) {
                        lines[i] = lines[i]
                            .replace("\"${ref.name}\":\"$old\"", "\"${ref.name}\":\"$newValue\"")
                            .replace("\"${ref.name}\": \"$old\"", "\"${ref.name}\": \"$newValue\"")
                            .replace("\"${ref.name}\":$old", "\"${ref.name}\":$newValue")
                            .replace("\"${ref.name}\": $old", "\"${ref.name}\": $newValue")
                    }
                }
            }
            "body-form" -> {
                val blank = lines.indexOfFirst { it.isBlank() }
                if (blank in 0 until lines.size) for (i in blank + 1 until lines.size)
                    lines[i] = lines[i].replace("${ref.name}=$old", "${ref.name}=$newValue")
            }
            else -> return rawRequest.replaceFirst(old, newValue)
        }
        return lines.joinToString(lineSep)
    }

    // ---------------------------------------------------------------------
    // 4. Canary / signature verdict for HORIZONTAL IDOR (methodology §25)
    // ---------------------------------------------------------------------

    /**
     * One cross-identity read: [reader] requested an object owned by [owner]
     * ([targetId]) and got [status]/[body]. [ownerCanary] is a token that should
     * appear ONLY in the owner's own data; [readerCanary] is the reader's own
     * token (used to catch own-data reflection false positives).
     */
    data class CanaryProbe(
        val reader: String,
        val owner: String,
        val targetId: String,
        val status: Int,
        val body: String,
        val ownerCanary: String?,
        val readerCanary: String?
    )

    data class Finding(val severity: String, val id: String, val detail: String)

    /**
     * Grade horizontal-IDOR canary probes. This is the confirmation step the
     * identity-only auth_diff engine cannot do: it asserts that account A's
     * response literally contains account B's canary (A read B's data), while
     * filtering the dominant false positive — the app ignoring the id and just
     * echoing the reader's own data.
     */
    fun assessCanary(probes: List<CanaryProbe>): List<Finding> {
        val findings = mutableListOf<Finding>()
        for (p in probes) {
            if (p.reader == p.owner) continue // baseline / own read
            val ok = p.status in 200..299
            val sawOwner = p.ownerCanary != null && p.ownerCanary.isNotBlank() && p.body.contains(p.ownerCanary)
            val sawReaderOwn = p.readerCanary != null && p.readerCanary.isNotBlank() && p.body.contains(p.readerCanary)

            when {
                ok && sawOwner && !sawReaderOwn ->
                    findings.add(Finding("critical", "confirmed_horizontal_idor",
                        "CONFIRMED: '${p.reader}' read '${p.owner}'s object ${p.targetId} — the response contains ${p.owner}'s canary and not ${p.reader}'s own. Cross-user data exposure (IDOR/BOLA)."))
                ok && sawOwner && sawReaderOwn ->
                    findings.add(Finding("high", "canary_ambiguous",
                        "'${p.reader}' → ${p.owner}'s object ${p.targetId} returned 2xx containing BOTH canaries — likely a shared/merged view; verify manually whether ${p.owner}'s private fields leaked."))
                ok && sawReaderOwn && !sawOwner ->
                    findings.add(Finding("info", "own_data_reflection_fp",
                        "'${p.reader}' → ${p.owner}'s object ${p.targetId} returned the reader's OWN data (own canary, not the owner's) — the app ignores the object id; not an IDOR. Try a different injection location."))
                ok && p.ownerCanary == null ->
                    findings.add(Finding("high", "candidate_needs_canary",
                        "'${p.reader}' → ${p.owner}'s object ${p.targetId} returned ${p.status} but no canary was provided to confirm ownership — CANDIDATE; supply an owner canary to promote to confirmed."))
                ok ->
                    findings.add(Finding("high", "candidate_2xx_no_leak",
                        "'${p.reader}' → ${p.owner}'s object ${p.targetId} returned ${p.status} but the owner canary was absent — candidate: response may be a stub/empty; inspect body."))
                p.status in 401..403 -> {} // properly denied — no finding
                else ->
                    findings.add(Finding("info", "denied_or_error",
                        "'${p.reader}' → ${p.owner}'s object ${p.targetId} returned ${p.status} — not accessible; if 404 try a status/timing/error oracle for blind IDOR."))
            }
        }
        return findings
    }

    /** Highest severity present, for a one-line summary. */
    fun topSeverity(findings: List<Finding>): String = when {
        findings.any { it.severity == "critical" } -> "critical"
        findings.any { it.severity == "high" } -> "high"
        findings.any { it.severity == "medium" } -> "medium"
        findings.any { it.severity == "low" } -> "low"
        findings.any { it.severity == "info" } -> "info"
        else -> "none"
    }
}
