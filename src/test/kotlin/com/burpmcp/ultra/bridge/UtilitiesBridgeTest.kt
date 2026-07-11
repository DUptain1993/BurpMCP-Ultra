package com.burpmcp.ultra.bridge

import burp.api.montoya.utilities.CompressionType
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Unit tests for the pure, API-free decompression-input validation helpers on
 * [UtilitiesBridge]. These cover the fix for util_decompress silently echoing or
 * truncating malformed / wrong-format input instead of rejecting it.
 */
class UtilitiesBridgeTest {

    // --- validateCompressedInput: empty input guard ---------------------------

    @Test
    fun `validateCompressedInput rejects empty input for GZIP`() {
        val ex = assertFailsWith<IllegalArgumentException> {
            UtilitiesBridge.validateCompressedInput(ByteArray(0), CompressionType.GZIP)
        }
        assertTrue(ex.message!!.contains("empty input"))
    }

    @Test
    fun `validateCompressedInput rejects empty input for DEFLATE`() {
        assertFailsWith<IllegalArgumentException> {
            UtilitiesBridge.validateCompressedInput(ByteArray(0), CompressionType.DEFLATE)
        }
    }

    @Test
    fun `validateCompressedInput rejects empty input for BROTLI`() {
        assertFailsWith<IllegalArgumentException> {
            UtilitiesBridge.validateCompressedInput(ByteArray(0), CompressionType.BROTLI)
        }
    }

    // --- validateCompressedInput: GZIP magic-byte guard -----------------------

    @Test
    fun `validateCompressedInput rejects non-GZIP bytes when GZIP is declared`() {
        // Plain ASCII "hello" is not a GZIP stream.
        val notGzip = "hello".toByteArray()
        val ex = assertFailsWith<IllegalArgumentException> {
            UtilitiesBridge.validateCompressedInput(notGzip, CompressionType.GZIP)
        }
        assertTrue(ex.message!!.contains("GZIP magic bytes"))
    }

    @Test
    fun `validateCompressedInput rejects single-byte input when GZIP is declared`() {
        val oneByte = byteArrayOf(0x1f)
        assertFailsWith<IllegalArgumentException> {
            UtilitiesBridge.validateCompressedInput(oneByte, CompressionType.GZIP)
        }
    }

    @Test
    fun `validateCompressedInput accepts input starting with GZIP magic bytes`() {
        // 0x1f 0x8b is the GZIP magic (RFC 1952); remaining bytes are a plausible header.
        val gzipHeader = byteArrayOf(0x1f.toByte(), 0x8b.toByte(), 0x08, 0x00, 0x00, 0x00)
        // Should not throw.
        UtilitiesBridge.validateCompressedInput(gzipHeader, CompressionType.GZIP)
    }

    @Test
    fun `validateCompressedInput does not magic-check DEFLATE input`() {
        // DEFLATE has no reliable fixed magic; any non-empty input passes the pre-check.
        val arbitrary = "not-really-deflate".toByteArray()
        UtilitiesBridge.validateCompressedInput(arbitrary, CompressionType.DEFLATE)
    }

    @Test
    fun `validateCompressedInput does not magic-check BROTLI input`() {
        val arbitrary = byteArrayOf(0x00, 0x01, 0x02, 0x03)
        UtilitiesBridge.validateCompressedInput(arbitrary, CompressionType.BROTLI)
    }

    // --- isEchoedDecompression: silent-echo failure detection -----------------

    @Test
    fun `isEchoedDecompression flags byte-identical passthrough as failure`() {
        val input = byteArrayOf(0x01, 0x02, 0x03, 0x04)
        val echoed = input.copyOf()
        assertTrue(UtilitiesBridge.isEchoedDecompression(input, echoed))
    }

    @Test
    fun `isEchoedDecompression returns false for genuinely different output`() {
        val input = byteArrayOf(0x1f.toByte(), 0x8b.toByte(), 0x08, 0x00)
        val output = "decompressed payload".toByteArray()
        assertFalse(UtilitiesBridge.isEchoedDecompression(input, output))
    }

    @Test
    fun `isEchoedDecompression returns false when only length differs`() {
        val input = byteArrayOf(0x01, 0x02, 0x03)
        val truncated = byteArrayOf(0x01, 0x02)
        assertFalse(UtilitiesBridge.isEchoedDecompression(input, truncated))
    }

    @Test
    fun `isEchoedDecompression treats two empty arrays as echoed`() {
        // Defensive: empty in / empty out is a degenerate no-op, still an echo.
        assertEquals(true, UtilitiesBridge.isEchoedDecompression(ByteArray(0), ByteArray(0)))
    }
}
