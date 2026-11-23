package com.example.domain.engine

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.util.zip.Adler32

data class DexStripStats(
    val sourceFilesCleared: Int,
    val debugInfosCleared: Int,
)

/**
 * Direct binary Dalvik Executable (.dex) patcher.
 * Strips class source filenames (`source_file_idx`) and method debug symbol offsets (`debug_info_off`)
 * and recalculates the DEX SHA-1 signature and Adler32 checksum.
 */
object DexPatcher {

    private const val NO_INDEX = -1

    fun isValidDex(bytes: ByteArray): Boolean {
        return bytes.size >= 112 &&
            bytes[0] == 'd'.code.toByte() &&
            bytes[1] == 'e'.code.toByte() &&
            bytes[2] == 'x'.code.toByte() &&
            bytes[3] == '\n'.code.toByte()
    }

    fun containsAsciiMarker(dexBytes: ByteArray, marker: String): Boolean {
        val needle = marker.toByteArray(Charsets.UTF_8)
        if (needle.isEmpty() || dexBytes.size < needle.size) return false
        outer@ for (i in 0..(dexBytes.size - needle.size)) {
            for (j in needle.indices) {
                if (dexBytes[i + j] != needle[j]) continue@outer
            }
            return true
        }
        return false
    }

    fun stripDebugInfo(dexBytes: ByteArray): Pair<ByteArray, DexStripStats> {
        if (!isValidDex(dexBytes)) {
            return dexBytes to DexStripStats(0, 0)
        }

        val out = dexBytes.copyOf()
        val buf = ByteBuffer.wrap(out).order(ByteOrder.LITTLE_ENDIAN)
        val classDefsSize = buf.getInt(96)
        val classDefsOff = buf.getInt(100)

        if (classDefsSize <= 0 || classDefsOff <= 0 || classDefsOff + classDefsSize * 32 > out.size) {
            return dexBytes to DexStripStats(0, 0)
        }

        var sourceFilesCleared = 0
        var debugInfosCleared = 0

        for (i in 0 until classDefsSize) {
            val itemOff = classDefsOff + i * 32
            val sourceFileIdx = buf.getInt(itemOff + 16)
            if (sourceFileIdx != NO_INDEX) {
                buf.putInt(itemOff + 16, NO_INDEX)
                sourceFilesCleared++
            }

            val classDataOff = buf.getInt(itemOff + 24)
            if (classDataOff > 0 && classDataOff < out.size) {
                debugInfosCleared += clearClassDataMethodDebugOffsets(out, buf, classDataOff)
            }
        }

        if (sourceFilesCleared > 0 || debugInfosCleared > 0) {
            recomputeDexChecksums(out, buf)
        }

        return out to DexStripStats(sourceFilesCleared, debugInfosCleared)
    }

    fun recomputeDexChecksums(dexBytes: ByteArray) {
        if (!isValidDex(dexBytes)) return
        recomputeDexChecksums(dexBytes, ByteBuffer.wrap(dexBytes).order(ByteOrder.LITTLE_ENDIAN))
    }

    private fun recomputeDexChecksums(dexBytes: ByteArray, buf: ByteBuffer) {
        val sha1 = MessageDigest.getInstance("SHA-1").apply {
            update(dexBytes, 32, dexBytes.size - 32)
        }.digest()
        System.arraycopy(sha1, 0, dexBytes, 12, 20)

        val adler = Adler32().apply {
            update(dexBytes, 12, dexBytes.size - 12)
        }.value
        buf.putInt(8, adler.toInt())
    }

    private fun clearClassDataMethodDebugOffsets(
        bytes: ByteArray,
        buf: ByteBuffer,
        startOffset: Int,
    ): Int {
        var pos = startOffset
        val staticFields = readUleb128(bytes, pos).also { pos = it.nextPos }.value
        val instanceFields = readUleb128(bytes, pos).also { pos = it.nextPos }.value
        val directMethods = readUleb128(bytes, pos).also { pos = it.nextPos }.value
        val virtualMethods = readUleb128(bytes, pos).also { pos = it.nextPos }.value

        // Skip encoded_field entries: field_idx_diff, access_flags
        val totalFields = staticFields + instanceFields
        for (i in 0 until totalFields) {
            pos = readUleb128(bytes, pos).nextPos
            pos = readUleb128(bytes, pos).nextPos
        }

        var cleared = 0
        val totalMethods = directMethods + virtualMethods
        for (i in 0 until totalMethods) {
            pos = readUleb128(bytes, pos).nextPos // method_idx_diff
            pos = readUleb128(bytes, pos).nextPos // access_flags
            val codeOffRes = readUleb128(bytes, pos)
            pos = codeOffRes.nextPos
            val codeOff = codeOffRes.value
            if (codeOff > 0 && codeOff + 12 <= bytes.size) {
                val debugInfoOff = buf.getInt(codeOff + 8)
                if (debugInfoOff != 0) {
                    buf.putInt(codeOff + 8, 0)
                    cleared++
                }
            }
        }
        return cleared
    }

    private data class UlebResult(val value: Int, val nextPos: Int)

    private fun readUleb128(bytes: ByteArray, start: Int): UlebResult {
        var result = 0
        var shift = 0
        var pos = start
        while (pos < bytes.size) {
            val b = bytes[pos++].toInt() and 0xFF
            result = result or ((b and 0x7F) shl shift)
            if ((b and 0x80) == 0) break
            shift += 7
        }
        return UlebResult(result, pos)
    }
}
