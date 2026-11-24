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

        val dataSize = buf.getInt(104)
        val dataOff = buf.getInt(108)
        val dataEnd = if (dataOff > 0 && dataSize > 0) minOf(out.size, dataOff + dataSize) else out.size

        var sourceFilesCleared = 0
        var debugInfosCleared = 0
        val debugItemOffsets = LinkedHashSet<Int>()

        for (i in 0 until classDefsSize) {
            val itemOff = classDefsOff + i * 32
            val sourceFileIdx = buf.getInt(itemOff + 16)
            if (sourceFileIdx != NO_INDEX) {
                buf.putInt(itemOff + 16, NO_INDEX)
                sourceFilesCleared++
            }

            val classDataOff = buf.getInt(itemOff + 24)
            if (classDataOff > 0 && classDataOff < out.size) {
                debugInfosCleared += clearClassDataMethodDebugOffsets(out, buf, classDataOff, debugItemOffsets)
            }
        }

        for (debugOff in debugItemOffsets) {
            if (debugOff >= dataOff && debugOff < dataEnd) {
                wipeDebugInfoItem(out, debugOff, dataEnd)
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
        debugItemOffsets: MutableSet<Int>,
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
                    if (debugInfoOff > 0) {
                        debugItemOffsets += debugInfoOff
                    }
                    buf.putInt(codeOff + 8, 0)
                    cleared++
                }
            }
        }
        return cleared
    }

    private fun wipeDebugInfoItem(bytes: ByteArray, start: Int, limit: Int) {
        var pos = start
        pos = readUleb128(bytes, pos, limit).nextPos // line_start
        val paramRes = readUleb128(bytes, pos, limit)
        pos = paramRes.nextPos
        val paramCount = paramRes.value
        if (paramCount < 0 || paramCount > 255 || pos >= limit) return
        for (i in 0 until paramCount) {
            pos = readUleb128(bytes, pos, limit).nextPos
            if (pos > limit) return
        }
        var steps = 0
        while (pos < limit && steps < 65536) {
            steps++
            val op = bytes[pos++].toInt() and 0xFF
            when (op) {
                0x00 -> {
                    // Valid end of debug_info_item: overwrite all consumed bytes with 0x00
                    for (k in start until pos) {
                        bytes[k] = 0
                    }
                    return
                }
                0x01, 0x02, 0x05, 0x06, 0x09 -> {
                    pos = readUleb128(bytes, pos, limit).nextPos
                }
                0x03 -> {
                    pos = readUleb128(bytes, pos, limit).nextPos
                    pos = readUleb128(bytes, pos, limit).nextPos
                    pos = readUleb128(bytes, pos, limit).nextPos
                }
                0x04 -> {
                    pos = readUleb128(bytes, pos, limit).nextPos
                    pos = readUleb128(bytes, pos, limit).nextPos
                    pos = readUleb128(bytes, pos, limit).nextPos
                    pos = readUleb128(bytes, pos, limit).nextPos
                }
                else -> Unit // 0x07, 0x08, and 0x0A..0xFF special opcodes take no operands
            }
        }
    }

    private data class UlebResult(val value: Int, val nextPos: Int)

    private fun readUleb128(bytes: ByteArray, start: Int, limit: Int = bytes.size): UlebResult {
        var result = 0
        var shift = 0
        var pos = start
        while (pos < limit && shift <= 28) {
            val b = bytes[pos++].toInt() and 0xFF
            result = result or ((b and 0x7F) shl shift)
            if ((b and 0x80) == 0) break
            shift += 7
        }
        return UlebResult(result, pos)
    }
}
