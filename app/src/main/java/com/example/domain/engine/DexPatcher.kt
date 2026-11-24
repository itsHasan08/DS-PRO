package com.example.domain.engine

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.util.zip.Adler32
import java.util.zip.Deflater

data class DexStripStats(
    val sourceFilesCleared: Int,
    val debugInfosCleared: Int,
)

data class DexCfoStats(
    val methodsScanned: Int,
    val transformedUnits: Int,
)

data class DexStringEncryptResult(
    val encryptedDexBytes: ByteArray,
    val encryptedStringCount: Int,
    val compressedPatchBlob: ByteArray,
)

/**
 * Direct binary Dalvik Executable (.dex) patcher.
 * Supports:
 * - Debug symbol & debug_info_item payload stripping
 * - In-place non-structural ASCII literal string encryption (MUTF-8 / sort-safe)
 * - Verifier-safe Dalvik Control Flow Obfuscation (nop->goto chaining + branch threading)
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
        val nLen = needle.size
        if (nLen == 0 || dexBytes.size < nLen) return false
        val first = needle[0]
        val limit = dexBytes.size - nLen
        var i = 0
        while (i <= limit) {
            if (dexBytes[i] == first) {
                var j = 1
                while (j < nLen && dexBytes[i + j] == needle[j]) {
                    j++
                }
                if (j == nLen) return true
            }
            i++
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

    /**
     * Encrypts non-structural printable ASCII DEX string_data_item entries in-place with a
     * per-DEX SHA-256 high-bit keystream (guaranteed non-zero ciphertext so MUTF-8 null
     * terminators and string lengths stay exact). Returns a deflated patch list of
     * (stringDataOffset, byteLength) pairs for fast runtime in-memory restoration before
     * ART InMemoryDexClassLoader verification.
     */
    fun encryptLiteralStrings(dexBytes: ByteArray, stringKey: ByteArray): DexStringEncryptResult {
        if (!isValidDex(dexBytes) || stringKey.isEmpty()) {
            return DexStringEncryptResult(dexBytes, 0, ByteArray(0))
        }

        val out = dexBytes.copyOf()
        val buf = ByteBuffer.wrap(out).order(ByteOrder.LITTLE_ENDIAN)

        val stringIdsSize = buf.getInt(56)
        val stringIdsOff = buf.getInt(60)
        if (stringIdsSize <= 0 || stringIdsOff <= 0 || stringIdsOff + stringIdsSize * 4 > out.size) {
            return DexStringEncryptResult(dexBytes, 0, ByteArray(0))
        }

        val protectedStringIndices = BooleanArray(stringIdsSize)

        // 1. Protect type descriptors
        val typeIdsSize = buf.getInt(64)
        val typeIdsOff = buf.getInt(68)
        if (typeIdsSize > 0 && typeIdsOff > 0 && typeIdsOff + typeIdsSize * 4 <= out.size) {
            for (i in 0 until typeIdsSize) {
                val sIdx = buf.getInt(typeIdsOff + i * 4)
                if (sIdx in 0 until stringIdsSize) protectedStringIndices[sIdx] = true
            }
        }

        // 2. Protect proto shorty descriptors
        val protoIdsSize = buf.getInt(72)
        val protoIdsOff = buf.getInt(76)
        if (protoIdsSize > 0 && protoIdsOff > 0 && protoIdsOff + protoIdsSize * 12 <= out.size) {
            for (i in 0 until protoIdsSize) {
                val sIdx = buf.getInt(protoIdsOff + i * 12)
                if (sIdx in 0 until stringIdsSize) protectedStringIndices[sIdx] = true
            }
        }

        // 3. Protect field names
        val fieldIdsSize = buf.getInt(80)
        val fieldIdsOff = buf.getInt(84)
        if (fieldIdsSize > 0 && fieldIdsOff > 0 && fieldIdsOff + fieldIdsSize * 8 <= out.size) {
            for (i in 0 until fieldIdsSize) {
                val sIdx = buf.getInt(fieldIdsOff + i * 8 + 4)
                if (sIdx in 0 until stringIdsSize) protectedStringIndices[sIdx] = true
            }
        }

        // 4. Protect method names
        val methodIdsSize = buf.getInt(88)
        val methodIdsOff = buf.getInt(92)
        if (methodIdsSize > 0 && methodIdsOff > 0 && methodIdsOff + methodIdsSize * 8 <= out.size) {
            for (i in 0 until methodIdsSize) {
                val sIdx = buf.getInt(methodIdsOff + i * 8 + 4)
                if (sIdx in 0 until stringIdsSize) protectedStringIndices[sIdx] = true
            }
        }

        // 5. Protect class_defs source_file_idx
        val classDefsSize = buf.getInt(96)
        val classDefsOff = buf.getInt(100)
        if (classDefsSize > 0 && classDefsOff > 0 && classDefsOff + classDefsSize * 32 <= out.size) {
            for (i in 0 until classDefsSize) {
                val sIdx = buf.getInt(classDefsOff + i * 32 + 16)
                if (sIdx in 0 until stringIdsSize) protectedStringIndices[sIdx] = true
            }
        }

        val protectedOffsets = HashSet<Int>()
        for (idx in 0 until stringIdsSize) {
            if (protectedStringIndices[idx]) {
                val itemOff = buf.getInt(stringIdsOff + idx * 4)
                if (itemOff > 0) protectedOffsets.add(itemOff)
            }
        }

        val sha256 = MessageDigest.getInstance("SHA-256")
        val patchEntries = ArrayList<Pair<Int, Int>>()
        val seenDataOffsets = HashSet<Int>()

        for (idx in 0 until stringIdsSize) {
            if (protectedStringIndices[idx]) continue
            val itemOff = buf.getInt(stringIdsOff + idx * 4)
            if (itemOff <= 0 || itemOff >= out.size || !protectedOffsets.add(itemOff)) continue

            val utf16Res = readUleb128(out, itemOff, out.size)
            val utf16Len = utf16Res.value
            val dataStart = utf16Res.nextPos
            if (utf16Len < 2 || utf16Len > 2048 || dataStart + utf16Len >= out.size) continue
            if (!seenDataOffsets.add(dataStart)) continue

            // Only encrypt pure printable ASCII (0x20..0x7E) strings whose MUTF-8 length == utf16Len
            if (out[dataStart + utf16Len].toInt() != 0) continue
            var purePrintableAscii = true
            for (k in 0 until utf16Len) {
                val c = out[dataStart + k].toInt() and 0xFF
                if (c < 0x20 || c > 0x7E) {
                    purePrintableAscii = false
                    break
                }
            }
            if (!purePrintableAscii) continue

            applyAsciiStreamXor(out, dataStart, utf16Len, stringKey, sha256)
            patchEntries += dataStart to utf16Len
        }

        if (patchEntries.isEmpty()) {
            return DexStringEncryptResult(dexBytes, 0, ByteArray(0))
        }

        val rawPatch = ByteArrayOutputStream(patchEntries.size * 8 + 4)
        DataOutputStream(rawPatch).use { dos ->
            dos.writeInt(patchEntries.size)
            for ((off, len) in patchEntries) {
                dos.writeInt(off)
                dos.writeShort(len)
            }
            dos.flush()
        }

        val deflater = Deflater(Deflater.BEST_COMPRESSION)
        val deflatedPatch = ByteArrayOutputStream()
        try {
            val rawBytes = rawPatch.toByteArray()
            deflater.setInput(rawBytes)
            deflater.finish()
            val bufChunk = ByteArray(4096)
            while (!deflater.finished()) {
                val n = deflater.deflate(bufChunk)
                if (n <= 0) break
                deflatedPatch.write(bufChunk, 0, n)
            }
        } finally {
            deflater.end()
        }

        return DexStringEncryptResult(
            encryptedDexBytes = out,
            encryptedStringCount = patchEntries.size,
            compressedPatchBlob = deflatedPatch.toByteArray(),
        )
    }

    /**
     * Symmetric high-bit stream transform matching DsProCoreLoader.unlockStringTable():
     * every mask byte has bit 7 set (0x80..0xFF), so printable ASCII (0x20..0x7E) never
     * XORs to 0x00 and preserves MUTF-8 null termination.
     */
    fun applyAsciiStreamXor(
        bytes: ByteArray,
        offset: Int,
        length: Int,
        key: ByteArray,
        sha256: MessageDigest = MessageDigest.getInstance("SHA-256"),
    ) {
        sha256.reset()
        sha256.update(key)
        sha256.update(
            byteArrayOf(
                (offset ushr 24).toByte(),
                (offset ushr 16).toByte(),
                (offset ushr 8).toByte(),
                offset.toByte(),
                (length ushr 8).toByte(),
                length.toByte(),
            ),
        )
        var block = sha256.digest()
        var bPos = 0
        for (i in 0 until length) {
            if (bPos >= block.size) {
                sha256.reset()
                sha256.update(block)
                sha256.update(key)
                block = sha256.digest()
                bPos = 0
            }
            val mask = (block[bPos++].toInt() and 0x7F) or 0x80
            bytes[offset + i] = ((bytes[offset + i].toInt() and 0xFF) xor mask).toByte()
        }
    }

    /**
     * Performs 100% ART-verifier-safe Dalvik bytecode control-flow obfuscation in-place:
     * 1) Replaces reachable nop (0x0000) instructions (outside switch/array payloads) with goto +1 (0x0128)
     * 2) Threads branch targets (if-* / goto / goto/16) through downstream unconditional goto chains
     *    to scramble static CFG edges without altering code_item sizes, map_list, or execution semantics.
     */
    fun obfuscateControlFlow(dexBytes: ByteArray): Pair<ByteArray, DexCfoStats> {
        if (!isValidDex(dexBytes)) {
            return dexBytes to DexCfoStats(0, 0)
        }

        val out = dexBytes.copyOf()
        val buf = ByteBuffer.wrap(out).order(ByteOrder.LITTLE_ENDIAN)
        val classDefsSize = buf.getInt(96)
        val classDefsOff = buf.getInt(100)
        if (classDefsSize <= 0 || classDefsOff <= 0 || classDefsOff + classDefsSize * 32 > out.size) {
            return dexBytes to DexCfoStats(0, 0)
        }

        val visitedCodeOffsets = HashSet<Int>()
        var methodsScanned = 0
        var transformedUnits = 0

        for (i in 0 until classDefsSize) {
            val itemOff = classDefsOff + i * 32
            val classDataOff = buf.getInt(itemOff + 24)
            if (classDataOff <= 0 || classDataOff >= out.size) continue

            var pos = classDataOff
            val staticFields = readUleb128(out, pos).also { pos = it.nextPos }.value
            val instanceFields = readUleb128(out, pos).also { pos = it.nextPos }.value
            val directMethods = readUleb128(out, pos).also { pos = it.nextPos }.value
            val virtualMethods = readUleb128(out, pos).also { pos = it.nextPos }.value

            val totalFields = staticFields + instanceFields
            for (f in 0 until totalFields) {
                pos = readUleb128(out, pos).nextPos
                pos = readUleb128(out, pos).nextPos
            }

            val totalMethods = directMethods + virtualMethods
            for (m in 0 until totalMethods) {
                pos = readUleb128(out, pos).nextPos
                pos = readUleb128(out, pos).nextPos
                val codeOffRes = readUleb128(out, pos)
                pos = codeOffRes.nextPos
                val codeOff = codeOffRes.value
                if (codeOff > 0 && codeOff + 16 <= out.size && visitedCodeOffsets.add(codeOff)) {
                    methodsScanned++
                    transformedUnits += obfuscateMethodCodeItem(out, buf, codeOff)
                }
            }
        }

        if (transformedUnits > 0) {
            recomputeDexChecksums(out, buf)
        }
        return out to DexCfoStats(methodsScanned, transformedUnits)
    }

    private fun obfuscateMethodCodeItem(bytes: ByteArray, buf: ByteBuffer, codeOff: Int): Int {
        val insnsSize = buf.getInt(codeOff + 12)
        val insnsByteOff = codeOff + 16
        if (insnsSize <= 1 || insnsByteOff + insnsSize * 2 > bytes.size) return 0

        val units = ShortArray(insnsSize) { idx -> buf.getShort(insnsByteOff + idx * 2) }
        val payloadMask = BooleanArray(insnsSize)
        val payloadStarts = HashSet<Int>()

        // Pass 1: discover all 31t payloads (packed-switch, sparse-switch, fill-array-data)
        var pc = 0
        while (pc < insnsSize) {
            val unit = units[pc].toInt() and 0xFFFF
            if (unit == 0x0100 || unit == 0x0200 || unit == 0x0300) {
                val pWidth = payloadCodeUnits(units, pc)
                if (pWidth <= 0 || pc + pWidth > insnsSize) break
                payloadStarts += pc
                for (k in pc until (pc + pWidth)) payloadMask[k] = true
                pc += pWidth
                continue
            }
            val op = unit and 0xFF
            val width = dalvikInsnWidth(op)
            if (pc + width > insnsSize) break
            if ((op == 0x26 || op == 0x2b || op == 0x2c) && pc + 2 < insnsSize) {
                val rel = (units[pc + 1].toInt() and 0xFFFF) or (units[pc + 2].toInt() shl 16)
                val target = pc + rel
                if (target in 0 until insnsSize) {
                    payloadStarts += target
                    val pw = payloadCodeUnits(units, target)
                    if (pw > 0 && target + pw <= insnsSize) {
                        for (k in target until (target + pw)) payloadMask[k] = true
                    }
                }
            }
            pc += width
        }

        // Pass 2: collect valid instruction starts
        val validStarts = BooleanArray(insnsSize)
        pc = 0
        while (pc < insnsSize) {
            if (payloadMask[pc]) {
                pc++
                continue
            }
            validStarts[pc] = true
            val width = dalvikInsnWidth(units[pc].toInt() and 0xFF)
            if (pc + width > insnsSize) break
            pc += width
        }

        var changed = 0

        // Pass 3A: replace reachable nop (0x0000) with goto +1 (0x0128)
        pc = 0
        while (pc < insnsSize) {
            if (payloadMask[pc]) {
                pc++
                continue
            }
            val unit = units[pc].toInt() and 0xFFFF
            val op = unit and 0xFF
            if (unit == 0x0000 &&
                (pc + 1) < insnsSize &&
                !payloadStarts.contains(pc + 1) &&
                validStarts[pc + 1] &&
                !(units[pc + 1].toInt() == 0 && (pc + 2) < insnsSize && payloadStarts.contains(pc + 2))
            ) {
                units[pc] = 0x0128.toShort()
                buf.putShort(insnsByteOff + pc * 2, units[pc])
                changed++
            }
            val width = dalvikInsnWidth(op)
            if (pc + width > insnsSize) break
            pc += width
        }

        // Pass 3B: thread conditional/unconditional branch targets across goto trampolines
        pc = 0
        while (pc < insnsSize) {
            if (payloadMask[pc]) {
                pc++
                continue
            }
            val unit = units[pc].toInt() and 0xFFFF
            val op = unit and 0xFF
            val width = dalvikInsnWidth(op)
            if (pc + width > insnsSize) break

            when {
                op == 0x28 -> { // goto +AA (8-bit)
                    val signedAA = units[pc].toInt() shr 8
                    val target = pc + signedAA
                    val hopped = resolveGotoChain(units, validStarts, payloadMask, target, pc)
                    if (hopped != target && hopped != pc) {
                        val newRel = hopped - pc
                        if (newRel in -128..127) {
                            units[pc] = (((newRel and 0xFF) shl 8) or 0x28).toShort()
                            buf.putShort(insnsByteOff + pc * 2, units[pc])
                            changed++
                        }
                    }
                }
                op == 0x29 || op in 0x32..0x3d -> { // goto/16 or if-* / if-*z (16-bit at pc+1)
                    if (pc + 1 < insnsSize) {
                        val signedRel = units[pc + 1].toInt()
                        val target = pc + signedRel
                        val hopped = resolveGotoChain(units, validStarts, payloadMask, target, pc)
                        if (hopped != target && hopped != pc) {
                            val newRel = hopped - pc
                            if (newRel in -32768..32767) {
                                units[pc + 1] = newRel.toShort()
                                buf.putShort(insnsByteOff + (pc + 1) * 2, units[pc + 1])
                                changed++
                            }
                        }
                    }
                }
            }
            pc += width
        }

        return changed
    }

    private fun resolveGotoChain(
        units: ShortArray,
        validStarts: BooleanArray,
        payloadMask: BooleanArray,
        initialTarget: Int,
        originPc: Int,
    ): Int {
        var cur = initialTarget
        for (depth in 0 until 4) {
            if (cur !in units.indices || payloadMask[cur] || !validStarts[cur]) break
            val u = units[cur].toInt() and 0xFFFF
            val op = u and 0xFF
            val next = when (op) {
                0x28 -> cur + (units[cur].toInt() shr 8)
                0x29 -> if (cur + 1 < units.size) cur + units[cur + 1].toInt() else break
                else -> break
            }
            if (next == cur || next == originPc || next == initialTarget || next !in units.indices) break
            cur = next
        }
        return cur
    }

    private fun payloadCodeUnits(units: ShortArray, pc: Int): Int {
        if (pc + 1 >= units.size) return 0
        val ident = units[pc].toInt() and 0xFFFF
        val size = units[pc + 1].toInt() and 0xFFFF
        return when (ident) {
            0x0100 -> 4 + size * 2 // packed-switch-payload
            0x0200 -> 2 + size * 4 // sparse-switch-payload
            0x0300 -> { // fill-array-data-payload: elemWidth(1), size(2), data
                if (pc + 3 >= units.size) return 0
                val dataCount = (units[pc + 2].toInt() and 0xFFFF) or ((units[pc + 3].toInt() and 0xFFFF) shl 16)
                val totalBytes = size.toLong() * dataCount.toLong()
                if (totalBytes < 0 || totalBytes > 16 * 1024 * 1024) return 0
                (4 + ((totalBytes + 1) / 2)).toInt()
            }
            else -> 0
        }
    }

    private fun dalvikInsnWidth(op: Int): Int = when (op) {
        0x00, 0x01, 0x04, 0x07 -> 1
        in 0x0a..0x12 -> 1
        0x1d, 0x1e, 0x21, 0x27, 0x28 -> 1
        in 0x3e..0x43 -> 1
        0x73, 0x79, 0x7a -> 1
        in 0x7b..0x8f -> 1
        in 0xb0..0xcf -> 1
        in 0xe3..0xf9 -> 1
        0x18 -> 5
        0xfa, 0xfb -> 4
        0x03, 0x06, 0x09, 0x14, 0x17, 0x1b -> 3
        0x24, 0x25, 0x26, 0x2a, 0x2b, 0x2c -> 3
        in 0x6e..0x72 -> 3
        in 0x74..0x78 -> 3
        0xfc, 0xfd -> 3
        else -> 2
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

        val totalFields = staticFields + instanceFields
        for (i in 0 until totalFields) {
            pos = readUleb128(bytes, pos).nextPos
            pos = readUleb128(bytes, pos).nextPos
        }

        var cleared = 0
        val totalMethods = directMethods + virtualMethods
        for (i in 0 until totalMethods) {
            pos = readUleb128(bytes, pos).nextPos
            pos = readUleb128(bytes, pos).nextPos
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
        pos = readUleb128(bytes, pos, limit).nextPos
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
                else -> Unit
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
