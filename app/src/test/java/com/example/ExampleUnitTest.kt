package com.example

import com.example.domain.engine.ApkFileStorageService
import com.example.domain.engine.ApkProtectionProcessor
import com.example.domain.engine.AxmlManifestPatcher
import com.example.domain.engine.AxmlPatchOptions
import com.example.domain.engine.DexPatcher
import com.example.domain.engine.formatBytes
import com.example.domain.model.ApkAnalysisResult
import com.example.domain.model.ProtectionConfig
import com.example.domain.model.ProtectionSection
import com.example.ui.viewmodel.DsProUiState
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.File
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files
import java.security.MessageDigest
import java.util.zip.Adler32
import java.util.zip.CRC32
import java.util.zip.Inflater
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class ExampleUnitTest {

    private fun sampleApk(path: String = "/tmp/demo.apk") = ApkAnalysisResult(
        fileName = "demo.apk",
        cachedApkPath = path,
        packageName = "com.demo.app",
        appName = "Demo",
        versionName = "1.0",
        versionCode = 1L,
        minSdk = 26,
        targetSdk = 35,
        fileSizeBytes = 1024L,
        totalEntries = 11,
        dexCount = 1,
        logCallMatches = 3,
        signingCertSha256 = "AB:CD:EF",
        isSigned = true,
    )

    private fun buildSyntheticDex(withDebugInfo: Boolean = true, descriptor: String? = null): ByteArray {
        val totalSize = 256
        val bytes = ByteArray(totalSize)
        val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)

        System.arraycopy("dex\n035\u0000".toByteArray(Charsets.US_ASCII), 0, bytes, 0, 8)
        buf.putInt(32, totalSize)
        buf.putInt(36, 112)
        buf.putInt(40, 0x12345678)

        val classDefsOff = 112
        buf.putInt(96, 1)
        buf.putInt(100, classDefsOff)

        buf.putInt(classDefsOff + 16, if (withDebugInfo) 7 else -1)
        val classDataOff = 144
        buf.putInt(classDefsOff + 24, classDataOff)

        val codeOff = 160
        bytes[144] = 0
        bytes[145] = 0
        bytes[146] = 1
        bytes[147] = 0
        bytes[148] = 1
        bytes[149] = 1
        bytes[150] = (0x80 or (codeOff and 0x7F)).toByte()
        bytes[151] = (codeOff shr 7).toByte()

        buf.putInt(codeOff + 8, if (withDebugInfo) 200 else 0)

        if (descriptor != null) {
            val descBytes = descriptor.toByteArray(Charsets.UTF_8)
            System.arraycopy(descBytes, 0, bytes, 200, minOf(descBytes.size, totalSize - 200))
        }

        DexPatcher.recomputeDexChecksums(bytes)
        return bytes
    }

    private fun buildSyntheticDexWithStrings(
        typeDescriptor: String = "Lcom/demo/KeepType;",
        secretLiteral: String = "https://api.secret.dspro.test/v2",
    ): ByteArray {
        val totalSize = 512
        val bytes = ByteArray(totalSize)
        val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)

        System.arraycopy("dex\n035\u0000".toByteArray(Charsets.US_ASCII), 0, bytes, 0, 8)
        buf.putInt(32, totalSize)
        buf.putInt(36, 112)
        buf.putInt(40, 0x12345678)

        // string_ids (2 strings) at 112..120
        val stringIdsOff = 112
        buf.putInt(56, 2)
        buf.putInt(60, stringIdsOff)

        // type_ids (1 type referencing string idx 0) at 120..124
        val typeIdsOff = 120
        buf.putInt(64, 1)
        buf.putInt(68, typeIdsOff)
        buf.putInt(typeIdsOff, 0)

        // Place string_data_items at 220 and 300
        val str0Off = 220
        val str1Off = 300
        buf.putInt(stringIdsOff, str0Off)
        buf.putInt(stringIdsOff + 4, str1Off)

        fun writeStringItem(off: Int, value: String) {
            val raw = value.toByteArray(Charsets.US_ASCII)
            bytes[off] = raw.size.toByte()
            System.arraycopy(raw, 0, bytes, off + 1, raw.size)
            bytes[off + 1 + raw.size] = 0
        }

        writeStringItem(str0Off, typeDescriptor)
        writeStringItem(str1Off, secretLiteral)

        DexPatcher.recomputeDexChecksums(bytes)
        return bytes
    }

    private fun buildSyntheticDexWithControlFlow(): ByteArray {
        val totalSize = 512
        val bytes = ByteArray(totalSize)
        val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)

        System.arraycopy("dex\n035\u0000".toByteArray(Charsets.US_ASCII), 0, bytes, 0, 8)
        buf.putInt(32, totalSize)
        buf.putInt(36, 112)
        buf.putInt(40, 0x12345678)

        val classDefsOff = 112
        buf.putInt(96, 1)
        buf.putInt(100, classDefsOff)
        buf.putInt(classDefsOff + 16, -1)
        val classDataOff = 144
        buf.putInt(classDefsOff + 24, classDataOff)

        val codeOff = 160
        bytes[144] = 0
        bytes[145] = 0
        bytes[146] = 1
        bytes[147] = 0
        bytes[148] = 1
        bytes[149] = 1
        bytes[150] = (0x80 or (codeOff and 0x7F)).toByte()
        bytes[151] = (codeOff shr 7).toByte()

        // Instructions (14 units):
        // pc=0: nop (0x0000) -> becomes goto +1 (0x0128)
        // pc=1..2: if-eqz v0, +3 (target pc=4) -> target pc=4 is goto +2 -> threads to pc=6!
        // pc=3: return-void (0x000e)
        // pc=4: goto +2 (0x0228) -> hops to pc=6
        // pc=5: return-void (0x000e)
        // pc=6: return-void (0x000e)
        // pc=7..12: packed-switch-payload (0x0100, size=1, firstKey=0, target=0) - MUST stay untouched!
        val insns = shortArrayOf(
            0x0000.toShort(), // 0: nop
            0x0038.toShort(), // 1: if-eqz v0
            0x0003.toShort(), // 2: +3 -> pc=4
            0x000e.toShort(), // 3: return-void
            0x0228.toShort(), // 4: goto +2 -> pc=6
            0x000e.toShort(), // 5: return-void
            0x000e.toShort(), // 6: return-void
            0x0100.toShort(), // 7: packed-switch-payload ident
            0x0001.toShort(), // 8: size = 1
            0x0000.toShort(), // 9: first_key low (also 0x0000 inside payload)
            0x0000.toShort(), // 10: first_key high
            0x0000.toShort(), // 11: target[0] low
            0x0000.toShort(), // 12: target[0] high
        )
        buf.putInt(codeOff + 12, insns.size)
        for (i in insns.indices) {
            buf.putShort(codeOff + 16 + i * 2, insns[i])
        }

        DexPatcher.recomputeDexChecksums(bytes)
        return bytes
    }

    private fun inflatePlain(compressed: ByteArray): ByteArray {
        val inflater = Inflater()
        return try {
            inflater.setInput(compressed)
            val out = ByteArrayOutputStream()
            val buf = ByteArray(8192)
            while (!inflater.finished()) {
                val n = inflater.inflate(buf)
                if (n <= 0) break
                out.write(buf, 0, n)
            }
            out.toByteArray()
        } finally {
            inflater.end()
        }
    }

    private fun decryptCorePayloads(zip: ZipFile, packageName: String): Pair<List<String>, List<ByteArray>> {
        val containerName = ApkProtectionProcessor.coreContainerAssetPath(packageName)
        val entry = zip.getEntry(containerName)
            ?: throw AssertionError("Missing encrypted DS PRO container $containerName")
        val coreDexBytes = zip.getInputStream(zip.getEntry("classes.dex")).use { it.readBytes() }
        val sha256 = MessageDigest.getInstance("SHA-256")
        val coreDexSha256 = sha256.digest(coreDexBytes)
        val guardEntry = zip.getEntry(ApkProtectionProcessor.guardConfigAssetPath(packageName))
        val guardDexSha256 = if (guardEntry != null) {
            val gBytes = zip.getInputStream(zip.getEntry("classes2.dex")).use { it.readBytes() }
            sha256.reset()
            sha256.digest(gBytes)
        } else {
            ByteArray(32)
        }

        zip.getInputStream(entry).use { rawIn ->
            DataInputStream(rawIn).use { dis ->
                val salt = ByteArray(16).also { dis.readFully(it) }
                val maskedPepper = ByteArray(32).also { dis.readFully(it) }
                val metaIv = ByteArray(12).also { dis.readFully(it) }
                val metaLen = dis.readInt()
                val metaCipher = ByteArray(metaLen).also { dis.readFully(it) }

                val pkgBytes = packageName.toByteArray(Charsets.UTF_8)
                sha256.reset()
                sha256.update(pkgBytes)
                sha256.update(":V5M:".toByteArray(Charsets.UTF_8))
                sha256.update(salt)
                sha256.update(coreDexSha256)
                sha256.update(guardDexSha256)
                val bindingMask = sha256.digest()
                val pepper = ByteArray(32) { i ->
                    (maskedPepper[i].toInt() xor bindingMask[i].toInt()).toByte()
                }

                sha256.reset()
                sha256.update(pepper)
                sha256.update(salt)
                sha256.update(coreDexSha256)
                sha256.update(guardDexSha256)
                sha256.update(pkgBytes)
                var metaKey = sha256.digest()
                for (round in 0 until 1024) {
                    sha256.reset()
                    sha256.update(metaKey)
                    sha256.update(pepper)
                    sha256.update((round and 0xFF).toByte())
                    metaKey = sha256.digest()
                }

                val metaCipherObj = Cipher.getInstance("AES/GCM/NoPadding")
                metaCipherObj.init(Cipher.DECRYPT_MODE, SecretKeySpec(metaKey, "AES"), GCMParameterSpec(128, metaIv))
                val metaPlain = String(metaCipherObj.doFinal(metaCipher), Charsets.UTF_8)

                val lines = metaPlain.split("\n")
                val dexCount = lines[0].trim().toInt()
                val aesKeyHex = lines[3].trim()
                val aesKey = ByteArray(aesKeyHex.length / 2) { i ->
                    ((Character.digit(aesKeyHex[i * 2], 16) shl 4) +
                        Character.digit(aesKeyHex[i * 2 + 1], 16)).toByte()
                }
                val isCompressed = lines.size >= 6 && lines[5].trim() == "Z1"
                val expectedDigests = if (lines.size >= 9 && lines[8].trim().isNotEmpty()) {
                    lines[8].trim().split(",")
                } else {
                    emptyList()
                }

                val dexList = (0 until dexCount).map { idx ->
                    val iv = ByteArray(12).also { dis.readFully(it) }
                    val patchLen = dis.readInt()
                    val patchCipher = if (patchLen > 0) ByteArray(patchLen).also { dis.readFully(it) } else null
                    val cLen = dis.readInt()
                    val enc = ByteArray(cLen).also { dis.readFully(it) }

                    val ivHex = iv.joinToString("") { "%02x".format(it) }
                    sha256.reset()
                    sha256.update(aesKey)
                    sha256.update(":DEX:$idx:$ivHex".toByteArray(Charsets.UTF_8))
                    sha256.update(coreDexSha256)
                    val entryKey = sha256.digest()
                    val entryKeySpec = SecretKeySpec(entryKey, "AES")

                    val patchPlain = patchCipher?.let { pc ->
                        val patchIv = iv.copyOf().apply { this[0] = (this[0].toInt() xor 0x5A).toByte() }
                        val compressedPatch = Cipher.getInstance("AES/GCM/NoPadding").run {
                            init(Cipher.DECRYPT_MODE, entryKeySpec, GCMParameterSpec(128, patchIv))
                            doFinal(pc)
                        }
                        inflatePlain(compressedPatch)
                    }

                    val plain = Cipher.getInstance("AES/GCM/NoPadding").run {
                        init(Cipher.DECRYPT_MODE, entryKeySpec, GCMParameterSpec(128, iv))
                        doFinal(enc)
                    }
                    val restoredDex = if (!isCompressed) plain else inflatePlain(plain)

                    if (patchPlain != null) {
                        sha256.reset()
                        sha256.update(entryKey)
                        sha256.update(":STR:$idx".toByteArray(Charsets.UTF_8))
                        val strKey = sha256.digest()
                        DataInputStream(ByteArrayInputStream(patchPlain)).use { pdis ->
                            val count = pdis.readInt()
                            for (p in 0 until count) {
                                val off = pdis.readInt()
                                val len = pdis.readUnsignedShort()
                                DexPatcher.applyAsciiStreamXor(restoredDex, off, len, strKey, sha256)
                            }
                        }
                    }

                    if (idx < expectedDigests.size && expectedDigests[idx].isNotBlank()) {
                        sha256.reset()
                        val actualHex = sha256.digest(restoredDex).joinToString("") { "%02x".format(it) }
                        assertEquals(expectedDigests[idx].trim(), actualHex)
                    }

                    restoredDex
                }
                return lines to dexList
            }
        }
    }

    private fun decryptGuardPolicy(zip: ZipFile, packageName: String): List<String> {
        val guardName = ApkProtectionProcessor.guardConfigAssetPath(packageName)
        val entry = zip.getEntry(guardName)
            ?: throw AssertionError("Missing encrypted Guard policy $guardName")
        val blob = zip.getInputStream(entry).use { it.readBytes() }
        assertTrue(blob.size > 28)
        val salt = blob.copyOfRange(0, 16)
        val iv = blob.copyOfRange(16, 28)
        val saltHex = salt.joinToString("") { "%02x".format(it) }
        val key = MessageDigest.getInstance("SHA-256").digest(
            "$packageName:DSPRO_GCFG_KEY:$saltHex".toByteArray(Charsets.UTF_8),
        )
        val plain = Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
            String(doFinal(blob, 28, blob.size - 28), Charsets.UTF_8)
        }
        return plain.trimEnd('\n').split("\n")
    }

    private fun decryptResourceVault(zip: ZipFile, packageName: String): Map<String, ByteArray> {
        val vaultPath = ApkProtectionProcessor.resourceVaultAssetPath(packageName)
        val entry = zip.getEntry(vaultPath)
            ?: throw AssertionError("Missing encrypted Resource Vault $vaultPath")
        val blob = zip.getInputStream(entry).use { it.readBytes() }
        assertTrue(blob.size > 28)
        val salt = blob.copyOfRange(0, 16)
        val iv = blob.copyOfRange(16, 28)
        val saltHex = salt.joinToString("") { "%02x".format(it) }
        val key = MessageDigest.getInstance("SHA-256").digest(
            "$packageName:DSPRO_RES_V1:$saltHex".toByteArray(Charsets.UTF_8),
        )
        val plainZip = Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
            doFinal(blob, 28, blob.size - 28)
        }
        val out = linkedMapOf<String, ByteArray>()
        ZipInputStream(ByteArrayInputStream(plainZip)).use { zis ->
            var ze = zis.nextEntry
            while (ze != null) {
                out[ze.name] = zis.readBytes()
                zis.closeEntry()
                ze = zis.nextEntry
            }
        }
        return out
    }

    @Test
    fun `default config starts with zero active options and start disabled`() {
        val defaultCfg = ProtectionConfig()
        assertEquals(0, defaultCfg.activeToggleCount)
        assertFalse(defaultCfg.requiresRuntimeGuard)
        assertFalse(defaultCfg.requiresGuardDex)
        assertFalse(defaultCfg.requiresCoreDexContainer)
        assertFalse(DsProUiState().isStartEnabled)
        assertFalse(
            DsProUiState(
                selectedApkUri = "content://downloads/demo.apk",
                selectedApk = sampleApk(),
                config = defaultCfg,
            ).isStartEnabled,
        )
    }

    @Test
    fun `start button disabled until both apk uri and protection toggle active`() {
        assertFalse(DsProUiState(config = ProtectionConfig()).isStartEnabled)
        assertFalse(DsProUiState(config = ProtectionConfig(dsProDexEncryption = true)).isStartEnabled)
        assertTrue(
            DsProUiState(
                selectedApkUri = "content://downloads/demo.apk",
                selectedApk = sampleApk(),
                config = ProtectionConfig(dsProDexEncryption = true),
            ).isStartEnabled,
        )
        assertTrue(
            DsProUiState(
                selectedApkUri = "content://downloads/demo.apk",
                selectedApk = sampleApk(),
                config = ProtectionConfig(stringEncryption = true),
            ).isStartEnabled,
        )
        assertTrue(
            DsProUiState(
                selectedApkUri = "content://downloads/demo.apk",
                selectedApk = sampleApk(),
                config = ProtectionConfig(resourceEncryption = true),
            ).isStartEnabled,
        )
        assertFalse(
            DsProUiState(
                selectedApkUri = "content://downloads/demo.apk",
                selectedApk = sampleApk(),
                config = ProtectionConfig(dsProDexEncryption = true),
                isProcessing = true,
            ).isStartEnabled,
        )
    }

    @Test
    fun `section active counts match 7 upper section and 6 lower section toggles`() {
        val allOn = ProtectionConfig(
            detectRoot = true,
            detectDebugger = true,
            antiScreenshot = true,
            antiTampering = true,
            antiDump = true,
            dexIntegrityProtection = true,
            assistEncrypt = true,
            dsProDexEncryption = true,
            stringEncryption = true,
            controlFlowObfuscation = true,
            resourceEncryption = true,
            disableDebuggable = true,
            stripDexDebug = true,
        )
        assertEquals(7, allOn.activeCountFor(ProtectionSection.RUNTIME_GUARD))
        assertEquals(6, allOn.activeCountFor(ProtectionSection.BINARY_HARDENING))
        assertEquals(13, allOn.activeToggleCount)
        assertTrue(allOn.requiresRuntimeGuard)
        assertTrue(allOn.requiresGuardDex)
        assertTrue(allOn.requiresCoreDexContainer)
        assertFalse(ProtectionConfig(assistEncrypt = true).requiresRuntimeGuard)
        assertTrue(ProtectionConfig(assistEncrypt = true).requiresGuardDex)
    }

    @Test
    fun `axml manifest patcher disables debuggable preserves allowBackup and injects guard plus dspro core`() {
        val rawManifest = AxmlManifestPatcher.buildMinimalManifestForTest(
            packageName = "com.demo.app",
            debuggable = true,
            allowBackup = true,
        )
        val patched = AxmlManifestPatcher.patch(
            rawManifest,
            AxmlPatchOptions(
                disableDebuggable = true,
                injectGuardProvider = true,
                enableCoreProtection = true,
                protectionIdentifier = AxmlManifestPatcher.PROTECTION_IDENTIFIER_VALUE,
                packageName = "com.demo.app",
            ),
        )
        assertTrue(patched.debuggableDisabled)
        assertTrue(patched.guardProviderInjected)
        assertTrue(patched.coreProtectionInjected)
        assertTrue(patched.protectionIdentifierEmbedded)

        val verified = AxmlManifestPatcher.inspectForTest(patched.manifestBytes)
        assertEquals(false, verified.first)
        assertEquals(true, verified.second)
        assertTrue(verified.third)

        val (appName, factoryName) = AxmlManifestPatcher.inspectCoreForTest(patched.manifestBytes)
        assertEquals(AxmlManifestPatcher.CORE_APP_CLASS, appName)
        assertEquals(AxmlManifestPatcher.CORE_FACTORY_CLASS, factoryName)

        val summary = AxmlManifestPatcher.inspectSecuritySummary(patched.manifestBytes)
        assertEquals(AxmlManifestPatcher.PROTECTION_IDENTIFIER_VALUE, summary?.protectionIdentifier)
    }

    @Test
    fun `dex patcher strips source file and debug info and updates checksums`() {
        val dex = buildSyntheticDex(withDebugInfo = true)
        dex[200] = 1
        dex[201] = 0
        dex[202] = 0
        DexPatcher.recomputeDexChecksums(dex)

        val (stripped, stats) = DexPatcher.stripDebugInfo(dex)

        assertEquals(1, stats.sourceFilesCleared)
        assertEquals(1, stats.debugInfosCleared)

        val buf = ByteBuffer.wrap(stripped).order(ByteOrder.LITTLE_ENDIAN)
        assertEquals(-1, buf.getInt(112 + 16))
        assertEquals(0, buf.getInt(160 + 8))
        assertEquals(0, stripped[200].toInt())
        assertEquals(0, stripped[201].toInt())
        assertEquals(0, stripped[202].toInt())

        val (_, secondStats) = DexPatcher.stripDebugInfo(stripped)
        assertEquals(0, secondStats.sourceFilesCleared)
        assertEquals(0, secondStats.debugInfosCleared)
    }

    @Test
    fun `dex string encryption masks literal strings while preserving structural descriptors and decrypts losslessly`() {
        val rawDex = buildSyntheticDexWithStrings(
            typeDescriptor = "Lcom/demo/KeepType;",
            secretLiteral = "https://api.secret.dspro.test/v2",
        )
        val strKey = MessageDigest.getInstance("SHA-256").digest("test-str-key".toByteArray())

        val res = DexPatcher.encryptLiteralStrings(rawDex, strKey)
        assertEquals(1, res.encryptedStringCount)
        assertTrue(res.compressedPatchBlob.isNotEmpty())
        assertTrue(DexPatcher.containsAsciiMarker(res.encryptedDexBytes, "Lcom/demo/KeepType;"))
        assertFalse(DexPatcher.containsAsciiMarker(res.encryptedDexBytes, "api.secret.dspro.test"))

        val inflatedPatch = inflatePlain(res.compressedPatchBlob)
        val unlocked = res.encryptedDexBytes.copyOf()
        DataInputStream(ByteArrayInputStream(inflatedPatch)).use { pdis ->
            val count = pdis.readInt()
            assertEquals(1, count)
            val off = pdis.readInt()
            val len = pdis.readUnsignedShort()
            DexPatcher.applyAsciiStreamXor(unlocked, off, len, strKey)
        }
        assertArrayEquals(rawDex, unlocked)
    }

    @Test
    fun `control flow obfuscation transforms nop and threads branches without touching switch payloads`() {
        val rawDex = buildSyntheticDexWithControlFlow()
        val (cfoDex, stats) = DexPatcher.obfuscateControlFlow(rawDex)

        assertTrue(DexPatcher.isValidDex(cfoDex))
        assertEquals(1, stats.methodsScanned)
        assertTrue(stats.transformedUnits >= 2)

        val buf = ByteBuffer.wrap(cfoDex).order(ByteOrder.LITTLE_ENDIAN)
        val insnsOff = 160 + 16
        // pc=0: nop (0x0000) -> goto +1 (0x0128)
        assertEquals(0x0128, buf.getShort(insnsOff).toInt() and 0xFFFF)
        // pc=1..2: if-eqz offset +3 (to pc=4 goto +2) -> threaded directly to pc=6 (+5 relative to pc=1)
        assertEquals(5, buf.getShort(insnsOff + 2 * 2).toInt())
        // pc=7..12 packed-switch-payload unchanged (0x0100 ident, 0x0000 inside payload untouched)
        assertEquals(0x0100, buf.getShort(insnsOff + 7 * 2).toInt() and 0xFFFF)
        assertEquals(0x0000, buf.getShort(insnsOff + 9 * 2).toInt() and 0xFFFF)

        // Verify recomputed Adler32 matches bytes[12..end)
        val headerAdler = buf.getInt(8).toLong() and 0xFFFFFFFFL
        val computedAdler = Adler32().apply { update(cfoDex, 12, cfoDex.size - 12) }.value
        assertEquals(computedAdler, headerAdler)
    }

    @Test
    fun `dspro core string resource cfo and dex integrity encrypt and roundtrip cleanly`() {
        val tempDir = Files.createTempDirectory("dspro_core_test").toFile()
        try {
            val inputApk = File(tempDir, "sample.apk")
            val rawManifest = AxmlManifestPatcher.buildMinimalManifestForTest("com.demo.app", debuggable = true, allowBackup = true)
            val appDex1 = buildSyntheticDexWithStrings(
                typeDescriptor = "Lcom/demo/app/Main;",
                secretLiteral = "https://endpoint.hidden.example/token",
            )
            val appDex2 = buildSyntheticDexWithControlFlow()
            val guardDex = buildSyntheticDex(withDebugInfo = false, descriptor = "Lcom/dspro/guard/DsProGuardProvider;")
            val coreDex = buildSyntheticDex(withDebugInfo = false, descriptor = "Lcom/dspro/core/DsProApplication;")
            val arscBytes = ByteArray(64) { 0x42 }
            val soBytes = ByteArray(64) { 0x7F }
            val jsonAsset = """{"secret":"value","mode":"prod"}""".toByteArray(Charsets.UTF_8)
            val txtAsset = "confidential-config-line".toByteArray(Charsets.UTF_8)

            ZipOutputStream(FileOutputStream(inputApk)).use { zip ->
                zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
                zip.write(rawManifest)
                zip.closeEntry()

                zip.putNextEntry(ZipEntry("classes.dex"))
                zip.write(appDex1)
                zip.closeEntry()

                zip.putNextEntry(ZipEntry("classes2.dex"))
                zip.write(appDex2)
                zip.closeEntry()

                zip.putNextEntry(ZipEntry("assets/config/app.json"))
                zip.write(jsonAsset)
                zip.closeEntry()

                zip.putNextEntry(ZipEntry("assets/secret.txt"))
                zip.write(txtAsset)
                zip.closeEntry()

                zip.putNextEntry(ZipEntry("resources.arsc").apply {
                    method = ZipEntry.STORED
                    size = arscBytes.size.toLong()
                    compressedSize = arscBytes.size.toLong()
                    crc = CRC32().apply { update(arscBytes) }.value
                })
                zip.write(arscBytes)
                zip.closeEntry()

                zip.putNextEntry(ZipEntry("lib/arm64-v8a/libnative.so").apply {
                    method = ZipEntry.STORED
                    size = soBytes.size.toLong()
                    compressedSize = soBytes.size.toLong()
                    crc = CRC32().apply { update(soBytes) }.value
                })
                zip.write(soBytes)
                zip.closeEntry()

                zip.putNextEntry(ZipEntry("META-INF/CERT.RSA"))
                zip.write(byteArrayOf(7, 8, 9))
                zip.closeEntry()
            }

            val dsProFolder = File(tempDir, ApkFileStorageService.PROTECTED_FOLDER_NAME)
            val stagingApk = File(tempDir, "staging.apk")
            val fullConfig = ProtectionConfig(
                detectRoot = true,
                detectDebugger = true,
                antiScreenshot = true,
                antiTampering = true,
                antiDump = true,
                dexIntegrityProtection = true,
                assistEncrypt = true,
                dsProDexEncryption = true,
                stringEncryption = true,
                controlFlowObfuscation = true,
                resourceEncryption = true,
                disableDebuggable = true,
                stripDexDebug = true,
            )

            val stats = ApkProtectionProcessor.transformApkArchive(
                inputFile = inputApk,
                outputFile = stagingApk,
                analysis = sampleApk(inputApk.absolutePath),
                config = fullConfig,
                guardDexBytes = guardDex,
                coreDexBytes = coreDex,
            )

            val outputApk = ApkFileStorageService.saveFileToDirectory(
                sourceApk = stagingApk,
                targetDirectory = dsProFolder,
                fileName = ApkFileStorageService.buildProtectedFileName("com.demo.app", 123456L),
            ).getOrThrow()

            assertTrue(stats.coreProtectionInjected)
            assertEquals(2, stats.encryptedDexCount)
            assertEquals(1, stats.encryptedStringsCount)
            assertEquals(2, stats.encryptedResourceCount)
            assertEquals(2, stats.encryptedAssistCount)
            assertTrue(stats.cfoTransformedUnits >= 2)
            assertEquals(2, stats.dexIntegrityCount)
            assertEquals("classes2.dex", stats.injectedGuardDexName)
            // manifest + arsc + lib + dspro_res.bin + dspro_core.bin + core classes.dex + guard classes2.dex = 7
            assertEquals(7, stats.integrityCount)

            val (valid, _) = ApkProtectionProcessor.verifyOutputApk(outputApk)
            assertTrue(valid)

            ZipFile(outputApk).use { outZip ->
                assertArrayEquals(coreDex, outZip.getInputStream(outZip.getEntry("classes.dex")).readBytes())
                assertArrayEquals(guardDex, outZip.getInputStream(outZip.getEntry("classes2.dex")).readBytes())
                assertTrue(outZip.getEntry("classes3.dex") == null)
                assertTrue(outZip.getEntry("assets/config/app.json") == null)
                assertTrue(outZip.getEntry("assets/secret.txt") == null)
                assertTrue(outZip.getEntry("assets/dspro_res.bin") != null)
                assertTrue(outZip.entries().asSequence().none { it.name.contains("dpt", ignoreCase = true) })

                val decryptedAssets = decryptResourceVault(outZip, "com.demo.app")
                assertTrue(decryptedAssets.containsKey("AndroidManifest.xml"))
                assertEquals(3, decryptedAssets.size)
                assertArrayEquals(jsonAsset, decryptedAssets["assets/config/app.json"])
                assertArrayEquals(txtAsset, decryptedAssets["assets/secret.txt"])

                val (metaLines, decryptedList) = decryptCorePayloads(outZip, "com.demo.app")
                assertEquals("1", metaLines[4].trim()) // guard anti-removal binding enabled
                assertEquals("Z1", metaLines[5].trim()) // pre-encryption DEX compression enabled
                assertEquals("1", metaLines[6].trim()) // strict pre-decrypt anti-dump enabled
                assertEquals("S1", metaLines[7].trim()) // string encryption enabled
                assertEquals(2, metaLines[8].trim().split(",").size) // 2 inner DEX SHA-256 digests
                assertEquals(2, decryptedList.size)
                assertArrayEquals(appDex1, decryptedList[0])
                assertArrayEquals(DexPatcher.obfuscateControlFlow(appDex2).first, decryptedList[1])

                val guardBlob = outZip.getInputStream(
                    outZip.getEntry(ApkProtectionProcessor.guardConfigAssetPath("com.demo.app")),
                ).use { it.readBytes() }
                val rawText = String(guardBlob, Charsets.ISO_8859_1)
                assertFalse(rawText.contains("detectRoot"))
                assertFalse(rawText.contains("AndroidManifest.xml"))

                val guardLines = decryptGuardPolicy(outZip, "com.demo.app")
                // 1 + 16 + 32 + 64 + 256 + 512 = 881
                assertEquals("881", guardLines[0])
                assertEquals("NONE", guardLines[1])
                assertEquals("7", guardLines[2])
                val dexCountLine = guardLines[3 + 7]
                assertEquals("2", dexCountLine)
                val dexRow0 = guardLines[3 + 7 + 1]
                assertTrue(dexRow0.endsWith("|classes.dex"))

                val patchedManifest = outZip.getInputStream(outZip.getEntry("AndroidManifest.xml")).readBytes()
                val (appName, factoryName) = AxmlManifestPatcher.inspectCoreForTest(patchedManifest)
                assertEquals("com.dspro.core.DsProApplication", appName)
                assertEquals(AxmlManifestPatcher.CORE_FACTORY_CLASS, factoryName)
            }
        } finally {
            tempDir.deleteRecursively()
        }
    }

    @Test
    fun `real compiled app-debug apk transforms cleanly with real dspro core dex guard dex and aapt2 axml`() {
        val candidateApks = listOf(
            File("build/outputs/apk/debug/app-debug.apk"),
            File("app/build/outputs/apk/debug/app-debug.apk"),
        )
        val realApk = candidateApks.firstOrNull { it.exists() }
        val candidateGuardDex = listOf(
            File("build/generated/dspro_guard_assets/debug/ds_pro_guard.dex"),
            File("app/build/generated/dspro_guard_assets/debug/ds_pro_guard.dex"),
        )
        val realGuardDex = candidateGuardDex.firstOrNull { it.exists() }
        val candidateCoreDex = listOf(
            File("build/generated/dspro_guard_assets/debug/ds_pro_core.dex"),
            File("app/build/generated/dspro_guard_assets/debug/ds_pro_core.dex"),
        )
        val realCoreDex = candidateCoreDex.firstOrNull { it.exists() }
        if (realApk == null || realGuardDex == null || realCoreDex == null) return

        val guardBytes = realGuardDex.readBytes()
        val coreBytes = realCoreDex.readBytes()
        assertTrue(DexPatcher.isValidDex(guardBytes))
        assertTrue(DexPatcher.isValidDex(coreBytes))
        assertTrue(DexPatcher.containsAsciiMarker(guardBytes, "Lcom/dspro/guard/DsProGuardProvider;"))
        assertTrue(DexPatcher.containsAsciiMarker(coreBytes, "Lcom/dspro/core/DsProComponentFactory;"))
        assertTrue(DexPatcher.containsAsciiMarker(coreBytes, "Lcom/dspro/core/DsProApplication;"))
        assertTrue(DexPatcher.containsAsciiMarker(coreBytes, "Lcom/dspro/core/DsProHostClassLoader;"))
        assertFalse(DexPatcher.containsAsciiMarker(coreBytes, "Lcom/stub/StubApp;"))
        assertFalse(DexPatcher.containsAsciiMarker(guardBytes, "isEmulator"))
        assertFalse(DexPatcher.containsAsciiMarker(guardBytes, "XposedBridge"))
        // Verify compile-time XOR obfuscation hid sensitive runtime strings from plaintext DEX inspection
        assertFalse(DexPatcher.containsAsciiMarker(coreBytes, "blackdex"))
        assertFalse(DexPatcher.containsAsciiMarker(coreBytes, "/proc/self/maps"))
        assertFalse(DexPatcher.containsAsciiMarker(coreBytes, ":V5M:"))
        assertFalse(DexPatcher.containsAsciiMarker(guardBytes, "blackdex"))
        assertFalse(DexPatcher.containsAsciiMarker(guardBytes, "/proc/self/maps"))
        assertFalse(DexPatcher.containsAsciiMarker(guardBytes, ":DSPRO_GCFG_KEY:"))

        val tempDir = Files.createTempDirectory("dspro_real_apk_core_test").toFile()
        try {
            val outApk = File(tempDir, "dspro_core_protected_unsigned.apk")
            val analysis = ApkAnalysisResult(
                fileName = realApk.name,
                cachedApkPath = realApk.absolutePath,
                packageName = "com.dspro.protection",
                appName = "DS PRO",
                versionName = "1.0",
                versionCode = 1L,
                minSdk = 26,
                targetSdk = 36,
                fileSizeBytes = realApk.length(),
                totalEntries = 100,
                dexCount = 1,
                logCallMatches = 0,
                signingCertSha256 = "AA:BB:CC:DD",
                isSigned = true,
            )
            val config = ProtectionConfig(
                detectRoot = true,
                detectDebugger = true,
                antiScreenshot = true,
                antiTampering = true,
                antiDump = true,
                dexIntegrityProtection = true,
                assistEncrypt = true,
                dsProDexEncryption = true,
                stringEncryption = true,
                controlFlowObfuscation = true,
                resourceEncryption = true,
                disableDebuggable = true,
                stripDexDebug = true,
            )

            val stats = ApkProtectionProcessor.transformApkArchive(
                inputFile = realApk,
                outputFile = outApk,
                analysis = analysis,
                config = config,
                guardDexBytes = guardBytes,
                coreDexBytes = coreBytes,
            )

            assertTrue(stats.debuggableDisabled)
            assertTrue(stats.guardProviderInjected)
            assertTrue(stats.coreProtectionInjected)
            assertTrue(stats.encryptedDexCount >= 1)
            assertTrue(stats.encryptedStringsCount > 100)
            assertTrue(stats.cfoTransformedUnits > 100)
            assertTrue(stats.dexDebugItemsCleared > 0)
            assertTrue(stats.integrityCount > 0)
            assertEquals(2, stats.dexIntegrityCount)
            assertTrue(stats.protectionIdentifierEmbedded)

            val (valid, msg) = ApkProtectionProcessor.verifyOutputApk(outApk)
            assertTrue(msg, valid)

            ZipFile(outApk).use { zip ->
                val manifestBytes = zip.getInputStream(zip.getEntry("AndroidManifest.xml")).readBytes()
                val (dbg, bkp, hasProvider) = AxmlManifestPatcher.inspectForTest(manifestBytes)
                assertEquals(false, dbg)
                assertEquals(false, bkp) // source app manifest already has allowBackup="false"
                assertTrue(hasProvider)

                val (shellApp, shellFactory) = AxmlManifestPatcher.inspectCoreForTest(manifestBytes)
                assertEquals(AxmlManifestPatcher.CORE_APP_CLASS, shellApp)
                assertEquals(AxmlManifestPatcher.CORE_FACTORY_CLASS, shellFactory)

                val (metaLines, decryptedDexes) = decryptCorePayloads(zip, "com.dspro.protection")
                assertEquals("androidx.core.app.CoreComponentFactory", metaLines[2].trim())
                assertEquals("1", metaLines[4].trim())
                assertEquals("S1", metaLines[7].trim())
                assertEquals(stats.encryptedDexCount, decryptedDexes.size)
                decryptedDexes.forEach { assertTrue(DexPatcher.isValidDex(it)) }

                val summary = AxmlManifestPatcher.inspectSecuritySummary(manifestBytes)
                assertTrue(summary != null && summary.hasGuardProvider && summary.hasCoreProtection && !summary.isDebuggable)
                assertEquals("DS 专业版", summary?.protectionIdentifier)

                assertArrayEquals(coreBytes, zip.getInputStream(zip.getEntry("classes.dex")).readBytes())
                assertArrayEquals(guardBytes, zip.getInputStream(zip.getEntry("classes2.dex")).readBytes())

                // Critical regression check: self-protected DS PRO must preserve its own bundled assets/ds_pro_*.dex
                val preservedCoreEntry = zip.getEntry("assets/ds_pro_core.dex")
                val preservedGuardEntry = zip.getEntry("assets/ds_pro_guard.dex")
                assertTrue("Protected DS PRO lost assets/ds_pro_core.dex", preservedCoreEntry != null)
                assertTrue("Protected DS PRO lost assets/ds_pro_guard.dex", preservedGuardEntry != null)
                val extractedCore = zip.getInputStream(preservedCoreEntry).readBytes()
                val extractedGuard = zip.getInputStream(preservedGuardEntry).readBytes()
                assertArrayEquals(coreBytes, extractedCore)
                assertArrayEquals(guardBytes, extractedGuard)

                // Verify the self-protected DS PRO can protect another APK cleanly using those preserved assets
                val secondInput = File(tempDir, "second_target.apk")
                ZipOutputStream(FileOutputStream(secondInput)).use { targetZip ->
                    targetZip.putNextEntry(ZipEntry("AndroidManifest.xml"))
                    targetZip.write(AxmlManifestPatcher.buildMinimalManifestForTest("com.second.app", debuggable = true, allowBackup = true))
                    targetZip.closeEntry()
                    targetZip.putNextEntry(ZipEntry("classes.dex"))
                    targetZip.write(buildSyntheticDexWithStrings("Lcom/second/app/Main;", "https://second.target.example/v1"))
                    targetZip.closeEntry()
                }
                val secondOut = File(tempDir, "second_protected.apk")
                val secondStats = ApkProtectionProcessor.transformApkArchive(
                    inputFile = secondInput,
                    outputFile = secondOut,
                    analysis = sampleApk(secondInput.absolutePath).copy(packageName = "com.second.app"),
                    config = config,
                    guardDexBytes = extractedGuard,
                    coreDexBytes = extractedCore,
                )
                assertTrue(secondStats.coreProtectionInjected)
                assertTrue(secondStats.guardProviderInjected)
                assertTrue(secondStats.protectionIdentifierEmbedded)
                assertTrue(ApkProtectionProcessor.verifyOutputApk(secondOut).first)
                ZipFile(secondOut).use { secondZip ->
                    val secondManifest = secondZip.getInputStream(secondZip.getEntry("AndroidManifest.xml")).readBytes()
                    assertEquals("DS 专业版", AxmlManifestPatcher.inspectSecuritySummary(secondManifest)?.protectionIdentifier)
                }
            }

            // Re-protecting an already Core-protected APK must reject cleanly without corrupting
            val doubleOut = File(tempDir, "double_protected.apk")
            val reprotectErr = runCatching {
                ApkProtectionProcessor.transformApkArchive(
                    inputFile = outApk,
                    outputFile = doubleOut,
                    analysis = analysis.copy(cachedApkPath = outApk.absolutePath),
                    config = ProtectionConfig(disableDebuggable = true),
                )
            }.exceptionOrNull()
            assertTrue(reprotectErr is IllegalArgumentException)
            assertTrue(reprotectErr?.message?.contains("already protected", ignoreCase = true) == true)
        } finally {
            tempDir.deleteRecursively()
        }
    }

    @Test
    fun `output apk preserves 16kb so alignment 4b resource alignment stored assets and kotlin runtime metadata`() {
        val tempDir = Files.createTempDirectory("dspro_align_test").toFile()
        try {
            val inputApk = File(tempDir, "aligned_input.apk")
            val rawManifest = AxmlManifestPatcher.buildMinimalManifestForTest("com.real.target", debuggable = true, allowBackup = true)
            val appDex = buildSyntheticDex(withDebugInfo = true)
            val guardDex = buildSyntheticDex(withDebugInfo = false, descriptor = "Lcom/dspro/guard/DsProGuardProvider;")
            val coreDex = buildSyntheticDex(withDebugInfo = false, descriptor = "Lcom/dspro/core/DsProApplication;")
            val arscBytes = ByteArray(123) { 0x42 }
            val tfliteBytes = ByteArray(77) { 0x33 }
            val soBytes = ByteArray(256) { 0x7F }
            val kotlinBuiltinBytes = byteArrayOf(10, 20, 30, 40)
            val kotlinModuleBytes = byteArrayOf(50, 60, 70)

            ZipOutputStream(FileOutputStream(inputApk)).use { zip ->
                zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
                zip.write(rawManifest)
                zip.closeEntry()

                zip.putNextEntry(ZipEntry("classes.dex"))
                zip.write(appDex)
                zip.closeEntry()

                zip.putNextEntry(ZipEntry("assets/odd_name_1.txt"))
                zip.write("hello-world".toByteArray())
                zip.closeEntry()

                zip.putNextEntry(ZipEntry("resources.arsc").apply {
                    method = ZipEntry.STORED
                    size = arscBytes.size.toLong()
                    compressedSize = arscBytes.size.toLong()
                    crc = CRC32().apply { update(arscBytes) }.value
                })
                zip.write(arscBytes)
                zip.closeEntry()

                zip.putNextEntry(ZipEntry("assets/model.tflite").apply {
                    method = ZipEntry.STORED
                    size = tfliteBytes.size.toLong()
                    compressedSize = tfliteBytes.size.toLong()
                    crc = CRC32().apply { update(tfliteBytes) }.value
                })
                zip.write(tfliteBytes)
                zip.closeEntry()

                zip.putNextEntry(ZipEntry("lib/arm64-v8a/libnative.so").apply {
                    method = ZipEntry.STORED
                    size = soBytes.size.toLong()
                    compressedSize = soBytes.size.toLong()
                    crc = CRC32().apply { update(soBytes) }.value
                })
                zip.write(soBytes)
                zip.closeEntry()

                zip.putNextEntry(ZipEntry("kotlin/kotlin.kotlin_builtins"))
                zip.write(kotlinBuiltinBytes)
                zip.closeEntry()

                zip.putNextEntry(ZipEntry("META-INF/app.kotlin_module"))
                zip.write(kotlinModuleBytes)
                zip.closeEntry()
            }

            val outApk = File(tempDir, "aligned_output.apk")
            val analysisWithFallbackPkg = sampleApk(inputApk.absolutePath).copy(packageName = "unknown.package")
            val config = ProtectionConfig(
                detectRoot = true,
                antiTampering = true,
                dsProDexEncryption = true,
                resourceEncryption = true,
                disableDebuggable = true,
                stripDexDebug = true,
            )

            ApkProtectionProcessor.transformApkArchive(
                inputFile = inputApk,
                outputFile = outApk,
                analysis = analysisWithFallbackPkg,
                config = config,
                guardDexBytes = guardDex,
                coreDexBytes = coreDex,
            )

            val (valid, msg) = ApkProtectionProcessor.verifyOutputApk(outApk)
            assertTrue(msg, valid)

            val offsets = readLocalEntryDataOffsets(outApk)
            assertEquals(0L, offsets.getValue("resources.arsc") % 4L)
            assertEquals(0L, offsets.getValue("assets/model.tflite") % 4L)
            assertEquals(0L, offsets.getValue("lib/arm64-v8a/libnative.so") % 16384L)

            ZipFile(outApk).use { zip ->
                assertEquals(ZipEntry.STORED, zip.getEntry("resources.arsc").method)
                assertEquals(ZipEntry.STORED, zip.getEntry("assets/model.tflite").method)
                assertEquals(ZipEntry.STORED, zip.getEntry("lib/arm64-v8a/libnative.so").method)
                assertArrayEquals(kotlinBuiltinBytes, zip.getInputStream(zip.getEntry("kotlin/kotlin.kotlin_builtins")).readBytes())
                assertArrayEquals(kotlinModuleBytes, zip.getInputStream(zip.getEntry("META-INF/app.kotlin_module")).readBytes())

                val (_, decrypted) = decryptCorePayloads(zip, "com.real.target")
                assertEquals(1, decrypted.size)
                assertTrue(DexPatcher.isValidDex(decrypted[0]))

                // odd_name_1.txt was moved into encrypted dspro_res.bin; STORED model.tflite stays in APK
                val assetNames = zip.entries().asSequence().map { it.name }.filter { it.startsWith("assets/") }.toList()
                assertEquals(
                    listOf(
                        "assets/model.tflite",
                        "assets/dspro_core.bin",
                        "assets/dspro_guard.bin",
                        "assets/dspro_res.bin",
                    ).sorted(),
                    assetNames.sorted(),
                )
            }
        } finally {
            tempDir.deleteRecursively()
        }
    }

    @Test
    fun `binary hardening without core or resource encryption adds zero files to assets folder`() {
        val tempDir = Files.createTempDirectory("dspro_zero_assets_test").toFile()
        try {
            val inputApk = File(tempDir, "plain.apk")
            val rawManifest = AxmlManifestPatcher.buildMinimalManifestForTest("com.clean.app", debuggable = true, allowBackup = true)
            val appDex = buildSyntheticDexWithControlFlow()

            ZipOutputStream(FileOutputStream(inputApk)).use { zip ->
                zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
                zip.write(rawManifest)
                zip.closeEntry()
                zip.putNextEntry(ZipEntry("classes.dex"))
                zip.write(appDex)
                zip.closeEntry()
            }

            val outApk = File(tempDir, "hardened_only.apk")
            val stats = ApkProtectionProcessor.transformApkArchive(
                inputFile = inputApk,
                outputFile = outApk,
                analysis = sampleApk(inputApk.absolutePath).copy(packageName = "com.clean.app"),
                config = ProtectionConfig(
                    controlFlowObfuscation = true,
                    disableDebuggable = true,
                    stripDexDebug = true,
                ),
            )

            assertTrue(stats.protectionIdentifierEmbedded)
            ZipFile(outApk).use { zip ->
                val assetEntries = zip.entries().asSequence().filter { it.name.startsWith("assets/") }.toList()
                assertTrue(assetEntries.isEmpty())
                val manifestBytes = zip.getInputStream(zip.getEntry("AndroidManifest.xml")).readBytes()
                val summary = AxmlManifestPatcher.inspectSecuritySummary(manifestBytes)
                assertEquals("DS 专业版", summary?.protectionIdentifier)
            }
        } finally {
            tempDir.deleteRecursively()
        }
    }

    @Test
    fun `protection identifier updates cleanly on repatch without breaking manifest or duplicating metadata`() {
        val rawManifest = AxmlManifestPatcher.buildMinimalManifestForTest(
            packageName = "com.demo.identifier",
            debuggable = true,
            allowBackup = true,
        )
        val firstPatch = AxmlManifestPatcher.patch(
            rawManifest,
            AxmlPatchOptions(
                protectionIdentifier = "DS Legacy",
                packageName = "com.demo.identifier",
            ),
        )
        assertTrue(firstPatch.protectionIdentifierEmbedded)
        assertEquals(
            "DS Legacy",
            AxmlManifestPatcher.inspectSecuritySummary(firstPatch.manifestBytes)?.protectionIdentifier,
        )

        val secondPatch = AxmlManifestPatcher.patch(
            firstPatch.manifestBytes,
            AxmlPatchOptions(
                disableDebuggable = true,
                protectionIdentifier = AxmlManifestPatcher.PROTECTION_IDENTIFIER_VALUE,
                packageName = "com.demo.identifier",
            ),
        )
        assertTrue(secondPatch.protectionIdentifierEmbedded)
        assertTrue(secondPatch.debuggableDisabled)
        val summary = AxmlManifestPatcher.inspectSecuritySummary(secondPatch.manifestBytes)
        assertEquals("com.demo.identifier", summary?.packageName)
        assertEquals(false, summary?.isDebuggable)
        assertEquals("DS 专业版", summary?.protectionIdentifier)
    }

    private fun readLocalEntryDataOffsets(apkFile: File): Map<String, Long> {
        val bytes = apkFile.readBytes()
        val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        var eocdOff = -1
        for (i in (bytes.size - 22) downTo 0) {
            if (buf.getInt(i) == 0x06054b50) {
                eocdOff = i
                break
            }
        }
        assertTrue("Missing EOCD", eocdOff >= 0)
        val cdSize = buf.getInt(eocdOff + 12)
        val cdOffset = buf.getInt(eocdOff + 16)
        val result = linkedMapOf<String, Long>()
        var pos = cdOffset
        while (pos < cdOffset + cdSize) {
            assertEquals(0x02014b50, buf.getInt(pos))
            val cdNameLen = buf.getShort(pos + 28).toInt() and 0xFFFF
            val cdExtraLen = buf.getShort(pos + 30).toInt() and 0xFFFF
            val cdCommentLen = buf.getShort(pos + 32).toInt() and 0xFFFF
            val lfhOffset = buf.getInt(pos + 42)
            val name = String(bytes, pos + 46, cdNameLen, Charsets.UTF_8)

            assertEquals(0x04034b50, buf.getInt(lfhOffset))
            val lfhNameLen = buf.getShort(lfhOffset + 26).toInt() and 0xFFFF
            val lfhExtraLen = buf.getShort(lfhOffset + 28).toInt() and 0xFFFF
            assertTrue("Truncated LFH extra for $name", lfhExtraLen == 0 || lfhExtraLen >= 4)
            result[name] = lfhOffset.toLong() + 30L + lfhNameLen + lfhExtraLen

            pos += 46 + cdNameLen + cdExtraLen + cdCommentLen
        }
        return result
    }

    @Test
    fun `formatBytes renders readable sizes`() {
        assertEquals("512 B", formatBytes(512))
        assertTrue(formatBytes(2048).contains("KB"))
        assertTrue(formatBytes(4 * 1024 * 1024L).contains("MB"))
    }

    @Test
    fun `refresh state disables start temporarily and preserves selected apk and toggles`() {
        val activeState = DsProUiState(
            selectedApkUri = "content://downloads/demo.apk",
            selectedApk = sampleApk(),
            config = ProtectionConfig(
                detectRoot = true,
                dsProDexEncryption = true,
                disableDebuggable = true,
                antiTampering = true,
            ),
            progress = 100,
        )
        assertTrue(activeState.isStartEnabled)
        assertEquals(4, activeState.config.activeToggleCount)

        val refreshingState = activeState.copy(
            isRefreshing = true,
            progress = 0,
            steps = emptyList(),
            runResult = null,
        )
        assertFalse(refreshingState.isStartEnabled)
        assertEquals("content://downloads/demo.apk", refreshingState.selectedApkUri)
        assertEquals(4, refreshingState.config.activeToggleCount)

        val completedRefresh = refreshingState.copy(
            isRefreshing = false,
            statusMessage = "Reloaded demo.apk",
        )
        assertTrue(completedRefresh.isStartEnabled)
        assertEquals("Reloaded demo.apk", completedRefresh.statusMessage)
    }

    @Test
    fun `runtime guard toggles emit exact policy bitmasks and guard-plus-resource survives subsequent hardening`() {
        val tempDir = Files.createTempDirectory("dspro_guard_bitmask_test").toFile()
        try {
            val inputApk = File(tempDir, "input.apk")
            val rawManifest = AxmlManifestPatcher.buildMinimalManifestForTest("com.guard.bitmask", debuggable = true, allowBackup = true)
            val appDex = buildSyntheticDex(withDebugInfo = false)
            val guardDex = buildSyntheticDex(withDebugInfo = false, descriptor = "Lcom/dspro/guard/DsProGuardProvider;")
            val txtAsset = "guard-secret-asset".toByteArray(Charsets.UTF_8)

            ZipOutputStream(FileOutputStream(inputApk)).use { zip ->
                zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
                zip.write(rawManifest)
                zip.closeEntry()
                zip.putNextEntry(ZipEntry("classes.dex"))
                zip.write(appDex)
                zip.closeEntry()
                zip.putNextEntry(ZipEntry("assets/secret.txt"))
                zip.write(txtAsset)
                zip.closeEntry()
            }

            val bitmaskCases = listOf(
                ProtectionConfig(detectRoot = true) to "1",
                ProtectionConfig(detectDebugger = true) to "16",
                ProtectionConfig(antiScreenshot = true) to "32",
                ProtectionConfig(antiTampering = true) to "64",
                ProtectionConfig(antiDump = true) to "256",
                ProtectionConfig(dexIntegrityProtection = true) to "512",
                ProtectionConfig(assistEncrypt = true) to "0",
            )

            bitmaskCases.forEachIndexed { idx, (cfg, expectedMask) ->
                val out = File(tempDir, "mask_$idx.apk")
                ApkProtectionProcessor.transformApkArchive(
                    inputFile = inputApk,
                    outputFile = out,
                    analysis = sampleApk(inputApk.absolutePath).copy(packageName = "com.guard.bitmask"),
                    config = cfg,
                    guardDexBytes = guardDex,
                )
                ZipFile(out).use { zip ->
                    val guardLines = decryptGuardPolicy(zip, "com.guard.bitmask")
                    assertEquals("Mismatch for case #$idx", expectedMask, guardLines[0])
                }
            }

            val guardPlusResApk = File(tempDir, "guard_res.apk")
            ApkProtectionProcessor.transformApkArchive(
                inputFile = inputApk,
                outputFile = guardPlusResApk,
                analysis = sampleApk(inputApk.absolutePath).copy(packageName = "com.guard.bitmask"),
                config = ProtectionConfig(detectRoot = true, resourceEncryption = true),
                guardDexBytes = guardDex,
            )

            val hardenedFollowupApk = File(tempDir, "guard_res_hardened.apk")
            val followupStats = ApkProtectionProcessor.transformApkArchive(
                inputFile = guardPlusResApk,
                outputFile = hardenedFollowupApk,
                analysis = sampleApk(guardPlusResApk.absolutePath).copy(packageName = "com.guard.bitmask"),
                config = ProtectionConfig(disableDebuggable = true),
            )

            assertTrue(followupStats.debuggableDisabled)
            assertTrue(ApkProtectionProcessor.verifyOutputApk(hardenedFollowupApk).first)
            ZipFile(hardenedFollowupApk).use { zip ->
                assertTrue(zip.getEntry("classes2.dex") != null)
                assertTrue(zip.getEntry(ApkProtectionProcessor.guardConfigAssetPath("com.guard.bitmask")) != null)
                assertTrue(zip.getEntry(ApkProtectionProcessor.resourceVaultAssetPath("com.guard.bitmask")) != null)
                val guardLines = decryptGuardPolicy(zip, "com.guard.bitmask")
                assertEquals("1", guardLines[0])
                val decryptedAssets = decryptResourceVault(zip, "com.guard.bitmask")
                assertArrayEquals(txtAsset, decryptedAssets["assets/secret.txt"])
            }
        } finally {
            tempDir.deleteRecursively()
        }
    }

    @Test
    fun `every individual protection toggle increments its exact section count and dependency flags`() {
        val upperCases = listOf(
            ProtectionConfig(detectRoot = true) to Pair(true, true),
            ProtectionConfig(detectDebugger = true) to Pair(true, true),
            ProtectionConfig(antiScreenshot = true) to Pair(true, true),
            ProtectionConfig(antiTampering = true) to Pair(true, true),
            ProtectionConfig(antiDump = true) to Pair(true, true),
            ProtectionConfig(dexIntegrityProtection = true) to Pair(true, true),
            ProtectionConfig(assistEncrypt = true) to Pair(false, true),
        )
        upperCases.forEach { (cfg, expected) ->
            val (needsRuntimeGuard, needsGuardDex) = expected
            assertEquals(1, cfg.activeToggleCount)
            assertEquals(1, cfg.activeCountFor(ProtectionSection.RUNTIME_GUARD))
            assertEquals(0, cfg.activeCountFor(ProtectionSection.BINARY_HARDENING))
            assertEquals(needsRuntimeGuard, cfg.requiresRuntimeGuard)
            assertEquals(needsGuardDex, cfg.requiresGuardDex)
            assertFalse(cfg.requiresCoreDexContainer)
        }

        val lowerCases = listOf(
            Triple(ProtectionConfig(dsProDexEncryption = true), false, true),
            Triple(ProtectionConfig(stringEncryption = true), false, true),
            Triple(ProtectionConfig(controlFlowObfuscation = true), false, false),
            Triple(ProtectionConfig(resourceEncryption = true), true, false),
            Triple(ProtectionConfig(disableDebuggable = true), false, false),
            Triple(ProtectionConfig(stripDexDebug = true), false, false),
        )
        lowerCases.forEach { (cfg, needsGuardDex, needsCoreDex) ->
            assertEquals(1, cfg.activeToggleCount)
            assertEquals(0, cfg.activeCountFor(ProtectionSection.RUNTIME_GUARD))
            assertEquals(1, cfg.activeCountFor(ProtectionSection.BINARY_HARDENING))
            assertFalse(cfg.requiresRuntimeGuard)
            assertEquals(needsGuardDex, cfg.requiresGuardDex)
            assertEquals(needsCoreDex, cfg.requiresCoreDexContainer)
        }
    }

    @Test
    fun `assist encrypt seals stored xml zip json and db files while keeping flutter and native assets untouched`() {
        val tempDir = Files.createTempDirectory("dspro_assist_encrypt_test").toFile()
        try {
            val inputApk = File(tempDir, "assist_target.apk")
            val rawManifest = AxmlManifestPatcher.buildMinimalManifestForTest("com.assist.target", debuggable = true, allowBackup = true)
            val appDex = buildSyntheticDex(withDebugInfo = false)
            val guardDex = buildSyntheticDex(withDebugInfo = false, descriptor = "Lcom/dspro/guard/DsProGuardProvider;")

            val storedXml = "<config><feature enabled=\"true\"/></config>".toByteArray(Charsets.UTF_8)
            val nestedZipBytes = ByteArrayOutputStream().apply {
                ZipOutputStream(this).use { inner ->
                    inner.putNextEntry(ZipEntry("rules/patch.json"))
                    inner.write("""{"unlock":false}""".toByteArray(Charsets.UTF_8))
                    inner.closeEntry()
                }
            }.toByteArray()
            val deflatedJson = """{"endpoint":"https://config.target/v1"}""".toByteArray(Charsets.UTF_8)
            val deflatedDb = byteArrayOf(0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6F, 0x72, 0x6D, 0x61, 0x74, 0x20, 0x33, 0x00)
            val flutterBlob = byteArrayOf(0x01, 0x02, 0x03, 0x04)
            val tfliteBlob = byteArrayOf(0x11, 0x22, 0x33, 0x44)

            ZipOutputStream(FileOutputStream(inputApk)).use { zip ->
                zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
                zip.write(rawManifest)
                zip.closeEntry()

                zip.putNextEntry(ZipEntry("classes.dex"))
                zip.write(appDex)
                zip.closeEntry()

                zip.putNextEntry(ZipEntry("assets/config/rules.xml").apply {
                    method = ZipEntry.STORED
                    size = storedXml.size.toLong()
                    compressedSize = storedXml.size.toLong()
                    crc = CRC32().apply { update(storedXml) }.value
                })
                zip.write(storedXml)
                zip.closeEntry()

                zip.putNextEntry(ZipEntry("assets/bundle/patch.zip").apply {
                    method = ZipEntry.STORED
                    size = nestedZipBytes.size.toLong()
                    compressedSize = nestedZipBytes.size.toLong()
                    crc = CRC32().apply { update(nestedZipBytes) }.value
                })
                zip.write(nestedZipBytes)
                zip.closeEntry()

                zip.putNextEntry(ZipEntry("assets/settings.json"))
                zip.write(deflatedJson)
                zip.closeEntry()

                zip.putNextEntry(ZipEntry("assets/data/game.db"))
                zip.write(deflatedDb)
                zip.closeEntry()

                zip.putNextEntry(ZipEntry("assets/flutter_assets/kernel_blob.bin"))
                zip.write(flutterBlob)
                zip.closeEntry()

                zip.putNextEntry(ZipEntry("assets/model.tflite").apply {
                    method = ZipEntry.STORED
                    size = tfliteBlob.size.toLong()
                    compressedSize = tfliteBlob.size.toLong()
                    crc = CRC32().apply { update(tfliteBlob) }.value
                })
                zip.write(tfliteBlob)
                zip.closeEntry()
            }

            val outApk = File(tempDir, "assist_protected.apk")
            val stats = ApkProtectionProcessor.transformApkArchive(
                inputFile = inputApk,
                outputFile = outApk,
                analysis = sampleApk(inputApk.absolutePath).copy(packageName = "com.assist.target"),
                config = ProtectionConfig(assistEncrypt = true),
                guardDexBytes = guardDex,
            )

            assertEquals(4, stats.encryptedAssistCount)
            assertTrue(stats.guardProviderInjected)
            assertTrue(ApkProtectionProcessor.verifyOutputApk(outApk).first)

            ZipFile(outApk).use { zip ->
                // Plain editable files are no longer exposed in assets/
                assertTrue(zip.getEntry("assets/config/rules.xml") == null)
                assertTrue(zip.getEntry("assets/bundle/patch.zip") == null)
                assertTrue(zip.getEntry("assets/settings.json") == null)
                assertTrue(zip.getEntry("assets/data/game.db") == null)

                // Engine / ML assets remain untouched in APK
                assertArrayEquals(flutterBlob, zip.getInputStream(zip.getEntry("assets/flutter_assets/kernel_blob.bin")).readBytes())
                assertArrayEquals(tfliteBlob, zip.getInputStream(zip.getEntry("assets/model.tflite")).readBytes())
                assertTrue(zip.getEntry("assets/dspro_res.bin") != null)

                // Manifest keeps original allowBackup intact and embeds DsProGuardProvider
                val outManifest = zip.getInputStream(zip.getEntry("AndroidManifest.xml")).readBytes()
                val summary = AxmlManifestPatcher.inspectSecuritySummary(outManifest)
                assertTrue(summary?.allowsBackup == true)
                assertTrue(summary?.hasGuardProvider == true)

                // Decrypt the dspro_res.bin vault APK and verify STORED compression methods + exact contents
                val vaultBlob = zip.getInputStream(zip.getEntry("assets/dspro_res.bin")).use { it.readBytes() }
                val salt = vaultBlob.copyOfRange(0, 16)
                val iv = vaultBlob.copyOfRange(16, 28)
                val saltHex = salt.joinToString("") { "%02x".format(it) }
                val key = MessageDigest.getInstance("SHA-256").digest("com.assist.target:DSPRO_RES_V1:$saltHex".toByteArray(Charsets.UTF_8))
                val plainVaultApk = Cipher.getInstance("AES/GCM/NoPadding").run {
                    init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
                    doFinal(vaultBlob, 28, vaultBlob.size - 28)
                }
                val vaultFile = File(tempDir, "decrypted_vault.apk").apply { writeBytes(plainVaultApk) }
                ZipFile(vaultFile).use { vaultZip ->
                    assertTrue(vaultZip.getEntry("AndroidManifest.xml") != null)
                    assertEquals(ZipEntry.STORED, vaultZip.getEntry("assets/config/rules.xml").method)
                    assertEquals(ZipEntry.STORED, vaultZip.getEntry("assets/bundle/patch.zip").method)
                    assertEquals(ZipEntry.DEFLATED, vaultZip.getEntry("assets/settings.json").method)
                    assertEquals(ZipEntry.DEFLATED, vaultZip.getEntry("assets/data/game.db").method)
                    assertArrayEquals(storedXml, vaultZip.getInputStream(vaultZip.getEntry("assets/config/rules.xml")).readBytes())
                    assertArrayEquals(nestedZipBytes, vaultZip.getInputStream(vaultZip.getEntry("assets/bundle/patch.zip")).readBytes())
                    assertArrayEquals(deflatedJson, vaultZip.getInputStream(vaultZip.getEntry("assets/settings.json")).readBytes())
                    assertArrayEquals(deflatedDb, vaultZip.getInputStream(vaultZip.getEntry("assets/data/game.db")).readBytes())
                }
            }
        } finally {
            tempDir.deleteRecursively()
        }
    }

    @Test
    fun `transform emits monotonically increasing stage progress and manual export state defaults clean`() {
        val tempDir = Files.createTempDirectory("dspro_stage_progress_test").toFile()
        try {
            val inputApk = File(tempDir, "target.apk")
            val rawManifest = AxmlManifestPatcher.buildMinimalManifestForTest("com.stage.progress", debuggable = true, allowBackup = true)
            val appDex = buildSyntheticDexWithStrings("Lcom/stage/progress/App;", "https://stage.example/api")
            val coreDex = buildSyntheticDex(withDebugInfo = false, descriptor = "Lcom/dspro/core/DsProApplication;")
            val guardDex = buildSyntheticDex(withDebugInfo = false, descriptor = "Lcom/dspro/guard/DsProGuardProvider;")

            ZipOutputStream(FileOutputStream(inputApk)).use { zip ->
                zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
                zip.write(rawManifest)
                zip.closeEntry()
                zip.putNextEntry(ZipEntry("classes.dex"))
                zip.write(appDex)
                zip.closeEntry()
                zip.putNextEntry(ZipEntry("assets/data.json"))
                zip.write("""{"ok":true}""".toByteArray())
                zip.closeEntry()
            }

            val stages = mutableListOf<Pair<Int, String>>()
            val outApk = File(tempDir, "out.apk")
            ApkProtectionProcessor.transformApkArchive(
                inputFile = inputApk,
                outputFile = outApk,
                analysis = sampleApk(inputApk.absolutePath).copy(packageName = "com.stage.progress"),
                config = ProtectionConfig(
                    detectRoot = true,
                    dsProDexEncryption = true,
                    stringEncryption = true,
                    resourceEncryption = true,
                    disableDebuggable = true,
                ),
                guardDexBytes = guardDex,
                coreDexBytes = coreDex,
                onStageProgress = { pct, label -> stages += pct to label },
            )

            assertTrue("Expected at least 5 live stage callbacks", stages.size >= 5)
            for (i in 1 until stages.size) {
                assertTrue(
                    "Progress must never decrease: ${stages[i - 1]} -> ${stages[i]}",
                    stages[i].first >= stages[i - 1].first,
                )
            }
            assertTrue(stages.all { it.second.isNotBlank() })

            val state = DsProUiState(
                selectedApkUri = "content://demo.apk",
                selectedApk = sampleApk(),
                isProcessing = true,
                progress = 72,
                activeStageDetail = stages.last().second,
            )
            assertFalse(state.isExported)
            assertEquals(null, state.exportedSizeBytes)
        } finally {
            tempDir.deleteRecursively()
        }
    }
}


