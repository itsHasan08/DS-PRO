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
import java.io.File
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files
import java.security.MessageDigest
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
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

    private fun decryptDptPayloads(zip: ZipFile, packageName: String): Pair<List<String>, List<ByteArray>> {
        val containerName = ApkProtectionProcessor.dptContainerAssetPath(packageName)
        val entry = zip.getEntry(containerName)
            ?: throw AssertionError("Missing encrypted DPT container $containerName")
        zip.getInputStream(entry).use { rawIn ->
            java.io.DataInputStream(rawIn).use { dis ->
                val salt = ByteArray(16).also { dis.readFully(it) }
                val metaIv = ByteArray(12).also { dis.readFully(it) }
                val metaLen = dis.readInt()
                val metaCipher = ByteArray(metaLen).also { dis.readFully(it) }

                val saltHex = salt.joinToString("") { "%02x".format(it) }
                val metaKey = MessageDigest.getInstance("SHA-256").digest(
                    "$packageName:DSPRO_DPT_META_V2:$saltHex".toByteArray(Charsets.UTF_8),
                )
                val metaPlain = Cipher.getInstance("AES/GCM/NoPadding").run {
                    init(Cipher.DECRYPT_MODE, SecretKeySpec(metaKey, "AES"), GCMParameterSpec(128, metaIv))
                    String(doFinal(metaCipher), Charsets.UTF_8)
                }
                val lines = metaPlain.split("\n")
                val dexCount = lines[0].trim().toInt()
                val aesKeyHex = lines[3].trim()
                val aesKey = ByteArray(aesKeyHex.length / 2) { i ->
                    ((Character.digit(aesKeyHex[i * 2], 16) shl 4) +
                        Character.digit(aesKeyHex[i * 2 + 1], 16)).toByte()
                }
                val keySpec = SecretKeySpec(aesKey, "AES")
                val dexList = (0 until dexCount).map {
                    val iv = ByteArray(12).also { dis.readFully(it) }
                    val cLen = dis.readInt()
                    val enc = ByteArray(cLen).also { dis.readFully(it) }
                    Cipher.getInstance("AES/GCM/NoPadding").run {
                        init(Cipher.DECRYPT_MODE, keySpec, GCMParameterSpec(128, iv))
                        doFinal(enc)
                    }
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

    @Test
    fun `default config starts with zero active options and start disabled`() {
        val defaultCfg = ProtectionConfig()
        assertEquals(0, defaultCfg.activeToggleCount)
        assertFalse(defaultCfg.requiresRuntimeGuard)
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
        assertFalse(DsProUiState(config = ProtectionConfig(dptDexEncryption = true)).isStartEnabled)
        assertTrue(
            DsProUiState(
                selectedApkUri = "content://downloads/demo.apk",
                selectedApk = sampleApk(),
                config = ProtectionConfig(dptDexEncryption = true),
            ).isStartEnabled,
        )
        assertTrue(
            DsProUiState(
                selectedApkUri = "content://downloads/demo.apk",
                selectedApk = sampleApk(),
                config = ProtectionConfig(detectRoot = true),
            ).isStartEnabled,
        )
        assertFalse(
            DsProUiState(
                selectedApkUri = "content://downloads/demo.apk",
                selectedApk = sampleApk(),
                config = ProtectionConfig(dptDexEncryption = true),
                isProcessing = true,
            ).isStartEnabled,
        )
    }

    @Test
    fun `section active counts match enabled real toggles`() {
        val cfg = ProtectionConfig(
            detectRoot = true,
            antiScreenshot = true,
            antiTampering = true,
            dptDexEncryption = true,
            disableDebuggable = true,
            stripDexDebug = true,
        )
        assertEquals(3, cfg.activeCountFor(ProtectionSection.RUNTIME_GUARD))
        assertEquals(3, cfg.activeCountFor(ProtectionSection.BINARY_HARDENING))
        assertEquals(6, cfg.activeToggleCount)
    }

    @Test
    fun `axml manifest patcher disables debuggable backup and injects guard plus dpt shell`() {
        val rawManifest = AxmlManifestPatcher.buildMinimalManifestForTest(
            packageName = "com.demo.app",
            debuggable = true,
            allowBackup = true,
        )
        val patched = AxmlManifestPatcher.patch(
            rawManifest,
            AxmlPatchOptions(
                disableDebuggable = true,
                disableBackup = true,
                injectGuardProvider = true,
                enableDptShell = true,
                packageName = "com.demo.app",
            ),
        )
        assertTrue(patched.debuggableDisabled)
        assertTrue(patched.backupDisabled)
        assertTrue(patched.guardProviderInjected)
        assertTrue(patched.dptShellInjected)

        val verified = AxmlManifestPatcher.inspectForTest(patched.manifestBytes)
        assertEquals(false, verified.first)
        assertEquals(false, verified.second)
        assertTrue(verified.third)

        val (appName, factoryName) = AxmlManifestPatcher.inspectDptForTest(patched.manifestBytes)
        assertEquals(AxmlManifestPatcher.DPT_SHELL_APP_CLASS, appName)
        assertEquals(AxmlManifestPatcher.DPT_SHELL_FACTORY_CLASS, factoryName)
    }

    @Test
    fun `dex patcher strips source file and debug info and updates checksums`() {
        val dex = buildSyntheticDex(withDebugInfo = true)
        val (stripped, stats) = DexPatcher.stripDebugInfo(dex)

        assertEquals(1, stats.sourceFilesCleared)
        assertEquals(1, stats.debugInfosCleared)

        val buf = ByteBuffer.wrap(stripped).order(ByteOrder.LITTLE_ENDIAN)
        assertEquals(-1, buf.getInt(112 + 16))
        assertEquals(0, buf.getInt(160 + 8))

        val (_, secondStats) = DexPatcher.stripDebugInfo(stripped)
        assertEquals(0, secondStats.sourceFilesCleared)
        assertEquals(0, secondStats.debugInfosCleared)
    }

    @Test
    fun `dpt encryption encrypts all dex payloads with AES-256-GCM and replaces classes dex`() {
        val tempDir = Files.createTempDirectory("dspro_dpt_test").toFile()
        try {
            val inputApk = File(tempDir, "sample.apk")
            val rawManifest = AxmlManifestPatcher.buildMinimalManifestForTest("com.demo.app", debuggable = true, allowBackup = true)
            val appDex1 = buildSyntheticDex(withDebugInfo = true)
            val appDex2 = buildSyntheticDex(withDebugInfo = true, descriptor = "Lcom/demo/app/Feature;")
            val guardDex = buildSyntheticDex(withDebugInfo = false, descriptor = "Lcom/dspro/guard/DsProGuardProvider;")
            val dptShellDex = buildSyntheticDex(withDebugInfo = false, descriptor = "Lcom/dspro/dpt/DsProShellApplication;")
            val arscBytes = ByteArray(64) { 0x42 }
            val soBytes = ByteArray(64) { 0x7F }

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

                zip.putNextEntry(ZipEntry("DebugProbesKt.bin"))
                zip.write(byteArrayOf(1, 2, 3))
                zip.closeEntry()

                zip.putNextEntry(ZipEntry("META-INF/CERT.RSA"))
                zip.write(byteArrayOf(7, 8, 9))
                zip.closeEntry()
            }

            val dsProFolder = File(tempDir, ApkFileStorageService.PROTECTED_FOLDER_NAME)
            val stagingApk = File(tempDir, "staging.apk")
            val fullConfig = ProtectionConfig(
                detectRoot = true,
                detectEmulator = true,
                detectVpn = true,
                detectXposed = true,
                detectDebugger = true,
                antiScreenshot = true,
                antiTampering = true,
                signaturePinning = true,
                dptDexEncryption = true,
                disableDebuggable = true,
                disableBackup = true,
                stripDexDebug = true,
                stripMetadataBloat = true,
                bestCompression = true,
            )

            val stats = ApkProtectionProcessor.transformApkArchive(
                inputFile = inputApk,
                outputFile = stagingApk,
                analysis = sampleApk(inputApk.absolutePath),
                config = fullConfig,
                guardDexBytes = guardDex,
                dptShellDexBytes = dptShellDex,
            )

            val outputApk = ApkFileStorageService.saveFileToDirectory(
                sourceApk = stagingApk,
                targetDirectory = dsProFolder,
                fileName = ApkFileStorageService.buildProtectedFileName("com.demo.app", 123456L),
            ).getOrThrow()

            assertTrue(stats.dptShellInjected)
            assertEquals(2, stats.encryptedDexCount)
            assertEquals("classes2.dex", stats.injectedGuardDexName)
            assertEquals(4, stats.dexDebugItemsCleared)
            assertEquals(1, stats.strippedBloatCount)
            // manifest + arsc + lib + single dpt container + shell classes.dex + guard classes2.dex = 6
            assertEquals(6, stats.integrityCount)

            val (valid, _) = ApkProtectionProcessor.verifyOutputApk(outputApk)
            assertTrue(valid)

            ZipFile(outputApk).use { outZip ->
                assertArrayEquals(dptShellDex, outZip.getInputStream(outZip.getEntry("classes.dex")).readBytes())
                assertArrayEquals(guardDex, outZip.getInputStream(outZip.getEntry("classes2.dex")).readBytes())
                assertTrue(outZip.getEntry("classes3.dex") == null)
                assertTrue(outZip.getEntry("assets/ds_pro_security_config.json") == null)
                assertTrue(outZip.getEntry("assets/ds_pro_integrity.sha256") == null)
                assertTrue(outZip.getEntry("assets/ds_pro_dpt.idx") == null)

                val (_, decryptedList) = decryptDptPayloads(outZip, "com.demo.app")
                assertEquals(2, decryptedList.size)
                assertArrayEquals(DexPatcher.stripDebugInfo(appDex1).first, decryptedList[0])
                assertArrayEquals(DexPatcher.stripDebugInfo(appDex2).first, decryptedList[1])

                val guardBlob = outZip.getInputStream(
                    outZip.getEntry(ApkProtectionProcessor.guardConfigAssetPath("com.demo.app")),
                ).use { it.readBytes() }
                val rawText = String(guardBlob, Charsets.ISO_8859_1)
                assertFalse(rawText.contains("detectRoot"))
                assertFalse(rawText.contains("AndroidManifest.xml"))

                val guardLines = decryptGuardPolicy(outZip, "com.demo.app")
                assertEquals("255", guardLines[0]) // all 8 runtime flags enabled
                assertEquals("AB:CD:EF", guardLines[1])
                assertEquals("6", guardLines[2])

                val patchedManifest = outZip.getInputStream(outZip.getEntry("AndroidManifest.xml")).readBytes()
                val (appName, factoryName) = AxmlManifestPatcher.inspectDptForTest(patchedManifest)
                assertEquals(AxmlManifestPatcher.DPT_SHELL_APP_CLASS, appName)
                assertEquals(AxmlManifestPatcher.DPT_SHELL_FACTORY_CLASS, factoryName)
            }
        } finally {
            tempDir.deleteRecursively()
        }
    }

    @Test
    fun `real compiled app-debug apk transforms cleanly with real DPT shell dex guard dex and aapt2 axml`() {
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
        val candidateDptDex = listOf(
            File("build/generated/dspro_guard_assets/debug/ds_pro_dpt_shell.dex"),
            File("app/build/generated/dspro_guard_assets/debug/ds_pro_dpt_shell.dex"),
        )
        val realDptDex = candidateDptDex.firstOrNull { it.exists() }
        if (realApk == null || realGuardDex == null || realDptDex == null) return

        val guardBytes = realGuardDex.readBytes()
        val dptBytes = realDptDex.readBytes()
        assertTrue(DexPatcher.isValidDex(guardBytes))
        assertTrue(DexPatcher.isValidDex(dptBytes))
        assertTrue(DexPatcher.containsAsciiMarker(guardBytes, "Lcom/dspro/guard/DsProGuardProvider;"))
        assertTrue(DexPatcher.containsAsciiMarker(dptBytes, "Lcom/dspro/dpt/DsProAppComponentFactory;"))
        assertTrue(DexPatcher.containsAsciiMarker(dptBytes, "Lcom/dspro/dpt/DsProShellApplication;"))

        val tempDir = Files.createTempDirectory("dspro_real_apk_dpt_test").toFile()
        try {
            val outApk = File(tempDir, "dspro_dpt_protected_unsigned.apk")
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
                detectEmulator = true,
                detectVpn = true,
                detectXposed = true,
                detectDebugger = true,
                antiScreenshot = true,
                antiTampering = true,
                signaturePinning = true,
                dptDexEncryption = true,
                disableDebuggable = true,
                disableBackup = true,
                stripDexDebug = true,
                stripMetadataBloat = true,
                bestCompression = true,
            )

            val stats = ApkProtectionProcessor.transformApkArchive(
                inputFile = realApk,
                outputFile = outApk,
                analysis = analysis,
                config = config,
                guardDexBytes = guardBytes,
                dptShellDexBytes = dptBytes,
            )

            assertTrue(stats.debuggableDisabled)
            assertTrue(stats.backupDisabled)
            assertTrue(stats.guardProviderInjected)
            assertTrue(stats.dptShellInjected)
            assertTrue(stats.encryptedDexCount >= 1)
            assertTrue(stats.dexDebugItemsCleared > 0)
            assertTrue(stats.integrityCount > 0)

            val (valid, msg) = ApkProtectionProcessor.verifyOutputApk(outApk)
            assertTrue(msg, valid)

            ZipFile(outApk).use { zip ->
                val manifestBytes = zip.getInputStream(zip.getEntry("AndroidManifest.xml")).readBytes()
                val (dbg, bkp, hasProvider) = AxmlManifestPatcher.inspectForTest(manifestBytes)
                assertEquals(false, dbg)
                assertEquals(false, bkp)
                assertTrue(hasProvider)

                val (shellApp, shellFactory) = AxmlManifestPatcher.inspectDptForTest(manifestBytes)
                assertEquals(AxmlManifestPatcher.DPT_SHELL_APP_CLASS, shellApp)
                assertEquals(AxmlManifestPatcher.DPT_SHELL_FACTORY_CLASS, shellFactory)

                val (metaLines, decryptedDexes) = decryptDptPayloads(zip, "com.dspro.protection")
                assertEquals("androidx.core.app.CoreComponentFactory", metaLines[2].trim())
                assertEquals(stats.encryptedDexCount, decryptedDexes.size)
                decryptedDexes.forEach { assertTrue(DexPatcher.isValidDex(it)) }

                val summary = AxmlManifestPatcher.inspectSecuritySummary(manifestBytes)
                assertTrue(summary != null && summary.hasGuardProvider && summary.hasDptShell && !summary.isDebuggable && !summary.allowsBackup)

                assertArrayEquals(dptBytes, zip.getInputStream(zip.getEntry("classes.dex")).readBytes())
                assertArrayEquals(guardBytes, zip.getInputStream(zip.getEntry("classes2.dex")).readBytes())
            }
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
            val dptShellDex = buildSyntheticDex(withDebugInfo = false, descriptor = "Lcom/dspro/dpt/DsProShellApplication;")
            val arscBytes = ByteArray(123) { 0x42 }
            val tfliteBytes = ByteArray(77) { 0x33 }
            val soBytes = ByteArray(256) { 0x7F }
            val kotlinBuiltinBytes = byteArrayOf(10, 20, 30, 40)
            val kotlinModuleBytes = byteArrayOf(50, 60, 70)

            ZipOutputStream(FileOutputStream(inputApk)).use { zip ->
                // Put some odd-length deflated entries before resources/libs to guarantee unaligned start offsets
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

                zip.putNextEntry(ZipEntry("DebugProbesKt.bin"))
                zip.write(byteArrayOf(1, 2, 3))
                zip.closeEntry()
            }

            val outApk = File(tempDir, "aligned_output.apk")
            // Deliberately pass unknown.package to verify real package is resolved from binary manifest
            val analysisWithFallbackPkg = sampleApk(inputApk.absolutePath).copy(packageName = "unknown.package")
            val config = ProtectionConfig(
                detectRoot = true,
                antiTampering = true,
                dptDexEncryption = true,
                disableDebuggable = true,
                disableBackup = true,
                stripDexDebug = true,
                stripMetadataBloat = true,
                bestCompression = true,
            )

            val stats = ApkProtectionProcessor.transformApkArchive(
                inputFile = inputApk,
                outputFile = outApk,
                analysis = analysisWithFallbackPkg,
                config = config,
                guardDexBytes = guardDex,
                dptShellDexBytes = dptShellDex,
            )

            assertEquals(1, stats.strippedBloatCount)
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
                assertTrue(zip.getEntry("DebugProbesKt.bin") == null)

                // Decryption must succeed with com.real.target (not unknown.package)
                val (_, decrypted) = decryptDptPayloads(zip, "com.real.target")
                assertEquals(1, decrypted.size)
                assertTrue(DexPatcher.isValidDex(decrypted[0]))

                // Only clean branded encrypted dspro_*.bin assets added
                val assetNames = zip.entries().asSequence().map { it.name }.filter { it.startsWith("assets/") }.toList()
                assertEquals(
                    listOf(
                        "assets/odd_name_1.txt",
                        "assets/model.tflite",
                        "assets/dspro_dpt.bin",
                        "assets/dspro_guard.bin",
                    ).sorted(),
                    assetNames.sorted(),
                )
            }
        } finally {
            tempDir.deleteRecursively()
        }
    }

    @Test
    fun `binary hardening only adds zero files to assets folder`() {
        val tempDir = Files.createTempDirectory("dspro_zero_assets_test").toFile()
        try {
            val inputApk = File(tempDir, "plain.apk")
            val rawManifest = AxmlManifestPatcher.buildMinimalManifestForTest("com.clean.app", debuggable = true, allowBackup = true)
            val appDex = buildSyntheticDex(withDebugInfo = true)

            ZipOutputStream(FileOutputStream(inputApk)).use { zip ->
                zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
                zip.write(rawManifest)
                zip.closeEntry()
                zip.putNextEntry(ZipEntry("classes.dex"))
                zip.write(appDex)
                zip.closeEntry()
            }

            val outApk = File(tempDir, "hardened_only.apk")
            ApkProtectionProcessor.transformApkArchive(
                inputFile = inputApk,
                outputFile = outApk,
                analysis = sampleApk(inputApk.absolutePath).copy(packageName = "com.clean.app"),
                config = ProtectionConfig(
                    disableDebuggable = true,
                    disableBackup = true,
                    stripDexDebug = true,
                    bestCompression = true,
                ),
            )

            ZipFile(outApk).use { zip ->
                val assetEntries = zip.entries().asSequence().filter { it.name.startsWith("assets/") }.toList()
                assertTrue(assetEntries.isEmpty())
            }
        } finally {
            tempDir.deleteRecursively()
        }
    }

    private fun readLocalEntryDataOffsets(apkFile: File): Map<String, Long> {
        val bytes = apkFile.readBytes()
        val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        // Find End of Central Directory (0x06054b50)
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
    fun `reset ui state clears apk config progress and disables start`() {
        val activeState = DsProUiState(
            selectedApkUri = "content://downloads/demo.apk",
            selectedApk = sampleApk(),
            config = ProtectionConfig(
                detectRoot = true,
                dptDexEncryption = true,
                disableDebuggable = true,
                antiTampering = true,
            ),
            progress = 100,
        )
        assertTrue(activeState.isStartEnabled)
        assertEquals(4, activeState.config.activeToggleCount)

        val refreshingState = activeState.copy(isRefreshing = true)
        assertFalse(refreshingState.isStartEnabled)

        val resetState = DsProUiState(statusMessage = "Everything has been reset.")
        assertEquals(null, resetState.selectedApkUri)
        assertEquals(null, resetState.selectedApk)
        assertEquals(0, resetState.config.activeToggleCount)
        assertEquals(0, resetState.progress)
        assertTrue(resetState.steps.isEmpty())
        assertEquals(null, resetState.runResult)
        assertFalse(resetState.isStartEnabled)
    }
}
