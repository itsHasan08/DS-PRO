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

    private fun decryptDptPayloads(zip: ZipFile, packageName: String): List<ByteArray> {
        val idxLines = zip.getInputStream(zip.getEntry("assets/ds_pro_dpt.idx"))
            .bufferedReader().readLines()
        assertEquals("DSPRO_DPT_V1", idxLines[0])
        val dexCount = idxLines[1].toInt()
        val saltHex = idxLines[4].trim()
        val maskedKeyHex = idxLines[5].trim()

        val mask = MessageDigest.getInstance("SHA-256").digest(
            "$packageName:DSPRO_DPT_V1:$dexCount:$saltHex".toByteArray(Charsets.UTF_8),
        )
        val maskedKey = ByteArray(maskedKeyHex.length / 2) { i ->
            ((Character.digit(maskedKeyHex[i * 2], 16) shl 4) +
                Character.digit(maskedKeyHex[i * 2 + 1], 16)).toByte()
        }
        val aesKey = ByteArray(maskedKey.size) { i ->
            (maskedKey[i].toInt() xor mask[i].toInt()).toByte()
        }
        val keySpec = SecretKeySpec(aesKey, "AES")

        return (0 until dexCount).map { i ->
            val enc = zip.getInputStream(zip.getEntry("assets/ds_pro_dpt_$i.bin")).readBytes()
            val iv = enc.copyOfRange(0, 12)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, keySpec, GCMParameterSpec(128, iv))
            cipher.doFinal(enc, 12, enc.size - 12)
        }
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
            // manifest + arsc + lib + dpt_0 + dpt_1 + dpt.idx + shell classes.dex + guard classes2.dex = 8
            assertEquals(8, stats.integrityCount)

            val (valid, _) = ApkProtectionProcessor.verifyOutputApk(outputApk)
            assertTrue(valid)

            ZipFile(outputApk).use { outZip ->
                assertArrayEquals(dptShellDex, outZip.getInputStream(outZip.getEntry("classes.dex")).readBytes())
                assertArrayEquals(guardDex, outZip.getInputStream(outZip.getEntry("classes2.dex")).readBytes())
                assertTrue(outZip.getEntry("classes3.dex") == null)

                val decryptedList = decryptDptPayloads(outZip, "com.demo.app")
                assertEquals(2, decryptedList.size)
                assertArrayEquals(DexPatcher.stripDebugInfo(appDex1).first, decryptedList[0])
                assertArrayEquals(DexPatcher.stripDebugInfo(appDex2).first, decryptedList[1])

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
                packageName = "com.aistudio.dspro.kxmqzp",
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

                val idxLines = zip.getInputStream(zip.getEntry("assets/ds_pro_dpt.idx")).bufferedReader().readLines()
                assertEquals("androidx.core.app.CoreComponentFactory", idxLines[3])

                val decryptedDexes = decryptDptPayloads(zip, "com.aistudio.dspro.kxmqzp")
                assertEquals(stats.encryptedDexCount, decryptedDexes.size)
                decryptedDexes.forEach { assertTrue(DexPatcher.isValidDex(it)) }

                assertArrayEquals(dptBytes, zip.getInputStream(zip.getEntry("classes.dex")).readBytes())
                assertArrayEquals(guardBytes, zip.getInputStream(zip.getEntry("classes2.dex")).readBytes())
            }
        } finally {
            tempDir.deleteRecursively()
        }
    }

    @Test
    fun `formatBytes renders readable sizes`() {
        assertEquals("512 B", formatBytes(512))
        assertTrue(formatBytes(2048).contains("KB"))
        assertTrue(formatBytes(4 * 1024 * 1024L).contains("MB"))
    }
}
