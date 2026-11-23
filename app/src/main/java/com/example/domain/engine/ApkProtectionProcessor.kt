package com.example.domain.engine

import android.content.Context
import android.net.Uri
import com.example.domain.model.ApkAnalysisResult
import com.example.domain.model.ProtectionConfig
import com.example.domain.model.ProtectionRunResult
import com.example.domain.model.ProtectionStepResult
import com.example.domain.model.SavedApkLocation
import com.example.domain.model.StepStatus
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.BufferedOutputStream
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.zip.CRC32
import java.util.zip.Deflater
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

data class ArchiveTransformStats(
    val debuggableDisabled: Boolean,
    val backupDisabled: Boolean,
    val guardProviderInjected: Boolean,
    val dptShellInjected: Boolean,
    val encryptedDexCount: Int,
    val injectedGuardDexName: String?,
    val dexDebugItemsCleared: Int,
    val strippedBloatCount: Int,
    val integrityCount: Int,
    val inputSizeBytes: Long,
    val outputSizeBytes: Long,
)

class ApkProtectionProcessor(
    private val context: Context,
    private val fileStorageService: ApkFileStorageService = ApkFileStorageService(context),
) {

    private val workDir: File
        get() = File(context.cacheDir, "dspro_work").apply { mkdirs() }

    suspend fun processApk(
        analysis: ApkAnalysisResult,
        config: ProtectionConfig,
        onProgress: suspend (Int, List<ProtectionStepResult>) -> Unit,
    ): ProtectionRunResult = withContext(Dispatchers.IO) {
        val steps = mutableListOf<ProtectionStepResult>()
        val inputFile = File(analysis.cachedApkPath)

        if (!inputFile.exists() || !inputFile.canRead()) {
            steps += ProtectionStepResult(
                id = "input",
                title = "Input Validation",
                status = StepStatus.FAILED,
                detail = "Selected APK file is no longer accessible.",
            )
            onProgress(100, steps.toList())
            return@withContext ProtectionRunResult(
                outputApkPath = null,
                outputSizeBytes = 0L,
                isValidBuild = false,
                summary = "Input APK missing.",
                steps = steps.toList(),
            )
        }

        if (config.signaturePinning && !analysis.isSigned) {
            steps += ProtectionStepResult(
                id = "signature",
                title = "Signature Pinning",
                status = StepStatus.FAILED,
                detail = "Cannot pin signature: input APK has no signing certificate.",
            )
            onProgress(100, steps.toList())
            return@withContext ProtectionRunResult(
                outputApkPath = null,
                outputSizeBytes = 0L,
                isValidBuild = false,
                summary = "Input APK is unsigned; Signature Pinning requires a signed APK.",
                steps = steps.toList(),
            )
        }

        val guardDexBytes = if (config.requiresRuntimeGuard) {
            runCatching {
                context.assets.open(GUARD_DEX_ASSET).use { it.readBytes() }
            }.getOrElse { err ->
                steps += ProtectionStepResult(
                    id = "guard_asset",
                    title = "Runtime Guard Payload",
                    status = StepStatus.FAILED,
                    detail = err.message ?: "Missing ds_pro_guard.dex payload.",
                )
                onProgress(100, steps.toList())
                return@withContext ProtectionRunResult(null, 0L, false, "Guard DEX asset unavailable.", steps.toList())
            }
        } else {
            null
        }

        val dptShellDexBytes = if (config.dptDexEncryption) {
            runCatching {
                context.assets.open(DPT_SHELL_DEX_ASSET).use { it.readBytes() }
            }.getOrElse { err ->
                steps += ProtectionStepResult(
                    id = "dpt_asset",
                    title = "DPT Shell Payload",
                    status = StepStatus.FAILED,
                    detail = err.message ?: "Missing ds_pro_dpt_shell.dex payload.",
                )
                onProgress(100, steps.toList())
                return@withContext ProtectionRunResult(null, 0L, false, "DPT shell asset unavailable.", steps.toList())
            }
        } else {
            null
        }

        workDir.listFiles()?.filter { it.name.startsWith("protected_unsigned_") }?.forEach { it.delete() }
        val outputFile = File(
            workDir,
            "protected_unsigned_${analysis.packageName.replace('.', '_')}_${System.currentTimeMillis()}.apk",
        )

        steps += ProtectionStepResult(
            id = "input",
            title = "Archive Validation",
            status = StepStatus.SUCCESS,
            detail = "Verified ${analysis.fileName} (${analysis.totalEntries} entries, ${analysis.dexCount} DEX).",
        )
        onProgress(20, steps.toList())

        val transformResult = runCatching {
            transformApkArchive(
                inputFile = inputFile,
                outputFile = outputFile,
                analysis = analysis,
                config = config,
                guardDexBytes = guardDexBytes,
                dptShellDexBytes = dptShellDexBytes,
            )
        }

        val stats = transformResult.getOrNull()
        if (stats == null) {
            val err = transformResult.exceptionOrNull()?.message ?: "APK protection failed."
            outputFile.delete()
            steps += ProtectionStepResult("build", "APK Protection", StepStatus.FAILED, err)
            onProgress(100, steps.toList())
            return@withContext ProtectionRunResult(null, 0L, false, err, steps.toList())
        }

        if (config.dptDexEncryption) {
            steps += ProtectionStepResult(
                id = "dpt",
                title = "DPT DEX Encryption (AES-256-GCM)",
                status = StepStatus.SUCCESS,
                detail = "Encrypted ${stats.encryptedDexCount} DEX file(s) into single stealth container.",
            )
        }
        onProgress(38, steps.toList())

        if (config.disableDebuggable || config.disableBackup || config.requiresRuntimeGuard || config.dptDexEncryption) {
            val manifestActions = buildList {
                if (stats.dptShellInjected) add("DPT AppComponentFactory + ShellApplication")
                if (stats.debuggableDisabled) add("debuggable=false")
                if (stats.backupDisabled) add("allowBackup=false")
                if (stats.guardProviderInjected) add("<provider> DsProGuardProvider")
            }
            steps += ProtectionStepResult(
                id = "manifest",
                title = "Binary Manifest Patched",
                status = StepStatus.SUCCESS,
                detail = manifestActions.joinToString(", "),
            )
        }
        onProgress(55, steps.toList())

        if (config.requiresRuntimeGuard) {
            val guards = buildList {
                if (config.detectRoot) add("Root")
                if (config.detectEmulator) add("Emulator")
                if (config.detectVpn) add("VPN")
                if (config.detectXposed) add("Xposed/Frida")
                if (config.detectDebugger) add("Debugger")
                if (config.antiScreenshot) add("Anti-Screenshot")
                if (config.antiTampering) add("Tamper(${stats.integrityCount})")
                if (config.signaturePinning) add("SigPin (Same Key)")
            }
            steps += ProtectionStepResult(
                id = "guard",
                title = "Runtime Guard Injected",
                status = StepStatus.SUCCESS,
                detail = "${stats.injectedGuardDexName ?: "classes2.dex"} -> encrypted policy (${guards.joinToString(", ")})",
            )
        }
        onProgress(70, steps.toList())

        if (config.stripDexDebug || config.stripMetadataBloat || config.bestCompression) {
            val binaryParts = buildList {
                if (config.stripDexDebug) add("${stats.dexDebugItemsCleared} DEX debug items stripped")
                if (config.stripMetadataBloat) add("${stats.strippedBloatCount} bloat files removed")
                if (config.bestCompression) {
                    val delta = stats.inputSizeBytes - stats.outputSizeBytes
                    add(if (delta > 0) "saved ${formatBytes(delta)}" else "level-9 compressed")
                }
            }
            steps += ProtectionStepResult(
                id = "binary",
                title = "DEX & Archive Hardening",
                status = StepStatus.SUCCESS,
                detail = binaryParts.joinToString(" | "),
            )
        }
        onProgress(82, steps.toList())

        val (valid, verifyDetail) = verifyOutputApk(outputFile)
        steps += ProtectionStepResult(
            id = "verify",
            title = "Output Verification",
            status = if (valid) StepStatus.SUCCESS else StepStatus.FAILED,
            detail = verifyDetail,
        )

        var savedLocation: SavedApkLocation? = null
        if (valid) {
            fileStorageService.saveProtectedApk(outputFile, analysis.packageName)
                .onSuccess { loc ->
                    savedLocation = loc
                    steps += ProtectionStepResult(
                        id = "save",
                        title = "Saved to ${ApkFileStorageService.PROTECTED_FOLDER_NAME}",
                        status = StepStatus.SUCCESS,
                        detail = "${loc.folderDisplay}/${loc.fileName}",
                    )
                }
                .onFailure { err ->
                    steps += ProtectionStepResult(
                        id = "save",
                        title = "Storage Save",
                        status = StepStatus.FAILED,
                        detail = err.message ?: "Could not save to ${ApkFileStorageService.PROTECTED_FOLDER_NAME}.",
                    )
                }
        } else {
            outputFile.delete()
        }

        onProgress(100, steps.toList())

        ProtectionRunResult(
            outputApkPath = if (valid) outputFile.absolutePath else null,
            outputSizeBytes = if (valid) outputFile.length() else 0L,
            isValidBuild = valid,
            summary = savedLocation?.takeIf { valid }?.let { loc ->
                "Saved to ${loc.folderDisplay}/${loc.fileName}"
            } ?: verifyDetail,
            steps = steps.toList(),
            savedLocation = savedLocation,
        )
    }

    suspend fun exportUnsignedApk(outputApkPath: String, destinationUri: Uri): Result<Long> =
        withContext(Dispatchers.IO) {
            val source = File(outputApkPath)
            val (valid, reason) = verifyOutputApk(source)
            if (!valid) {
                return@withContext Result.failure(IllegalStateException(reason))
            }
            fileStorageService.exportCopyToUri(source, destinationUri)
        }

    companion object {
        const val GUARD_DEX_ASSET = "ds_pro_guard.dex"
        const val DPT_SHELL_DEX_ASSET = "ds_pro_dpt_shell.dex"
        private const val GUARD_DESCRIPTOR = "Lcom/dspro/guard/DsProGuardProvider;"
        private const val DPT_DESCRIPTOR = "Lcom/dspro/dpt/DsProShellApplication;"

        fun guardConfigAssetPath(packageName: String): String {
            val shortHash = sha256Hex("$packageName:DSPRO_GCFG_NAME".toByteArray(Charsets.UTF_8)).substring(0, 8)
            return "assets/$shortHash.bin"
        }

        fun dptContainerAssetPath(packageName: String): String {
            val shortHash = sha256Hex("$packageName:DSPRO_DPT_NAME".toByteArray(Charsets.UTF_8)).substring(0, 8)
            return "assets/$shortHash.bin"
        }

        fun transformApkArchive(
            inputFile: File,
            outputFile: File,
            analysis: ApkAnalysisResult,
            config: ProtectionConfig,
            guardDexBytes: ByteArray? = null,
            dptShellDexBytes: ByteArray? = null,
        ): ArchiveTransformStats {
            if (config.requiresRuntimeGuard) {
                require(guardDexBytes != null && DexPatcher.isValidDex(guardDexBytes)) {
                    "Valid guard DEX payload is required for Runtime Guard features."
                }
            }
            if (config.dptDexEncryption) {
                require(dptShellDexBytes != null && DexPatcher.isValidDex(dptShellDexBytes)) {
                    "Valid DPT shell DEX payload is required for DPT DEX Encryption."
                }
            }

            val integrityLines = mutableListOf<String>()
            var strippedBloatCount = 0
            var dexDebugItemsCleared = 0
            var debuggableDisabled = false
            var backupDisabled = false
            var guardProviderInjected = false
            var dptShellInjected = false
            var originalAppClass = ""
            var originalFactoryClass = ""
            var injectedGuardDexName: String? = null

            val collectedDex = mutableListOf<Pair<String, ByteArray>>()
            var manifestBytes: ByteArray? = null

            ZipFile(inputFile).use { zipIn ->
                require(zipIn.getEntry("assets/ds_pro_dpt.idx") == null) {
                    "Input APK is already DPT-encrypted by DS PRO."
                }

                val countingOut = CountingOutputStream(BufferedOutputStream(FileOutputStream(outputFile), 64 * 1024))
                ZipOutputStream(countingOut).use { zipOut ->
                    zipOut.setLevel(if (config.bestCompression) Deflater.BEST_COMPRESSION else Deflater.DEFAULT_COMPRESSION)
                    val written = hashSetOf<String>()

                    val rawManifestEntry = zipIn.getEntry("AndroidManifest.xml")
                        ?: error("Selected APK does not contain AndroidManifest.xml.")
                    val rawManifestInitial = zipIn.getInputStream(rawManifestEntry).use { it.readBytes() }
                    val manifestSummary = AxmlManifestPatcher.inspectSecuritySummary(rawManifestInitial)
                    val manifestPkg = manifestSummary?.packageName.orEmpty()
                    val effectivePackageName = manifestPkg.ifBlank {
                        analysis.packageName.takeIf { it.isNotBlank() && it != "unknown.package" }.orEmpty()
                    }
                    val guardAssetName = guardConfigAssetPath(effectivePackageName)
                    val dptAssetName = dptContainerAssetPath(effectivePackageName)
                    val inputHasDptShell = manifestSummary?.hasDptShell == true || zipIn.getEntry(dptAssetName) != null
                    val inputHasGuardProvider = manifestSummary?.hasGuardProvider == true

                    require(!(config.dptDexEncryption && inputHasDptShell)) {
                        "Input APK is already DPT-encrypted by DS PRO."
                    }

                    val entries = zipIn.entries()
                    while (entries.hasMoreElements()) {
                        val entry = entries.nextElement()
                        if (entry.isDirectory) continue
                        val name = entry.name

                        if (isV1SignatureEntry(name) ||
                            name.startsWith("assets/ds_pro_") ||
                            name == guardAssetName ||
                            name == dptAssetName
                        ) {
                            continue
                        }
                        if (config.stripMetadataBloat && isBloatEntry(name)) {
                            strippedBloatCount++
                            continue
                        }

                        val rawBytes = zipIn.getInputStream(entry).use { it.readBytes() }

                        if (isClassesDex(name)) {
                            if (inputHasDptShell && DexPatcher.containsAsciiMarker(rawBytes, DPT_DESCRIPTOR)) {
                                continue
                            }
                            if (inputHasGuardProvider && DexPatcher.containsAsciiMarker(rawBytes, GUARD_DESCRIPTOR)) {
                                continue
                            }
                            var dexBytes = rawBytes
                            if (config.stripDexDebug) {
                                val (strippedDex, dexStats) = DexPatcher.stripDebugInfo(dexBytes)
                                dexBytes = strippedDex
                                dexDebugItemsCleared += dexStats.sourceFilesCleared + dexStats.debugInfosCleared
                            }
                            collectedDex += name to dexBytes
                            continue
                        }

                        if (name == "AndroidManifest.xml") {
                            manifestBytes = rawBytes
                            continue
                        }

                        val shouldPreserveStored = entry.method == ZipEntry.STORED ||
                            name == "resources.arsc" ||
                            name.endsWith(".so")
                        if (writeZipBytes(countingOut, zipOut, written, name, rawBytes, keepStored = shouldPreserveStored)) {
                            if (config.antiTampering && isIntegrityTrackedEntry(name)) {
                                integrityLines += "${sha256Hex(rawBytes)}|$name"
                            }
                        }
                    }

                    val rawManifest = manifestBytes ?: rawManifestInitial

                    val finalManifest = if (
                        config.disableDebuggable ||
                        config.disableBackup ||
                        config.requiresRuntimeGuard ||
                        config.dptDexEncryption
                    ) {
                        val patchResult = AxmlManifestPatcher.patch(
                            axmlBytes = rawManifest,
                            options = AxmlPatchOptions(
                                disableDebuggable = config.disableDebuggable,
                                disableBackup = config.disableBackup,
                                injectGuardProvider = config.requiresRuntimeGuard,
                                enableDptShell = config.dptDexEncryption,
                                packageName = effectivePackageName,
                            ),
                        )
                        debuggableDisabled = patchResult.debuggableDisabled
                        backupDisabled = patchResult.backupDisabled
                        guardProviderInjected = patchResult.guardProviderInjected
                        dptShellInjected = patchResult.dptShellInjected
                        originalAppClass = patchResult.originalAppClass
                        originalFactoryClass = patchResult.originalFactoryClass
                        patchResult.manifestBytes
                    } else {
                        rawManifest
                    }

                    if (writeZipBytes(countingOut, zipOut, written, "AndroidManifest.xml", finalManifest)) {
                        if (config.antiTampering) {
                            integrityLines += "${sha256Hex(finalManifest)}|AndroidManifest.xml"
                        }
                    }

                    val sortedOriginalDex = collectedDex.sortedBy { parseDexIndex(it.first) }
                    if (config.dptDexEncryption && dptShellDexBytes != null) {
                        require(sortedOriginalDex.isNotEmpty()) { "No classes.dex found to encrypt." }

                        val rng = SecureRandom()
                        val dptContainerBytes = buildEncryptedDptContainer(
                            rng = rng,
                            packageName = effectivePackageName,
                            originalAppClass = originalAppClass,
                            originalFactoryClass = originalFactoryClass,
                            dexPayloads = sortedOriginalDex.map { it.second },
                        )
                        if (writeZipBytes(countingOut, zipOut, written, dptAssetName, dptContainerBytes)) {
                            if (config.antiTampering) {
                                integrityLines += "${sha256Hex(dptContainerBytes)}|$dptAssetName"
                            }
                        }

                        if (writeZipBytes(countingOut, zipOut, written, "classes.dex", dptShellDexBytes)) {
                            if (config.antiTampering) {
                                integrityLines += "${sha256Hex(dptShellDexBytes)}|classes.dex"
                            }
                        }

                        if (config.requiresRuntimeGuard && guardDexBytes != null) {
                            val guardDexName = "classes2.dex"
                            injectedGuardDexName = guardDexName
                            if (writeZipBytes(countingOut, zipOut, written, guardDexName, guardDexBytes)) {
                                if (config.antiTampering) {
                                    integrityLines += "${sha256Hex(guardDexBytes)}|$guardDexName"
                                }
                            }
                        }
                    } else {
                        var maxDexIndex = 0
                        sortedOriginalDex.forEach { (dexName, dexBytes) ->
                            maxDexIndex = maxOf(maxDexIndex, parseDexIndex(dexName))
                            if (writeZipBytes(countingOut, zipOut, written, dexName, dexBytes)) {
                                if (config.antiTampering) {
                                    integrityLines += "${sha256Hex(dexBytes)}|$dexName"
                                }
                            }
                        }
                        if (config.requiresRuntimeGuard && guardDexBytes != null) {
                            val nextIdx = (maxDexIndex + 1).coerceAtLeast(2)
                            val guardDexName = "classes$nextIdx.dex"
                            injectedGuardDexName = guardDexName
                            if (writeZipBytes(countingOut, zipOut, written, guardDexName, guardDexBytes)) {
                                if (config.antiTampering) {
                                    integrityLines += "${sha256Hex(guardDexBytes)}|$guardDexName"
                                }
                            }
                        }
                    }

                    if (config.requiresRuntimeGuard) {
                        val encryptedPolicyBytes = buildEncryptedGuardPolicy(
                            rng = SecureRandom(),
                            packageName = effectivePackageName,
                            analysis = analysis,
                            config = config,
                            integrityEntries = integrityLines,
                        )
                        writeZipBytes(countingOut, zipOut, written, guardAssetName, encryptedPolicyBytes)
                    }

                    zipOut.flush()
                }
            }

            return ArchiveTransformStats(
                debuggableDisabled = debuggableDisabled,
                backupDisabled = backupDisabled,
                guardProviderInjected = guardProviderInjected,
                dptShellInjected = dptShellInjected,
                encryptedDexCount = if (config.dptDexEncryption) collectedDex.size else 0,
                injectedGuardDexName = injectedGuardDexName,
                dexDebugItemsCleared = dexDebugItemsCleared,
                strippedBloatCount = strippedBloatCount,
                integrityCount = integrityLines.size,
                inputSizeBytes = inputFile.length(),
                outputSizeBytes = outputFile.length(),
            )
        }

        private fun buildEncryptedDptContainer(
            rng: SecureRandom,
            packageName: String,
            originalAppClass: String,
            originalFactoryClass: String,
            dexPayloads: List<ByteArray>,
        ): ByteArray {
            val aesKey = ByteArray(32).also { rng.nextBytes(it) }
            val salt = ByteArray(16).also { rng.nextBytes(it) }
            val saltHex = salt.joinToString("") { "%02x".format(it) }

            val metaKey = MessageDigest.getInstance("SHA-256").digest(
                "$packageName:DSPRO_DPT_META_V2:$saltHex".toByteArray(Charsets.UTF_8),
            )
            val aesKeyHex = aesKey.joinToString("") { "%02x".format(it) }
            val metaPlain = buildString {
                appendLine(dexPayloads.size)
                appendLine(originalAppClass)
                appendLine(originalFactoryClass)
                append(aesKeyHex)
            }.toByteArray(Charsets.UTF_8)

            val metaIv = ByteArray(12).also { rng.nextBytes(it) }
            val metaCipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
                init(Cipher.ENCRYPT_MODE, SecretKeySpec(metaKey, "AES"), GCMParameterSpec(128, metaIv))
            }.doFinal(metaPlain)

            val out = ByteArrayOutputStream()
            DataOutputStream(out).use { dos ->
                dos.write(salt)
                dos.write(metaIv)
                dos.writeInt(metaCipher.size)
                dos.write(metaCipher)

                val keySpec = SecretKeySpec(aesKey, "AES")
                dexPayloads.forEach { dexBytes ->
                    val iv = ByteArray(12).also { rng.nextBytes(it) }
                    val cipherText = Cipher.getInstance("AES/GCM/NoPadding").apply {
                        init(Cipher.ENCRYPT_MODE, keySpec, GCMParameterSpec(128, iv))
                    }.doFinal(dexBytes)
                    dos.write(iv)
                    dos.writeInt(cipherText.size)
                    dos.write(cipherText)
                }
                dos.flush()
            }
            return out.toByteArray()
        }

        private fun buildEncryptedGuardPolicy(
            rng: SecureRandom,
            packageName: String,
            analysis: ApkAnalysisResult,
            config: ProtectionConfig,
            integrityEntries: List<String>,
        ): ByteArray {
            var flags = 0
            if (config.detectRoot) flags = flags or 1
            if (config.detectEmulator) flags = flags or (1 shl 1)
            if (config.detectVpn) flags = flags or (1 shl 2)
            if (config.detectXposed) flags = flags or (1 shl 3)
            if (config.detectDebugger) flags = flags or (1 shl 4)
            if (config.antiScreenshot) flags = flags or (1 shl 5)
            if (config.antiTampering) flags = flags or (1 shl 6)
            if (config.signaturePinning) flags = flags or (1 shl 7)

            val pinnedCert = if (config.signaturePinning && analysis.isSigned) analysis.signingCertSha256 else "UNSIGNED"
            val entries = if (config.antiTampering) integrityEntries else emptyList()
            val plain = buildString {
                appendLine(flags)
                appendLine(pinnedCert)
                appendLine(entries.size)
                entries.forEach { appendLine(it) }
            }.toByteArray(Charsets.UTF_8)

            val salt = ByteArray(16).also { rng.nextBytes(it) }
            val iv = ByteArray(12).also { rng.nextBytes(it) }
            val saltHex = salt.joinToString("") { "%02x".format(it) }
            val key = MessageDigest.getInstance("SHA-256").digest(
                "$packageName:DSPRO_GCFG_KEY:$saltHex".toByteArray(Charsets.UTF_8),
            )
            val cipherText = Cipher.getInstance("AES/GCM/NoPadding").apply {
                init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
            }.doFinal(plain)

            return ByteArray(salt.size + iv.size + cipherText.size).also { out ->
                System.arraycopy(salt, 0, out, 0, salt.size)
                System.arraycopy(iv, 0, out, salt.size, iv.size)
                System.arraycopy(cipherText, 0, out, salt.size + iv.size, cipherText.size)
            }
        }

        fun verifyOutputApk(file: File): Pair<Boolean, String> {
            if (!file.exists() || file.length() < 64) return false to "Output APK missing."
            return runCatching {
                var hasManifest = false
                var hasDex = false
                var hasStaleSig = false
                ZipFile(file).use { zip ->
                    val e = zip.entries()
                    while (e.hasMoreElements()) {
                        val entry = e.nextElement()
                        if (entry.name == "AndroidManifest.xml" && entry.size > 0) hasManifest = true
                        if (isClassesDex(entry.name) && entry.size > 0) hasDex = true
                        if (isV1SignatureEntry(entry.name)) hasStaleSig = true
                    }
                }
                when {
                    !hasManifest -> false to "Invalid output: AndroidManifest.xml missing."
                    !hasDex -> false to "Invalid output: classes.dex missing."
                    hasStaleSig -> false to "Invalid output: stale v1 signature entries remain."
                    else -> true to "Valid unsigned APK (${formatBytes(file.length())})."
                }
            }.getOrElse { false to (it.message ?: "Output APK verification failed.") }
        }

        private class CountingOutputStream(
            private val delegate: OutputStream,
        ) : OutputStream() {
            var bytesWritten: Long = 0L
                private set

            override fun write(b: Int) {
                delegate.write(b)
                bytesWritten++
            }

            override fun write(b: ByteArray, off: Int, len: Int) {
                delegate.write(b, off, len)
                bytesWritten += len
            }

            override fun flush() {
                delegate.flush()
            }

            override fun close() {
                delegate.close()
            }
        }

        private const val PAGE_ALIGN_BYTES = 16384
        private const val DATA_ALIGN_BYTES = 4
        private const val ANDROID_ZIPALIGN_EXTRA_TAG = 0xD935.toShort()

        private fun buildAlignmentPaddingExtra(pad: Int): ByteArray {
            if (pad <= 0) return ByteArray(0)
            if (pad < 4) return ByteArray(pad)
            val extra = ByteArray(pad)
            val buf = ByteBuffer.wrap(extra).order(ByteOrder.LITTLE_ENDIAN)
            buf.putShort(ANDROID_ZIPALIGN_EXTRA_TAG)
            buf.putShort((pad - 4).toShort())
            return extra
        }

        private fun writeZipBytes(
            countingOut: CountingOutputStream,
            zipOut: ZipOutputStream,
            written: HashSet<String>,
            name: String,
            bytes: ByteArray,
            keepStored: Boolean = false,
        ): Boolean {
            if (!written.add(name)) return false
            val entry = ZipEntry(name)
            val mustStore = keepStored || name == "resources.arsc" || name.endsWith(".so")
            if (mustStore) {
                val alignment = if (name.endsWith(".so")) PAGE_ALIGN_BYTES else DATA_ALIGN_BYTES
                val nameLen = name.toByteArray(Charsets.UTF_8).size
                val unpaddedDataOffset = countingOut.bytesWritten + 30L + nameLen
                val remainder = (unpaddedDataOffset % alignment).toInt()
                val pad = if (remainder == 0) 0 else alignment - remainder
                if (pad > 0) {
                    entry.extra = buildAlignmentPaddingExtra(pad)
                }
                entry.method = ZipEntry.STORED
                entry.size = bytes.size.toLong()
                entry.compressedSize = bytes.size.toLong()
                entry.crc = CRC32().apply { update(bytes) }.value
            } else {
                entry.method = ZipEntry.DEFLATED
            }
            zipOut.putNextEntry(entry)
            zipOut.write(bytes)
            zipOut.closeEntry()
            return true
        }

        private fun isClassesDex(name: String): Boolean {
            return name == "classes.dex" ||
                (name.startsWith("classes") && name.endsWith(".dex") && name.indexOf('/') == -1)
        }

        private fun parseDexIndex(name: String): Int {
            if (name == "classes.dex") return 1
            return name.removePrefix("classes").removeSuffix(".dex").toIntOrNull() ?: 1
        }

        private fun isV1SignatureEntry(name: String): Boolean {
            if (!name.startsWith("META-INF/")) return false
            val upper = name.uppercase()
            return upper == "META-INF/MANIFEST.MF" ||
                upper.endsWith(".SF") ||
                upper.endsWith(".RSA") ||
                upper.endsWith(".DSA") ||
                upper.endsWith(".EC")
        }

        private fun isBloatEntry(name: String): Boolean {
            return name == "DebugProbesKt.bin" ||
                name == "kotlin-tooling-metadata.json" ||
                name.startsWith("META-INF/proguard/") ||
                (name.startsWith("META-INF/") && name.endsWith(".version"))
        }

        private fun isIntegrityTrackedEntry(name: String): Boolean {
            return name == "AndroidManifest.xml" ||
                name == "resources.arsc" ||
                isClassesDex(name) ||
                (name.startsWith("lib/") && name.endsWith(".so"))
        }

        private fun sha256Hex(bytes: ByteArray): String =
            MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    }
}

fun formatBytes(bytes: Long): String {
    if (bytes < 1024) return "$bytes B"
    val kb = bytes / 1024.0
    if (kb < 1024) return "%.1f KB".format(kb)
    return "%.2f MB".format(kb / 1024.0)
}
