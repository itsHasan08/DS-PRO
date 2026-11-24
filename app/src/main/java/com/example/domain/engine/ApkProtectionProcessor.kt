package com.example.domain.engine

import android.content.Context
import android.net.Uri
import com.example.domain.model.ApkAnalysisResult
import com.example.domain.model.ProtectionConfig
import com.example.domain.model.ProtectionRunResult
import com.example.domain.model.ProtectionStepResult
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
    val guardProviderInjected: Boolean,
    val coreProtectionInjected: Boolean,
    val encryptedDexCount: Int,
    val encryptedStringsCount: Int,
    val encryptedResourceCount: Int,
    val encryptedAssistCount: Int = 0,
    val cfoTransformedUnits: Int,
    val cfoMethodsScanned: Int,
    val injectedGuardDexName: String?,
    val dexDebugItemsCleared: Int,
    val integrityCount: Int,
    val dexIntegrityCount: Int,
    val protectionIdentifierEmbedded: Boolean = false,
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
        onProgress: (Int, String, List<ProtectionStepResult>) -> Unit,
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
            onProgress(100, "Input APK missing.", steps.toList())
            return@withContext ProtectionRunResult(
                outputApkPath = null,
                outputSizeBytes = 0L,
                isValidBuild = false,
                summary = "Input APK missing.",
                steps = steps.toList(),
            )
        }

        onProgress(8, "Loading protection payloads...", steps.toList())

        val guardDexBytes = if (config.requiresGuardDex) {
            runCatching {
                context.assets.open(GUARD_DEX_ASSET).use { it.readBytes() }
            }.getOrElse { err ->
                steps += ProtectionStepResult(
                    id = "guard_asset",
                    title = "Runtime Guard Payload",
                    status = StepStatus.FAILED,
                    detail = err.message ?: "Missing ds_pro_guard.dex payload.",
                )
                onProgress(100, "Guard DEX asset unavailable.", steps.toList())
                return@withContext ProtectionRunResult(null, 0L, false, "Guard DEX asset unavailable.", steps.toList())
            }
        } else {
            null
        }

        val coreDexBytes = if (config.requiresCoreDexContainer) {
            runCatching {
                context.assets.open(CORE_DEX_ASSET).use { it.readBytes() }
            }.getOrElse { err ->
                steps += ProtectionStepResult(
                    id = "dspro_core",
                    title = "DS PRO Core Payload",
                    status = StepStatus.FAILED,
                    detail = err.message ?: "Missing ds_pro_core.dex payload.",
                )
                onProgress(100, "DS PRO core asset unavailable.", steps.toList())
                return@withContext ProtectionRunResult(null, 0L, false, "DS PRO core asset unavailable.", steps.toList())
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
        onProgress(16, "Inspecting APK structure...", steps.toList())

        val transformResult = runCatching {
            transformApkArchive(
                inputFile = inputFile,
                outputFile = outputFile,
                analysis = analysis,
                config = config,
                guardDexBytes = guardDexBytes,
                coreDexBytes = coreDexBytes,
                onStageProgress = { pct, stageLabel ->
                    onProgress(pct, stageLabel, steps.toList())
                },
            )
        }

        val stats = transformResult.getOrNull()
        if (stats == null) {
            val err = transformResult.exceptionOrNull()?.message ?: "APK protection failed."
            outputFile.delete()
            steps += ProtectionStepResult("build", "APK Protection", StepStatus.FAILED, err)
            onProgress(100, err, steps.toList())
            return@withContext ProtectionRunResult(null, 0L, false, err, steps.toList())
        }

        if (config.requiresCoreDexContainer) {
            val parts = buildList {
                if (config.dsProDexEncryption) add("AES-256-GCM V5 (${stats.encryptedDexCount} DEX)")
                if (config.stringEncryption) add("${stats.encryptedStringsCount} strings encrypted")
            }
            steps += ProtectionStepResult(
                id = "dspro_core",
                title = "DS PRO Core & String Encryption",
                status = StepStatus.SUCCESS,
                detail = parts.joinToString(" | "),
            )
        }

        if (config.disableDebuggable || config.requiresGuardDex || config.requiresCoreDexContainer || stats.protectionIdentifierEmbedded) {
            val manifestActions = buildList {
                if (stats.coreProtectionInjected) add("DS PRO ComponentFactory + Application")
                if (stats.debuggableDisabled) add("debuggable=false")
                if (stats.guardProviderInjected) add("<provider> DsProGuardProvider")
                if (stats.protectionIdentifierEmbedded) add("Identifier: ${AxmlManifestPatcher.PROTECTION_IDENTIFIER_VALUE}")
            }
            steps += ProtectionStepResult(
                id = "manifest",
                title = "Binary Manifest Patched",
                status = StepStatus.SUCCESS,
                detail = manifestActions.joinToString(", "),
            )
        }

        if (config.requiresRuntimeGuard) {
            val guards = buildList {
                if (config.detectRoot) add("Root")
                if (config.detectDebugger) add("Debugger")
                if (config.antiScreenshot) add("Anti-Screenshot")
                if (config.antiTampering) add("Tamper(${stats.integrityCount})")
                if (config.antiDump) add("Anti-Dump")
                if (config.dexIntegrityProtection) add("DEX-Integrity(${stats.dexIntegrityCount})")
            }
            steps += ProtectionStepResult(
                id = "guard",
                title = "Runtime Guard Injected",
                status = StepStatus.SUCCESS,
                detail = "${stats.injectedGuardDexName ?: "classes2.dex"} -> encrypted policy (${guards.joinToString(", ")})",
            )
        }

        if (config.assistEncrypt) {
            steps += ProtectionStepResult(
                id = "assist_encrypt",
                title = "Assist Encrypt",
                status = StepStatus.SUCCESS,
                detail = if (stats.encryptedAssistCount > 0) {
                    "${stats.encryptedAssistCount} assist files (XML/ZIP/config/data) encrypted into dspro_res.bin"
                } else {
                    "No modifiable files found in assets/ folder; app assets preserved."
                },
            )
        }

        if (config.stripDexDebug || config.controlFlowObfuscation || config.resourceEncryption) {
            val binaryParts = buildList {
                if (config.stripDexDebug) add("${stats.dexDebugItemsCleared} debug symbols wiped")
                if (config.controlFlowObfuscation) add("CFO ${stats.cfoTransformedUnits} edges (${stats.cfoMethodsScanned} methods)")
                if (config.resourceEncryption) add("${stats.encryptedResourceCount} assets encrypted")
            }
            steps += ProtectionStepResult(
                id = "binary",
                title = "DEX & Resource Hardening",
                status = StepStatus.SUCCESS,
                detail = binaryParts.joinToString(" | "),
            )
        }

        onProgress(95, "Verifying output APK integrity...", steps.toList())

        val (valid, verifyDetail) = verifyOutputApk(outputFile)
        steps += ProtectionStepResult(
            id = "verify",
            title = "Output Verification",
            status = if (valid) StepStatus.SUCCESS else StepStatus.FAILED,
            detail = verifyDetail,
        )

        if (!valid) {
            outputFile.delete()
        }

        val finalMessage = if (valid) {
            "Ready to save (${formatBytes(outputFile.length())})"
        } else {
            verifyDetail
        }
        onProgress(100, finalMessage, steps.toList())

        ProtectionRunResult(
            outputApkPath = if (valid) outputFile.absolutePath else null,
            outputSizeBytes = if (valid) outputFile.length() else 0L,
            isValidBuild = valid,
            summary = finalMessage,
            steps = steps.toList(),
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
        const val CORE_DEX_ASSET = "ds_pro_core.dex"
        const val GUARD_POLICY_ASSET = "assets/dspro_guard.bin"
        const val CORE_CONTAINER_ASSET = "assets/dspro_core.bin"
        const val RESOURCE_VAULT_ASSET = "assets/dspro_res.bin"
        private const val GUARD_DESCRIPTOR = "Lcom/dspro/guard/DsProGuardProvider;"
        private const val CORE_DESCRIPTOR = "Lcom/dspro/core/DsProApplication;"

        fun guardConfigAssetPath(packageName: String): String = GUARD_POLICY_ASSET

        fun coreContainerAssetPath(packageName: String): String = CORE_CONTAINER_ASSET

        fun resourceVaultAssetPath(packageName: String): String = RESOURCE_VAULT_ASSET

        fun transformApkArchive(
            inputFile: File,
            outputFile: File,
            analysis: ApkAnalysisResult,
            config: ProtectionConfig,
            guardDexBytes: ByteArray? = null,
            coreDexBytes: ByteArray? = null,
            onStageProgress: ((Int, String) -> Unit)? = null,
        ): ArchiveTransformStats {
            if (config.requiresGuardDex) {
                require(guardDexBytes != null && DexPatcher.isValidDex(guardDexBytes)) {
                    "Valid guard DEX payload is required for Runtime Guard / Resource Encryption."
                }
            }
            if (config.requiresCoreDexContainer) {
                require(coreDexBytes != null && DexPatcher.isValidDex(coreDexBytes)) {
                    "Valid DS PRO core DEX payload is required for DS PRO / String Encryption."
                }
            }

            val integrityLines = mutableListOf<String>()
            val dexIntegrityLines = mutableListOf<String>()
            var dexDebugItemsCleared = 0
            var cfoTransformedUnits = 0
            var cfoMethodsScanned = 0
            var encryptedStringsCount = 0
            var encryptedResourceCount = 0
            var encryptedAssistCount = 0
            var debuggableDisabled = false
            var guardProviderInjected = false
            var coreProtectionInjected = false
            var protectionIdentifierEmbedded = false
            var originalAppClass = ""
            var originalFactoryClass = ""
            var injectedGuardDexName: String? = null

            val collectedDex = mutableListOf<Pair<String, ByteArray>>()
            val encryptedResourceAssets = mutableListOf<VaultAssetEntry>()
            var manifestBytes: ByteArray? = null

            ZipFile(inputFile).use { zipIn ->
                val countingOut = CountingOutputStream(BufferedOutputStream(FileOutputStream(outputFile), 128 * 1024))
                val copyBuf = ByteArray(64 * 1024)
                ZipOutputStream(countingOut).use { zipOut ->
                    zipOut.setLevel(Deflater.DEFAULT_COMPRESSION)
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
                    val coreAssetName = coreContainerAssetPath(effectivePackageName)
                    val resAssetName = resourceVaultAssetPath(effectivePackageName)
                    val inputHasCoreProtection = manifestSummary?.hasCoreProtection == true || zipIn.getEntry(coreAssetName) != null
                    val inputHasGuardProvider = manifestSummary?.hasGuardProvider == true

                    require(!inputHasCoreProtection) {
                        "Input APK is already protected by DS PRO Core Encryption."
                    }
                    val replaceGuardArtifacts = inputHasGuardProvider && config.requiresGuardDex

                    onStageProgress?.invoke(22, "Streaming entries & hardening DEX...")
                    val totalEntries = zipIn.size().coerceAtLeast(1)
                    var processedEntries = 0
                    var lastReportedPct = 22

                    val entries = zipIn.entries()
                    while (entries.hasMoreElements()) {
                        val entry = entries.nextElement()
                        processedEntries++
                        if (entry.isDirectory) continue
                        val name = entry.name

                        val streamPct = 22 + ((processedEntries * 28) / totalEntries).coerceIn(0, 28)
                        if (streamPct - lastReportedPct >= 4) {
                            lastReportedPct = streamPct
                            onStageProgress?.invoke(
                                streamPct,
                                when {
                                    collectedDex.isNotEmpty() -> "Hardening DEX (${collectedDex.size}) & resources..."
                                    else -> "Reading archive entries ($processedEntries/$totalEntries)..."
                                },
                            )
                        }

                        if (isV1SignatureEntry(name) ||
                            name == "assets/libjiagu.so" ||
                            (replaceGuardArtifacts && name == guardAssetName) ||
                            (config.requiresAssetVault && name == resAssetName)
                        ) {
                            continue
                        }

                        if (isClassesDex(name)) {
                            val rawBytes = zipIn.getInputStream(entry).use { it.readBytes() }
                            if (replaceGuardArtifacts && DexPatcher.containsAsciiMarker(rawBytes, GUARD_DESCRIPTOR)) {
                                continue
                            }
                            var dexBytes = rawBytes
                            if (config.stripDexDebug) {
                                val (strippedDex, dexStats) = DexPatcher.stripDebugInfo(dexBytes)
                                dexBytes = strippedDex
                                dexDebugItemsCleared += dexStats.sourceFilesCleared + dexStats.debugInfosCleared
                            }
                            if (config.controlFlowObfuscation) {
                                val (cfoDex, cfoStats) = DexPatcher.obfuscateControlFlow(dexBytes)
                                dexBytes = cfoDex
                                cfoMethodsScanned += cfoStats.methodsScanned
                                cfoTransformedUnits += cfoStats.transformedUnits
                            }
                            collectedDex += name to dexBytes
                            continue
                        }

                        if (name == "AndroidManifest.xml") {
                            manifestBytes = zipIn.getInputStream(entry).use { it.readBytes() }
                            continue
                        }

                        val captureForResource = config.resourceEncryption && isEncryptableAsset(name, entry)
                        val captureForAssist = config.assistEncrypt && isAssistEncryptableAsset(name)
                        if (captureForResource || captureForAssist) {
                            val assetData = zipIn.getInputStream(entry).use { it.readBytes() }
                            val wasStored = entry.method == ZipEntry.STORED
                            encryptedResourceAssets += VaultAssetEntry(
                                name = name,
                                bytes = assetData,
                                keepStored = wasStored,
                            )
                            if (captureForResource) encryptedResourceCount++
                            if (captureForAssist) encryptedAssistCount++
                            continue
                        }

                        val shouldPreserveStored = entry.method == ZipEntry.STORED ||
                            name == "resources.arsc" ||
                            name.endsWith(".so")
                        val trackIntegrity = config.antiTampering && isIntegrityTrackedEntry(name)
                        if (shouldPreserveStored && entry.size >= 0 && entry.crc >= 0) {
                            val digest = streamStoredZipEntry(
                                countingOut = countingOut,
                                zipOut = zipOut,
                                written = written,
                                name = name,
                                size = entry.size,
                                crc = entry.crc,
                                zipIn = zipIn,
                                entry = entry,
                                copyBuf = copyBuf,
                                computeSha256 = trackIntegrity,
                            )
                            if (digest != null) {
                                integrityLines += "$digest|$name"
                            }
                        } else if (shouldPreserveStored) {
                            val rawBytes = zipIn.getInputStream(entry).use { it.readBytes() }
                            if (writeZipBytes(countingOut, zipOut, written, name, rawBytes, keepStored = true)) {
                                if (trackIntegrity) {
                                    integrityLines += "${sha256Hex(rawBytes)}|$name"
                                }
                            }
                        } else {
                            val digest = streamDeflatedZipEntry(
                                zipOut = zipOut,
                                written = written,
                                name = name,
                                zipIn = zipIn,
                                entry = entry,
                                copyBuf = copyBuf,
                                computeSha256 = trackIntegrity,
                            )
                            if (digest != null) {
                                integrityLines += "$digest|$name"
                            }
                        }
                    }

                    onStageProgress?.invoke(54, "Patching binary AndroidManifest.xml...")

                    val rawManifest = manifestBytes ?: rawManifestInitial

                    val shouldEmbedIdentifier = config.activeToggleCount > 0
                    val finalManifest = if (
                        config.disableDebuggable ||
                        config.requiresGuardDex ||
                        config.requiresCoreDexContainer ||
                        shouldEmbedIdentifier
                    ) {
                        val patchResult = AxmlManifestPatcher.patch(
                            axmlBytes = rawManifest,
                            options = AxmlPatchOptions(
                                disableDebuggable = config.disableDebuggable,
                                injectGuardProvider = config.requiresGuardDex,
                                enableCoreProtection = config.requiresCoreDexContainer,
                                protectionIdentifier = if (shouldEmbedIdentifier) AxmlManifestPatcher.PROTECTION_IDENTIFIER_VALUE else "",
                                packageName = effectivePackageName,
                            ),
                        )
                        debuggableDisabled = patchResult.debuggableDisabled
                        guardProviderInjected = patchResult.guardProviderInjected
                        coreProtectionInjected = patchResult.coreProtectionInjected
                        protectionIdentifierEmbedded = patchResult.protectionIdentifierEmbedded
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

                    if (config.requiresAssetVault && encryptedResourceAssets.isNotEmpty()) {
                        onStageProgress?.invoke(63, "Encrypting ${encryptedResourceAssets.size} assist & resource assets...")
                        val resVaultBytes = buildEncryptedResourceVault(
                            rng = SecureRandom(),
                            packageName = effectivePackageName,
                            assetEntries = encryptedResourceAssets,
                        )
                        if (writeZipBytes(countingOut, zipOut, written, resAssetName, resVaultBytes, keepStored = true)) {
                            if (config.antiTampering) {
                                integrityLines += "${sha256Hex(resVaultBytes)}|$resAssetName"
                            }
                        }
                    }

                    val sortedOriginalDex = collectedDex.sortedBy { parseDexIndex(it.first) }
                    if (config.requiresCoreDexContainer && coreDexBytes != null) {
                        require(sortedOriginalDex.isNotEmpty()) { "No classes.dex found to protect." }
                        onStageProgress?.invoke(72, "Encrypting ${sortedOriginalDex.size} DEX & string tables (AES-GCM)...")

                        val rng = SecureRandom()
                        val sha = MessageDigest.getInstance("SHA-256")
                        val coreDexSha256 = sha.digest(coreDexBytes)
                        val guardDexSha256 = if (config.requiresGuardDex && guardDexBytes != null) {
                            sha.reset()
                            sha.digest(guardDexBytes)
                        } else {
                            ByteArray(32)
                        }
                        val (coreContainerBytes, encStringsTotal) = buildEncryptedCoreContainer(
                            rng = rng,
                            packageName = effectivePackageName,
                            originalAppClass = originalAppClass,
                            originalFactoryClass = originalFactoryClass,
                            requireGuard = config.requiresGuardDex,
                            antiDumpEnabled = config.antiDump,
                            encryptStrings = config.stringEncryption,
                            dexIntegrityEnabled = config.dexIntegrityProtection,
                            coreDexSha256 = coreDexSha256,
                            guardDexSha256 = guardDexSha256,
                            dexPayloads = sortedOriginalDex.map { it.second },
                        )
                        encryptedStringsCount = encStringsTotal
                        if (writeZipBytes(countingOut, zipOut, written, coreAssetName, coreContainerBytes, keepStored = true)) {
                            if (config.antiTampering) {
                                integrityLines += "${sha256Hex(coreContainerBytes)}|$coreAssetName"
                            }
                        }

                        if (writeZipBytes(countingOut, zipOut, written, "classes.dex", coreDexBytes)) {
                            if (config.antiTampering) {
                                integrityLines += "${sha256Hex(coreDexBytes)}|classes.dex"
                            }
                            if (config.dexIntegrityProtection) {
                                dexIntegrityLines += buildDexIntegrityLine("classes.dex", coreDexBytes)
                            }
                        }

                        if (config.requiresGuardDex && guardDexBytes != null) {
                            val guardDexName = "classes2.dex"
                            injectedGuardDexName = guardDexName
                            if (writeZipBytes(countingOut, zipOut, written, guardDexName, guardDexBytes)) {
                                if (config.antiTampering) {
                                    integrityLines += "${sha256Hex(guardDexBytes)}|$guardDexName"
                                }
                                if (config.dexIntegrityProtection) {
                                    dexIntegrityLines += buildDexIntegrityLine(guardDexName, guardDexBytes)
                                }
                            }
                        }
                    } else {
                        onStageProgress?.invoke(72, "Writing hardened DEX files...")
                        var maxDexIndex = 0
                        sortedOriginalDex.forEach { (dexName, dexBytes) ->
                            maxDexIndex = maxOf(maxDexIndex, parseDexIndex(dexName))
                            if (writeZipBytes(countingOut, zipOut, written, dexName, dexBytes)) {
                                if (config.antiTampering) {
                                    integrityLines += "${sha256Hex(dexBytes)}|$dexName"
                                }
                                if (config.dexIntegrityProtection) {
                                    dexIntegrityLines += buildDexIntegrityLine(dexName, dexBytes)
                                }
                            }
                        }
                        if (config.requiresGuardDex && guardDexBytes != null) {
                            val nextIdx = (maxDexIndex + 1).coerceAtLeast(2)
                            val guardDexName = "classes$nextIdx.dex"
                            injectedGuardDexName = guardDexName
                            if (writeZipBytes(countingOut, zipOut, written, guardDexName, guardDexBytes)) {
                                if (config.antiTampering) {
                                    integrityLines += "${sha256Hex(guardDexBytes)}|$guardDexName"
                                }
                                if (config.dexIntegrityProtection) {
                                    dexIntegrityLines += buildDexIntegrityLine(guardDexName, guardDexBytes)
                                }
                            }
                        }
                    }

                    if (config.requiresGuardDex) {
                        onStageProgress?.invoke(85, "Sealing encrypted Runtime Guard policy...")
                        val encryptedPolicyBytes = buildEncryptedGuardPolicy(
                            rng = SecureRandom(),
                            packageName = effectivePackageName,
                            analysis = analysis,
                            config = config,
                            integrityEntries = integrityLines,
                            dexIntegrityEntries = dexIntegrityLines,
                        )
                        writeZipBytes(countingOut, zipOut, written, guardAssetName, encryptedPolicyBytes, keepStored = true)
                    }

                    onStageProgress?.invoke(91, "Finalizing aligned APK archive...")
                    zipOut.flush()
                }
            }

            return ArchiveTransformStats(
                debuggableDisabled = debuggableDisabled,
                guardProviderInjected = guardProviderInjected,
                coreProtectionInjected = coreProtectionInjected,
                encryptedDexCount = if (config.requiresCoreDexContainer) collectedDex.size else 0,
                encryptedStringsCount = encryptedStringsCount,
                encryptedResourceCount = encryptedResourceCount,
                encryptedAssistCount = encryptedAssistCount,
                cfoTransformedUnits = cfoTransformedUnits,
                cfoMethodsScanned = cfoMethodsScanned,
                injectedGuardDexName = injectedGuardDexName,
                dexDebugItemsCleared = dexDebugItemsCleared,
                integrityCount = integrityLines.size,
                dexIntegrityCount = dexIntegrityLines.size,
                protectionIdentifierEmbedded = protectionIdentifierEmbedded,
                inputSizeBytes = inputFile.length(),
                outputSizeBytes = outputFile.length(),
            )
        }

        private data class VaultAssetEntry(
            val name: String,
            val bytes: ByteArray,
            val keepStored: Boolean,
        )

        private fun buildDexIntegrityLine(entryName: String, dexBytes: ByteArray): String {
            val adler = if (dexBytes.size >= 12) {
                ByteBuffer.wrap(dexBytes).order(ByteOrder.LITTLE_ENDIAN).getInt(8).toLong() and 0xFFFFFFFFL
            } else {
                0L
            }
            return "${sha256Hex(dexBytes)}|$adler|${dexBytes.size}|$entryName"
        }

        private fun isProtectedSystemOrEngineAsset(lower: String): Boolean {
            if (lower.startsWith("assets/dspro_") ||
                lower.startsWith("assets/ds_pro_") ||
                lower.startsWith("assets/flutter_assets/") ||
                lower.startsWith("assets/bin/data/") ||
                lower.startsWith("assets/dexopt/") ||
                lower.startsWith("assets/webkit/")
            ) {
                return true
            }
            return lower.endsWith(".so") ||
                lower.endsWith(".tflite") ||
                lower.endsWith(".lite") ||
                lower.endsWith(".onnx") ||
                lower.endsWith(".mp3") ||
                lower.endsWith(".mp4") ||
                lower.endsWith(".ogg") ||
                lower.endsWith(".wav") ||
                lower.endsWith(".m4a") ||
                lower.endsWith(".aac") ||
                lower.endsWith(".webm") ||
                lower.endsWith(".mkv") ||
                lower.endsWith(".ttf") ||
                lower.endsWith(".otf")
        }

        private fun isEncryptableAsset(name: String, entry: ZipEntry): Boolean {
            if (entry.method == ZipEntry.STORED) return false
            if (!name.startsWith("assets/")) return false
            return !isProtectedSystemOrEngineAsset(name.lowercase())
        }

        private fun isAssistEncryptableAsset(name: String): Boolean {
            if (!name.startsWith("assets/")) return false
            return !isProtectedSystemOrEngineAsset(name.lowercase())
        }

        private fun buildEncryptedResourceVault(
            rng: SecureRandom,
            packageName: String,
            assetEntries: List<VaultAssetEntry>,
        ): ByteArray {
            val zipOutBytes = ByteArrayOutputStream()
            val innerCountingOut = CountingOutputStream(zipOutBytes)
            val innerWritten = hashSetOf<String>()
            val vaultPkg = "${packageName.ifBlank { "com.dspro.vault" }}.dspro.resvault"
            val vaultManifest = AxmlManifestPatcher.buildMinimalManifestForTest(
                packageName = vaultPkg,
                debuggable = null,
                allowBackup = null,
            )
            ZipOutputStream(innerCountingOut).use { innerZip ->
                innerZip.setLevel(Deflater.BEST_COMPRESSION)
                writeZipBytes(innerCountingOut, innerZip, innerWritten, "AndroidManifest.xml", vaultManifest, keepStored = false)
                for (asset in assetEntries) {
                    writeZipBytes(
                        countingOut = innerCountingOut,
                        zipOut = innerZip,
                        written = innerWritten,
                        name = asset.name,
                        bytes = asset.bytes,
                        keepStored = asset.keepStored,
                    )
                }
            }
            val plainZip = zipOutBytes.toByteArray()
            val salt = ByteArray(16).also { rng.nextBytes(it) }
            val iv = ByteArray(12).also { rng.nextBytes(it) }
            val saltHex = salt.joinToString("") { "%02x".format(it) }
            val key = MessageDigest.getInstance("SHA-256").digest(
                "$packageName:DSPRO_RES_V1:$saltHex".toByteArray(Charsets.UTF_8),
            )
            val cipherText = Cipher.getInstance("AES/GCM/NoPadding").apply {
                init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
            }.doFinal(plainZip)
            key.fill(0)
            plainZip.fill(0)

            return ByteArray(salt.size + iv.size + cipherText.size).also { out ->
                System.arraycopy(salt, 0, out, 0, salt.size)
                System.arraycopy(iv, 0, out, salt.size, iv.size)
                System.arraycopy(cipherText, 0, out, salt.size + iv.size, cipherText.size)
            }
        }

        private fun buildEncryptedCoreContainer(
            rng: SecureRandom,
            packageName: String,
            originalAppClass: String,
            originalFactoryClass: String,
            requireGuard: Boolean,
            antiDumpEnabled: Boolean,
            encryptStrings: Boolean,
            dexIntegrityEnabled: Boolean,
            coreDexSha256: ByteArray,
            guardDexSha256: ByteArray,
            dexPayloads: List<ByteArray>,
        ): Pair<ByteArray, Int> {
            val aesKey = ByteArray(32).also { rng.nextBytes(it) }
            val salt = ByteArray(16).also { rng.nextBytes(it) }
            val pepper = ByteArray(32).also { rng.nextBytes(it) }
            val pkgBytes = packageName.toByteArray(Charsets.UTF_8)

            val sha256 = MessageDigest.getInstance("SHA-256")
            sha256.update(pkgBytes)
            sha256.update(":V5M:".toByteArray(Charsets.UTF_8))
            sha256.update(salt)
            sha256.update(coreDexSha256)
            sha256.update(guardDexSha256)
            val bindingMask = sha256.digest()
            val maskedPepper = ByteArray(32) { i ->
                (pepper[i].toInt() xor bindingMask[i].toInt()).toByte()
            }
            bindingMask.fill(0)

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
                metaKey.fill(0)
                metaKey = sha256.digest()
            }
            pepper.fill(0)

            // Precompute original SHA-256 of each DEX payload for runtime DEX Integrity Protection
            val dexPayloadDigests = if (dexIntegrityEnabled) {
                dexPayloads.joinToString(",") { bytes ->
                    sha256.reset()
                    sha256.digest(bytes).joinToString("") { "%02x".format(it) }
                }
            } else {
                ""
            }

            val aesKeyHex = aesKey.joinToString("") { "%02x".format(it) }
            val metaPlain = buildString {
                appendLine(dexPayloads.size)
                appendLine(originalAppClass)
                appendLine(originalFactoryClass)
                appendLine(aesKeyHex)
                appendLine(if (requireGuard) "1" else "0")
                appendLine("Z1")
                appendLine(if (antiDumpEnabled) "1" else "0")
                appendLine(if (encryptStrings) "S1" else "S0")
                append(dexPayloadDigests)
            }.toByteArray(Charsets.UTF_8)

            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val metaIv = ByteArray(12).also { rng.nextBytes(it) }
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(metaKey, "AES"), GCMParameterSpec(128, metaIv))
            val metaCipher = cipher.doFinal(metaPlain)
            metaPlain.fill(0)
            metaKey.fill(0)

            var totalEncryptedStrings = 0
            val out = ByteArrayOutputStream()
            DataOutputStream(out).use { dos ->
                dos.write(salt)
                dos.write(maskedPepper)
                dos.write(metaIv)
                dos.writeInt(metaCipher.size)
                dos.write(metaCipher)

                val iv = ByteArray(12)
                dexPayloads.forEachIndexed { idx, rawDexBytes ->
                    rng.nextBytes(iv)
                    val ivHex = iv.joinToString("") { "%02x".format(it) }

                    sha256.reset()
                    sha256.update(aesKey)
                    sha256.update(":DEX:$idx:$ivHex".toByteArray(Charsets.UTF_8))
                    sha256.update(coreDexSha256)
                    val entryKey = sha256.digest()

                    val payloadForCompression: ByteArray
                    var patchCipher: ByteArray = ByteArray(0)
                    if (encryptStrings) {
                        sha256.reset()
                        sha256.update(entryKey)
                        sha256.update(":STR:$idx".toByteArray(Charsets.UTF_8))
                        val strKey = sha256.digest()
                        val strRes = DexPatcher.encryptLiteralStrings(rawDexBytes, strKey)
                        strKey.fill(0)
                        payloadForCompression = strRes.encryptedDexBytes
                        totalEncryptedStrings += strRes.encryptedStringCount
                        if (strRes.compressedPatchBlob.isNotEmpty()) {
                            val patchIv = iv.copyOf().apply { this[0] = (this[0].toInt() xor 0x5A).toByte() }
                            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(entryKey, "AES"), GCMParameterSpec(128, patchIv))
                            patchCipher = cipher.doFinal(strRes.compressedPatchBlob)
                        }
                    } else {
                        payloadForCompression = rawDexBytes
                    }

                    val compressedDex = deflateBytes(payloadForCompression, Deflater.BEST_COMPRESSION)
                    if (payloadForCompression !== rawDexBytes) {
                        payloadForCompression.fill(0)
                    }
                    cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(entryKey, "AES"), GCMParameterSpec(128, iv))
                    val cipherText = cipher.doFinal(compressedDex)
                    compressedDex.fill(0)
                    entryKey.fill(0)

                    dos.write(iv)
                    dos.writeInt(patchCipher.size)
                    if (patchCipher.isNotEmpty()) {
                        dos.write(patchCipher)
                    }
                    dos.writeInt(cipherText.size)
                    dos.write(cipherText)
                }
                aesKey.fill(0)
                dos.flush()
            }
            return out.toByteArray() to totalEncryptedStrings
        }

        private fun deflateBytes(input: ByteArray, level: Int): ByteArray {
            val deflater = Deflater(level)
            try {
                deflater.setInput(input)
                deflater.finish()
                val out = ByteArrayOutputStream((input.size / 2).coerceAtLeast(256))
                val buf = ByteArray(16 * 1024)
                while (!deflater.finished()) {
                    val count = deflater.deflate(buf)
                    if (count <= 0) break
                    out.write(buf, 0, count)
                }
                return out.toByteArray()
            } finally {
                deflater.end()
            }
        }

        private fun buildEncryptedGuardPolicy(
            rng: SecureRandom,
            packageName: String,
            analysis: ApkAnalysisResult,
            config: ProtectionConfig,
            integrityEntries: List<String>,
            dexIntegrityEntries: List<String>,
        ): ByteArray {
            var flags = 0
            if (config.detectRoot) flags = flags or 1
            if (config.detectDebugger) flags = flags or (1 shl 4)
            if (config.antiScreenshot) flags = flags or (1 shl 5)
            if (config.antiTampering) flags = flags or (1 shl 6)
            if (config.antiDump) flags = flags or (1 shl 8)
            if (config.dexIntegrityProtection) flags = flags or (1 shl 9)

            val entries = if (config.antiTampering) integrityEntries else emptyList()
            val dexEntries = if (config.dexIntegrityProtection) dexIntegrityEntries else emptyList()
            val plain = buildString {
                appendLine(flags)
                appendLine("NONE")
                appendLine(entries.size)
                entries.forEach { appendLine(it) }
                appendLine(dexEntries.size)
                dexEntries.forEach { appendLine(it) }
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

        private fun streamStoredZipEntry(
            countingOut: CountingOutputStream,
            zipOut: ZipOutputStream,
            written: HashSet<String>,
            name: String,
            size: Long,
            crc: Long,
            zipIn: ZipFile,
            entry: ZipEntry,
            copyBuf: ByteArray,
            computeSha256: Boolean,
        ): String? {
            if (!written.add(name)) return null
            val outEntry = ZipEntry(name)
            val alignment = if (name.endsWith(".so")) PAGE_ALIGN_BYTES else DATA_ALIGN_BYTES
            val nameLen = name.toByteArray(Charsets.UTF_8).size
            val unpaddedDataOffset = countingOut.bytesWritten + 30L + nameLen
            val remainder = (unpaddedDataOffset % alignment).toInt()
            var pad = if (remainder == 0) 0 else alignment - remainder
            if (pad in 1..3) {
                pad += alignment
            }
            if (pad > 0) {
                outEntry.extra = buildAlignmentPaddingExtra(pad)
            }
            outEntry.method = ZipEntry.STORED
            outEntry.size = size
            outEntry.compressedSize = size
            outEntry.crc = crc
            zipOut.putNextEntry(outEntry)
            val md = if (computeSha256) MessageDigest.getInstance("SHA-256") else null
            zipIn.getInputStream(entry).use { input ->
                var read: Int
                while (input.read(copyBuf).also { read = it } != -1) {
                    zipOut.write(copyBuf, 0, read)
                    md?.update(copyBuf, 0, read)
                }
            }
            zipOut.closeEntry()
            return md?.digest()?.joinToString("") { "%02x".format(it) }
        }

        private fun streamDeflatedZipEntry(
            zipOut: ZipOutputStream,
            written: HashSet<String>,
            name: String,
            zipIn: ZipFile,
            entry: ZipEntry,
            copyBuf: ByteArray,
            computeSha256: Boolean,
        ): String? {
            if (!written.add(name)) return null
            val outEntry = ZipEntry(name).apply { method = ZipEntry.DEFLATED }
            zipOut.putNextEntry(outEntry)
            val md = if (computeSha256) MessageDigest.getInstance("SHA-256") else null
            zipIn.getInputStream(entry).use { input ->
                var read: Int
                while (input.read(copyBuf).also { read = it } != -1) {
                    zipOut.write(copyBuf, 0, read)
                    md?.update(copyBuf, 0, read)
                }
            }
            zipOut.closeEntry()
            return md?.digest()?.joinToString("") { "%02x".format(it) }
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
                var pad = if (remainder == 0) 0 else alignment - remainder
                if (pad in 1..3) {
                    pad += alignment
                }
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
