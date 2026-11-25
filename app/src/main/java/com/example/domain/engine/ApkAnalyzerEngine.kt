package com.example.domain.engine

import android.content.Context
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.OpenableColumns
import com.example.domain.model.ApkAnalysisResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import java.security.MessageDigest
import java.util.zip.ZipFile
import kotlin.math.min

class ApkAnalyzerEngine(private val context: Context) {

    private val workDir: File
        get() = File(context.cacheDir, "dspro_work").apply { mkdirs() }

    suspend fun loadApkFromUri(uri: Uri): Result<ApkAnalysisResult> = withContext(Dispatchers.IO) {
        runCatching {
            // Retain URI read permission when supported by the document provider
            runCatching {
                context.contentResolver.takePersistableUriPermission(
                    uri,
                    Intent.FLAG_GRANT_READ_URI_PERMISSION,
                )
            }

            val displayName = resolveDisplayName(uri) ?: "selected.apk"
            val sanitizedName = displayName.replace(Regex("[^A-Za-z0-9._-]"), "_")
            val targetFile = File(workDir, "input_${System.currentTimeMillis()}_$sanitizedName")

            context.contentResolver.openInputStream(uri)?.use { input ->
                java.io.BufferedOutputStream(FileOutputStream(targetFile), 128 * 1024).use { output ->
                    val buffer = ByteArray(128 * 1024)
                    var read: Int
                    while (input.read(buffer).also { read = it } != -1) {
                        output.write(buffer, 0, read)
                    }
                    output.flush()
                }
            } ?: error("Could not read selected file.")

            require(targetFile.exists() && targetFile.length() > 64) {
                targetFile.delete()
                "Selected file is empty or invalid."
            }

            val magic = ByteArray(4)
            targetFile.inputStream().use { it.read(magic) }
            require(
                magic[0] == 0x50.toByte() &&
                    magic[1] == 0x4B.toByte() &&
                    magic[2] == 0x03.toByte() &&
                    magic[3] == 0x04.toByte()
            ) {
                targetFile.delete()
                "Please select a valid .apk file."
            }

            workDir.listFiles()
                ?.filter { it.name.startsWith("input_") && it.name != targetFile.name }
                ?.forEach { it.delete() }

            inspectApkFile(targetFile, displayName)
        }
    }

    private fun inspectApkFile(apkFile: File, displayName: String): ApkAnalysisResult {
        val pm = context.packageManager
        val pkgInfo = loadPackageArchiveInfo(pm, apkFile.absolutePath)

        val appInfo = pkgInfo?.applicationInfo?.apply {
            sourceDir = apkFile.absolutePath
            publicSourceDir = apkFile.absolutePath
        }

        val appName = appInfo?.let {
            runCatching { pm.getApplicationLabel(it).toString() }.getOrNull()
        }?.takeIf { it.isNotBlank() } ?: displayName.removeSuffix(".apk")

        val pmPackageName = pkgInfo?.packageName?.takeIf { it.isNotBlank() }
        val versionName = pkgInfo?.versionName ?: "1.0"
        val versionCode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            pkgInfo?.longVersionCode ?: 1L
        } else {
            @Suppress("DEPRECATION")
            (pkgInfo?.versionCode?.toLong() ?: 1L)
        }
        val minSdk = appInfo?.minSdkVersion ?: 0
        val targetSdk = appInfo?.targetSdkVersion ?: 0
        val (certSha256, isSigned) = extractCertSha256(pkgInfo)

        var totalEntries = 0
        var hasManifest = false
        var manifestSummary: AxmlSecuritySummary? = null
        var dexCount = 0

        ZipFile(apkFile).use { zip ->
            val entries = zip.entries()
            while (entries.hasMoreElements()) {
                val entry = entries.nextElement()
                if (entry.isDirectory) continue
                totalEntries++
                val name = entry.name
                if (name == "AndroidManifest.xml") {
                    hasManifest = true
                    manifestSummary = zip.getInputStream(entry).use { stream ->
                        AxmlManifestPatcher.inspectSecuritySummary(stream.readBytes())
                    }
                } else if (name.startsWith("classes") && name.endsWith(".dex") && name.indexOf('/') == -1) {
                    dexCount++
                }
            }
        }

        require(hasManifest) {
            apkFile.delete()
            "Selected archive does not contain AndroidManifest.xml."
        }

        val packageName = pmPackageName ?: manifestSummary?.packageName.orEmpty().ifBlank { "unknown.package" }

        val pmProtectionId = appInfo?.metaData
            ?.getString(AxmlManifestPatcher.PROTECTION_IDENTIFIER_META_NAME)
            ?.takeIf { it.isNotBlank() }
        val protectionIdentifier = manifestSummary?.protectionIdentifier ?: pmProtectionId

        return ApkAnalysisResult(
            fileName = displayName,
            cachedApkPath = apkFile.absolutePath,
            packageName = packageName,
            appName = appName,
            versionName = versionName,
            versionCode = versionCode,
            minSdk = minSdk,
            targetSdk = targetSdk,
            fileSizeBytes = apkFile.length(),
            totalEntries = totalEntries,
            dexCount = dexCount,
            logCallMatches = 0,
            signingCertSha256 = certSha256,
            isSigned = isSigned,
            isDebuggable = manifestSummary?.isDebuggable ?: false,
            allowsBackup = manifestSummary?.allowsBackup ?: true,
            hasGuardProvider = manifestSummary?.hasGuardProvider ?: false,
            hasCoreProtection = manifestSummary?.hasCoreProtection ?: false,
            protectionIdentifier = protectionIdentifier,
        )
    }

    private fun resolveDisplayName(uri: Uri): String? {
        return runCatching {
            context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)
                ?.use { cursor ->
                    if (cursor.moveToFirst()) {
                        val idx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                        if (idx >= 0) cursor.getString(idx) else null
                    } else {
                        null
                    }
                }
        }.getOrNull()
    }

    @Suppress("DEPRECATION")
    private fun loadPackageArchiveInfo(pm: PackageManager, path: String): PackageInfo? {
        val sigFlag = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            PackageManager.GET_SIGNING_CERTIFICATES
        } else {
            PackageManager.GET_SIGNATURES
        }
        val queryFlags = sigFlag or PackageManager.GET_META_DATA
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getPackageArchiveInfo(path, PackageManager.PackageInfoFlags.of(queryFlags.toLong()))
        } else {
            pm.getPackageArchiveInfo(path, queryFlags)
        }
    }

    @Suppress("DEPRECATION")
    private fun extractCertSha256(pkgInfo: PackageInfo?): Pair<String, Boolean> {
        if (pkgInfo == null) return "Unsigned" to false
        val raw = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val info = pkgInfo.signingInfo
            val signers = if (info?.hasMultipleSigners() == true) {
                info.apkContentsSigners
            } else {
                info?.signingCertificateHistory
            }
            signers?.firstOrNull()?.toByteArray()
        } else {
            pkgInfo.signatures?.firstOrNull()?.toByteArray()
        } ?: return "Unsigned" to false

        val sha256 = MessageDigest.getInstance("SHA-256")
            .digest(raw)
            .joinToString(":") { "%02X".format(it) }
        return sha256 to true
    }
}
