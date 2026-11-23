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
            workDir.listFiles()?.filter { it.name.startsWith("input_") }?.forEach { it.delete() }
            val targetFile = File(workDir, "input_${System.currentTimeMillis()}_$sanitizedName")

            context.contentResolver.openInputStream(uri)?.use { input ->
                FileOutputStream(targetFile).use { output ->
                    val buffer = ByteArray(16 * 1024)
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

        val packageName = pkgInfo?.packageName ?: "unknown.package"
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
        var dexCount = 0
        var logCallMatches = 0

        ZipFile(apkFile).use { zip ->
            val entries = zip.entries()
            while (entries.hasMoreElements()) {
                val entry = entries.nextElement()
                if (entry.isDirectory) continue
                totalEntries++
                val name = entry.name
                if (name == "AndroidManifest.xml") {
                    hasManifest = true
                } else if (name.startsWith("classes") && name.endsWith(".dex")) {
                    dexCount++
                    zip.getInputStream(entry).use { stream ->
                        val maxScanBytes = 2 * 1024 * 1024
                        var scanned = 0
                        val chunk = ByteArray(32 * 1024)
                        var tail = ""
                        while (scanned < maxScanBytes) {
                            val n = stream.read(chunk, 0, min(chunk.size, maxScanBytes - scanned))
                            if (n <= 0) break
                            scanned += n
                            val text = tail + String(chunk, 0, n, Charsets.ISO_8859_1)
                            logCallMatches += countOccurrences(text, "Landroid/util/Log;")
                            tail = if (text.length > 32) text.takeLast(32) else text
                        }
                    }
                }
            }
        }

        require(hasManifest) {
            apkFile.delete()
            "Selected archive does not contain AndroidManifest.xml."
        }

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
            logCallMatches = logCallMatches,
            signingCertSha256 = certSha256,
            isSigned = isSigned,
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
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getPackageArchiveInfo(path, PackageManager.PackageInfoFlags.of(sigFlag.toLong()))
        } else {
            pm.getPackageArchiveInfo(path, sigFlag)
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

    private fun countOccurrences(haystack: String, needle: String): Int {
        var count = 0
        var idx = haystack.indexOf(needle)
        while (idx != -1) {
            count++
            idx = haystack.indexOf(needle, idx + needle.length)
        }
        return count
    }
}
