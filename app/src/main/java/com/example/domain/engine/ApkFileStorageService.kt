package com.example.domain.engine

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import androidx.compose.runtime.Immutable
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.File

@Immutable
data class ExportedApkInfo(
    val fileName: String,
    val folderLabel: String,
    val sizeBytes: Long,
)

class ApkFileStorageService(private val context: Context) {

    suspend fun exportCopyWithDetailsToUri(
        sourceApk: File,
        destinationUri: Uri,
    ): Result<ExportedApkInfo> = withContext(Dispatchers.IO) {
        runCatching {
            require(sourceApk.exists() && sourceApk.length() > 0L) {
                "No valid protected APK build available to export."
            }
            context.contentResolver.openOutputStream(destinationUri)?.use { rawOut ->
                BufferedOutputStream(rawOut, 256 * 1024).use { out ->
                    BufferedInputStream(sourceApk.inputStream(), 256 * 1024).use { input ->
                        val buf = ByteArray(256 * 1024)
                        var read: Int
                        while (input.read(buf).also { read = it } != -1) {
                            out.write(buf, 0, read)
                        }
                    }
                    out.flush()
                }
            } ?: error("Cannot open destination URI for writing.")

            val savedName = resolveDisplayName(destinationUri) ?: sourceApk.name
            ExportedApkInfo(
                fileName = savedName,
                folderLabel = "Selected Storage",
                sizeBytes = sourceApk.length(),
            )
        }
    }

    suspend fun exportCopyToUri(
        sourceApk: File,
        destinationUri: Uri,
    ): Result<Long> = exportCopyWithDetailsToUri(sourceApk, destinationUri).map { it.sizeBytes }

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

    companion object {
        const val PROTECTED_FOLDER_NAME = "DS_PRO_Protected"
        const val APK_MIME_TYPE = "application/vnd.android.package-archive"

        fun buildProtectedFileName(
            packageName: String,
            timestampMillis: Long = System.currentTimeMillis(),
        ): String {
            val safePkg = packageName.replace(Regex("[^A-Za-z0-9._-]"), "_")
                .ifBlank { "app" }
            return "${safePkg}_dspro_protected_$timestampMillis.apk"
        }

        fun saveFileToDirectory(
            sourceApk: File,
            targetDirectory: File,
            fileName: String,
        ): Result<File> = runCatching {
            require(sourceApk.exists() && sourceApk.length() > 0L) {
                "Source APK file does not exist or is empty."
            }
            if (!targetDirectory.exists()) {
                require(targetDirectory.mkdirs()) {
                    "Failed to create directory: ${targetDirectory.absolutePath}"
                }
            }
            val destination = File(targetDirectory, fileName)
            sourceApk.inputStream().use { input ->
                destination.outputStream().use { output ->
                    input.copyTo(output, bufferSize = 32 * 1024)
                    output.flush()
                }
            }
            require(destination.exists() && destination.length() == sourceApk.length()) {
                "Copied APK size verification failed."
            }
            destination
        }
    }
}
