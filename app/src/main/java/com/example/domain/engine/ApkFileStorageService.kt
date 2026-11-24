package com.example.domain.engine

import android.content.Context
import android.net.Uri
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

class ApkFileStorageService(private val context: Context) {

    suspend fun exportCopyToUri(
        sourceApk: File,
        destinationUri: Uri,
    ): Result<Long> = withContext(Dispatchers.IO) {
        runCatching {
            require(sourceApk.exists() && sourceApk.length() > 0L) {
                "No valid protected APK build available to export."
            }
            context.contentResolver.openOutputStream(destinationUri)?.use { out ->
                sourceApk.inputStream().use { input ->
                    input.copyTo(out, bufferSize = 32 * 1024)
                }
                out.flush()
            } ?: error("Cannot open destination URI for writing.")
            sourceApk.length()
        }
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
