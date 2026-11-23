package com.example.domain.engine

import android.content.ContentValues
import android.content.Context
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import com.example.domain.model.SavedApkLocation
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

class ApkFileStorageService(private val context: Context) {

    suspend fun saveProtectedApk(
        sourceApk: File,
        packageName: String,
    ): Result<SavedApkLocation> = withContext(Dispatchers.IO) {
        runCatching {
            require(sourceApk.exists() && sourceApk.length() > 0L) {
                "Protected APK file is missing or empty."
            }

            val fileName = buildProtectedFileName(packageName)

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                saveViaMediaStore(sourceApk, fileName)
            } else {
                saveViaLegacyExternalFolder(sourceApk, fileName)
            }
        }
    }

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

    private fun saveViaMediaStore(sourceApk: File, fileName: String): SavedApkLocation {
        val relativePath = "${Environment.DIRECTORY_DOWNLOADS}/$PROTECTED_FOLDER_NAME"
        val values = ContentValues().apply {
            put(MediaStore.MediaColumns.DISPLAY_NAME, fileName)
            put(MediaStore.MediaColumns.MIME_TYPE, APK_MIME_TYPE)
            put(MediaStore.MediaColumns.RELATIVE_PATH, relativePath)
            put(MediaStore.MediaColumns.IS_PENDING, 1)
        }

        val resolver = context.contentResolver
        val insertedUri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
            ?: error("Unable to create APK entry in $relativePath.")

        return try {
            resolver.openOutputStream(insertedUri)?.use { out ->
                sourceApk.inputStream().use { input ->
                    input.copyTo(out, bufferSize = 32 * 1024)
                }
                out.flush()
            } ?: error("Failed to write APK stream to MediaStore.")

            val finalizeValues = ContentValues().apply {
                put(MediaStore.MediaColumns.IS_PENDING, 0)
            }
            resolver.update(insertedUri, finalizeValues, null, null)

            SavedApkLocation(
                folderDisplay = relativePath,
                fileName = fileName,
                savedUri = insertedUri.toString(),
            )
        } catch (t: Throwable) {
            runCatching { resolver.delete(insertedUri, null, null) }
            throw t
        }
    }

    private fun saveViaLegacyExternalFolder(sourceApk: File, fileName: String): SavedApkLocation {
        val baseDir = context.getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS) ?: context.filesDir
        val protectedDir = File(baseDir, PROTECTED_FOLDER_NAME)
        val savedFile = saveFileToDirectory(sourceApk, protectedDir, fileName).getOrThrow()

        return SavedApkLocation(
            folderDisplay = "${Environment.DIRECTORY_DOWNLOADS}/$PROTECTED_FOLDER_NAME",
            fileName = savedFile.name,
            savedUri = Uri.fromFile(savedFile).toString(),
        )
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
