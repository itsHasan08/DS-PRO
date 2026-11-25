package com.example.domain.engine

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import androidx.compose.runtime.Immutable
import androidx.core.content.ContextCompat
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

@Immutable
data class StorageAccessStatus(
    val hasAccess: Boolean,
    val hasPersistedFolder: Boolean,
    val folderLabel: String?,
)

class ApkFileStorageService(private val context: Context) {

    private val prefs by lazy {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }

    fun getPersistedStorageTreeUri(): Uri? {
        val raw = prefs.getString(KEY_STORAGE_TREE_URI, null) ?: return null
        val uri = runCatching { Uri.parse(raw) }.getOrNull() ?: return null
        val granted = context.contentResolver.persistedUriPermissions.any {
            it.uri == uri && it.isReadPermission && it.isWritePermission
        }
        if (!granted) {
            prefs.edit().remove(KEY_STORAGE_TREE_URI).apply()
            return null
        }
        return uri
    }

    fun saveStorageTreeUri(treeUri: Uri): StorageAccessStatus {
        runCatching {
            context.contentResolver.takePersistableUriPermission(
                treeUri,
                Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION,
            )
        }
        prefs.edit().putString(KEY_STORAGE_TREE_URI, treeUri.toString()).apply()
        return getStorageAccessStatus()
    }

    fun clearPersistedStorageTreeUri() {
        prefs.edit().remove(KEY_STORAGE_TREE_URI).apply()
    }

    fun getStorageAccessStatus(): StorageAccessStatus {
        val treeUri = getPersistedStorageTreeUri()
        val folderLabel = treeUri?.let { extractFolderLabel(it) }
        val hasLegacy = if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.Q) {
            ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.WRITE_EXTERNAL_STORAGE,
            ) == PackageManager.PERMISSION_GRANTED
        } else {
            false
        }
        return StorageAccessStatus(
            hasAccess = treeUri != null || hasLegacy,
            hasPersistedFolder = treeUri != null,
            folderLabel = folderLabel,
        )
    }

    suspend fun exportToGrantedStorageFolder(
        sourceApk: File,
        fileName: String,
    ): Result<ExportedApkInfo> = withContext(Dispatchers.IO) {
        runCatching {
            require(sourceApk.exists() && sourceApk.length() > 0L) {
                "No valid protected APK build available to export."
            }
            val treeUri = getPersistedStorageTreeUri()
                ?: error("Storage folder permission not granted.")
            val treeDocId = DocumentsContract.getTreeDocumentId(treeUri)
            val parentDocUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, treeDocId)
            val createdUri = DocumentsContract.createDocument(
                context.contentResolver,
                parentDocUri,
                APK_MIME_TYPE,
                fileName,
            ) ?: error("Could not create APK file in selected folder.")

            try {
                context.contentResolver.openOutputStream(createdUri)?.use { rawOut ->
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
                } ?: error("Cannot write to selected storage folder.")
            } catch (t: Throwable) {
                runCatching { DocumentsContract.deleteDocument(context.contentResolver, createdUri) }
                throw t
            }

            val savedName = resolveDisplayName(createdUri) ?: fileName
            val folderLabel = extractFolderLabel(treeUri)
            ExportedApkInfo(
                fileName = savedName,
                folderLabel = folderLabel,
                sizeBytes = sourceApk.length(),
            )
        }
    }

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
                folderLabel = "Device Storage",
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

    private fun extractFolderLabel(treeUri: Uri): String {
        val docId = runCatching { DocumentsContract.getTreeDocumentId(treeUri) }.getOrNull().orEmpty()
        val afterColon = docId.substringAfter(':', docId).trim('/')
        return when {
            afterColon.isNotBlank() -> afterColon
            docId.equals("primary:", ignoreCase = true) || docId.equals("primary", ignoreCase = true) -> "Internal Storage"
            else -> "Selected Folder"
        }
    }

    companion object {
        const val PROTECTED_FOLDER_NAME = "DS_PRO_Protected"
        const val APK_MIME_TYPE = "application/vnd.android.package-archive"
        private const val PREFS_NAME = "dspro_storage_prefs"
        private const val KEY_STORAGE_TREE_URI = "persisted_storage_tree_uri"

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
