package com.example.domain.model

enum class ProtectionSection(val label: String) {
    RUNTIME_GUARD("Runtime Guard"),
    BINARY_HARDENING("DPT & APK Hardening"),
}

data class ProtectionFeatureInfo(
    val id: String,
    val title: String,
    val whatTurnsOn: String,
    val howItWorks: String,
)

data class ProtectionConfig(
    // Runtime Guard (all OFF by default — enforced via injected DsProGuardProvider DEX)
    val detectRoot: Boolean = false,
    val detectEmulator: Boolean = false,
    val detectVpn: Boolean = false,
    val detectXposed: Boolean = false,
    val detectDebugger: Boolean = false,
    val antiScreenshot: Boolean = false,
    val antiTampering: Boolean = false,
    val signaturePinning: Boolean = false,

    // DPT & Binary Hardening (DEX encryption shell + direct AXML/DEX/ZIP modifications)
    val dptDexEncryption: Boolean = false,
    val disableDebuggable: Boolean = false,
    val disableBackup: Boolean = false,
    val stripDexDebug: Boolean = false,
    val stripMetadataBloat: Boolean = false,
    val bestCompression: Boolean = false,
) {
    val requiresRuntimeGuard: Boolean
        get() = detectRoot ||
            detectEmulator ||
            detectVpn ||
            detectXposed ||
            detectDebugger ||
            antiScreenshot ||
            antiTampering ||
            signaturePinning

    val activeToggleCount: Int
        get() = listOf(
            detectRoot,
            detectEmulator,
            detectVpn,
            detectXposed,
            detectDebugger,
            antiScreenshot,
            antiTampering,
            signaturePinning,
            dptDexEncryption,
            disableDebuggable,
            disableBackup,
            stripDexDebug,
            stripMetadataBloat,
            bestCompression,
        ).count { it }

    fun activeCountFor(section: ProtectionSection): Int = when (section) {
        ProtectionSection.RUNTIME_GUARD -> listOf(
            detectRoot,
            detectEmulator,
            detectVpn,
            detectXposed,
            detectDebugger,
            antiScreenshot,
            antiTampering,
            signaturePinning,
        ).count { it }

        ProtectionSection.BINARY_HARDENING -> listOf(
            dptDexEncryption,
            disableDebuggable,
            disableBackup,
            stripDexDebug,
            stripMetadataBloat,
            bestCompression,
        ).count { it }
    }
}

data class ApkAnalysisResult(
    val fileName: String,
    val cachedApkPath: String,
    val packageName: String,
    val appName: String,
    val versionName: String,
    val versionCode: Long,
    val minSdk: Int,
    val targetSdk: Int,
    val fileSizeBytes: Long,
    val totalEntries: Int,
    val dexCount: Int,
    val logCallMatches: Int,
    val signingCertSha256: String,
    val isSigned: Boolean,
    val isDebuggable: Boolean = false,
    val allowsBackup: Boolean = true,
    val hasGuardProvider: Boolean = false,
    val hasDptShell: Boolean = false,
)

enum class StepStatus {
    SUCCESS,
    FAILED,
    SKIPPED,
}

data class ProtectionStepResult(
    val id: String,
    val title: String,
    val status: StepStatus,
    val detail: String,
)

data class SavedApkLocation(
    val folderDisplay: String,
    val fileName: String,
    val savedUri: String?,
)

data class ProtectionRunResult(
    val outputApkPath: String?,
    val outputSizeBytes: Long,
    val isValidBuild: Boolean,
    val summary: String,
    val steps: List<ProtectionStepResult>,
    val savedLocation: SavedApkLocation? = null,
)
