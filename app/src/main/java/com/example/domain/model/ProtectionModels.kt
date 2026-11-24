package com.example.domain.model

enum class ProtectionSection(val label: String) {
    RUNTIME_GUARD("Runtime Guard"),
    BINARY_HARDENING("DS PRO & APK Hardening"),
}

data class ProtectionFeatureInfo(
    val id: String,
    val title: String,
    val whatTurnsOn: String,
    val howItWorks: String,
)

data class ProtectionConfig(
    // Runtime Guard & Assist Protection (all OFF by default — enforced via injected DsProGuardProvider DEX)
    val detectRoot: Boolean = false,
    val detectDebugger: Boolean = false,
    val antiScreenshot: Boolean = false,
    val antiTampering: Boolean = false,
    val antiDump: Boolean = false,
    val dexIntegrityProtection: Boolean = false,
    val assistEncrypt: Boolean = false,

    // DS PRO Core & Binary Hardening (DEX/String/Resource encryption, CFO, AXML/DEX hardening)
    val dsProDexEncryption: Boolean = false,
    val stringEncryption: Boolean = false,
    val controlFlowObfuscation: Boolean = false,
    val resourceEncryption: Boolean = false,
    val disableDebuggable: Boolean = false,
    val stripDexDebug: Boolean = false,
) {
    val requiresRuntimeGuard: Boolean
        get() = detectRoot ||
            detectDebugger ||
            antiScreenshot ||
            antiTampering ||
            antiDump ||
            dexIntegrityProtection

    val requiresAssetVault: Boolean
        get() = resourceEncryption || assistEncrypt

    val requiresGuardDex: Boolean
        get() = requiresRuntimeGuard || requiresAssetVault

    val requiresCoreDexContainer: Boolean
        get() = dsProDexEncryption || stringEncryption

    val activeToggleCount: Int
        get() = listOf(
            detectRoot,
            detectDebugger,
            antiScreenshot,
            antiTampering,
            antiDump,
            dexIntegrityProtection,
            assistEncrypt,
            dsProDexEncryption,
            stringEncryption,
            controlFlowObfuscation,
            resourceEncryption,
            disableDebuggable,
            stripDexDebug,
        ).count { it }

    fun activeCountFor(section: ProtectionSection): Int = when (section) {
        ProtectionSection.RUNTIME_GUARD -> listOf(
            detectRoot,
            detectDebugger,
            antiScreenshot,
            antiTampering,
            antiDump,
            dexIntegrityProtection,
            assistEncrypt,
        ).count { it }

        ProtectionSection.BINARY_HARDENING -> listOf(
            dsProDexEncryption,
            stringEncryption,
            controlFlowObfuscation,
            resourceEncryption,
            disableDebuggable,
            stripDexDebug,
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
    val hasCoreProtection: Boolean = false,
    val protectionIdentifier: String? = null,
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

data class ProtectionRunResult(
    val outputApkPath: String?,
    val outputSizeBytes: Long,
    val isValidBuild: Boolean,
    val summary: String,
    val steps: List<ProtectionStepResult>,
)
