package com.example.ui.screens

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.GridItemSpan
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarDuration
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.material3.pulltorefresh.PullToRefreshDefaults.Indicator
import androidx.compose.material3.pulltorefresh.rememberPullToRefreshState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.example.domain.engine.formatBytes
import com.example.domain.model.ProtectionConfig
import com.example.domain.model.ProtectionFeatureInfo
import com.example.domain.model.ProtectionSection
import com.example.ui.components.CenteredToastHost
import com.example.ui.components.DsProTopBar
import com.example.ui.components.FeatureInfoDialog
import com.example.ui.components.GridGroupHeader
import com.example.ui.components.GridToggleTile
import com.example.ui.components.KeyValueLine
import com.example.ui.components.ProtectionPipelineCard
import com.example.ui.components.SectionCard
import com.example.ui.components.StatusPill
import com.example.ui.theme.BorderSubtle
import com.example.ui.theme.CharcoalText
import com.example.ui.theme.ErrorRed
import com.example.ui.theme.ErrorTint
import com.example.ui.theme.ProBlue
import com.example.ui.theme.ProBlueTint
import com.example.ui.theme.PureWhite
import com.example.ui.theme.SuccessEmerald
import com.example.ui.theme.SuccessTint
import com.example.ui.theme.TealAccent
import com.example.ui.theme.TealTint
import com.example.ui.theme.WarningAmber
import com.example.ui.theme.WarningTint
import com.example.ui.viewmodel.MainViewModel
import kotlinx.coroutines.withTimeoutOrNull

private data class ToggleSpec(
    val info: ProtectionFeatureInfo,
    val checked: Boolean,
    val tag: String,
    val onToggle: (Boolean) -> Unit,
)

@OptIn(ExperimentalLayoutApi::class, ExperimentalMaterial3Api::class)
@Composable
fun MainScreen(
    viewModel: MainViewModel,
) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    var activeInfoDialog by remember { mutableStateOf<Pair<ProtectionFeatureInfo, Boolean>?>(null) }
    val pullToRefreshState = rememberPullToRefreshState()

    val apkPickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument(),
    ) { uri ->
        if (uri != null) {
            viewModel.onApkUriSelected(uri)
        }
    }

    val exportLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("application/vnd.android.package-archive"),
    ) { uri ->
        if (uri != null) {
            viewModel.exportUnsignedApk(uri)
        }
    }

    LaunchedEffect(uiState.statusMessage) {
        val msg = uiState.statusMessage
        if (msg != null) {
            snackbarHostState.currentSnackbarData?.dismiss()
            viewModel.clearStatusMessage()
            withTimeoutOrNull(2200L) {
                snackbarHostState.showSnackbar(
                    message = msg,
                    duration = SnackbarDuration.Indefinite,
                )
            }
            snackbarHostState.currentSnackbarData?.dismiss()
        }
    }

    val cfg = uiState.config
    val runtimeToggles = remember(cfg, viewModel) { runtimeGuardToggles(cfg, viewModel) }
    val binaryToggles = remember(cfg, viewModel) { binaryHardeningToggles(cfg, viewModel) }
    val refreshAlpha by animateFloatAsState(
        targetValue = if (uiState.isRefreshing) 0.68f else 1f,
        animationSpec = tween(durationMillis = 220),
        label = "refresh_alpha",
    )

    activeInfoDialog?.let { (info, enabled) ->
        FeatureInfoDialog(
            info = info,
            isEnabled = enabled,
            onDismiss = { activeInfoDialog = null },
        )
    }

    Box(modifier = Modifier.fillMaxSize()) {
        Scaffold(
            modifier = Modifier
                .fillMaxSize()
                .background(PureWhite),
            containerColor = PureWhite,
            contentWindowInsets = WindowInsets.navigationBars,
            topBar = {
                DsProTopBar(activeCount = cfg.activeToggleCount)
            },
        ) { innerPadding ->
            PullToRefreshBox(
                isRefreshing = uiState.isRefreshing,
                onRefresh = { viewModel.refreshWorkspace() },
                state = pullToRefreshState,
                indicator = {
                    Indicator(
                        modifier = Modifier.align(Alignment.TopCenter),
                        isRefreshing = uiState.isRefreshing,
                        containerColor = PureWhite,
                        color = ProBlue,
                        state = pullToRefreshState,
                    )
                },
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding),
            ) {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .alpha(refreshAlpha),
                    contentAlignment = Alignment.TopCenter,
                ) {
                    LazyVerticalGrid(
                        columns = GridCells.Adaptive(minSize = 156.dp),
                        modifier = Modifier
                            .fillMaxSize()
                            .widthIn(max = 840.dp),
                        contentPadding = PaddingValues(16.dp),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                    // 1. Select APK + Metadata + Protection Badge (Full Span)
                    item(span = { GridItemSpan(maxLineSpan) }) {
                        SectionCard(
                            title = "APK File",
                            icon = Icons.Filled.FolderOpen,
                            accentColor = ProBlue,
                            accentTint = ProBlueTint,
                        ) {
                            Button(
                                onClick = {
                                    apkPickerLauncher.launch(
                                        arrayOf(
                                            "application/vnd.android.package-archive",
                                            "application/octet-stream",
                                            "*/*",
                                        ),
                                    )
                                },
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .heightIn(min = 48.dp)
                                    .testTag("select_apk_button"),
                                shape = RoundedCornerShape(12.dp),
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = ProBlue,
                                    contentColor = PureWhite,
                                ),
                            ) {
                                Icon(Icons.Filled.FolderOpen, contentDescription = null, modifier = Modifier.size(18.dp))
                                Spacer(modifier = Modifier.width(8.dp))
                                Text(
                                    text = if (uiState.selectedApk == null) "Select APK" else "Change APK",
                                    fontWeight = FontWeight.SemiBold,
                                )
                            }

                            if (uiState.isLoadingApk) {
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(vertical = 4.dp),
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                                ) {
                                    CircularProgressIndicator(
                                        modifier = Modifier.size(20.dp),
                                        strokeWidth = 2.dp,
                                        color = ProBlue,
                                    )
                                    Text(
                                        text = "Reading APK...",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = CharcoalText,
                                    )
                                }
                            }

                            if (uiState.apkError != null) {
                                Surface(
                                    modifier = Modifier.fillMaxWidth(),
                                    shape = RoundedCornerShape(10.dp),
                                    color = ErrorTint,
                                    border = BorderStroke(1.dp, ErrorRed.copy(alpha = 0.35f)),
                                ) {
                                    Text(
                                        text = uiState.apkError!!,
                                        style = MaterialTheme.typography.bodySmall,
                                        color = ErrorRed,
                                        modifier = Modifier.padding(10.dp),
                                    )
                                }
                            }

                            val apk = uiState.selectedApk
                            if (apk != null) {
                                Surface(
                                    modifier = Modifier.fillMaxWidth(),
                                    shape = RoundedCornerShape(12.dp),
                                    color = PureWhite,
                                    border = BorderStroke(1.dp, BorderSubtle),
                                ) {
                                    Column(
                                        modifier = Modifier.padding(12.dp),
                                        verticalArrangement = Arrangement.spacedBy(4.dp),
                                    ) {
                                        KeyValueLine("App Name", apk.appName)
                                        KeyValueLine("Package", apk.packageName, mono = true)
                                        KeyValueLine("Version", "${apk.versionName} (${apk.versionCode})")
                                        KeyValueLine("Size", "${formatBytes(apk.fileSizeBytes)} (${apk.dexCount} DEX)")
                                        Spacer(modifier = Modifier.size(2.dp))
                                        FlowRow(
                                            horizontalArrangement = Arrangement.spacedBy(6.dp),
                                            verticalArrangement = Arrangement.spacedBy(6.dp),
                                        ) {
                                            val isProtected = apk.hasCoreProtection || apk.hasGuardProvider
                                            StatusPill(
                                                text = when {
                                                    apk.hasCoreProtection && apk.hasGuardProvider -> "DS PRO Protected"
                                                    apk.hasCoreProtection -> "DS PRO Core"
                                                    apk.hasGuardProvider -> "DS PRO Guard"
                                                    else -> "Unprotected"
                                                },
                                                containerColor = if (isProtected) SuccessTint else WarningTint,
                                                contentColor = if (isProtected) SuccessEmerald else WarningAmber,
                                                icon = if (isProtected) Icons.Filled.VerifiedUser else Icons.Outlined.Shield,
                                            )
                                            StatusPill(
                                                text = if (apk.isSigned) "Signed" else "Unsigned",
                                                containerColor = if (apk.isSigned) ProBlueTint else ErrorTint,
                                                contentColor = if (apk.isSigned) ProBlue else ErrorRed,
                                            )
                                            StatusPill(
                                                text = if (apk.isDebuggable) "Debuggable" else "Non-Debuggable",
                                                containerColor = if (apk.isDebuggable) ErrorTint else TealTint,
                                                contentColor = if (apk.isDebuggable) ErrorRed else TealAccent,
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // 2. Runtime Guard Group (2-column compact grid with ProBlue accent)
                    item(span = { GridItemSpan(maxLineSpan) }, contentType = { "header" }) {
                        GridGroupHeader(
                            title = ProtectionSection.RUNTIME_GUARD.label,
                            icon = Icons.Filled.Security,
                            activeCount = cfg.activeCountFor(ProtectionSection.RUNTIME_GUARD),
                            accentColor = ProBlue,
                            accentTint = ProBlueTint,
                        )
                    }
                    items(
                        items = runtimeToggles,
                        key = { it.tag },
                        contentType = { "toggle" },
                    ) { item ->
                        GridToggleTile(
                            title = item.info.title,
                            checked = item.checked,
                            onCheckedChange = item.onToggle,
                            onInfoClick = { activeInfoDialog = item.info to item.checked },
                            testTag = item.tag,
                            accentColor = ProBlue,
                            accentTint = ProBlueTint,
                        )
                    }

                    // 3. Binary & Manifest Hardening Group (2-column compact grid with TealAccent)
                    item(span = { GridItemSpan(maxLineSpan) }, contentType = { "header" }) {
                        GridGroupHeader(
                            title = ProtectionSection.BINARY_HARDENING.label,
                            icon = Icons.Filled.Build,
                            activeCount = cfg.activeCountFor(ProtectionSection.BINARY_HARDENING),
                            accentColor = TealAccent,
                            accentTint = TealTint,
                        )
                    }
                    items(
                        items = binaryToggles,
                        key = { it.tag },
                        contentType = { "toggle" },
                    ) { item ->
                        GridToggleTile(
                            title = item.info.title,
                            checked = item.checked,
                            onCheckedChange = item.onToggle,
                            onInfoClick = { activeInfoDialog = item.info to item.checked },
                            testTag = item.tag,
                            accentColor = TealAccent,
                            accentTint = TealTint,
                        )
                    }

                    // 4. Start + Progress + DS_PRO_Protected Folder Output (Full Span)
                    item(span = { GridItemSpan(maxLineSpan) }) {
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(top = 8.dp),
                            verticalArrangement = Arrangement.spacedBy(10.dp),
                        ) {
                            if (cfg.signaturePinning) {
                                Surface(
                                    modifier = Modifier.fillMaxWidth(),
                                    shape = RoundedCornerShape(10.dp),
                                    color = ErrorTint,
                                    border = BorderStroke(1.dp, ErrorRed.copy(alpha = 0.35f)),
                                ) {
                                    Text(
                                        text = "Signature Pinning is ON: re-sign the output APK with the original signing certificate, otherwise the app will exit on launch.",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = ErrorRed,
                                        modifier = Modifier.padding(10.dp),
                                    )
                                }
                            }

                            Button(
                                onClick = { viewModel.startProtection() },
                                enabled = uiState.isStartEnabled,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .heightIn(min = 52.dp)
                                    .testTag("start_protection_button"),
                                shape = RoundedCornerShape(12.dp),
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = ProBlue,
                                    contentColor = PureWhite,
                                ),
                            ) {
                                Icon(Icons.Filled.PlayArrow, contentDescription = null, modifier = Modifier.size(20.dp))
                                Spacer(modifier = Modifier.width(8.dp))
                                Text(
                                    text = if (uiState.isProcessing) "Processing (${uiState.progress}%)..." else "Start",
                                    fontWeight = FontWeight.SemiBold,
                                )
                            }

                            if (uiState.isProcessing || uiState.progress > 0 || uiState.steps.isNotEmpty() || uiState.runResult != null) {
                                ProtectionPipelineCard(
                                    isProcessing = uiState.isProcessing,
                                    progress = uiState.progress,
                                    steps = uiState.steps,
                                    runResult = uiState.runResult,
                                    onExportClick = {
                                        val pkg = uiState.selectedApk?.packageName ?: "app"
                                        exportLauncher.launch("${pkg}_dspro_unsigned.apk")
                                    },
                                )
                            }
                        }
                    }
                }
            }
        }
        }
        CenteredToastHost(
            hostState = snackbarHostState,
            modifier = Modifier.align(Alignment.Center),
        )
    }
}

private val INFO_DETECT_ROOT = ProtectionFeatureInfo(
    id = "detect_root",
    title = "Detect Root",
    whatTurnsOn = "Activates Root Environment Guard inside encrypted assets/dspro_guard.bin and injects DsProGuardProvider.",
    howItWorks = "Scans for su binaries, Magisk/KernelSU/APatch mounts, and test-keys ROM builds before the app starts. If root is detected, the app immediately crashes with 'Root detected'.",
)

private val INFO_DETECT_EMULATOR = ProtectionFeatureInfo(
    id = "detect_emulator",
    title = "Detect Emulator",
    whatTurnsOn = "Activates Emulator & Virtual Device Guard inside encrypted assets/dspro_guard.bin.",
    howItWorks = "Inspects system build properties (fingerprint, model, goldfish/ranchu/vbox/nox hardware) and QEMU sockets. Stops execution with 'Emulator detected' on virtual devices.",
)

private val INFO_DETECT_XPOSED = ProtectionFeatureInfo(
    id = "detect_xposed",
    title = "Detect Xposed / Frida",
    whatTurnsOn = "Activates Anti-Hooking Guard against Xposed, LSPosed, EdXposed, Substrate, and Frida.",
    howItWorks = "Inspects loaded classes, call stacks, active threads (gum-js-loop, linjector), and /proc/self/maps continuously. Crashes immediately if hooking is detected.",
)

private val INFO_DETECT_DEBUGGER = ProtectionFeatureInfo(
    id = "detect_debugger",
    title = "Detect Debugger",
    whatTurnsOn = "Activates Active Debugger & TracerPid Guard at startup, resume, and in the live watchdog.",
    howItWorks = "Checks Debug.isDebuggerConnected() and /proc/self/status TracerPid for attached JDWP or native ptrace debuggers. Crashes immediately when attached.",
)

private val INFO_ANTI_SCREENSHOT = ProtectionFeatureInfo(
    id = "anti_screenshot",
    title = "Anti Screenshot",
    whatTurnsOn = "Registers an Activity lifecycle guard that applies WindowManager.LayoutParams.FLAG_SECURE.",
    howItWorks = "Automatically prevents screenshots, screen recording, and recent-apps preview thumbnails on every screen of the protected application.",
)

private val INFO_ANTI_TAMPERING = ProtectionFeatureInfo(
    id = "anti_tampering",
    title = "Anti Tampering",
    whatTurnsOn = "Records SHA-256 digests of AndroidManifest.xml, resources.arsc, DEX, .so libs, and protected assets inside encrypted assets/dspro_guard.bin.",
    howItWorks = "Verifies every tracked file inside the installed APK at startup and periodically via watchdog. If any file is altered or replaced, the app crashes with 'APK tampering detected'.",
)

private val INFO_SIGNATURE_PINNING = ProtectionFeatureInfo(
    id = "signature_pinning",
    title = "Signature Pinning",
    whatTurnsOn = "Pins the input APK's signing certificate SHA-256 hash inside encrypted assets/dspro_guard.bin.",
    howItWorks = "Checks the installed app's signing certificate at runtime. Note: you must re-sign the output APK with the original keystore, otherwise it crashes with 'APK signature mismatch'.",
)

private val INFO_ANTI_DUMP = ProtectionFeatureInfo(
    id = "anti_dump",
    title = "Anti Dump",
    whatTurnsOn = "Activates Live Anti-Dump Watchdog inside DsProGuardProvider and enforces pre-decrypt memory guards.",
    howItWorks = "Blocks Frida-dexdump, BlackDex, FUPK3/Youpk/DrizzleDumper, Frida sockets (27042/27043), gum-js-loop threads, and ptrace memory dumping both before decryption and continuously at runtime.",
)

private val INFO_DSPRO_ENCRYPT = ProtectionFeatureInfo(
    id = "dspro_dex_encryption",
    title = "DS PRO Encrypt",
    whatTurnsOn = "Compresses and encrypts all original classes*.dex payloads with AES-256-GCM into assets/dspro_core.bin, injects DsProApplication + DsProComponentFactory, wipes keys, and binds guard integrity.",
    howItWorks = "Replaces classes.dex with the compact DS PRO loader and decrypts compressed DEX payloads strictly in memory to keep protected APK size minimal.",
)

private val INFO_DISABLE_DEBUGGABLE = ProtectionFeatureInfo(
    id = "disable_debuggable",
    title = "Block Debuggable",
    whatTurnsOn = "Patches binary AndroidManifest.xml to set android:debuggable=\"false\".",
    howItWorks = "Blocks JDWP debugger attachment and run-as inspection at the Android OS level without altering the rest of the manifest.",
)

private val INFO_DISABLE_BACKUP = ProtectionFeatureInfo(
    id = "disable_backup",
    title = "Block App Backup",
    whatTurnsOn = "Patches binary AndroidManifest.xml to set android:allowBackup=\"false\".",
    howItWorks = "Prevents ADB backup and automatic cloud backup extraction of the app's private data directory.",
)

private val INFO_STRIP_DEX_DEBUG = ProtectionFeatureInfo(
    id = "strip_dex_debug",
    title = "Strip DEX Debug",
    whatTurnsOn = "Zeros source_file_idx and method debug_info_off across all DEX bytecode and recalculates DEX SHA-1/Adler32 checksums.",
    howItWorks = "Strips original source file names, line numbers, and local variable debug symbols so reverse-engineering tools cannot inspect debug names.",
)

private val INFO_STRIP_BLOAT = ProtectionFeatureInfo(
    id = "strip_bloat",
    title = "Strip Bloat Metadata",
    whatTurnsOn = "Removes non-runtime build metadata (DebugProbesKt.bin, kotlin-tooling-metadata.json, META-INF/proguard/*, META-INF/*.version).",
    howItWorks = "Cleans unnecessary tooling metadata and reduces APK size while preserving .kotlin_module and .kotlin_builtins needed at runtime.",
)

private val INFO_BEST_COMPRESSION = ProtectionFeatureInfo(
    id = "best_compression",
    title = "Best Compression",
    whatTurnsOn = "Enables Deflater level 9 compression for deflated ZIP entries while keeping 16KB/4B aligned STORED .so, resources.arsc, and raw assets.",
    howItWorks = "Shrinks final APK size cleanly while preserving Android 11–16 resource and native library alignment rules.",
)

private fun runtimeGuardToggles(cfg: ProtectionConfig, vm: MainViewModel) = listOf(
    ToggleSpec(INFO_DETECT_ROOT, cfg.detectRoot, "switch_detect_root") { v -> vm.updateConfig { it.copy(detectRoot = v) } },
    ToggleSpec(INFO_DETECT_EMULATOR, cfg.detectEmulator, "switch_detect_emulator") { v -> vm.updateConfig { it.copy(detectEmulator = v) } },
    ToggleSpec(INFO_DETECT_XPOSED, cfg.detectXposed, "switch_detect_xposed") { v -> vm.updateConfig { it.copy(detectXposed = v) } },
    ToggleSpec(INFO_DETECT_DEBUGGER, cfg.detectDebugger, "switch_detect_debugger") { v -> vm.updateConfig { it.copy(detectDebugger = v) } },
    ToggleSpec(INFO_ANTI_SCREENSHOT, cfg.antiScreenshot, "switch_anti_screenshot") { v -> vm.updateConfig { it.copy(antiScreenshot = v) } },
    ToggleSpec(INFO_ANTI_TAMPERING, cfg.antiTampering, "switch_anti_tampering") { v -> vm.updateConfig { it.copy(antiTampering = v) } },
    ToggleSpec(INFO_SIGNATURE_PINNING, cfg.signaturePinning, "switch_signature_pinning") { v -> vm.updateConfig { it.copy(signaturePinning = v) } },
    ToggleSpec(INFO_ANTI_DUMP, cfg.antiDump, "switch_anti_dump") { v -> vm.updateConfig { it.copy(antiDump = v) } },
)

private fun binaryHardeningToggles(cfg: ProtectionConfig, vm: MainViewModel) = listOf(
    ToggleSpec(INFO_DSPRO_ENCRYPT, cfg.dsProDexEncryption, "switch_dspro_dex_encryption") { v -> vm.updateConfig { it.copy(dsProDexEncryption = v) } },
    ToggleSpec(INFO_DISABLE_DEBUGGABLE, cfg.disableDebuggable, "switch_disable_debuggable") { v -> vm.updateConfig { it.copy(disableDebuggable = v) } },
    ToggleSpec(INFO_DISABLE_BACKUP, cfg.disableBackup, "switch_disable_backup") { v -> vm.updateConfig { it.copy(disableBackup = v) } },
    ToggleSpec(INFO_STRIP_DEX_DEBUG, cfg.stripDexDebug, "switch_strip_dex_debug") { v -> vm.updateConfig { it.copy(stripDexDebug = v) } },
    ToggleSpec(INFO_STRIP_BLOAT, cfg.stripMetadataBloat, "switch_strip_bloat") { v -> vm.updateConfig { it.copy(stripMetadataBloat = v) } },
    ToggleSpec(INFO_BEST_COMPRESSION, cfg.bestCompression, "switch_best_compression") { v -> vm.updateConfig { it.copy(bestCompression = v) } },
)
