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
import androidx.compose.foundation.lazy.grid.rememberLazyGridState
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
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.example.domain.engine.formatBytes
import com.example.domain.model.ProtectionConfig
import com.example.domain.model.ProtectionFeatureInfo
import com.example.domain.model.ProtectionSection
import com.example.ui.components.CenteredToastHost
import com.example.ui.components.DeveloperInfoDialog
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
    var showDeveloperInfo by remember { mutableStateOf(false) }
    val pullToRefreshState = rememberPullToRefreshState()
    val gridState = rememberLazyGridState()

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
        targetValue = if (uiState.isRefreshing) 0.78f else 1f,
        animationSpec = tween(durationMillis = 260),
        label = "refresh_alpha",
    )

    LaunchedEffect(uiState.isProcessing, uiState.runResult, uiState.selectedApkUri, uiState.isRefreshing) {
        if (uiState.isProcessing || uiState.runResult != null) {
            val lastIdx = (gridState.layoutInfo.totalItemsCount - 1).coerceAtLeast(0)
            gridState.animateScrollToItem(lastIdx)
        } else if (!uiState.isRefreshing && uiState.selectedApkUri == null && gridState.firstVisibleItemIndex > 0) {
            gridState.animateScrollToItem(0)
        }
    }

    activeInfoDialog?.let { (info, enabled) ->
        FeatureInfoDialog(
            info = info,
            isEnabled = enabled,
            onDismiss = { activeInfoDialog = null },
        )
    }

    if (showDeveloperInfo) {
        DeveloperInfoDialog(onDismiss = { showDeveloperInfo = false })
    }

    Box(modifier = Modifier.fillMaxSize()) {
        Scaffold(
            modifier = Modifier
                .fillMaxSize()
                .background(PureWhite),
            containerColor = PureWhite,
            contentWindowInsets = WindowInsets.navigationBars,
            topBar = {
                DsProTopBar(onInfoClick = { showDeveloperInfo = true })
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
                val density = LocalDensity.current
                val maxPullShiftPx = remember(density) { with(density) { 28.dp.toPx() } }
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .graphicsLayer {
                            alpha = refreshAlpha
                            translationY = pullToRefreshState.distanceFraction.coerceIn(0f, 1.2f) * maxPullShiftPx
                        },
                    contentAlignment = Alignment.TopCenter,
                ) {
                    LazyVerticalGrid(
                        state = gridState,
                        columns = GridCells.Adaptive(minSize = 156.dp),
                        modifier = Modifier
                            .fillMaxSize()
                            .widthIn(max = 840.dp),
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 14.dp),
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
                                            val hasIdentifier = !apk.protectionIdentifier.isNullOrBlank()
                                            val isProtected = apk.hasCoreProtection || apk.hasGuardProvider || hasIdentifier
                                            StatusPill(
                                                text = when {
                                                    apk.hasCoreProtection && apk.hasGuardProvider -> "DS PRO Protected"
                                                    apk.hasCoreProtection -> "DS PRO Core"
                                                    apk.hasGuardProvider -> "DS PRO Guard"
                                                    hasIdentifier -> "DS PRO Protected"
                                                    else -> "Unprotected"
                                                },
                                                containerColor = if (isProtected) SuccessTint else WarningTint,
                                                contentColor = if (isProtected) SuccessEmerald else WarningAmber,
                                                icon = if (isProtected) Icons.Filled.VerifiedUser else Icons.Outlined.Shield,
                                            )
                                            if (hasIdentifier) {
                                                StatusPill(
                                                    text = apk.protectionIdentifier!!,
                                                    containerColor = SuccessTint,
                                                    contentColor = SuccessEmerald,
                                                )
                                            }
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
                                if (uiState.isProcessing) {
                                    CircularProgressIndicator(
                                        modifier = Modifier.size(18.dp),
                                        strokeWidth = 2.dp,
                                        color = PureWhite,
                                    )
                                } else {
                                    Icon(Icons.Filled.PlayArrow, contentDescription = null, modifier = Modifier.size(20.dp))
                                }
                                Spacer(modifier = Modifier.width(8.dp))
                                Text(
                                    text = if (uiState.isProcessing) "Encrypting (${uiState.progress}%)..." else "Start Encrypt",
                                    fontWeight = FontWeight.SemiBold,
                                )
                            }

                            if (uiState.isProcessing || uiState.progress > 0 || uiState.steps.isNotEmpty() || uiState.runResult != null) {
                                ProtectionPipelineCard(
                                    isProcessing = uiState.isProcessing,
                                    progress = uiState.progress,
                                    activeStageDetail = uiState.activeStageDetail,
                                    steps = uiState.steps,
                                    runResult = uiState.runResult,
                                    isExported = uiState.isExported,
                                    exportedSizeBytes = uiState.exportedSizeBytes,
                                    onExportClick = {
                                        val pkg = uiState.selectedApk?.packageName ?: "app"
                                        exportLauncher.launch("${pkg}_dspro_protected.apk")
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
    fullName = "Root Environment Detection",
    summary = "Stops your app from running on rooted phones.",
    protections = listOf(
        "Blocks devices with root access or root-hiding apps",
        "Blocks uncertified test-keys custom ROM environments",
        "Shows a warning and closes the app immediately on rooted phones",
    ),
)

private val INFO_DETECT_DEBUGGER = ProtectionFeatureInfo(
    id = "detect_debugger",
    title = "Detect Debugger",
    fullName = "Active Debugger Detection",
    summary = "Blocks outsiders from attaching debugging tools to your running app.",
    protections = listOf(
        "Stops live debuggers from inspecting or controlling your app",
        "Keeps checking both at startup and while the app runs",
        "Closes the app immediately if any debugger is attached",
    ),
)

private val INFO_DEVICE_CERTIFICATE = ProtectionFeatureInfo(
    id = "device_certificate",
    title = "Certificate",
    fullName = "Device Certificate & Play Integrity Check",
    summary = "Checks that Google Play Store is active and the device is properly certified.",
    protections = listOf(
        "Blocks rooted phones where Play Store or Play Services are disabled",
        "Detects unlocked bootloaders and uncertified modified devices",
        "Displays a warning popup before closing the app",
    ),
)

private val INFO_ANTI_SCREENSHOT = ProtectionFeatureInfo(
    id = "anti_screenshot",
    title = "Screen Guard",
    fullName = "Anti-Screenshot & Screen Recording Block",
    summary = "Stops anyone from capturing or recording your app's screens.",
    protections = listOf(
        "Blocks screenshots across every screen inside the app",
        "Turns screen recordings and screen casting completely black",
        "Hides sensitive app previews in the Recent Apps list",
    ),
)

private val INFO_ANTI_TAMPERING = ProtectionFeatureInfo(
    id = "anti_tampering",
    title = "Modified Guard",
    fullName = "Anti-Tampering & APK Modification Guard",
    summary = "Prevents your app from being edited, hacked, or turned into a mod APK.",
    protections = listOf(
        "Detects any change to app code, layouts, or internal files",
        "Blocks repacked, patched, or re-signed mod APKs from opening",
        "Verifies app integrity at startup and during use",
    ),
)

private val INFO_ANTI_DUMP = ProtectionFeatureInfo(
    id = "anti_dump",
    title = "Anti Dump",
    fullName = "Anti-Dump & Memory Hook Blocker",
    summary = "Blocks memory dumpers, app cloners, and runtime hooking tools.",
    protections = listOf(
        "Stops tools from copying your app's code out of phone memory",
        "Blocks virtual app cloners and sandbox environments",
        "Detects and stops live hooking frameworks in real time",
    ),
)

private val INFO_DEX_INTEGRITY = ProtectionFeatureInfo(
    id = "dex_integrity",
    title = "DEX Integrity",
    fullName = "DEX Bytecode Integrity Verification",
    summary = "Makes sure no extra mod code or cheat patches were added to your app.",
    protections = listOf(
        "Verifies your app's compiled code files before launch",
        "Detects extra or modified code injected into memory",
        "Stops the app immediately if any unauthorized code is found",
    ),
)

private val INFO_ASSIST_ENCRYPT = ProtectionFeatureInfo(
    id = "assist_encrypt",
    title = "Assist Encrypt",
    fullName = "Assets Folder File Encryption",
    summary = "Locks editable files inside the assets folder so nobody can modify them.",
    protections = listOf(
        "Protects XML, JSON, ZIP, database, and config files in assets",
        "Prevents modders from opening or editing those files inside the APK",
        "Keeps all original app features working smoothly",
    ),
)

private val INFO_DSPRO_ENCRYPT = ProtectionFeatureInfo(
    id = "dspro_dex_encryption",
    title = "DS PRO Encrypt",
    fullName = "DS PRO Core DEX Encryption",
    summary = "Locks and hides your app's main compiled program code.",
    protections = listOf(
        "Hides your app's classes and logic from decompiler tools",
        "Prevents hackers from easily reading or copying app behavior",
        "Loads the protected code safely only while running",
    ),
)

private val INFO_STRING_ENCRYPTION = ProtectionFeatureInfo(
    id = "string_encryption",
    title = "String Encryption",
    fullName = "DEX String Literal Encryption",
    summary = "Hides important text inside your app's code from static scanning.",
    protections = listOf(
        "Hides website links, API endpoints, and server addresses",
        "Masks secret text, messages, and internal keywords in the APK",
        "Restores text automatically when your app needs it",
    ),
)

private val INFO_CONTROL_FLOW = ProtectionFeatureInfo(
    id = "control_flow_obfuscation",
    title = "Obfuscation",
    fullName = "Control Flow Obfuscation",
    summary = "Makes your app's code logic very hard for reverse engineers to follow.",
    protections = listOf(
        "Scrambles condition paths and logic flow inside decompilers",
        "Makes code analysis confusing and time-consuming for attackers",
        "Keeps your app running smoothly at normal speed",
    ),
)

private val INFO_RESOURCE_ENCRYPTION = ProtectionFeatureInfo(
    id = "resource_encryption",
    title = "Resource Encryption",
    fullName = "App Resource & Data Encryption",
    summary = "Protects internal app data and configuration files inside the APK.",
    protections = listOf(
        "Locks packaged JSON, text, web, and data files from extraction",
        "Prevents outsiders from viewing or copying internal data files",
        "Keeps media and native features working normally",
    ),
)

private val INFO_DISABLE_DEBUGGABLE = ProtectionFeatureInfo(
    id = "disable_debuggable",
    title = "Block Debug",
    fullName = "Disable App Debuggable Mode",
    summary = "Forces the app into strict release mode at the Android system level.",
    protections = listOf(
        "Blocks USB/ADB debugging attachment by Android OS",
        "Stops outsiders from accessing private app storage files",
        "Secures apps that were originally built with debug mode enabled",
    ),
)

private val INFO_STRIP_DEX_DEBUG = ProtectionFeatureInfo(
    id = "strip_dex_debug",
    title = "Strip DEX Debug",
    fullName = "Strip DEX Debug Information",
    summary = "Removes leftover developer debug clues from the compiled app.",
    protections = listOf(
        "Removes original source file names from the compiled code",
        "Clears line numbers and internal variable names",
        "Makes decompiled code much harder to understand without slowing the app",
    ),
)

private fun runtimeGuardToggles(cfg: ProtectionConfig, vm: MainViewModel) = listOf(
    ToggleSpec(INFO_DETECT_ROOT, cfg.detectRoot, "switch_detect_root") { v -> vm.updateConfig { it.copy(detectRoot = v) } },
    ToggleSpec(INFO_DETECT_DEBUGGER, cfg.detectDebugger, "switch_detect_debugger") { v -> vm.updateConfig { it.copy(detectDebugger = v) } },
    ToggleSpec(INFO_DEVICE_CERTIFICATE, cfg.deviceCertificate, "switch_device_certificate") { v -> vm.updateConfig { it.copy(deviceCertificate = v) } },
    ToggleSpec(INFO_ANTI_SCREENSHOT, cfg.antiScreenshot, "switch_anti_screenshot") { v -> vm.updateConfig { it.copy(antiScreenshot = v) } },
    ToggleSpec(INFO_ANTI_TAMPERING, cfg.antiTampering, "switch_anti_tampering") { v -> vm.updateConfig { it.copy(antiTampering = v) } },
    ToggleSpec(INFO_ANTI_DUMP, cfg.antiDump, "switch_anti_dump") { v -> vm.updateConfig { it.copy(antiDump = v) } },
    ToggleSpec(INFO_DEX_INTEGRITY, cfg.dexIntegrityProtection, "switch_dex_integrity") { v -> vm.updateConfig { it.copy(dexIntegrityProtection = v) } },
    ToggleSpec(INFO_ASSIST_ENCRYPT, cfg.assistEncrypt, "switch_assist_encrypt") { v -> vm.updateConfig { it.copy(assistEncrypt = v) } },
)

private fun binaryHardeningToggles(cfg: ProtectionConfig, vm: MainViewModel) = listOf(
    ToggleSpec(INFO_DSPRO_ENCRYPT, cfg.dsProDexEncryption, "switch_dspro_dex_encryption") { v -> vm.updateConfig { it.copy(dsProDexEncryption = v) } },
    ToggleSpec(INFO_STRING_ENCRYPTION, cfg.stringEncryption, "switch_string_encryption") { v -> vm.updateConfig { it.copy(stringEncryption = v) } },
    ToggleSpec(INFO_CONTROL_FLOW, cfg.controlFlowObfuscation, "switch_control_flow") { v -> vm.updateConfig { it.copy(controlFlowObfuscation = v) } },
    ToggleSpec(INFO_RESOURCE_ENCRYPTION, cfg.resourceEncryption, "switch_resource_encryption") { v -> vm.updateConfig { it.copy(resourceEncryption = v) } },
    ToggleSpec(INFO_DISABLE_DEBUGGABLE, cfg.disableDebuggable, "switch_disable_debuggable") { v -> vm.updateConfig { it.copy(disableDebuggable = v) } },
    ToggleSpec(INFO_STRIP_DEX_DEBUG, cfg.stripDexDebug, "switch_strip_dex_debug") { v -> vm.updateConfig { it.copy(stripDexDebug = v) } },
)
