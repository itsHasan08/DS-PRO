package com.example.ui.screens

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
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
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Security
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.example.domain.engine.formatBytes
import com.example.domain.model.ProtectionConfig
import com.example.domain.model.ProtectionSection
import com.example.ui.components.DsProTopBar
import com.example.ui.components.GridGroupHeader
import com.example.ui.components.GridToggleTile
import com.example.ui.components.KeyValueLine
import com.example.ui.components.SectionCard
import com.example.ui.components.StepResultRow
import com.example.ui.theme.BorderSubtle
import com.example.ui.theme.CharcoalText
import com.example.ui.theme.ErrorRed
import com.example.ui.theme.ErrorTint
import com.example.ui.theme.MonoCodeStyle
import com.example.ui.theme.ProBlue
import com.example.ui.theme.PureWhite
import com.example.ui.theme.SlateMuted
import com.example.ui.theme.SuccessEmerald
import com.example.ui.theme.SuccessTint
import com.example.ui.viewmodel.MainViewModel

private data class ToggleSpec(
    val title: String,
    val checked: Boolean,
    val tag: String,
    val onToggle: (Boolean) -> Unit,
)

@Composable
fun MainScreen(
    viewModel: MainViewModel,
) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }

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
            snackbarHostState.showSnackbar(msg)
            viewModel.clearStatusMessage()
        }
    }

    val cfg = uiState.config

    Scaffold(
        modifier = Modifier
            .fillMaxSize()
            .background(PureWhite),
        containerColor = PureWhite,
        contentWindowInsets = WindowInsets.navigationBars,
        topBar = {
            DsProTopBar(activeCount = cfg.activeToggleCount)
        },
        snackbarHost = { SnackbarHost(hostState = snackbarHostState) },
    ) { innerPadding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding),
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
                // 1. Select APK + Basic Metadata (Full Span)
                item(span = { GridItemSpan(maxLineSpan) }) {
                    SectionCard(
                        title = "APK File",
                        icon = Icons.Filled.FolderOpen,
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
                                    verticalArrangement = Arrangement.spacedBy(2.dp),
                                ) {
                                    KeyValueLine("App Name", apk.appName)
                                    KeyValueLine("Package", apk.packageName, mono = true)
                                    KeyValueLine("Version", "${apk.versionName} (${apk.versionCode})")
                                    KeyValueLine("Size", formatBytes(apk.fileSizeBytes))
                                }
                            }
                        }
                    }
                }

                // 2. Runtime Guard Group (Injected DEX Provider)
                item(span = { GridItemSpan(maxLineSpan) }) {
                    GridGroupHeader(
                        title = ProtectionSection.RUNTIME_GUARD.label,
                        icon = Icons.Filled.Security,
                        activeCount = cfg.activeCountFor(ProtectionSection.RUNTIME_GUARD),
                    )
                }
                items(
                    items = runtimeGuardToggles(cfg, viewModel),
                    key = { it.tag },
                ) { item ->
                    GridToggleTile(
                        title = item.title,
                        checked = item.checked,
                        onCheckedChange = item.onToggle,
                        testTag = item.tag,
                    )
                }

                // 3. Binary & Manifest Hardening Group
                item(span = { GridItemSpan(maxLineSpan) }) {
                    GridGroupHeader(
                        title = ProtectionSection.BINARY_HARDENING.label,
                        icon = Icons.Filled.Build,
                        activeCount = cfg.activeCountFor(ProtectionSection.BINARY_HARDENING),
                    )
                }
                items(
                    items = binaryHardeningToggles(cfg, viewModel),
                    key = { it.tag },
                ) { item ->
                    GridToggleTile(
                        title = item.title,
                        checked = item.checked,
                        onCheckedChange = item.onToggle,
                        testTag = item.tag,
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

                        if (uiState.isProcessing || uiState.progress > 0) {
                            LinearProgressIndicator(
                                progress = { uiState.progress / 100f },
                                modifier = Modifier.fillMaxWidth(),
                                color = ProBlue,
                                trackColor = BorderSubtle,
                            )
                        }

                        uiState.steps.forEach { step ->
                            StepResultRow(
                                title = step.title,
                                detail = step.detail,
                                status = step.status,
                            )
                        }

                        val runResult = uiState.runResult
                        if (runResult != null && runResult.isValidBuild) {
                            Surface(
                                modifier = Modifier.fillMaxWidth(),
                                shape = RoundedCornerShape(12.dp),
                                color = SuccessTint,
                                border = BorderStroke(1.dp, SuccessEmerald.copy(alpha = 0.4f)),
                            ) {
                                Column(
                                    modifier = Modifier.padding(12.dp),
                                    verticalArrangement = Arrangement.spacedBy(4.dp),
                                ) {
                                    Row(
                                        verticalAlignment = Alignment.CenterVertically,
                                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                                    ) {
                                        Icon(
                                            imageVector = Icons.Filled.Folder,
                                            contentDescription = null,
                                            tint = SuccessEmerald,
                                            modifier = Modifier.size(18.dp),
                                        )
                                        Text(
                                            text = "Protected APK Saved (${formatBytes(runResult.outputSizeBytes)})",
                                            style = MaterialTheme.typography.titleSmall,
                                            color = CharcoalText,
                                        )
                                    }
                                    runResult.savedLocation?.let { loc ->
                                        Text(
                                            text = "${loc.folderDisplay}/${loc.fileName}",
                                            style = MonoCodeStyle,
                                            color = SlateMuted,
                                        )
                                    }
                                }
                            }

                            OutlinedButton(
                                onClick = {
                                    val pkg = uiState.selectedApk?.packageName ?: "app"
                                    exportLauncher.launch("${pkg}_dspro_unsigned.apk")
                                },
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .heightIn(min = 48.dp)
                                    .testTag("export_apk_button"),
                                shape = RoundedCornerShape(12.dp),
                                border = BorderStroke(1.dp, ProBlue),
                            ) {
                                Icon(Icons.Filled.Download, contentDescription = null, tint = ProBlue, modifier = Modifier.size(18.dp))
                                Spacer(modifier = Modifier.width(8.dp))
                                Text("Save Copy As...", color = ProBlue, fontWeight = FontWeight.SemiBold)
                            }
                        }
                    }
                }
            }
        }
    }
}

private fun runtimeGuardToggles(cfg: ProtectionConfig, vm: MainViewModel) = listOf(
    ToggleSpec("Detect Root", cfg.detectRoot, "switch_detect_root") { v ->
        vm.updateConfig { it.copy(detectRoot = v) }
    },
    ToggleSpec("Detect Emulator", cfg.detectEmulator, "switch_detect_emulator") { v ->
        vm.updateConfig { it.copy(detectEmulator = v) }
    },
    ToggleSpec("Detect VPN", cfg.detectVpn, "switch_detect_vpn") { v ->
        vm.updateConfig { it.copy(detectVpn = v) }
    },
    ToggleSpec("Detect Xposed / Frida", cfg.detectXposed, "switch_detect_xposed") { v ->
        vm.updateConfig { it.copy(detectXposed = v) }
    },
    ToggleSpec("Detect Debugger", cfg.detectDebugger, "switch_detect_debugger") { v ->
        vm.updateConfig { it.copy(detectDebugger = v) }
    },
    ToggleSpec("Anti Screenshot", cfg.antiScreenshot, "switch_anti_screenshot") { v ->
        vm.updateConfig { it.copy(antiScreenshot = v) }
    },
    ToggleSpec("Anti Tampering", cfg.antiTampering, "switch_anti_tampering") { v ->
        vm.updateConfig { it.copy(antiTampering = v) }
    },
    ToggleSpec("Signature Pinning", cfg.signaturePinning, "switch_signature_pinning") { v ->
        vm.updateConfig { it.copy(signaturePinning = v) }
    },
)

private fun binaryHardeningToggles(cfg: ProtectionConfig, vm: MainViewModel) = listOf(
    ToggleSpec("DPT DEX Encrypt", cfg.dptDexEncryption, "switch_dpt_dex_encryption") { v ->
        vm.updateConfig { it.copy(dptDexEncryption = v) }
    },
    ToggleSpec("Block Debuggable", cfg.disableDebuggable, "switch_disable_debuggable") { v ->
        vm.updateConfig { it.copy(disableDebuggable = v) }
    },
    ToggleSpec("Block App Backup", cfg.disableBackup, "switch_disable_backup") { v ->
        vm.updateConfig { it.copy(disableBackup = v) }
    },
    ToggleSpec("Strip DEX Debug", cfg.stripDexDebug, "switch_strip_dex_debug") { v ->
        vm.updateConfig { it.copy(stripDexDebug = v) }
    },
    ToggleSpec("Strip Bloat Metadata", cfg.stripMetadataBloat, "switch_strip_bloat") { v ->
        vm.updateConfig { it.copy(stripMetadataBloat = v) }
    },
    ToggleSpec("Best Compression", cfg.bestCompression, "switch_best_compression") { v ->
        vm.updateConfig { it.copy(bestCompression = v) }
    },
)
