package com.example.ui.components

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.OpenInNew
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.Groups
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Phone
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.R
import com.example.domain.engine.formatBytes
import com.example.domain.model.ProtectionFeatureInfo
import com.example.domain.model.ProtectionRunResult
import com.example.domain.model.ProtectionStepResult
import com.example.domain.model.StepStatus
import com.example.ui.theme.BorderStrong
import com.example.ui.theme.BorderSubtle
import com.example.ui.theme.CharcoalText
import com.example.ui.theme.ErrorRed
import com.example.ui.theme.ErrorTint
import com.example.ui.theme.MonoCodeStyle
import com.example.ui.theme.ProBlue
import com.example.ui.theme.ProBlueDark
import com.example.ui.theme.ProBlueTint
import com.example.ui.theme.PureWhite
import com.example.ui.theme.SectionGrey
import com.example.ui.theme.SlateMuted
import com.example.ui.theme.SuccessEmerald
import com.example.ui.theme.SuccessTint
import com.example.ui.theme.TealAccent
import com.example.ui.theme.TealTint
import kotlinx.coroutines.delay
import java.util.Locale

@Composable
fun DsProTopBar(
    onInfoClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Surface(
        modifier = modifier.fillMaxWidth(),
        color = PureWhite,
        shadowElevation = 0.dp,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .statusBarsPadding(),
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(start = 16.dp, end = 8.dp, top = 8.dp, bottom = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    Box(
                        modifier = Modifier
                            .size(36.dp)
                            .clip(RoundedCornerShape(10.dp))
                            .background(
                                Brush.linearGradient(
                                    colors = listOf(ProBlue, ProBlueDark),
                                ),
                            ),
                        contentAlignment = Alignment.Center,
                    ) {
                        Icon(
                            imageVector = Icons.Filled.Shield,
                            contentDescription = stringResource(R.string.cd_app_shield),
                            tint = PureWhite,
                            modifier = Modifier.size(20.dp),
                        )
                    }
                    Text(
                        text = "DS PRO",
                        style = MaterialTheme.typography.titleLarge,
                        color = CharcoalText,
                        fontWeight = FontWeight.Bold,
                    )
                }

                Box(
                    modifier = Modifier
                        .heightIn(min = 48.dp)
                        .clickable(
                            interactionSource = remember { MutableInteractionSource() },
                            indication = null,
                            role = Role.Button,
                            onClick = onInfoClick,
                        )
                        .padding(horizontal = 4.dp)
                        .testTag("top_bar_info_button"),
                    contentAlignment = Alignment.Center,
                ) {
                    Surface(
                        shape = RoundedCornerShape(50),
                        color = ProBlueTint,
                        border = BorderStroke(1.dp, ProBlue.copy(alpha = 0.25f)),
                    ) {
                        Row(
                            modifier = Modifier.padding(horizontal = 12.dp, vertical = 7.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(5.dp),
                        ) {
                            Icon(
                                imageVector = Icons.Outlined.Info,
                                contentDescription = "Developer & App Info",
                                tint = ProBlueDark,
                                modifier = Modifier.size(18.dp),
                            )
                            Text(
                                text = "Info",
                                style = MaterialTheme.typography.labelLarge.copy(fontWeight = FontWeight.SemiBold),
                                color = ProBlueDark,
                            )
                        }
                    }
                }
            }
            HorizontalDivider(thickness = 1.dp, color = BorderSubtle)
        }
    }
}

@Composable
fun CenteredToastHost(
    hostState: SnackbarHostState,
    modifier: Modifier = Modifier,
) {
    SnackbarHost(
        hostState = hostState,
        modifier = modifier
            .padding(horizontal = 32.dp)
            .testTag("centered_toast_host"),
    ) { data ->
        Surface(
            shape = RoundedCornerShape(24.dp),
            color = PureWhite.copy(alpha = 0.88f),
            border = BorderStroke(1.dp, BorderStrong.copy(alpha = 0.55f)),
            shadowElevation = 8.dp,
        ) {
            Text(
                text = data.visuals.message,
                style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.Medium),
                color = Color.Black,
                textAlign = TextAlign.Center,
                modifier = Modifier.padding(horizontal = 20.dp, vertical = 12.dp),
            )
        }
    }
}

@Composable
fun SectionCard(
    title: String,
    icon: ImageVector,
    modifier: Modifier = Modifier,
    accentColor: Color = ProBlue,
    accentTint: Color = ProBlueTint,
    headerAction: (@Composable () -> Unit)? = null,
    content: @Composable ColumnScope.() -> Unit,
) {
    Surface(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        color = SectionGrey,
        border = BorderStroke(1.dp, accentColor.copy(alpha = 0.22f)),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Box(
                        modifier = Modifier
                            .size(28.dp)
                            .clip(RoundedCornerShape(8.dp))
                            .background(accentTint),
                        contentAlignment = Alignment.Center,
                    ) {
                        Icon(
                            imageVector = icon,
                            contentDescription = null,
                            tint = accentColor,
                            modifier = Modifier.size(17.dp),
                        )
                    }
                    Text(
                        text = title,
                        style = MaterialTheme.typography.titleMedium,
                        color = CharcoalText,
                    )
                }
                if (headerAction != null) {
                    headerAction()
                }
            }
            content()
        }
    }
}

@Composable
fun GridGroupHeader(
    title: String,
    icon: ImageVector,
    activeCount: Int,
    accentColor: Color = ProBlue,
    accentTint: Color = ProBlueTint,
    modifier: Modifier = Modifier,
) {
    Row(
        modifier = modifier
            .fillMaxWidth()
            .padding(top = 6.dp, bottom = 2.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Box(
            modifier = Modifier
                .size(24.dp)
                .clip(RoundedCornerShape(7.dp))
                .background(accentTint),
            contentAlignment = Alignment.Center,
        ) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = accentColor,
                modifier = Modifier.size(15.dp),
            )
        }
        Text(
            text = title,
            style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.Bold),
            color = CharcoalText,
        )
        if (activeCount > 0) {
            Box(
                modifier = Modifier
                    .clip(CircleShape)
                    .background(accentTint)
                    .padding(horizontal = 7.dp, vertical = 2.dp),
            ) {
                Text(
                    text = "$activeCount",
                    style = MaterialTheme.typography.labelSmall,
                    color = accentColor,
                )
            }
        }
    }
}

@Composable
fun GridToggleTile(
    title: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
    onInfoClick: () -> Unit,
    testTag: String,
    accentColor: Color = ProBlue,
    accentTint: Color = ProBlueTint,
    modifier: Modifier = Modifier,
) {
    Surface(
        onClick = { onCheckedChange(!checked) },
        modifier = modifier.testTag(testTag),
        shape = RoundedCornerShape(12.dp),
        color = if (checked) accentTint.copy(alpha = 0.7f) else PureWhite,
        border = BorderStroke(1.dp, if (checked) accentColor.copy(alpha = 0.5f) else BorderSubtle),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = 58.dp)
                .padding(start = 11.dp, end = 10.dp, top = 6.dp, bottom = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = title,
                style = MaterialTheme.typography.bodySmall.copy(
                    fontWeight = FontWeight.Medium,
                    lineHeight = 15.sp,
                    letterSpacing = 0.sp,
                ),
                color = CharcoalText,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f),
            )
            IconButton(
                onClick = onInfoClick,
                modifier = Modifier
                    .size(48.dp)
                    .testTag("info_$testTag"),
            ) {
                Icon(
                    imageVector = Icons.Outlined.Info,
                    contentDescription = "$title info",
                    tint = if (checked) accentColor else SlateMuted,
                    modifier = Modifier.size(18.dp),
                )
            }
            Box(
                modifier = Modifier.heightIn(min = 48.dp),
                contentAlignment = Alignment.Center,
            ) {
                DsProToggleSwitch(
                    checked = checked,
                    accentColor = accentColor,
                )
            }
        }
    }
}

@Composable
private fun DsProToggleSwitch(
    checked: Boolean,
    accentColor: Color,
    modifier: Modifier = Modifier,
) {
    val thumbTravelPx = with(LocalDensity.current) { 16.dp.toPx() }
    val thumbProgress by animateFloatAsState(
        targetValue = if (checked) 1f else 0f,
        animationSpec = spring(
            dampingRatio = 0.78f,
            stiffness = 460f,
        ),
        label = "dspro_switch_thumb",
    )
    val trackColor by animateColorAsState(
        targetValue = if (checked) accentColor else BorderSubtle,
        animationSpec = tween(durationMillis = 200),
        label = "dspro_switch_track",
    )
    val borderColor by animateColorAsState(
        targetValue = if (checked) accentColor else SlateMuted.copy(alpha = 0.35f),
        animationSpec = tween(durationMillis = 200),
        label = "dspro_switch_border",
    )

    Box(
        modifier = modifier
            .size(width = 38.dp, height = 22.dp)
            .clip(CircleShape)
            .background(trackColor)
            .border(1.dp, borderColor, CircleShape)
            .padding(horizontal = 3.dp),
        contentAlignment = Alignment.CenterStart,
    ) {
        Box(
            modifier = Modifier
                .size(16.dp)
                .graphicsLayer {
                    val p = thumbProgress.coerceIn(0f, 1.08f)
                    translationX = p * thumbTravelPx
                    val mid = (1f - kotlin.math.abs(p - 0.5f) * 2f).coerceAtLeast(0f)
                    scaleX = 1f + (mid * 0.14f)
                }
                .clip(CircleShape)
                .background(PureWhite)
                .border(0.75.dp, Color.Black.copy(alpha = 0.08f), CircleShape),
        )
    }
}

@Composable
fun ProtectionPipelineCard(
    isProcessing: Boolean,
    progress: Int,
    activeStageDetail: String?,
    steps: List<ProtectionStepResult>,
    runResult: ProtectionRunResult?,
    isExported: Boolean,
    exportedSizeBytes: Long?,
    exportedFileName: String? = null,
    exportedFolderLabel: String? = null,
    onExportClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val hasFailure = steps.any { it.status == StepStatus.FAILED } || (runResult != null && !runResult.isValidBuild)
    val isComplete = !isProcessing && runResult != null && runResult.isValidBuild && !hasFailure

    val accentColor = when {
        hasFailure -> ErrorRed
        isComplete -> SuccessEmerald
        else -> ProBlue
    }
    val secondaryAccent = when {
        hasFailure -> ErrorRed
        isComplete -> SuccessEmerald
        else -> ProBlueDark
    }
    val bannerBg = when {
        hasFailure -> ErrorTint
        isComplete -> SuccessTint
        else -> ProBlueTint
    }

    var elapsedMs by remember { mutableLongStateOf(0L) }
    LaunchedEffect(isProcessing) {
        if (isProcessing) {
            val started = System.currentTimeMillis()
            elapsedMs = 0L
            while (true) {
                delay(250L)
                elapsedMs = System.currentTimeMillis() - started
            }
        }
    }

    val phaseIndex = when {
        hasFailure -> -1
        isComplete || progress >= 100 -> 5
        progress >= 91 -> 4
        progress >= 63 -> 3
        progress >= 54 -> 2
        progress >= 22 -> 1
        else -> 0
    }
    val phaseLabels = remember { listOf("Scan", "Harden", "Manifest", "Encrypt", "Verify") }

    Surface(
        modifier = modifier
            .fillMaxWidth()
            .testTag("protection_pipeline_card"),
        shape = RoundedCornerShape(18.dp),
        color = PureWhite,
        border = BorderStroke(1.dp, accentColor.copy(alpha = 0.35f)),
        shadowElevation = 2.dp,
    ) {
        Column(modifier = Modifier.fillMaxWidth()) {
            // Top Live Orbital Shield Header
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(bannerBg)
                    .padding(horizontal = 14.dp, vertical = 14.dp),
            ) {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween,
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(12.dp),
                            modifier = Modifier.weight(1f),
                        ) {
                            OrbitalShieldBadge(
                                isProcessing = isProcessing,
                                hasFailure = hasFailure,
                                isComplete = isComplete,
                                accentColor = accentColor,
                            )
                            Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                                ) {
                                    Text(
                                        text = when {
                                            hasFailure -> "Protection Failed"
                                            isComplete -> "DS PRO Protection Applied"
                                            else -> "Encrypting APK"
                                        },
                                        style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.Bold),
                                        color = CharcoalText,
                                    )
                                    if (isProcessing) {
                                        LivePulseDot()
                                    }
                                }
                                Text(
                                    text = when {
                                        hasFailure -> activeStageDetail ?: "Review failed stage below"
                                        isComplete -> "${steps.size} stages verified • ${formatDuration(elapsedMs)}"
                                        else -> activeStageDetail ?: "Initializing protection engine..."
                                    },
                                    style = MaterialTheme.typography.labelSmall,
                                    color = if (hasFailure) ErrorRed else SlateMuted,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                )
                            }
                        }
                        Column(
                            horizontalAlignment = Alignment.End,
                            verticalArrangement = Arrangement.spacedBy(4.dp),
                        ) {
                            StatusPill(
                                text = "${progress.coerceIn(0, 100)}%",
                                containerColor = PureWhite,
                                contentColor = accentColor,
                            )
                            if (elapsedMs > 0L) {
                                Text(
                                    text = formatDuration(elapsedMs),
                                    style = MonoCodeStyle,
                                    color = SlateMuted,
                                )
                            }
                        }
                    }

                    ShimmerProgressBar(
                        progress = progress,
                        isProcessing = isProcessing,
                        accentColor = accentColor,
                        secondaryAccent = secondaryAccent,
                    )

                    // Compact 5-Stage Pipeline Stepper
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(4.dp),
                    ) {
                        phaseLabels.forEachIndexed { idx, label ->
                            val done = !hasFailure && phaseIndex > idx
                            val active = isProcessing && !hasFailure && phaseIndex == idx
                            val chipBg = when {
                                done -> SuccessTint
                                active -> PureWhite
                                else -> PureWhite.copy(alpha = 0.55f)
                            }
                            val chipFg = when {
                                done -> SuccessEmerald
                                active -> ProBlue
                                else -> SlateMuted
                            }
                            Surface(
                                modifier = Modifier.weight(1f),
                                shape = RoundedCornerShape(8.dp),
                                color = chipBg,
                                border = if (active) {
                                    BorderStroke(1.2.dp, ProBlue.copy(alpha = 0.75f))
                                } else {
                                    null
                                },
                            ) {
                                Text(
                                    text = label,
                                    style = MaterialTheme.typography.labelSmall.copy(
                                        fontWeight = if (active || done) FontWeight.Bold else FontWeight.Medium,
                                    ),
                                    color = chipFg,
                                    textAlign = TextAlign.Center,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                    modifier = Modifier.padding(vertical = 4.dp, horizontal = 2.dp),
                                )
                            }
                        }
                    }
                }
            }

            // Vertical Connected Timeline + Live Active Row
            if (steps.isNotEmpty() || isProcessing) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 14.dp, vertical = 12.dp),
                ) {
                    steps.forEachIndexed { index, step ->
                        key(step.id) {
                            PipelineTimelineStep(
                                step = step,
                                isLast = !isProcessing && index == steps.lastIndex,
                            )
                        }
                    }
                    if (isProcessing) {
                        LiveActiveTimelineRow(
                            detail = activeStageDetail ?: "Working...",
                        )
                    }
                }
            }

            // Manual Save Action Card (Zero auto-save — user saves explicitly once)
            if (runResult != null && runResult.isValidBuild) {
                HorizontalDivider(thickness = 1.dp, color = BorderSubtle)
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(SectionGrey)
                        .padding(14.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    if (isExported) {
                        Surface(
                            modifier = Modifier
                                .fillMaxWidth()
                                .testTag("save_complete_banner"),
                            shape = RoundedCornerShape(12.dp),
                            color = SuccessTint,
                            border = BorderStroke(1.dp, SuccessEmerald.copy(alpha = 0.45f)),
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(12.dp),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(10.dp),
                            ) {
                                Icon(
                                    imageVector = Icons.Filled.CheckCircle,
                                    contentDescription = null,
                                    tint = SuccessEmerald,
                                    modifier = Modifier.size(22.dp),
                                )
                                Column(
                                    modifier = Modifier.weight(1f),
                                    verticalArrangement = Arrangement.spacedBy(2.dp),
                                ) {
                                    Text(
                                        text = "Save Complete (${formatBytes(exportedSizeBytes ?: runResult.outputSizeBytes)})",
                                        style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.Bold),
                                        color = SuccessEmerald,
                                    )
                                    Text(
                                        text = buildString {
                                            append(exportedFileName ?: "Protected APK")
                                            append(" saved to ")
                                            append(exportedFolderLabel ?: "device storage")
                                        },
                                        style = MaterialTheme.typography.bodySmall,
                                        color = CharcoalText,
                                    )
                                }
                            }
                        }
                    } else {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(10.dp),
                        ) {
                            Box(
                                modifier = Modifier
                                    .size(38.dp)
                                    .clip(RoundedCornerShape(10.dp))
                                    .background(SuccessTint),
                                contentAlignment = Alignment.Center,
                            ) {
                                Icon(
                                    imageVector = Icons.Filled.Folder,
                                    contentDescription = null,
                                    tint = SuccessEmerald,
                                    modifier = Modifier.size(20.dp),
                                )
                            }
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = "Protected APK Ready (${formatBytes(runResult.outputSizeBytes)})",
                                    style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.Bold),
                                    color = CharcoalText,
                                )
                                Text(
                                    text = "Tap Save APK below to save the protected file to storage.",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = SlateMuted,
                                )
                            }
                        }
                    }

                    Button(
                        onClick = onExportClick,
                        modifier = Modifier
                            .fillMaxWidth()
                            .heightIn(min = 48.dp)
                            .testTag("export_apk_button"),
                        shape = RoundedCornerShape(12.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = TealAccent,
                            contentColor = PureWhite,
                        ),
                    ) {
                        Icon(
                            imageVector = Icons.Filled.Download,
                            contentDescription = null,
                            modifier = Modifier.size(18.dp),
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = if (isExported) "Save Another Copy" else "Save APK",
                            fontWeight = FontWeight.SemiBold,
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun OrbitalShieldBadge(
    isProcessing: Boolean,
    hasFailure: Boolean,
    isComplete: Boolean,
    accentColor: Color,
) {
    Box(
        modifier = Modifier.size(46.dp),
        contentAlignment = Alignment.Center,
    ) {
        if (isProcessing) {
            val infiniteTransition = rememberInfiniteTransition(label = "orbital_badge")
            val orbitAngle = infiniteTransition.animateFloat(
                initialValue = 0f,
                targetValue = 360f,
                animationSpec = infiniteRepeatable(
                    animation = tween(durationMillis = 1200, easing = LinearEasing),
                ),
                label = "orbit_angle",
            )
            val radarWave = infiniteTransition.animateFloat(
                initialValue = 0f,
                targetValue = 1f,
                animationSpec = infiniteRepeatable(
                    animation = tween(durationMillis = 1400, easing = LinearEasing),
                    repeatMode = RepeatMode.Restart,
                ),
                label = "radar_wave",
            )
            val pulseScale = infiniteTransition.animateFloat(
                initialValue = 0.94f,
                targetValue = 1.07f,
                animationSpec = infiniteRepeatable(
                    animation = tween(durationMillis = 750),
                    repeatMode = RepeatMode.Reverse,
                ),
                label = "pulse_scale",
            )

            Canvas(modifier = Modifier.fillMaxSize()) {
                val maxR = size.minDimension / 2f
                val wave = radarWave.value
                val angle = orbitAngle.value
                val r1 = (maxR * 0.56f) + (maxR * 0.44f * wave)
                drawCircle(
                    color = accentColor.copy(alpha = (1f - wave) * 0.42f),
                    radius = r1,
                    style = Stroke(width = 2.dp.toPx()),
                )
                drawArc(
                    color = TealAccent,
                    startAngle = angle,
                    sweepAngle = 115f,
                    useCenter = false,
                    style = Stroke(width = 2.6.dp.toPx(), cap = StrokeCap.Round),
                )
                drawArc(
                    color = ProBlue,
                    startAngle = angle + 180f,
                    sweepAngle = 80f,
                    useCenter = false,
                    style = Stroke(width = 2.2.dp.toPx(), cap = StrokeCap.Round),
                )
            }
            Box(
                modifier = Modifier
                    .size(34.dp)
                    .graphicsLayer {
                        val s = pulseScale.value
                        scaleX = s
                        scaleY = s
                    }
                    .clip(CircleShape)
                    .background(PureWhite),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    imageVector = Icons.Filled.Lock,
                    contentDescription = null,
                    tint = accentColor,
                    modifier = Modifier.size(19.dp),
                )
            }
        } else {
            Box(
                modifier = Modifier
                    .size(34.dp)
                    .clip(CircleShape)
                    .background(PureWhite),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    imageVector = when {
                        hasFailure -> Icons.Filled.Error
                        isComplete -> Icons.Filled.VerifiedUser
                        else -> Icons.Filled.Lock
                    },
                    contentDescription = null,
                    tint = accentColor,
                    modifier = Modifier.size(19.dp),
                )
            }
        }
    }
}

@Composable
private fun LivePulseDot() {
    val infiniteTransition = rememberInfiniteTransition(label = "live_dot")
    val dotAlpha = infiniteTransition.animateFloat(
        initialValue = 0.4f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 700),
            repeatMode = RepeatMode.Reverse,
        ),
        label = "dot_alpha",
    )
    Box(
        modifier = Modifier
            .size(7.dp)
            .graphicsLayer { alpha = dotAlpha.value }
            .clip(CircleShape)
            .background(TealAccent),
    )
}

@Composable
private fun ShimmerProgressBar(
    progress: Int,
    isProcessing: Boolean,
    accentColor: Color,
    secondaryAccent: Color,
) {
    val animatedProgress by animateFloatAsState(
        targetValue = (progress.coerceIn(0, 100)) / 100f,
        animationSpec = tween(durationMillis = 220),
        label = "pipeline_progress",
    )
    val shimmerOffset = if (isProcessing) {
        rememberInfiniteTransition(label = "bar_shimmer").animateFloat(
            initialValue = -0.35f,
            targetValue = 1.35f,
            animationSpec = infiniteRepeatable(
                animation = tween(durationMillis = 1100, easing = LinearEasing),
                repeatMode = RepeatMode.Restart,
            ),
            label = "progress_shimmer",
        )
    } else {
        null
    }

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .height(10.dp)
            .clip(RoundedCornerShape(50))
            .background(PureWhite.copy(alpha = 0.88f)),
    ) {
        val fillFraction = animatedProgress.coerceIn(0f, 1f)
        if (fillFraction > 0f) {
            Canvas(
                modifier = Modifier
                    .fillMaxWidth(fillFraction)
                    .fillMaxHeight()
                    .clip(RoundedCornerShape(50)),
            ) {
                val brush = if (shimmerOffset != null) {
                    val shift = shimmerOffset.value * size.width
                    Brush.linearGradient(
                        colors = listOf(
                            ProBlue,
                            TealAccent,
                            PureWhite.copy(alpha = 0.85f),
                            TealAccent,
                            ProBlueDark,
                        ),
                        start = Offset(shift - 180f, 0f),
                        end = Offset(shift + 180f, 0f),
                    )
                } else {
                    Brush.horizontalGradient(
                        colors = listOf(accentColor, secondaryAccent),
                    )
                }
                drawRect(brush = brush)
            }
        }
    }
}

@Composable
private fun LiveActiveTimelineRow(detail: String) {
    val liveTransition = rememberInfiniteTransition(label = "live_row")
    val haloAlpha = liveTransition.animateFloat(
        initialValue = 0.28f,
        targetValue = 0.9f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 700),
            repeatMode = RepeatMode.Reverse,
        ),
        label = "halo_alpha",
    )
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .height(IntrinsicSize.Min),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Box(
            modifier = Modifier
                .width(24.dp)
                .padding(top = 2.dp),
            contentAlignment = Alignment.Center,
        ) {
            Box(
                modifier = Modifier
                    .size(22.dp)
                    .graphicsLayer { alpha = haloAlpha.value }
                    .clip(CircleShape)
                    .background(ProBlueTint),
            )
            CircularProgressIndicator(
                modifier = Modifier.size(16.dp),
                strokeWidth = 2.dp,
                color = ProBlue,
            )
        }
        Column(
            modifier = Modifier
                .weight(1f)
                .padding(bottom = 2.dp),
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text(
                    text = "In Progress",
                    style = MaterialTheme.typography.labelLarge.copy(fontWeight = FontWeight.SemiBold),
                    color = ProBlue,
                )
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(6.dp))
                        .background(TealTint)
                        .padding(horizontal = 6.dp, vertical = 2.dp),
                ) {
                    Text(
                        text = "LIVE",
                        style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold),
                        color = TealAccent,
                        modifier = Modifier.graphicsLayer { alpha = haloAlpha.value },
                    )
                }
            }
            Text(
                text = detail,
                style = MaterialTheme.typography.bodySmall,
                color = SlateMuted,
            )
        }
    }
}

private fun formatDuration(ms: Long): String {
    val secs = ms / 1000.0
    return String.format(Locale.US, "%.1fs", secs)
}

@Composable
private fun PipelineTimelineStep(
    step: ProtectionStepResult,
    isLast: Boolean,
) {
    val (bg, fg, tag) = when (step.status) {
        StepStatus.SUCCESS -> Triple(SuccessTint, SuccessEmerald, "DONE")
        StepStatus.FAILED -> Triple(ErrorTint, ErrorRed, "FAIL")
        StepStatus.SKIPPED -> Triple(SectionGrey, SlateMuted, "SKIP")
    }
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .height(IntrinsicSize.Min),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Column(
            modifier = Modifier
                .width(24.dp)
                .fillMaxHeight(),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Box(
                modifier = Modifier
                    .padding(top = 2.dp)
                    .size(22.dp)
                    .clip(CircleShape)
                    .background(bg),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    imageVector = if (step.status == StepStatus.FAILED) Icons.Filled.Close else Icons.Filled.Check,
                    contentDescription = tag,
                    tint = fg,
                    modifier = Modifier.size(13.dp),
                )
            }
            if (!isLast) {
                Box(
                    modifier = Modifier
                        .width(2.dp)
                        .weight(1f)
                        .padding(vertical = 3.dp)
                        .background(BorderSubtle),
                )
            }
        }

        Column(
            modifier = Modifier
                .weight(1f)
                .padding(bottom = if (isLast) 2.dp else 12.dp),
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text(
                    text = step.title,
                    style = MaterialTheme.typography.labelLarge.copy(fontWeight = FontWeight.SemiBold),
                    color = CharcoalText,
                    modifier = Modifier.weight(1f),
                )
                Spacer(modifier = Modifier.width(6.dp))
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(6.dp))
                        .background(bg)
                        .padding(horizontal = 6.dp, vertical = 2.dp),
                ) {
                    Text(
                        text = tag,
                        style = MaterialTheme.typography.labelSmall,
                        color = fg,
                    )
                }
            }
            Text(
                text = step.detail,
                style = MaterialTheme.typography.bodySmall,
                color = SlateMuted,
            )
        }
    }
}

@Composable
fun FeatureInfoDialog(
    info: ProtectionFeatureInfo,
    isEnabled: Boolean,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = PureWhite,
        icon = {
            Box(
                modifier = Modifier
                    .size(42.dp)
                    .clip(CircleShape)
                    .background(ProBlueTint),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    imageVector = Icons.Outlined.Info,
                    contentDescription = null,
                    tint = ProBlue,
                    modifier = Modifier.size(22.dp),
                )
            }
        },
        title = {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text(
                    text = info.fullName,
                    style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
                    color = CharcoalText,
                    modifier = Modifier.weight(1f),
                )
                StatusPill(
                    text = if (isEnabled) "ON" else "OFF",
                    containerColor = if (isEnabled) SuccessTint else SectionGrey,
                    contentColor = if (isEnabled) SuccessEmerald else SlateMuted,
                )
            }
        },
        text = {
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp),
                color = SectionGrey,
                border = BorderStroke(1.dp, BorderSubtle),
            ) {
                Column(
                    modifier = Modifier.padding(14.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Text(
                        text = info.summary,
                        style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.Medium),
                        color = CharcoalText,
                    )
                    if (info.protections.isNotEmpty()) {
                        HorizontalDivider(thickness = 1.dp, color = BorderSubtle)
                        Text(
                            text = "Protections When Turned ON",
                            style = MaterialTheme.typography.labelMedium.copy(fontWeight = FontWeight.Bold),
                            color = ProBlueDark,
                        )
                        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                            info.protections.forEach { point ->
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    verticalAlignment = Alignment.Top,
                                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                                ) {
                                    Icon(
                                        imageVector = Icons.Filled.CheckCircle,
                                        contentDescription = null,
                                        tint = SuccessEmerald,
                                        modifier = Modifier
                                            .padding(top = 2.dp)
                                            .size(15.dp),
                                    )
                                    Text(
                                        text = point,
                                        style = MaterialTheme.typography.bodySmall,
                                        color = CharcoalText,
                                        modifier = Modifier.weight(1f),
                                    )
                                }
                            }
                        }
                    }
                }
            }
        },
        confirmButton = {
            TextButton(
                onClick = onDismiss,
                modifier = Modifier.testTag("feature_info_close_button"),
            ) {
                Text("Got It", color = ProBlue, fontWeight = FontWeight.SemiBold)
            }
        },
    )
}

@Composable
fun StatusPill(
    text: String,
    containerColor: Color,
    contentColor: Color,
    icon: ImageVector? = null,
) {
    Surface(
        shape = RoundedCornerShape(50),
        color = containerColor,
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 5.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            if (icon != null) {
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = contentColor,
                    modifier = Modifier.size(13.dp),
                )
            }
            Text(
                text = text,
                style = MaterialTheme.typography.labelSmall,
                color = contentColor,
            )
        }
    }
}

@Composable
fun DeveloperInfoDialog(
    onDismiss: () -> Unit,
) {
    val uriHandler = LocalUriHandler.current
    val scrollState = rememberScrollState()

    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = PureWhite,
        title = {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Box(
                    modifier = Modifier
                        .size(40.dp)
                        .clip(RoundedCornerShape(12.dp))
                        .background(
                            Brush.linearGradient(colors = listOf(ProBlue, ProBlueDark)),
                        ),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(
                        imageVector = Icons.Filled.Shield,
                        contentDescription = null,
                        tint = PureWhite,
                        modifier = Modifier.size(22.dp),
                    )
                }
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "DS PRO",
                        style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
                        color = CharcoalText,
                    )
                    Text(
                        text = "APK Protection & Hardening Tool",
                        style = MaterialTheme.typography.bodySmall,
                        color = SlateMuted,
                    )
                }
            }
        },
        text = {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .verticalScroll(scrollState),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                // Developer Identity Card
                Surface(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp),
                    color = ProBlueTint.copy(alpha = 0.55f),
                    border = BorderStroke(1.dp, ProBlue.copy(alpha = 0.25f)),
                ) {
                    Row(
                        modifier = Modifier.padding(12.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(10.dp),
                    ) {
                        Box(
                            modifier = Modifier
                                .size(36.dp)
                                .clip(CircleShape)
                                .background(PureWhite),
                            contentAlignment = Alignment.Center,
                        ) {
                            Icon(
                                imageVector = Icons.Filled.Person,
                                contentDescription = null,
                                tint = ProBlue,
                                modifier = Modifier.size(20.dp),
                            )
                        }
                        Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                            Text(
                                text = "DEVELOPER",
                                style = MaterialTheme.typography.labelSmall,
                                color = ProBlueDark,
                            )
                            Text(
                                text = "MAHEDI HASAN",
                                style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.Bold),
                                color = CharcoalText,
                            )
                        }
                    }
                }

                // Support & Community Buttons (no raw links displayed for privacy)
                Surface(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp),
                    color = SectionGrey,
                    border = BorderStroke(1.dp, BorderSubtle),
                ) {
                    Column(
                        modifier = Modifier.padding(12.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Text(
                            text = "Support & Community",
                            style = MaterialTheme.typography.labelMedium.copy(fontWeight = FontWeight.Bold),
                            color = CharcoalText,
                        )
                        SocialSupportButton(
                            icon = Icons.AutoMirrored.Filled.Send,
                            label = "Telegram",
                            accentColor = ProBlue,
                            accentTint = ProBlueTint,
                            testTag = "support_telegram_direct",
                            onClick = { runCatching { uriHandler.openUri("https://t.me/Its_Mahedi08") } },
                        )
                        SocialSupportButton(
                            icon = Icons.Filled.Groups,
                            label = "Telegram Channel",
                            accentColor = TealAccent,
                            accentTint = TealTint,
                            testTag = "support_telegram_channel",
                            onClick = { runCatching { uriHandler.openUri("https://t.me/CYBER_GENZ_OFC") } },
                        )
                        SocialSupportButton(
                            icon = Icons.Filled.Phone,
                            label = "WhatsApp",
                            accentColor = SuccessEmerald,
                            accentTint = SuccessTint,
                            testTag = "support_whatsapp",
                            onClick = { runCatching { uriHandler.openUri("https://wa.me/8801783862159") } },
                        )
                    }
                }

                // App Information & Important Guidelines
                Surface(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp),
                    color = PureWhite,
                    border = BorderStroke(1.dp, BorderSubtle),
                ) {
                    Column(
                        modifier = Modifier.padding(12.dp),
                        verticalArrangement = Arrangement.spacedBy(6.dp),
                    ) {
                        Text(
                            text = "App Information & Terms",
                            style = MaterialTheme.typography.labelMedium.copy(fontWeight = FontWeight.Bold),
                            color = CharcoalText,
                        )
                        InfoBulletLine("100% on-device APK protection & inspection without external uploads.")
                        InfoBulletLine("Use only on applications you own or have permission to protect.")
                        InfoBulletLine("Always keep a backup of your original APK and test after signing.")
                    }
                }
            }
        },
        confirmButton = {
            TextButton(
                onClick = onDismiss,
                modifier = Modifier.testTag("developer_info_close_button"),
            ) {
                Text("Close", color = ProBlue, fontWeight = FontWeight.SemiBold)
            }
        },
    )
}

@Composable
private fun SocialSupportButton(
    icon: ImageVector,
    label: String,
    accentColor: Color,
    accentTint: Color,
    testTag: String,
    onClick: () -> Unit,
) {
    Surface(
        onClick = onClick,
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 48.dp)
            .testTag(testTag),
        shape = RoundedCornerShape(10.dp),
        color = PureWhite,
        border = BorderStroke(1.dp, accentColor.copy(alpha = 0.25f)),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Box(
                modifier = Modifier
                    .size(32.dp)
                    .clip(RoundedCornerShape(8.dp))
                    .background(accentTint),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = accentColor,
                    modifier = Modifier.size(18.dp),
                )
            }
            Text(
                text = label,
                style = MaterialTheme.typography.labelLarge.copy(fontWeight = FontWeight.SemiBold),
                color = CharcoalText,
                modifier = Modifier.weight(1f),
            )
            Icon(
                imageVector = Icons.AutoMirrored.Filled.OpenInNew,
                contentDescription = "Open $label",
                tint = accentColor,
                modifier = Modifier.size(17.dp),
            )
        }
    }
}

@Composable
private fun InfoBulletLine(text: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.Top,
        horizontalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Icon(
            imageVector = Icons.Filled.CheckCircle,
            contentDescription = null,
            tint = ProBlue,
            modifier = Modifier
                .padding(top = 2.dp)
                .size(14.dp),
        )
        Text(
            text = text,
            style = MaterialTheme.typography.bodySmall,
            color = SlateMuted,
            modifier = Modifier.weight(1f),
        )
    }
}

@Composable
fun KeyValueLine(
    label: String,
    value: String,
    mono: Boolean = false,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 2.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodySmall,
            color = SlateMuted,
            modifier = Modifier.weight(0.32f),
        )
        Text(
            text = value,
            style = if (mono) MonoCodeStyle else MaterialTheme.typography.bodySmall.copy(fontWeight = FontWeight.Medium),
            color = CharcoalText,
            modifier = Modifier.weight(0.68f),
        )
    }
}


