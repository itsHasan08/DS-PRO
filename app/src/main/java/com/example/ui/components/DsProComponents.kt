package com.example.ui.components

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.slideInVertically
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
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
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.vector.ImageVector
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
        shadowElevation = 2.dp,
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
                        .clip(RoundedCornerShape(50))
                        .clickable(role = Role.Button, onClick = onInfoClick)
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
        modifier = modifier
            .clip(RoundedCornerShape(12.dp))
            .clickable(role = Role.Switch) { onCheckedChange(!checked) }
            .testTag(testTag),
        shape = RoundedCornerShape(12.dp),
        color = if (checked) accentTint.copy(alpha = 0.7f) else PureWhite,
        border = BorderStroke(1.dp, if (checked) accentColor.copy(alpha = 0.5f) else BorderSubtle),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = 58.dp)
                .padding(start = 10.dp, end = 4.dp, top = 6.dp, bottom = 6.dp),
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
                modifier = Modifier
                    .weight(1f)
                    .padding(end = 2.dp),
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
                modifier = Modifier.size(width = 40.dp, height = 48.dp),
                contentAlignment = Alignment.Center,
            ) {
                Switch(
                    checked = checked,
                    onCheckedChange = onCheckedChange,
                    modifier = Modifier.scale(0.74f),
                    colors = SwitchDefaults.colors(
                        checkedThumbColor = PureWhite,
                        checkedTrackColor = accentColor,
                        uncheckedThumbColor = PureWhite,
                        uncheckedTrackColor = BorderSubtle,
                        uncheckedBorderColor = SlateMuted.copy(alpha = 0.4f),
                    ),
                )
            }
        }
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
    val animatedProgress by animateFloatAsState(
        targetValue = (progress.coerceIn(0, 100)) / 100f,
        animationSpec = tween(durationMillis = 240),
        label = "pipeline_progress",
    )

    var elapsedMs by remember { mutableLongStateOf(0L) }
    LaunchedEffect(isProcessing) {
        if (isProcessing) {
            val started = System.currentTimeMillis()
            elapsedMs = 0L
            while (true) {
                delay(100L)
                elapsedMs = System.currentTimeMillis() - started
            }
        }
    }

    val infiniteTransition = rememberInfiniteTransition(label = "pipeline_live")
    val orbitAngle by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 1200, easing = LinearEasing),
        ),
        label = "orbit_angle",
    )
    val radarWave by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 1400, easing = LinearEasing),
            repeatMode = RepeatMode.Restart,
        ),
        label = "radar_wave",
    )
    val pulseScale by infiniteTransition.animateFloat(
        initialValue = 0.94f,
        targetValue = 1.07f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 750),
            repeatMode = RepeatMode.Reverse,
        ),
        label = "pulse_scale",
    )
    val shimmerOffset by infiniteTransition.animateFloat(
        initialValue = -0.35f,
        targetValue = 1.35f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 1100, easing = LinearEasing),
            repeatMode = RepeatMode.Restart,
        ),
        label = "progress_shimmer",
    )

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
                            Box(
                                modifier = Modifier.size(46.dp),
                                contentAlignment = Alignment.Center,
                            ) {
                                if (isProcessing) {
                                    Canvas(modifier = Modifier.fillMaxSize()) {
                                        val maxR = size.minDimension / 2f
                                        val r1 = (maxR * 0.56f) + (maxR * 0.44f * radarWave)
                                        drawCircle(
                                            color = accentColor.copy(alpha = (1f - radarWave) * 0.42f),
                                            radius = r1,
                                            style = Stroke(width = 2.dp.toPx()),
                                        )
                                        drawArc(
                                            color = TealAccent,
                                            startAngle = orbitAngle,
                                            sweepAngle = 115f,
                                            useCenter = false,
                                            style = Stroke(width = 2.6.dp.toPx(), cap = StrokeCap.Round),
                                        )
                                        drawArc(
                                            color = ProBlue,
                                            startAngle = orbitAngle + 180f,
                                            sweepAngle = 80f,
                                            useCenter = false,
                                            style = Stroke(width = 2.2.dp.toPx(), cap = StrokeCap.Round),
                                        )
                                    }
                                }
                                Box(
                                    modifier = Modifier
                                        .size(34.dp)
                                        .scale(if (isProcessing) pulseScale else 1f)
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
                                        Box(
                                            modifier = Modifier
                                                .size(7.dp)
                                                .alpha(if (pulseScale > 1f) 1f else 0.45f)
                                                .clip(CircleShape)
                                                .background(TealAccent),
                                        )
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

                    // Live Dual-Accent Wave Progress Track
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(10.dp)
                            .clip(RoundedCornerShape(50))
                            .background(PureWhite.copy(alpha = 0.88f)),
                    ) {
                        val fillFraction = animatedProgress.coerceIn(0f, 1f)
                        if (fillFraction > 0f) {
                            Box(
                                modifier = Modifier
                                    .fillMaxWidth(fillFraction)
                                    .fillMaxHeight()
                                    .clip(RoundedCornerShape(50))
                                    .background(
                                        brush = if (isProcessing) {
                                            Brush.linearGradient(
                                                colors = listOf(
                                                    ProBlue,
                                                    TealAccent,
                                                    PureWhite.copy(alpha = 0.85f),
                                                    TealAccent,
                                                    ProBlueDark,
                                                ),
                                                start = Offset(shimmerOffset * 600f - 180f, 0f),
                                                end = Offset(shimmerOffset * 600f + 180f, 0f),
                                            )
                                        } else {
                                            Brush.horizontalGradient(
                                                colors = listOf(accentColor, secondaryAccent),
                                            )
                                        },
                                    ),
                            )
                        }
                    }

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
                                    BorderStroke(1.2.dp, ProBlue.copy(alpha = if (pulseScale > 1f) 0.9f else 0.45f))
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
                        AnimatedVisibility(
                            visible = true,
                            enter = fadeIn(tween(180)) + slideInVertically { it / 4 },
                        ) {
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
                                imageVector = if (isExported) Icons.Filled.CheckCircle else Icons.Filled.Folder,
                                contentDescription = null,
                                tint = SuccessEmerald,
                                modifier = Modifier.size(20.dp),
                            )
                        }
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = if (isExported) {
                                    "APK Saved (${formatBytes(exportedSizeBytes ?: runResult.outputSizeBytes)})"
                                } else {
                                    "Protected APK Ready (${formatBytes(runResult.outputSizeBytes)})"
                                },
                                style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.Bold),
                                color = CharcoalText,
                            )
                            Text(
                                text = if (isExported) {
                                    "Saved to your selected folder. Tap below only if you want another copy."
                                } else {
                                    "Tap Save APK below to choose where to save the protected file."
                                },
                                style = MaterialTheme.typography.bodySmall,
                                color = SlateMuted,
                            )
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
private fun LiveActiveTimelineRow(detail: String) {
    val liveTransition = rememberInfiniteTransition(label = "live_row")
    val haloAlpha by liveTransition.animateFloat(
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
                    .alpha(haloAlpha)
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
                        modifier = Modifier.alpha(haloAlpha),
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

