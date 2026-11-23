package com.example.ui.components

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.rounded.RestartAlt
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.example.R
import com.example.domain.model.ProtectionFeatureInfo
import com.example.domain.model.StepStatus
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

@Composable
fun DsProTopBar(
    activeCount: Int,
    isResetEnabled: Boolean = true,
    onReset: () -> Unit = {},
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
                    .padding(horizontal = 16.dp, vertical = 10.dp),
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

                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    StatusPill(
                        text = "$activeCount Active",
                        containerColor = if (activeCount > 0) SuccessTint else ProBlueTint,
                        contentColor = if (activeCount > 0) SuccessEmerald else ProBlueDark,
                    )
                    Surface(
                        modifier = Modifier
                            .size(48.dp)
                            .clip(RoundedCornerShape(12.dp))
                            .clickable(
                                enabled = isResetEnabled,
                                role = Role.Button,
                                onClick = onReset,
                            )
                            .testTag("reset_button"),
                        shape = RoundedCornerShape(12.dp),
                        color = if (isResetEnabled) ProBlueTint else SectionGrey,
                        border = BorderStroke(
                            1.dp,
                            if (isResetEnabled) ProBlue.copy(alpha = 0.35f) else BorderSubtle,
                        ),
                    ) {
                        Box(contentAlignment = Alignment.Center) {
                            Icon(
                                imageVector = Icons.Rounded.RestartAlt,
                                contentDescription = "Reset all",
                                tint = if (isResetEnabled) ProBlueDark else SlateMuted,
                                modifier = Modifier.size(22.dp),
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
                .heightIn(min = 54.dp)
                .padding(start = 10.dp, end = 4.dp, top = 4.dp, bottom = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = title,
                style = MaterialTheme.typography.bodySmall.copy(fontWeight = FontWeight.Medium),
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
                modifier = Modifier.size(width = 42.dp, height = 48.dp),
                contentAlignment = Alignment.Center,
            ) {
                Switch(
                    checked = checked,
                    onCheckedChange = onCheckedChange,
                    modifier = Modifier.scale(0.76f),
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
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text(
                    text = info.title,
                    style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
                    color = CharcoalText,
                )
                StatusPill(
                    text = if (isEnabled) "ON" else "OFF",
                    containerColor = if (isEnabled) SuccessTint else SectionGrey,
                    contentColor = if (isEnabled) SuccessEmerald else SlateMuted,
                )
            }
        },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Surface(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(10.dp),
                    color = ProBlueTint.copy(alpha = 0.5f),
                    border = BorderStroke(1.dp, ProBlue.copy(alpha = 0.25f)),
                ) {
                    Column(modifier = Modifier.padding(10.dp)) {
                        Text(
                            text = "What Turns ON",
                            style = MaterialTheme.typography.labelMedium.copy(fontWeight = FontWeight.Bold),
                            color = ProBlueDark,
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = info.whatTurnsOn,
                            style = MaterialTheme.typography.bodySmall,
                            color = CharcoalText,
                        )
                    }
                }
                Surface(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(10.dp),
                    color = SectionGrey,
                    border = BorderStroke(1.dp, BorderSubtle),
                ) {
                    Column(modifier = Modifier.padding(10.dp)) {
                        Text(
                            text = "How It Works",
                            style = MaterialTheme.typography.labelMedium.copy(fontWeight = FontWeight.Bold),
                            color = CharcoalText,
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = info.howItWorks,
                            style = MaterialTheme.typography.bodySmall,
                            color = SlateMuted,
                        )
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

@Composable
fun StepResultRow(
    title: String,
    detail: String,
    status: StepStatus,
) {
    val (bg, fg, label) = when (status) {
        StepStatus.SUCCESS -> Triple(SuccessTint, SuccessEmerald, "SUCCESS")
        StepStatus.FAILED -> Triple(ErrorTint, ErrorRed, "FAILED")
        StepStatus.SKIPPED -> Triple(SectionGrey, SlateMuted, "SKIPPED")
    }
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(10.dp),
        color = PureWhite,
        border = BorderStroke(1.dp, BorderSubtle),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(10.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Box(
                modifier = Modifier
                    .size(22.dp)
                    .clip(CircleShape)
                    .background(bg),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    imageVector = if (status == StepStatus.FAILED) Icons.Filled.Error else Icons.Filled.CheckCircle,
                    contentDescription = label,
                    tint = fg,
                    modifier = Modifier.size(14.dp),
                )
            }
            Column(modifier = Modifier.weight(1f)) {
                Text(title, style = MaterialTheme.typography.titleSmall, color = CharcoalText)
                Text(detail, style = MaterialTheme.typography.bodySmall, color = SlateMuted)
            }
            Spacer(modifier = Modifier.width(4.dp))
            StatusPill(text = label, containerColor = bg, contentColor = fg)
        }
    }
}
