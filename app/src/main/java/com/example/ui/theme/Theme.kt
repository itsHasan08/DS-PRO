package com.example.ui.theme

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.unit.dp

private val DsProLightColorScheme = lightColorScheme(
    primary = ProBlue,
    onPrimary = PureWhite,
    primaryContainer = ProBlueTint,
    onPrimaryContainer = ProBlueDark,
    secondary = TealAccent,
    onSecondary = PureWhite,
    secondaryContainer = TealTint,
    onSecondaryContainer = CharcoalText,
    tertiary = SuccessEmerald,
    onTertiary = PureWhite,
    tertiaryContainer = SuccessTint,
    onTertiaryContainer = CharcoalText,
    background = CanvasFrost,
    onBackground = CharcoalText,
    surface = PureWhite,
    onSurface = CharcoalText,
    surfaceVariant = SectionGrey,
    onSurfaceVariant = SlateMuted,
    surfaceContainerLowest = PureWhite,
    surfaceContainerLow = SurfaceElevated,
    surfaceContainer = SectionGrey,
    surfaceContainerHigh = CanvasFrost,
    surfaceContainerHighest = BorderSubtle,
    outline = BorderStrong,
    outlineVariant = BorderSubtle,
    error = ErrorRed,
    onError = PureWhite,
    errorContainer = ErrorTint,
    onErrorContainer = ErrorRed,
)

val DsProShapes = Shapes(
    small = RoundedCornerShape(8.dp),
    medium = RoundedCornerShape(14.dp),
    large = RoundedCornerShape(18.dp),
    extraLarge = RoundedCornerShape(24.dp),
)

@Composable
fun DsProTheme(
    content: @Composable () -> Unit,
) {
    MaterialTheme(
        colorScheme = DsProLightColorScheme,
        typography = Typography,
        shapes = DsProShapes,
        content = content,
    )
}
