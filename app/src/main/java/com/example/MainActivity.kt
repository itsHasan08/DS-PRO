package com.example

import android.content.Context
import android.graphics.Color
import android.hardware.display.DisplayManager
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.Display
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import com.example.domain.engine.ApkAnalyzerEngine
import com.example.domain.engine.ApkFileStorageService
import com.example.domain.engine.ApkProtectionProcessor
import com.example.ui.screens.MainScreen
import com.example.ui.theme.DsProTheme
import com.example.ui.viewmodel.MainViewModel
import kotlin.math.abs

class MainActivity : ComponentActivity() {

    private val viewModel: MainViewModel by viewModels {
        val appContext = applicationContext
        val storageService = ApkFileStorageService(appContext)
        MainViewModel.Factory(
            analyzerEngine = ApkAnalyzerEngine(appContext),
            protectionProcessor = ApkProtectionProcessor(appContext, storageService),
        )
    }

    private var displayManager: DisplayManager? = null
    private val displayListener = object : DisplayManager.DisplayListener {
        override fun onDisplayAdded(displayId: Int) = Unit
        override fun onDisplayRemoved(displayId: Int) = Unit
        override fun onDisplayChanged(displayId: Int) {
            negotiateHighestSupportedRefreshRate()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.light(Color.WHITE, Color.WHITE),
            navigationBarStyle = SystemBarStyle.light(Color.WHITE, Color.WHITE),
        )
        displayManager = getSystemService(Context.DISPLAY_SERVICE) as? DisplayManager
        negotiateHighestSupportedRefreshRate()
        setContent {
            DsProTheme {
                MainScreen(viewModel = viewModel)
            }
        }
    }

    override fun onResume() {
        super.onResume()
        negotiateHighestSupportedRefreshRate()
        displayManager?.registerDisplayListener(displayListener, Handler(Looper.getMainLooper()))
        viewModel.refreshStoragePermissionState()
    }

    override fun onPause() {
        displayManager?.unregisterDisplayListener(displayListener)
        super.onPause()
    }

    private fun negotiateHighestSupportedRefreshRate() {
        val currentDisplay = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            display ?: displayManager?.getDisplay(Display.DEFAULT_DISPLAY)
        } else {
            displayManager?.getDisplay(Display.DEFAULT_DISPLAY)
        } ?: return

        val activeMode = currentDisplay.mode ?: return
        val supported = currentDisplay.supportedModes ?: return
        val matchingResolutionModes = supported.filter {
            it.physicalWidth == activeMode.physicalWidth &&
                it.physicalHeight == activeMode.physicalHeight
        }
        val bestMode = (matchingResolutionModes.ifEmpty { supported.toList() })
            .maxByOrNull { it.refreshRate } ?: return

        val attrs = window.attributes
        var updated = false
        if (attrs.preferredDisplayModeId != bestMode.modeId) {
            attrs.preferredDisplayModeId = bestMode.modeId
            updated = true
        }
        if (abs(attrs.preferredRefreshRate - bestMode.refreshRate) > 0.5f) {
            attrs.preferredRefreshRate = bestMode.refreshRate
            updated = true
        }
        if (updated) {
            window.attributes = attrs
        }
    }
}
