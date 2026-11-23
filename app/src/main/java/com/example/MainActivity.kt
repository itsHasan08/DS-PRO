package com.example

import android.graphics.Color
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.core.view.WindowCompat
import com.example.domain.engine.ApkAnalyzerEngine
import com.example.domain.engine.ApkProtectionProcessor
import com.example.ui.screens.MainScreen
import com.example.ui.theme.DsProTheme
import com.example.ui.viewmodel.MainViewModel

class MainActivity : ComponentActivity() {

    private val viewModel: MainViewModel by viewModels {
        val appContext = applicationContext
        val storageService = com.example.domain.engine.ApkFileStorageService(appContext)
        MainViewModel.Factory(
            analyzerEngine = ApkAnalyzerEngine(appContext),
            protectionProcessor = ApkProtectionProcessor(appContext, storageService),
        )
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.light(Color.WHITE, Color.WHITE),
            navigationBarStyle = SystemBarStyle.light(Color.WHITE, Color.WHITE),
        )
        setContent {
            DsProTheme {
                MainScreen(viewModel = viewModel)
            }
        }
    }
}
