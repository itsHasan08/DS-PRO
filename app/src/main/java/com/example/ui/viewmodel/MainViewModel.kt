package com.example.ui.viewmodel

import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.example.domain.engine.ApkAnalyzerEngine
import com.example.domain.engine.ApkProtectionProcessor
import com.example.domain.engine.formatBytes
import com.example.domain.model.ApkAnalysisResult
import com.example.domain.model.ProtectionConfig
import com.example.domain.model.ProtectionRunResult
import com.example.domain.model.ProtectionStepResult
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

data class DsProUiState(
    val selectedApkUri: String? = null,
    val isLoadingApk: Boolean = false,
    val isRefreshing: Boolean = false,
    val selectedApk: ApkAnalysisResult? = null,
    val apkError: String? = null,
    val config: ProtectionConfig = ProtectionConfig(),
    val isProcessing: Boolean = false,
    val progress: Int = 0,
    val steps: List<ProtectionStepResult> = emptyList(),
    val runResult: ProtectionRunResult? = null,
    val statusMessage: String? = null,
) {
    val hasActiveProtection: Boolean
        get() = config.activeToggleCount > 0

    val isStartEnabled: Boolean
        get() = selectedApkUri != null &&
            selectedApk != null &&
            hasActiveProtection &&
            !isLoadingApk &&
            !isRefreshing &&
            !isProcessing
}

class MainViewModel(
    private val analyzerEngine: ApkAnalyzerEngine,
    private val protectionProcessor: ApkProtectionProcessor,
) : ViewModel() {

    private val _uiState = MutableStateFlow(DsProUiState())
    val uiState: StateFlow<DsProUiState> = _uiState.asStateFlow()

    fun onApkUriSelected(uri: Uri) {
        viewModelScope.launch {
            _uiState.update {
                it.copy(
                    selectedApkUri = uri.toString(),
                    isLoadingApk = true,
                    apkError = null,
                    runResult = null,
                    steps = emptyList(),
                    progress = 0,
                )
            }
            analyzerEngine.loadApkFromUri(uri)
                .onSuccess { result ->
                    _uiState.update {
                        it.copy(
                            isLoadingApk = false,
                            selectedApk = result,
                            apkError = null,
                        )
                    }
                }
                .onFailure { err ->
                    _uiState.update {
                        it.copy(
                            selectedApkUri = null,
                            isLoadingApk = false,
                            selectedApk = null,
                            apkError = err.message ?: "Failed to load APK.",
                        )
                    }
                }
        }
    }

    fun updateConfig(transform: (ProtectionConfig) -> ProtectionConfig) {
        _uiState.update { it.copy(config = transform(it.config)) }
    }

    fun refreshWorkspace() {
        val currentState = _uiState.value
        if (currentState.isProcessing || currentState.isLoadingApk || currentState.isRefreshing) return

        val uriStr = currentState.selectedApkUri
        if (uriStr == null) {
            _uiState.update {
                it.copy(
                    apkError = null,
                    progress = 0,
                    steps = emptyList(),
                    runResult = null,
                    statusMessage = "Refreshed.",
                )
            }
            return
        }

        val parsedUri = runCatching { Uri.parse(uriStr) }.getOrNull() ?: return
        viewModelScope.launch {
            _uiState.update {
                it.copy(
                    isRefreshing = true,
                    apkError = null,
                    progress = 0,
                    steps = emptyList(),
                    runResult = null,
                )
            }
            analyzerEngine.loadApkFromUri(parsedUri)
                .onSuccess { result ->
                    _uiState.update {
                        it.copy(
                            isRefreshing = false,
                            selectedApk = result,
                            apkError = null,
                            statusMessage = "Reloaded ${result.fileName}.",
                        )
                    }
                }
                .onFailure { err ->
                    _uiState.update {
                        it.copy(
                            isRefreshing = false,
                            apkError = err.message ?: "Failed to reload APK.",
                            statusMessage = "Reload failed.",
                        )
                    }
                }
        }
    }

    fun resetAll() {
        if (_uiState.value.isProcessing) return
        _uiState.value = DsProUiState(
            statusMessage = "Everything has been reset.",
        )
    }

    fun startProtection() {
        val state = _uiState.value
        val apk = state.selectedApk
        if (state.selectedApkUri == null || apk == null) {
            _uiState.update { it.copy(statusMessage = "Please select an APK file first.") }
            return
        }
        if (!state.hasActiveProtection) {
            _uiState.update { it.copy(statusMessage = "Enable at least one protection option first.") }
            return
        }
        if (state.isProcessing) return

        viewModelScope.launch {
            _uiState.update {
                it.copy(
                    isProcessing = true,
                    progress = 5,
                    steps = emptyList(),
                    runResult = null,
                )
            }
            val result = protectionProcessor.processApk(apk, state.config) { pct, steps ->
                _uiState.update { it.copy(progress = pct, steps = steps) }
            }
            _uiState.update {
                it.copy(
                    isProcessing = false,
                    progress = 100,
                    steps = result.steps,
                    runResult = result,
                    statusMessage = result.summary,
                )
            }
        }
    }

    fun exportUnsignedApk(destinationUri: Uri) {
        val path = _uiState.value.runResult?.outputApkPath ?: return
        viewModelScope.launch {
            protectionProcessor.exportUnsignedApk(path, destinationUri)
                .onSuccess { size ->
                    _uiState.update {
                        it.copy(statusMessage = "Exported copy (${formatBytes(size)}).")
                    }
                }
                .onFailure { err ->
                    _uiState.update {
                        it.copy(statusMessage = "Export failed: ${err.message}")
                    }
                }
        }
    }

    fun clearStatusMessage() {
        _uiState.update { it.copy(statusMessage = null) }
    }

    class Factory(
        private val analyzerEngine: ApkAnalyzerEngine,
        private val protectionProcessor: ApkProtectionProcessor,
    ) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            return MainViewModel(analyzerEngine, protectionProcessor) as T
        }
    }
}
