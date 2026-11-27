// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2025-2026 InstallerX Revived contributors
@file:OptIn(ExperimentalMaterial3Api::class)

package com.rosan.installer.ui.page.main.settings.preferred.installer

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_WEAK
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.add
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LargeFlexibleTopAppBar
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.rememberTopAppBarState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.rosan.installer.R
import com.rosan.installer.apk.signing.SigSchemes
import com.rosan.installer.core.device.model.Manufacturer
import com.rosan.installer.core.env.DeviceConfig
import com.rosan.installer.crypto.ks.KeyStoreManager
import com.rosan.installer.domain.settings.action.InstallerSettingsAction
import com.rosan.installer.domain.settings.model.app.NamedPackage
import com.rosan.installer.domain.settings.model.app.SharedUid
import com.rosan.installer.domain.settings.model.config.BiometricAuthMode
import com.rosan.installer.ui.icons.AppIcons
import com.rosan.installer.ui.navigation.LocalNavigator
import com.rosan.installer.ui.navigation.Route
import com.rosan.installer.ui.page.main.widget.setting.DraggableList
import com.rosan.installer.ui.page.main.widget.setting.DropDownMenuWidget
import com.rosan.installer.ui.page.main.widget.setting.ExpressiveBackButton
import com.rosan.installer.ui.page.main.widget.setting.NavigationItemWidget
import com.rosan.installer.ui.page.main.widget.setting.SegmentedColumn
import com.rosan.installer.ui.page.main.widget.setting.SwitchWidget
import com.rosan.installer.ui.theme.getMaterial3AppBarColor
import com.rosan.installer.ui.theme.installerMaterial3BlurEffect
import com.rosan.installer.ui.theme.rememberMaterial3BlurBackdrop
import org.koin.androidx.compose.koinViewModel
import top.yukonga.miuix.kmp.blur.layerBackdrop

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun InstallerGlobalSettingsPage(useBlur: Boolean, viewModel: InstallerSettingsViewModel = koinViewModel()) {
    val navigator = LocalNavigator.current
    val context = LocalContext.current
    val uiState by viewModel.state.collectAsStateWithLifecycle()
    val topAppBarState = rememberTopAppBarState()
    val scrollBehavior = TopAppBarDefaults.exitUntilCollapsedScrollBehavior(topAppBarState)
    var isReordering by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) {
        topAppBarState.heightOffset = topAppBarState.heightOffsetLimit
    }

    val backdrop = rememberMaterial3BlurBackdrop(useBlur)

    Scaffold(
        modifier = Modifier
            .nestedScroll(scrollBehavior.nestedScrollConnection)
            .fillMaxSize(),
        containerColor = MaterialTheme.colorScheme.surfaceContainer,
        topBar = {
            LargeFlexibleTopAppBar(
                modifier = Modifier.installerMaterial3BlurEffect(backdrop),
                windowInsets = TopAppBarDefaults.windowInsets.add(WindowInsets(left = 12.dp)),
                title = {
                    Text(stringResource(R.string.installer_settings))
                },
                navigationIcon = {
                    Row {
                        ExpressiveBackButton { navigator.pop() }
                        Spacer(modifier = Modifier.size(16.dp))
                    }
                },
                scrollBehavior = scrollBehavior,
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = backdrop.getMaterial3AppBarColor(),
                    titleContentColor = MaterialTheme.colorScheme.onBackground,
                    scrolledContainerColor = backdrop.getMaterial3AppBarColor(),
                ),
            )
        },
    ) { paddingValues ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .then(backdrop?.let { Modifier.layerBackdrop(it) } ?: Modifier),
            contentPadding = paddingValues,
            userScrollEnabled = !isReordering,
        ) {
            item {
                val biometricAvailable = remember {
                    BiometricManager.from(context)
                        .canAuthenticate(BIOMETRIC_WEAK or BIOMETRIC_STRONG or DEVICE_CREDENTIAL) ==
                        BiometricManager.BIOMETRIC_SUCCESS
                }

                SegmentedColumn(title = stringResource(R.string.installer_settings_global_installer)) {
                    item {
                        NavigationItemWidget(
                            icon = AppIcons.Dialog,
                            title = stringResource(R.string.dialog_settings),
                            description = stringResource(R.string.dialog_settings_desc),
                            onClick = { navigator.push(Route.DialogSettings) },
                        )
                    }
                    item {
                        NavigationItemWidget(
                            icon = AppIcons.Notification,
                            title = stringResource(R.string.notification_settings),
                            description = stringResource(R.string.notification_settings_desc),
                            onClick = { navigator.push(Route.NotificationSettings) },
                        )
                    }
                    item {
                        NavigationItemWidget(
                            icon = AppIcons.Authorizer,
                            title = stringResource(R.string.authorizer_customization),
                            description = stringResource(R.string.authorizer_customization_desc),
                            onClick = { navigator.push(Route.AuthorizerCust) },
                        )
                    }
                    if (biometricAvailable) {
                        item {
                            DataInstallerBiometricAuthWidget(
                                currentMode = uiState.installerRequireBiometricAuth,
                                onModeChange = {
                                    viewModel.dispatch(InstallerSettingsAction.ChangeBiometricAuth(it))
                                },
                            )
                        }
                    }
                }
            }

            item {
                val canSign = KeyStoreManager.getInstance().containsKey("signing_key")

                SegmentedColumn(title = stringResource(R.string.installer_settings_apk_signing)) {
                    item {
                        SwitchWidget(
                            icon = AppIcons.Signature,
                            title = stringResource(R.string.installer_sign_apk),
                            description = stringResource(R.string.installer_sign_apk_desc),
                            checked = uiState.installerSignApk,
                            onCheckedChange = {
                                viewModel.dispatch(InstallerSettingsAction.ChangeInstallerSignApk(it))
                            },
                            enabled = canSign,
                        )
                    }
                    item(animatedVisibility = uiState.installerSignApk) {
                        SwitchWidget(
                            icon = AppIcons.ZipAlign,
                            title = stringResource(R.string.installer_zip_align),
                            description = stringResource(R.string.installer_zip_align_desc),
                            checked = uiState.installerZipAlign,
                            onCheckedChange = {
                                viewModel.dispatch(InstallerSettingsAction.ChangeInstallerZipAlign(it))
                            },
                        )
                    }
                    item(animatedVisibility = uiState.installerSignApk && canSign) {
                        DropDownMenuWidget(
                            icon = AppIcons.SigSchemes,
                            title = stringResource(R.string.installer_sig_schemes),
                            description = stringResource(R.string.installer_sig_schemes_desc),
                            choice = sigSchemeChoice(uiState.installerSigSchemes),
                            data = sigSchemeLabels(),
                            onChoiceChange = { index ->
                                val schemes = sigSchemeOptions().getOrNull(index) ?: return@DropDownMenuWidget
                                if (uiState.installerSigSchemes != schemes) {
                                    viewModel.dispatch(InstallerSettingsAction.ChangeInstallerSigSchemes(schemes))
                                }
                            },
                        )
                    }
                    if (!canSign) {
                        item {
                            Box(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(16.dp)
                                    .padding(top = 8.dp),
                            ) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Icon(
                                        imageVector = Icons.Default.Warning,
                                        contentDescription = null,
                                        tint = MaterialTheme.colorScheme.error,
                                    )
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Text(
                                        text = stringResource(R.string.installer_sign_apk_no_key),
                                        color = MaterialTheme.colorScheme.error,
                                        style = MaterialTheme.typography.bodyMedium,
                                    )
                                }
                            }
                        }
                    }
                }
            }

            item {
                SegmentedColumn(title = stringResource(R.string.installer_settings_signature_check)) {
                    item {
                        SwitchWidget(
                            icon = AppIcons.InstallRequestUpdateOwnership,
                            title = stringResource(R.string.config_check_app_signature),
                            description = stringResource(R.string.config_check_app_signature_desc),
                            checked = uiState.checkAppSignature,
                            onCheckedChange = {
                                viewModel.dispatch(InstallerSettingsAction.ChangeCheckAppSignature(it))
                            },
                        )
                    }
                    item(animatedVisibility = uiState.checkAppSignature) {
                        SwitchWidget(
                            icon = AppIcons.Info,
                            title = stringResource(R.string.config_check_source_stamp),
                            description = stringResource(R.string.config_check_source_stamp_desc),
                            checked = uiState.checkSourceStamp,
                            onCheckedChange = {
                                viewModel.dispatch(InstallerSettingsAction.ChangeCheckSourceStamp(it))
                            },
                        )
                    }
                    item(animatedVisibility = uiState.checkAppSignature) {
                        SwitchWidget(
                            icon = AppIcons.Info,
                            title = stringResource(R.string.config_show_signature_info_on_match),
                            description = stringResource(R.string.config_show_signature_info_on_match_desc),
                            checked = uiState.showSignatureInfoOnMatch,
                            onCheckedChange = {
                                viewModel.dispatch(InstallerSettingsAction.ChangeShowSignatureInfoOnMatch(it))
                            },
                        )
                    }
                    item(animatedVisibility = uiState.checkAppSignature) {
                        SwitchWidget(
                            icon = AppIcons.InstallAllowSigUnknown,
                            title = stringResource(R.string.config_show_signature_details),
                            description = stringResource(R.string.config_show_signature_details_desc),
                            checked = uiState.showSignatureDetails,
                            onCheckedChange = {
                                viewModel.dispatch(InstallerSettingsAction.ChangeShowSignatureDetails(it))
                            },
                        )
                    }
                }
            }

            item {
                SegmentedColumn(title = stringResource(R.string.installer_settings_xposed_detection)) {
                    item {
                        SwitchWidget(
                            icon = AppIcons.Xposed,
                            title = stringResource(R.string.config_detect_xposed_module),
                            description = stringResource(R.string.config_detect_xposed_module_desc),
                            checked = uiState.detectXposedModule,
                            onCheckedChange = {
                                viewModel.dispatch(InstallerSettingsAction.ChangeDetectXposedModule(it))
                            },
                        )
                    }
                    item(animatedVisibility = uiState.detectXposedModule) {
                        SwitchWidget(
                            icon = AppIcons.LSPosed,
                            title = stringResource(R.string.config_quick_open_lsposed),
                            description = stringResource(R.string.config_quick_open_lsposed_desc),
                            checked = uiState.quickOpenLSPosed,
                            onCheckedChange = {
                                viewModel.dispatch(InstallerSettingsAction.ChangeQuickOpenLSPosed(it))
                            },
                        )
                    }
                }
            }

            if (DeviceConfig.currentManufacturer == Manufacturer.OPPO ||
                DeviceConfig.currentManufacturer == Manufacturer.ONEPLUS
            ) {
                item {
                    SegmentedColumn(title = stringResource(R.string.installer_oppo_related)) {
                        item {
                            SwitchWidget(
                                icon = AppIcons.OEMSpecial,
                                title = stringResource(R.string.installer_show_oem_special),
                                description = stringResource(R.string.installer_show_oem_special_desc),
                                checked = uiState.showOPPOSpecial,
                                onCheckedChange = {
                                    viewModel.dispatch(InstallerSettingsAction.ChangeShowOPPOSpecial(it))
                                },
                            )
                        }
                    }
                }
            }

            item {
                SegmentedColumn(
                    modifier = Modifier.padding(top = 8.dp),
                    title = stringResource(R.string.config_managed_installer_packages_title),
                    contentPadding = PaddingValues(horizontal = 16.dp),
                ) {
                    item {
                        ManagedPackagesWidget(
                            noContentTitle = stringResource(R.string.config_no_preset_install_sources),
                            packages = uiState.managedInstallerPackages,
                            onAddPackage = { viewModel.dispatch(InstallerSettingsAction.AddManagedInstallerPackage(it)) },
                            onRemovePackage = { viewModel.dispatch(InstallerSettingsAction.RemoveManagedInstallerPackage(it)) },
                            onMovePackage = { from, to -> viewModel.dispatch(InstallerSettingsAction.MoveManagedInstallerPackage(from, to)) },
                            onDragStateChange = { isReordering = it },
                        )
                    }
                }
            }

            item {
                SegmentedColumn(
                    title = stringResource(R.string.config_managed_blacklist_by_package_name_title),
                    contentPadding = PaddingValues(horizontal = 16.dp),
                ) {
                    item {
                        ManagedPackagesWidget(
                            noContentTitle = stringResource(R.string.config_no_managed_blacklist),
                            packages = uiState.managedBlacklistPackages,
                            onAddPackage = { viewModel.dispatch(InstallerSettingsAction.AddManagedBlacklistPackage(it)) },
                            onRemovePackage = { viewModel.dispatch(InstallerSettingsAction.RemoveManagedBlacklistPackage(it)) },
                            onMovePackage = { from, to -> viewModel.dispatch(InstallerSettingsAction.MoveManagedBlacklistPackage(from, to)) },
                            onDragStateChange = { isReordering = it },
                        )
                    }
                }
            }

            item {
                SegmentedColumn(
                    title = stringResource(R.string.config_managed_blacklist_by_shared_user_id_title),
                    contentPadding = PaddingValues(horizontal = 16.dp),
                ) {
                    item {
                        ManagedUidsWidget(
                            noContentTitle = stringResource(R.string.config_no_managed_shared_user_id_blacklist),
                            uids = uiState.managedSharedUserIdBlacklist,
                            onAddUid = { viewModel.dispatch(InstallerSettingsAction.AddManagedSharedUserIdBlacklist(it)) },
                            onRemoveUid = { viewModel.dispatch(InstallerSettingsAction.RemoveManagedSharedUserIdBlacklist(it)) },
                            onMoveUid = { from, to -> viewModel.dispatch(InstallerSettingsAction.MoveManagedSharedUserIdBlacklist(from, to)) },
                            onDragStateChange = { isReordering = it },
                        )
                    }
                    item(animatedVisibility = uiState.managedSharedUserIdBlacklist.isNotEmpty()) {
                        ManagedPackagesWidget(
                            noContentTitle = stringResource(R.string.config_no_managed_shared_user_id_exempted_packages),
                            packages = uiState.managedSharedUserIdExemptedPackages,
                            infoText = stringResource(R.string.config_no_managed_shared_user_id_exempted_packages),
                            isInfoVisible = uiState.managedSharedUserIdExemptedPackages.isNotEmpty(),
                            onAddPackage = { viewModel.dispatch(InstallerSettingsAction.AddManagedSharedUserIdExemptedPackages(it)) },
                            onRemovePackage = { viewModel.dispatch(InstallerSettingsAction.RemoveManagedSharedUserIdExemptedPackages(it)) },
                            onMovePackage = { from, to -> viewModel.dispatch(InstallerSettingsAction.MoveManagedSharedUserIdExemptedPackages(from, to)) },
                            onDragStateChange = { isReordering = it },
                        )
                    }
                }
            }
        }
    }
}

private fun sigSchemeChoice(value: Int): Int = when (value) {
    SigSchemes.SIG_SCHEME_V1 -> 0
    SigSchemes.SIG_SCHEME_V2 -> 1
    SigSchemes.SIG_SCHEME_V3 -> 2
    SigSchemes.SIG_SCHEME_V4 -> 3
    SigSchemes.SIG_SCHEME_V1 or SigSchemes.SIG_SCHEME_V2 -> 4
    SigSchemes.SIG_SCHEME_V1 or SigSchemes.SIG_SCHEME_V2 or SigSchemes.SIG_SCHEME_V3 -> 5
    SigSchemes.SIG_SCHEME_V1 or SigSchemes.SIG_SCHEME_V2 or SigSchemes.SIG_SCHEME_V3 or SigSchemes.SIG_SCHEME_V4 -> 6
    else -> 4
}

private fun sigSchemeOptions(): List<Int> = listOf(
    SigSchemes.SIG_SCHEME_V1,
    SigSchemes.SIG_SCHEME_V2,
    SigSchemes.SIG_SCHEME_V3,
    SigSchemes.SIG_SCHEME_V4,
    SigSchemes.SIG_SCHEME_V1 or SigSchemes.SIG_SCHEME_V2,
    SigSchemes.SIG_SCHEME_V1 or SigSchemes.SIG_SCHEME_V2 or SigSchemes.SIG_SCHEME_V3,
    SigSchemes.SIG_SCHEME_V1 or SigSchemes.SIG_SCHEME_V2 or SigSchemes.SIG_SCHEME_V3 or SigSchemes.SIG_SCHEME_V4,
)

private fun sigSchemeLabels(): List<String> = listOf(
    "v1 (JAR)",
    "v2 (APK)",
    "v3 (APK+key rotation)",
    "v4 (ID sig)",
    "v1 + v2 (Recommended)",
    "v1 + v2 + v3",
    "v1 + v2 + v3 + v4",
)

@Composable
private fun DataInstallerBiometricAuthWidget(currentMode: BiometricAuthMode, onModeChange: (BiometricAuthMode) -> Unit) {
    val modes = remember {
        listOf(BiometricAuthMode.Disable, BiometricAuthMode.Enable, BiometricAuthMode.FollowConfig)
    }
    val options = modes.map { mode ->
        when (mode) {
            BiometricAuthMode.Disable -> stringResource(R.string.installer_biometric_auth_mode_disable)
            BiometricAuthMode.Enable -> stringResource(R.string.installer_biometric_auth_mode_enable)
            BiometricAuthMode.FollowConfig -> stringResource(R.string.installer_biometric_auth_mode_follow_config)
        }
    }
    val selectedIndex = modes.indexOf(currentMode).coerceAtLeast(0)
    val dynamicDescription = when (modes[selectedIndex]) {
        BiometricAuthMode.Disable -> stringResource(R.string.installer_biometric_auth_mode_disable_desc)
        BiometricAuthMode.Enable -> stringResource(R.string.installer_biometric_auth_mode_enable_desc)
        BiometricAuthMode.FollowConfig -> stringResource(R.string.installer_biometric_auth_mode_follow_config_desc)
    }
    DropDownMenuWidget(
        icon = AppIcons.BiometricAuth,
        title = stringResource(R.string.installer_settings_require_biometric_auth),
        description = dynamicDescription,
        choice = selectedIndex,
        data = options,
        onChoiceChange = { index ->
            val selectedMode = modes.getOrElse(index) { BiometricAuthMode.FollowConfig }
            if (currentMode != selectedMode) onModeChange(selectedMode)
        },
    )
}

@Composable
private fun ManagedPackagesWidget(
    modifier: Modifier = Modifier,
    noContentTitle: String,
    packages: List<NamedPackage>,
    infoText: String? = null,
    isInfoVisible: Boolean = false,
    infoColor: Color = MaterialTheme.colorScheme.primary,
    onAddPackage: (NamedPackage) -> Unit,
    onRemovePackage: (NamedPackage) -> Unit,
    onMovePackage: (fromIndex: Int, toIndex: Int) -> Unit,
    onDragStateChange: (Boolean) -> Unit,
) {
    var deleteTarget by remember { mutableStateOf<NamedPackage?>(null) }
    var showAddDialog by remember { mutableStateOf(false) }

    DraggableList(
        modifier = modifier,
        items = packages,
        itemKey = { it.packageName },
        itemName = { it.name },
        itemDescription = { it.packageName },
        leadingIcon = AppIcons.Android,
        onMove = onMovePackage,
        onDragStateChange = onDragStateChange,
        noContentTitle = noContentTitle,
        trailingContent = { item ->
            IconButton(onClick = { deleteTarget = item }) {
                Icon(Icons.Default.Delete, null, tint = MaterialTheme.colorScheme.error)
            }
        },
        bottomBarContent = {
            Row(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                AnimatedVisibility(visible = isInfoVisible && !infoText.isNullOrBlank()) {
                    Box(
                        modifier = Modifier.clip(RoundedCornerShape(50)).background(infoColor.copy(alpha = 0.1f)).padding(horizontal = 12.dp, vertical = 6.dp),
                    ) {
                        Text(infoText ?: "", color = infoColor, style = MaterialTheme.typography.labelMedium)
                    }
                }
                Spacer(modifier = Modifier.weight(1f))
                TextButton(onClick = { showAddDialog = true }) {
                    Icon(Icons.Default.Add, null, modifier = Modifier.size(18.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(stringResource(R.string.add))
                }
            }
        },
    )
    if (showAddDialog) {
        AddPackageDialog(onDismiss = { showAddDialog = false }, onConfirm = {
            onAddPackage(it)
            showAddDialog = false
        })
    }
    deleteTarget?.let { item ->
        DeleteNamedPackageConfirmationDialog(item, onDismiss = { deleteTarget = null }, onConfirm = {
            onRemovePackage(item)
            deleteTarget = null
        })
    }
}

@Composable
private fun ManagedUidsWidget(
    modifier: Modifier = Modifier,
    noContentTitle: String,
    uids: List<SharedUid>,
    onAddUid: (SharedUid) -> Unit,
    onRemoveUid: (SharedUid) -> Unit,
    onMoveUid: (fromIndex: Int, toIndex: Int) -> Unit,
    onDragStateChange: (Boolean) -> Unit,
) {
    var deleteTarget by remember { mutableStateOf<SharedUid?>(null) }
    var showAddDialog by remember { mutableStateOf(false) }

    DraggableList(
        modifier = modifier,
        items = uids,
        itemKey = { it.uidValue },
        itemName = { it.uidName },
        itemDescription = { "UID: ${it.uidValue}" },
        leadingIcon = AppIcons.BugReport,
        onMove = onMoveUid,
        onDragStateChange = onDragStateChange,
        noContentTitle = noContentTitle,
        trailingContent = { item ->
            IconButton(onClick = { deleteTarget = item }) {
                Icon(Icons.Default.Delete, null, tint = MaterialTheme.colorScheme.error)
            }
        },
        bottomBarContent = {
            Row(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
                horizontalArrangement = Arrangement.End,
            ) {
                TextButton(onClick = { showAddDialog = true }) {
                    Icon(Icons.Default.Add, null, modifier = Modifier.size(18.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(stringResource(R.string.add))
                }
            }
        },
    )
    if (showAddDialog) {
        AddUidDialog(onDismiss = { showAddDialog = false }, onConfirm = {
            onAddUid(it)
            showAddDialog = false
        })
    }
    deleteTarget?.let { item ->
        DeleteSharedUidConfirmationDialog(item, onDismiss = { deleteTarget = null }, onConfirm = {
            onRemoveUid(item)
            deleteTarget = null
        })
    }
}

@Composable
private fun AddPackageDialog(onDismiss: () -> Unit, onConfirm: (NamedPackage) -> Unit) {
    var name by remember { mutableStateOf("") }
    var packageName by remember { mutableStateOf("") }
    val isConfirmEnabled = name.isNotBlank() && packageName.isNotBlank()
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.config_add_new_package)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(value = name, onValueChange = { name = it }, label = { Text(stringResource(R.string.config_name)) }, singleLine = true)
                OutlinedTextField(value = packageName, onValueChange = { packageName = it }, label = { Text(stringResource(R.string.config_package_name)) }, singleLine = true)
            }
        },
        confirmButton = {
            TextButton(onClick = { onConfirm(NamedPackage(name, packageName)) }, enabled = isConfirmEnabled) {
                Text(stringResource(R.string.confirm))
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) } },
    )
}

@Composable
private fun AddUidDialog(onDismiss: () -> Unit, onConfirm: (SharedUid) -> Unit) {
    var uidName by remember { mutableStateOf("") }
    var uidValueString by remember { mutableStateOf("") }
    val isConfirmEnabled = uidName.isNotBlank() && uidValueString.toIntOrNull() != null
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.config_add_new_shared_uid)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(value = uidName, onValueChange = { uidName = it }, label = { Text(stringResource(R.string.config_shared_uid_name)) }, singleLine = true)
                OutlinedTextField(
                    value = uidValueString,
                    onValueChange = { uidValueString = it },
                    label = { Text(stringResource(R.string.config_shared_uid_value)) },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                )
            }
        },
        confirmButton = {
            TextButton(onClick = { onConfirm(SharedUid(uidName, uidValueString.toInt())) }, enabled = isConfirmEnabled) {
                Text(stringResource(R.string.confirm))
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) } },
    )
}

@Composable
private fun DeleteNamedPackageConfirmationDialog(item: NamedPackage, onDismiss: () -> Unit, onConfirm: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.config_confirm_deletion)) },
        text = { Text(stringResource(R.string.config_confirm_deletion_desc, item.name)) },
        confirmButton = { TextButton(onClick = onConfirm) { Text(stringResource(R.string.delete), color = MaterialTheme.colorScheme.error) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) } },
    )
}

@Composable
private fun DeleteSharedUidConfirmationDialog(item: SharedUid, onDismiss: () -> Unit, onConfirm: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.config_confirm_deletion)) },
        text = { Text(stringResource(R.string.config_confirm_deletion_desc, item.uidName)) },
        confirmButton = { TextButton(onClick = onConfirm) { Text(stringResource(R.string.delete), color = MaterialTheme.colorScheme.error) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) } },
    )
}
