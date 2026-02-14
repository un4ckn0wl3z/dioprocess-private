//! UEFI Bootkit management tab
//!
//! Provides controls for managing the DioProcess UEFI bootkit:
//! - DSE (Driver Signature Enforcement) bypass toggle
//! - PatchGuard/KPP bypass toggle
//! - EFI driver install/remove to ESP
//! - System firmware info display

use dioxus::prelude::*;
use uefi_manager::{
    clear_debug_log, is_efi_installed, is_secure_boot_enabled, is_test_signing_enabled,
    is_uefi_system, read_debug_log, read_uefi_config, write_uefi_config, UefiConfig,
};

/// System firmware information
#[derive(Clone, Debug, Default)]
struct SystemFirmwareInfo {
    is_uefi: bool,
    secure_boot: bool,
    test_signing: bool,
}

/// UEFI Bootkit management tab component
#[component]
pub fn UefiTab() -> Element {
    let mut uefi_config = use_signal(|| UefiConfig::default());
    let mut efi_installed = use_signal(|| false);
    let mut firmware_info = use_signal(|| SystemFirmwareInfo::default());
    let mut status_message = use_signal(String::new);
    let mut is_error = use_signal(|| false);
    let mut efi_binary_path = use_signal(String::new);
    let mut installing = use_signal(|| false);
    let mut saving = use_signal(|| false);
    let mut debug_log = use_signal(|| Option::<String>::None);
    let mut reading_log = use_signal(|| false);

    // Refresh all state
    let mut refresh = move || {
        // Read system firmware info
        let info = SystemFirmwareInfo {
            is_uefi: is_uefi_system(),
            secure_boot: is_secure_boot_enabled(),
            test_signing: is_test_signing_enabled(),
        };
        firmware_info.set(info.clone());

        if !info.is_uefi {
            return;
        }

        // Read NVRAM config
        match read_uefi_config() {
            Ok(config) => uefi_config.set(config),
            Err(e) => {
                status_message.set(format!("Failed to read NVRAM: {}", e));
                is_error.set(true);
            }
        }

        // Check ESP installation
        match is_efi_installed() {
            Ok(installed) => efi_installed.set(installed),
            Err(_) => efi_installed.set(false),
        }
    };

    // Auto-refresh on mount
    use_effect(move || {
        refresh();
    });

    // Keyboard handler
    let handle_keydown = move |e: KeyboardEvent| {
        if e.key() == Key::Escape {
            status_message.set(String::new());
        } else if e.key() == Key::F5 {
            refresh();
        }
    };

    let fw = firmware_info.read().clone();
    let config = uefi_config.read().clone();
    let installed = *efi_installed.read();
    let is_uefi = fw.is_uefi;

    rsx! {
        div {
            class: "service-tab",
            tabindex: "0",
            onkeydown: handle_keydown,

            // Header
            div { class: "header-box",
                h1 { class: "header-title", "UEFI Bootkit Configuration" }
                div { class: "header-stats",
                    span {
                        class: if is_uefi { "driver-status driver-status-loaded" } else { "driver-status driver-status-not-loaded" },
                        if is_uefi { "Firmware: UEFI" } else { "Firmware: Legacy BIOS" }
                    }
                    if is_uefi {
                        span {
                            class: if !fw.secure_boot { "driver-status driver-status-loaded" } else { "driver-status driver-status-not-loaded" },
                            if fw.secure_boot { "Secure Boot: ON" } else { "Secure Boot: OFF" }
                        }
                        span {
                            class: if installed { "driver-status driver-status-loaded" } else { "driver-status driver-status-not-loaded" },
                            if installed { "EFI: Installed" } else { "EFI: Not Installed" }
                        }
                    }
                    span { class: "header-shortcuts", "F5: Refresh | Esc: Clear" }
                }
                if !status_message.read().is_empty() {
                    div {
                        class: if *is_error.read() { "status-message status-error" } else { "status-message" },
                        "{status_message}"
                    }
                }
            }

            if !is_uefi {
                // Legacy BIOS — show warning
                div { class: "table-container",
                    div { class: "no-results",
                        "This system uses Legacy BIOS firmware. UEFI bootkit features require UEFI firmware."
                    }
                }
            } else {
                // Boot Patches Section
                div {
                    class: "controls",
                    style: "flex-direction: column; align-items: stretch; gap: 16px;",

                    // Section header
                    div {
                        style: "display: flex; align-items: center; gap: 10px; border-bottom: 1px solid var(--border-secondary); padding-bottom: 8px;",
                        span { class: "control-label", style: "font-size: 14px; font-weight: bold;", "Boot Patches (next reboot)" }
                    }

                    // DSE toggle
                    div {
                        style: "display: flex; align-items: center; gap: 15px;",
                        span { style: "color: var(--text-secondary); min-width: 280px;", "DSE (Driver Signature Enforcement)" }
                        button {
                            class: if config.dse_bypass { "btn btn-danger btn-small" } else { "btn btn-secondary btn-small" },
                            disabled: *saving.read(),
                            onclick: move |_| {
                                let mut c = uefi_config.read().clone();
                                c.dse_bypass = !c.dse_bypass;
                                uefi_config.set(c);
                            },
                            if config.dse_bypass { "BYPASS: ON" } else { "BYPASS: OFF" }
                        }
                        span {
                            style: if config.dse_bypass { "color: #ef4444; font-size: 12px;" } else { "color: #22c55e; font-size: 12px;" },
                            if config.dse_bypass { "Unsigned drivers will load" } else { "Normal enforcement active" }
                        }
                    }

                    // KPP toggle
                    div {
                        style: "display: flex; align-items: center; gap: 15px;",
                        span { style: "color: var(--text-secondary); min-width: 280px;", "PatchGuard / KPP (Kernel Patch Protection)" }
                        button {
                            class: if config.kpp_bypass { "btn btn-danger btn-small" } else { "btn btn-secondary btn-small" },
                            disabled: *saving.read(),
                            onclick: move |_| {
                                let mut c = uefi_config.read().clone();
                                c.kpp_bypass = !c.kpp_bypass;
                                uefi_config.set(c);
                            },
                            if config.kpp_bypass { "BYPASS: ON" } else { "BYPASS: OFF" }
                        }
                        span {
                            style: if config.kpp_bypass { "color: #ef4444; font-size: 12px;" } else { "color: #22c55e; font-size: 12px;" },
                            if config.kpp_bypass { "Kernel patching unrestricted" } else { "Normal protection active" }
                        }
                    }

                    // Warning + Save button
                    div {
                        style: "display: flex; align-items: center; gap: 15px; margin-top: 8px;",

                        span {
                            style: "color: #fbbf24; font-size: 12px;",
                            "Changes take effect on next reboot"
                        }

                        button {
                            class: "btn btn-primary",
                            disabled: *saving.read(),
                            onclick: move |_| {
                                let cfg = uefi_config.read().clone();
                                saving.set(true);
                                spawn(async move {
                                    let result = tokio::task::spawn_blocking(move || {
                                        write_uefi_config(&cfg)
                                    }).await;

                                    match result {
                                        Ok(Ok(())) => {
                                            status_message.set("NVRAM config saved successfully".to_string());
                                            is_error.set(false);
                                        }
                                        Ok(Err(e)) => {
                                            status_message.set(format!("Failed to save: {}", e));
                                            is_error.set(true);
                                        }
                                        Err(e) => {
                                            status_message.set(format!("Task error: {}", e));
                                            is_error.set(true);
                                        }
                                    }
                                    saving.set(false);

                                    spawn(async move {
                                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                                        status_message.set(String::new());
                                    });
                                });
                            },
                            if *saving.read() { "Saving..." } else { "Apply & Save to NVRAM" }
                        }
                    }
                }

                // EFI Driver Installation Section
                div {
                    class: "controls",
                    style: "flex-direction: column; align-items: stretch; gap: 16px;",

                    // Section header
                    div {
                        style: "display: flex; align-items: center; gap: 10px; border-bottom: 1px solid var(--border-secondary); padding-bottom: 8px;",
                        span { class: "control-label", style: "font-size: 14px; font-weight: bold;", "EFI Driver Installation" }
                        span {
                            class: if installed { "driver-status driver-status-loaded" } else { "driver-status driver-status-not-loaded" },
                            if installed { "Installed" } else { "Not Installed" }
                        }
                    }

                    // EFI binary path selector
                    div {
                        style: "display: flex; align-items: center; gap: 10px;",
                        span { style: "color: var(--text-secondary); min-width: 100px;", "EFI Binary:" }

                        input {
                            class: "search-input",
                            r#type: "text",
                            placeholder: "Path to DioProcessEfi.efi...",
                            value: "{efi_binary_path}",
                            readonly: true,
                            style: "flex: 1; font-size: 11px;",
                        }

                        button {
                            class: "btn btn-secondary",
                            disabled: *installing.read(),
                            onclick: move |_| {
                                spawn(async move {
                                    let file = rfd::AsyncFileDialog::new()
                                        .add_filter("EFI Binary", &["efi"])
                                        .add_filter("All files", &["*"])
                                        .set_title("Select DioProcessEfi.efi")
                                        .pick_file()
                                        .await;

                                    if let Some(f) = file {
                                        efi_binary_path.set(f.path().to_string_lossy().to_string());
                                    }
                                });
                            },
                            "Browse"
                        }
                    }

                    // Install / Remove buttons
                    div {
                        style: "display: flex; align-items: center; gap: 10px;",

                        button {
                            class: "btn btn-primary",
                            disabled: *installing.read() || efi_binary_path.read().is_empty() || installed,
                            onclick: move |_| {
                                let path = efi_binary_path.read().clone();
                                installing.set(true);
                                spawn(async move {
                                    let result = tokio::task::spawn_blocking(move || {
                                        uefi_manager::install_efi_driver(std::path::Path::new(&path))
                                    }).await;

                                    match result {
                                        Ok(Ok(())) => {
                                            status_message.set("EFI driver installed to ESP successfully".to_string());
                                            is_error.set(false);
                                            efi_installed.set(true);
                                        }
                                        Ok(Err(e)) => {
                                            status_message.set(format!("Install failed: {}", e));
                                            is_error.set(true);
                                        }
                                        Err(e) => {
                                            status_message.set(format!("Task error: {}", e));
                                            is_error.set(true);
                                        }
                                    }
                                    installing.set(false);

                                    spawn(async move {
                                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                                        status_message.set(String::new());
                                    });
                                });
                            },
                            if *installing.read() { "Installing..." } else { "Install to ESP" }
                        }

                        button {
                            class: "btn btn-danger",
                            disabled: *installing.read() || !installed,
                            onclick: move |_| {
                                installing.set(true);
                                spawn(async move {
                                    let result = tokio::task::spawn_blocking(|| {
                                        uefi_manager::remove_efi_driver()
                                    }).await;

                                    match result {
                                        Ok(Ok(())) => {
                                            status_message.set("EFI driver removed from ESP".to_string());
                                            is_error.set(false);
                                            efi_installed.set(false);
                                        }
                                        Ok(Err(e)) => {
                                            status_message.set(format!("Remove failed: {}", e));
                                            is_error.set(true);
                                        }
                                        Err(e) => {
                                            status_message.set(format!("Task error: {}", e));
                                            is_error.set(true);
                                        }
                                    }
                                    installing.set(false);

                                    spawn(async move {
                                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                                        status_message.set(String::new());
                                    });
                                });
                            },
                            if *installing.read() { "Removing..." } else { "Remove from ESP" }
                        }

                        button {
                            class: "btn btn-secondary",
                            onclick: move |_| refresh(),
                            "Refresh"
                        }
                    }

                    // Secure Boot warning
                    if fw.secure_boot {
                        div {
                            style: "background: rgba(239, 68, 68, 0.2); border: 1px solid #ef4444; border-radius: 5px; padding: 12px;",
                            span {
                                style: "color: #fbbf24; font-size: 13px;",
                                "Secure Boot is ON. The EFI driver will not load unless Secure Boot is disabled in BIOS/UEFI settings."
                            }
                        }
                    }
                }

                // Boot Debug Log Section
                div {
                    class: "controls",
                    style: "flex-direction: column; align-items: stretch; gap: 12px;",

                    div {
                        style: "display: flex; align-items: center; gap: 10px; border-bottom: 1px solid var(--border-secondary); padding-bottom: 8px;",
                        span { class: "control-label", style: "font-size: 14px; font-weight: bold;", "Boot Debug Log" }

                        button {
                            class: "btn btn-secondary btn-small",
                            disabled: *reading_log.read(),
                            onclick: move |_| {
                                reading_log.set(true);
                                spawn(async move {
                                    let result = tokio::task::spawn_blocking(read_debug_log).await;
                                    match result {
                                        Ok(log) => debug_log.set(log),
                                        Err(_) => debug_log.set(None),
                                    }
                                    reading_log.set(false);
                                });
                            },
                            if *reading_log.read() { "Reading..." } else { "Read Log" }
                        }

                        button {
                            class: "btn btn-secondary btn-small",
                            disabled: *reading_log.read() || debug_log.read().is_none(),
                            onclick: move |_| {
                                spawn(async move {
                                    let result = tokio::task::spawn_blocking(clear_debug_log).await;
                                    match result {
                                        Ok(Ok(())) => {
                                            debug_log.set(None);
                                            status_message.set("Debug log cleared".to_string());
                                            is_error.set(false);
                                        }
                                        Ok(Err(e)) => {
                                            status_message.set(format!("Clear failed: {}", e));
                                            is_error.set(true);
                                        }
                                        Err(e) => {
                                            status_message.set(format!("Task error: {}", e));
                                            is_error.set(true);
                                        }
                                    }

                                    spawn(async move {
                                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                                        status_message.set(String::new());
                                    });
                                });
                            },
                            "Clear Log"
                        }
                    }

                    div {
                        style: "background: var(--bg-primary); border: 1px solid var(--border-secondary); border-radius: 5px; padding: 12px; min-height: 60px; max-height: 200px; overflow-y: auto; font-family: monospace; font-size: 12px; white-space: pre-wrap; color: var(--text-secondary);",
                        match debug_log.read().as_ref() {
                            Some(log) => rsx! { "{log}" },
                            None => rsx! { span { style: "color: var(--text-muted); font-style: italic;", "No debug log available. Click 'Read Log' after booting with DioProcess UEFI." } },
                        }
                    }
                }

                // System Info Section
                div {
                    class: "controls",
                    style: "flex-direction: column; align-items: stretch; gap: 12px;",

                    div {
                        style: "border-bottom: 1px solid var(--border-secondary); padding-bottom: 8px;",
                        span { class: "control-label", style: "font-size: 14px; font-weight: bold;", "System Information" }
                    }

                    div { class: "table-container", style: "overflow: visible;",
                        table { class: "process-table",
                            tbody {
                                tr { class: "process-row",
                                    td { class: "cell", style: "width: 200px; color: var(--text-secondary);", "Firmware Type" }
                                    td { class: "cell",
                                        span {
                                            class: "status-badge status-running",
                                            "UEFI"
                                        }
                                    }
                                }
                                tr { class: "process-row",
                                    td { class: "cell", style: "width: 200px; color: var(--text-secondary);", "Secure Boot" }
                                    td { class: "cell",
                                        span {
                                            class: if fw.secure_boot { "status-badge status-stopped" } else { "status-badge status-running" },
                                            if fw.secure_boot { "ON (must disable)" } else { "OFF (ready)" }
                                        }
                                    }
                                }
                                tr { class: "process-row",
                                    td { class: "cell", style: "width: 200px; color: var(--text-secondary);", "Test Signing Mode" }
                                    td { class: "cell",
                                        span {
                                            class: if fw.test_signing { "status-badge status-running" } else { "status-badge status-stopped" },
                                            if fw.test_signing { "Enabled" } else { "Disabled" }
                                        }
                                    }
                                }
                                tr { class: "process-row",
                                    td { class: "cell", style: "width: 200px; color: var(--text-secondary);", "EFI Driver" }
                                    td { class: "cell",
                                        span {
                                            class: if installed { "status-badge status-running" } else { "status-badge status-stopped" },
                                            if installed { "Installed on ESP" } else { "Not Installed" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
