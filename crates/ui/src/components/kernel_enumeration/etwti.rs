//! ETWTI (ETW Threat Intelligence) sub-tab for kernel enumeration
//!
//! Provides system-wide ETW Threat Intelligence provider status and control.

use callback::{disable_etwti, enable_etwti, get_etwti_status, EtwtiStatus};
use dioxus::prelude::*;

/// ETWTI sub-tab component
#[component]
pub fn EtwtiTab(driver_loaded: bool) -> Element {
    let mut status = use_signal(|| None::<Result<EtwtiStatus, String>>);
    let mut is_loading = use_signal(|| false);
    let mut status_message = use_signal(|| String::new());

    // Auto-refresh status on mount
    use_future(move || async move {
        if driver_loaded {
            is_loading.set(true);
            let result = get_etwti_status()
                .map_err(|e| e.to_string());
            status.set(Some(result));
            is_loading.set(false);
        }
    });

    let refresh_status = move |_| {
        if driver_loaded {
            is_loading.set(true);
            let result = get_etwti_status()
                .map_err(|e| e.to_string());
            status.set(Some(result));
            is_loading.set(false);
        }
    };

    let handle_disable = move |_| {
        if !driver_loaded {
            return;
        }
        is_loading.set(true);
        match disable_etwti() {
            Ok(new_status) => {
                if !new_status.enabled {
                    status_message.set("✓ ETWTI disabled system-wide".to_string());
                } else {
                    status_message.set("✗ ETWTI disable failed - still enabled".to_string());
                }
                status.set(Some(Ok(new_status)));
            }
            Err(e) => {
                status_message.set(format!("✗ Failed to disable ETWTI: {}", e));
            }
        }
        is_loading.set(false);
        spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            status_message.set(String::new());
        });
    };

    let handle_enable = move |_| {
        if !driver_loaded {
            return;
        }
        is_loading.set(true);
        match enable_etwti() {
            Ok(new_status) => {
                if new_status.enabled {
                    status_message.set("✓ ETWTI enabled system-wide".to_string());
                } else {
                    status_message.set("✗ ETWTI enable failed - still disabled".to_string());
                }
                status.set(Some(Ok(new_status)));
            }
            Err(e) => {
                status_message.set(format!("✗ Failed to enable ETWTI: {}", e));
            }
        }
        is_loading.set(false);
        spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            status_message.set(String::new());
        });
    };

    rsx! {
        div {
            class: "etwti-tab",
            style: "padding: 16px;",

            // Description
            div {
                style: "margin-bottom: 16px; padding: 12px; background: var(--bg-tertiary); border-radius: 8px; border-left: 4px solid var(--accent-color);",
                h3 {
                    style: "margin: 0 0 8px 0; color: var(--text-primary);",
                    "ETW Threat Intelligence (ETWTI)"
                }
                p {
                    style: "margin: 0; color: var(--text-secondary); font-size: 13px; line-height: 1.5;",
                    "ETWTI is a kernel-level ETW provider that feeds telemetry to security products (EDR/AV). "
                    "Disabling it prevents security software from receiving kernel-level threat intelligence events. "
                }
                p {
                    style: "margin: 8px 0 0 0; color: var(--warning-color); font-size: 12px;",
                    "⚠️ This is a system-wide setting that affects all processes and security monitoring."
                }
            }

            // Status message
            if !status_message.read().is_empty() {
                div {
                    class: "status-message",
                    style: "margin-bottom: 12px; padding: 8px 12px; background: var(--bg-secondary); border-radius: 6px;",
                    "{status_message}"
                }
            }

            // Controls
            div {
                class: "controls",
                style: "margin-bottom: 16px;",

                button {
                    class: "btn btn-primary",
                    disabled: !driver_loaded || *is_loading.read(),
                    onclick: refresh_status,
                    if *is_loading.read() { "Loading..." } else { "🔄 Refresh Status" }
                }

                button {
                    class: "btn btn-danger",
                    disabled: !driver_loaded || *is_loading.read(),
                    onclick: handle_disable,
                    "🔇 Disable ETWTI"
                }

                button {
                    class: "btn btn-success",
                    disabled: !driver_loaded || *is_loading.read(),
                    onclick: handle_enable,
                    "🔊 Enable ETWTI"
                }
            }

            // Status display
            if !driver_loaded {
                div {
                    class: "warning-box",
                    style: "padding: 16px; background: var(--bg-tertiary); border-radius: 8px; text-align: center; color: var(--text-secondary);",
                    "⚠️ DioProcess kernel driver is not loaded. ETWTI operations require the driver."
                }
            } else {
                match status.read().as_ref() {
                    None => rsx! {
                        div {
                            style: "padding: 16px; text-align: center; color: var(--text-secondary);",
                            "Loading ETWTI status..."
                        }
                    },
                    Some(Err(e)) => rsx! {
                        div {
                            class: "error-box",
                            style: "padding: 16px; background: rgba(239, 68, 68, 0.1); border: 1px solid var(--danger-color); border-radius: 8px;",
                            h4 {
                                style: "margin: 0 0 8px 0; color: var(--danger-color);",
                                "❌ Failed to get ETWTI status"
                            }
                            p {
                                style: "margin: 0; color: var(--text-secondary); font-size: 13px;",
                                "{e}"
                            }
                            p {
                                style: "margin: 8px 0 0 0; color: var(--text-tertiary); font-size: 12px;",
                                "This may indicate an unsupported Windows build. Check if your Windows version is in the supported offsets table."
                            }
                        }
                    },
                    Some(Ok(etwti_status)) => rsx! {
                        div {
                            class: "status-card",
                            style: "background: var(--bg-tertiary); border-radius: 8px; overflow: hidden;",

                            // Status header
                            div {
                                style: if etwti_status.enabled {
                                    "padding: 16px; background: rgba(34, 197, 94, 0.15); border-bottom: 1px solid var(--border-secondary);"
                                } else {
                                    "padding: 16px; background: rgba(239, 68, 68, 0.15); border-bottom: 1px solid var(--border-secondary);"
                                },
                                div {
                                    style: "display: flex; align-items: center; gap: 12px;",
                                    span {
                                        style: "font-size: 32px;",
                                        if etwti_status.enabled { "🟢" } else { "🔴" }
                                    }
                                    div {
                                        h2 {
                                            style: "margin: 0; color: var(--text-primary);",
                                            if etwti_status.enabled { "ETWTI is ENABLED" } else { "ETWTI is DISABLED" }
                                        }
                                        p {
                                            style: "margin: 4px 0 0 0; color: var(--text-secondary); font-size: 13px;",
                                            if etwti_status.enabled {
                                                "Security products are receiving kernel threat intelligence events."
                                            } else {
                                                "Security products are NOT receiving kernel threat intelligence events."
                                            }
                                        }
                                    }
                                }
                            }

                            // Details
                            div {
                                style: "padding: 16px;",
                                table {
                                    style: "width: 100%; border-collapse: collapse;",
                                    tbody {
                                        tr {
                                            td {
                                                style: "padding: 8px 12px; color: var(--text-secondary); width: 200px;",
                                                "Windows Build"
                                            }
                                            td {
                                                style: "padding: 8px 12px; color: var(--text-primary); font-family: monospace;",
                                                "{etwti_status.build_number}"
                                            }
                                        }
                                        tr {
                                            td {
                                                style: "padding: 8px 12px; color: var(--text-secondary);",
                                                "ntoskrnl.exe Base"
                                            }
                                            td {
                                                style: "padding: 8px 12px; color: var(--text-primary); font-family: monospace;",
                                                "0x{etwti_status.ntoskrnl_base:X}"
                                            }
                                        }
                                        tr {
                                            td {
                                                style: "padding: 8px 12px; color: var(--text-secondary);",
                                                "ProviderEnableInfo"
                                            }
                                            td {
                                                style: "padding: 8px 12px; color: var(--text-primary); font-family: monospace;",
                                                "0x{etwti_status.provider_enable_info:02X}"
                                            }
                                        }
                                        tr {
                                            td {
                                                style: "padding: 8px 12px; color: var(--text-secondary);",
                                                "Offset Source"
                                            }
                                            td {
                                                style: "padding: 8px 12px; color: var(--text-primary); font-family: monospace;",
                                                if etwti_status.offsets_from_pdb {
                                                    "🟢 Dynamic PDB"
                                                } else {
                                                    "🟡 Hardcoded Fallback"
                                                }
                                            }
                                        }
                                        if etwti_status.offsets_from_pdb && !etwti_status.pdb_signature.is_empty() {
                                            tr {
                                                td {
                                                    style: "padding: 8px 12px; color: var(--text-secondary);",
                                                    "PDB Signature"
                                                }
                                                td {
                                                    style: "padding: 8px 12px; color: var(--text-primary); font-family: monospace; font-size: 11px;",
                                                    "{etwti_status.pdb_signature}"
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

            // Supported builds info
            div {
                style: "margin-top: 16px; padding: 12px; background: var(--bg-secondary); border-radius: 8px;",
                h4 {
                    style: "margin: 0 0 8px 0; color: var(--text-secondary); font-size: 12px; text-transform: uppercase;",
                    "Offset Resolution"
                }
                p {
                    style: "margin: 0; color: var(--text-tertiary); font-size: 12px; line-height: 1.6;",
                    "Offsets are resolved dynamically from ntoskrnl.pdb via Microsoft Symbol Server. "
                    "This ensures compatibility across all Windows builds and cumulative updates."
                }
                p {
                    style: "margin: 8px 0 0 0; color: var(--text-tertiary); font-size: 11px;",
                    "Fallback builds: Windows 10 22H2 (19045), Windows 11 22H2/23H2 (22621/22631), Windows 11 24H2 (26100), Windows Server 2022 (20348)"
                }
            }
        }
    }
}
