//! Scripts tab — DPH and DPR script management (shared between Memory Scanner and HV Scanner)

use callback::{hv_is_running, is_driver_loaded, list_ept_hooks, remove_ept_hook};
use dioxus::prelude::*;
use misc::free_remote_memory;

use crate::state::{
    DPH_SCRIPTS, DPR_SCRIPTS, EPT_HOOKS_LIST, EPT_HOOK_DETOUR_ALLOCS,
};

#[component]
pub fn ScriptsTab() -> Element {
    let mut dph_scripts = DPH_SCRIPTS.signal();
    let mut dpr_scripts = DPR_SCRIPTS.signal();
    let mut ept_hooks_list = EPT_HOOKS_LIST.signal();
    let detour_allocs = EPT_HOOK_DETOUR_ALLOCS.signal();

    let mut status_message = use_signal(|| String::new());
    let mut is_error = use_signal(|| false);
    let mut active_sub_tab = use_signal(|| 0usize); // 0 = DPH, 1 = DPR, 2 = Active Hooks

    let _driver_loaded = is_driver_loaded();
    let hv_running = hv_is_running();

    // Refresh hooks list
    let mut refresh_hooks = move || {
        if let Ok(hooks) = list_ept_hooks() {
            ept_hooks_list.set(hooks);
        }
    };

    rsx! {
        div {
            class: "tab-content",
            onclick: move |_| {},

            // Header
            div {
                class: "section-header",
                style: "display: flex; align-items: center; gap: 12px; margin-bottom: 16px;",
                h2 { class: "section-title", "Scripts" }
                span {
                    class: "experimental-badge",
                    style: if hv_running { "background: #22c55e;" } else { "background: #6b7280;" },
                    if hv_running { "HV Active" } else { "HV Off" }
                }
            }

            // Description
            div {
                style: "color: var(--text-secondary); font-size: 13px; margin-bottom: 16px;",
                "Manage DPH (Detour Patch Hook) and DPR (Detour Patch Replace) scripts. Scripts are shared between Memory Scanner and HV Scanner."
            }

            // Sub-tabs
            div {
                style: "display: flex; gap: 4px; margin-bottom: 16px;",
                button {
                    class: if *active_sub_tab.read() == 0 { "btn btn-primary" } else { "btn" },
                    onclick: move |_| active_sub_tab.set(0),
                    "DPH Scripts ({dph_scripts.read().len()})"
                }
                button {
                    class: if *active_sub_tab.read() == 1 { "btn btn-primary" } else { "btn" },
                    onclick: move |_| active_sub_tab.set(1),
                    "DPR Scripts ({dpr_scripts.read().len()})"
                }
                button {
                    class: if *active_sub_tab.read() == 2 { "btn btn-primary" } else { "btn" },
                    onclick: move |_| {
                        active_sub_tab.set(2);
                        refresh_hooks();
                    },
                    "Active Hooks ({ept_hooks_list.read().len()})"
                }
            }

            // Status message
            if !status_message.read().is_empty() {
                div {
                    class: if *is_error.read() { "status-bar status-error" } else { "status-bar status-success" },
                    "{status_message}"
                }
            }

            // DPH Scripts tab
            if *active_sub_tab.read() == 0 {
                div {
                    class: "process-table-container",
                    style: "max-height: calc(100vh - 300px);",

                    if dph_scripts.read().is_empty() {
                        div {
                            style: "color: var(--text-secondary); text-align: center; padding: 40px;",
                            "No DPH scripts. Load .dph files from Memory Scanner or HV Scanner."
                        }
                    } else {
                        table { class: "process-table",
                            thead {
                                tr {
                                    th { style: "width: 120px;", "Name" }
                                    th { style: "width: 140px;", "Target" }
                                    th { style: "width: 80px;", "Stolen" }
                                    th { "Code" }
                                    th { style: "width: 100px;", "Status" }
                                    th { style: "width: 120px;", "Actions" }
                                }
                            }
                            tbody {
                                for (idx, script) in dph_scripts.read().iter().enumerate() {
                                    {
                                        let status_class = if script.status.starts_with("Error") {
                                            "color: #ef4444;"
                                        } else if script.status.starts_with("Applied") || script.status.starts_with("Active") {
                                            "color: #22c55e;"
                                        } else {
                                            "color: var(--text-secondary);"
                                        };
                                        let addr_display = if let Some(addr) = script.resolved_addr {
                                            format!("0x{:X}", addr)
                                        } else {
                                            script.target_expr.clone()
                                        };
                                        rsx! {
                                            tr {
                                                td { "{script.name}" }
                                                td { style: "font-family: 'Consolas', monospace; color: var(--accent-primary);",
                                                    "{addr_display}"
                                                }
                                                td { "{script.stolen_bytes}" }
                                                td {
                                                    style: "font-family: 'Consolas', monospace; font-size: 11px; max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;",
                                                    title: "{script.code}",
                                                    "{script.code}"
                                                }
                                                td { style: "{status_class} font-size: 11px;", "{script.status}" }
                                                td {
                                                    div { style: "display: flex; gap: 4px;",
                                                        button {
                                                            class: "btn btn-small btn-danger",
                                                            onclick: move |_| {
                                                                dph_scripts.write().remove(idx);
                                                            },
                                                            "X"
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
            }

            // DPR Scripts tab
            if *active_sub_tab.read() == 1 {
                div {
                    class: "process-table-container",
                    style: "max-height: calc(100vh - 300px);",

                    if dpr_scripts.read().is_empty() {
                        div {
                            style: "color: var(--text-secondary); text-align: center; padding: 40px;",
                            "No DPR scripts. Load .dpr files from Memory Scanner or HV Scanner."
                        }
                    } else {
                        table { class: "process-table",
                            thead {
                                tr {
                                    th { style: "width: 120px;", "Name" }
                                    th { style: "width: 140px;", "Target" }
                                    th { style: "width: 80px;", "Register" }
                                    th { "Value" }
                                    th { style: "width: 100px;", "Status" }
                                    th { style: "width: 120px;", "Actions" }
                                }
                            }
                            tbody {
                                for (idx, script) in dpr_scripts.read().iter().enumerate() {
                                    {
                                        let status_class = if script.status.starts_with("Error") {
                                            "color: #ef4444;"
                                        } else if script.status.starts_with("Applied") || script.status.starts_with("Active") {
                                            "color: #22c55e;"
                                        } else {
                                            "color: var(--text-secondary);"
                                        };
                                        let addr_display = if let Some(addr) = script.resolved_addr {
                                            format!("0x{:X}", addr)
                                        } else {
                                            script.target_expr.clone()
                                        };
                                        rsx! {
                                            tr {
                                                td { "{script.name}" }
                                                td { style: "font-family: 'Consolas', monospace; color: var(--accent-primary);",
                                                    "{addr_display}"
                                                }
                                                td { "{script.register}" }
                                                td {
                                                    style: "font-family: 'Consolas', monospace; font-size: 11px;",
                                                    "{script.value_expr}"
                                                }
                                                td { style: "{status_class} font-size: 11px;", "{script.status}" }
                                                td {
                                                    div { style: "display: flex; gap: 4px;",
                                                        button {
                                                            class: "btn btn-small btn-danger",
                                                            onclick: move |_| {
                                                                dpr_scripts.write().remove(idx);
                                                            },
                                                            "X"
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
            }

            // Active Hooks tab
            if *active_sub_tab.read() == 2 {
                div {
                    class: "process-table-container",
                    style: "max-height: calc(100vh - 300px);",

                    div { style: "display: flex; gap: 8px; margin-bottom: 12px;",
                        button {
                            class: "btn",
                            onclick: move |_| refresh_hooks(),
                            "Refresh"
                        }
                    }

                    if ept_hooks_list.read().is_empty() {
                        div {
                            style: "color: var(--text-secondary); text-align: center; padding: 40px;",
                            "No active EPT hooks."
                        }
                    } else {
                        table { class: "process-table",
                            thead {
                                tr {
                                    th { style: "width: 60px;", "Index" }
                                    th { style: "width: 80px;", "PID" }
                                    th { style: "width: 160px;", "Address" }
                                    th { style: "width: 80px;", "Size" }
                                    th { style: "width: 80px;", "Active" }
                                    th { style: "width: 100px;", "Actions" }
                                }
                            }
                            tbody {
                                for hook in ept_hooks_list.read().iter() {
                                    {
                                        let hook_idx = hook.hook_index;
                                        let hook_pid = hook.process_id;
                                        let hook_addr = hook.target_address;
                                        let patch_size = hook.patch_size;
                                        let active = hook.active;
                                        rsx! {
                                            tr {
                                                td { "#{hook_idx}" }
                                                td { "{hook_pid}" }
                                                td { style: "font-family: 'Consolas', monospace; color: var(--accent-primary);",
                                                    "0x{hook_addr:X}"
                                                }
                                                td { "{patch_size}" }
                                                td { style: if active { "color: #22c55e;" } else { "color: #ef4444;" },
                                                    if active { "Yes" } else { "No" }
                                                }
                                                td {
                                                    button {
                                                        class: "btn btn-small btn-danger",
                                                        onclick: move |_| {
                                                            // Free detour allocation if exists
                                                            if let Some((pid, alloc_addr)) = detour_allocs.read().get(&hook_idx) {
                                                                let _ = free_remote_memory(*pid, *alloc_addr);
                                                            }
                                                            EPT_HOOK_DETOUR_ALLOCS.write().remove(&hook_idx);
                                                            
                                                            match remove_ept_hook(hook_idx) {
                                                                Ok(_) => {
                                                                    status_message.set(format!("Removed hook #{}", hook_idx));
                                                                    is_error.set(false);
                                                                }
                                                                Err(e) => {
                                                                    status_message.set(format!("Failed to remove hook: {}", e));
                                                                    is_error.set(true);
                                                                }
                                                            }
                                                            if let Ok(hooks) = list_ept_hooks() {
                                                                ept_hooks_list.set(hooks);
                                                            }
                                                        },
                                                        "Remove"
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
        }
    }
}
