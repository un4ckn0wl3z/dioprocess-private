//! Scripts tab — DPH and DPR script management (shared between Memory Scanner and HV Scanner)

use callback::{hv_is_running, is_driver_loaded, list_ept_hooks, list_reg_changes, remove_ept_hook, remove_reg_change};
use dioxus::prelude::*;
use misc::free_remote_memory;

use crate::state::{
    DPH_SCRIPTS, DPR_SCRIPTS, EPT_HOOKS_LIST, EPT_HOOK_DETOUR_ALLOCS, REG_CHANGE_LIST,
};
use crate::components::memory_scanner_tab::{
    parse_dph_script, parse_dpr_script, persist_dph, persist_dpr, apply_dph_script, apply_dpr_script,
};

#[component]
pub fn ScriptsTab() -> Element {
    let mut dph_scripts = DPH_SCRIPTS.signal();
    let mut dpr_scripts = DPR_SCRIPTS.signal();
    let mut ept_hooks_list = EPT_HOOKS_LIST.signal();
    let mut detour_allocs = EPT_HOOK_DETOUR_ALLOCS.signal();
    let mut rc_list = REG_CHANGE_LIST.signal();

    let mut status_message = use_signal(|| String::new());
    let mut is_error = use_signal(|| false);
    let mut active_sub_tab = use_signal(|| 0usize); // 0 = DPH, 1 = DPR, 2 = Active Hooks
    let mut pid_input = use_signal(|| String::new());

    let driver_loaded = is_driver_loaded();
    let hv_running = hv_is_running();

    // Refresh hooks list
    let refresh_hooks = move || {
        if let Ok(hooks) = list_ept_hooks() {
            EPT_HOOKS_LIST.write().clone_from(&hooks);
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
                // PID input
                div { style: "display: flex; align-items: center; gap: 8px; margin-left: auto;",
                    label { style: "color: var(--text-secondary); font-size: 13px;", "PID:" }
                    input {
                        class: "handle-filter-input",
                        r#type: "text",
                        placeholder: "Process ID",
                        style: "width: 100px;",
                        value: "{pid_input}",
                        oninput: move |e| pid_input.set(e.value()),
                    }
                }
            }

            // Description
            div {
                style: "color: var(--text-secondary); font-size: 13px; margin-bottom: 16px;",
                "Manage DPH (Detour Patch Hook) and DPR (Detour Patch Replace) scripts. Enter a PID to apply scripts to a target process."
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
                {
                    let scripts = dph_scripts.read().clone();
                    let pid_str_clone = pid_input.read().clone();
                    let pid_for_scripts = pid_str_clone.trim().parse::<u32>().unwrap_or(0);
                    rsx! {
                div {
                    class: "process-table-container",
                    style: "max-height: calc(100vh - 300px);",

                    // Action buttons
                    div {
                        style: "display: flex; gap: 8px; align-items: center; margin-bottom: 12px; padding: 8px; background: var(--bg-secondary); border-radius: 4px; border-left: 3px solid #f59e0b;",
                        button {
                            class: "btn",
                            style: "font-size: 12px; padding: 4px 12px;",
                            onclick: move |_| {
                                spawn(async move {
                                    if let Some(file) = rfd::AsyncFileDialog::new()
                                        .add_filter("DioProcess Hook Script", &["dph"])
                                        .set_title("Load .dph Script")
                                        .pick_file()
                                        .await
                                    {
                                        let path = file.path().to_string_lossy().to_string();
                                        match std::fs::read_to_string(file.path()) {
                                            Ok(content) => {
                                                match parse_dph_script(&content, &path) {
                                                    Ok(script) => {
                                                        DPH_SCRIPTS.write().push(script);
                                                        persist_dph(&DPH_SCRIPTS.read());
                                                        status_message.set("Script loaded".to_string());
                                                        is_error.set(false);
                                                    }
                                                    Err(e) => {
                                                        status_message.set(format!("Parse error: {}", e));
                                                        is_error.set(true);
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                status_message.set(format!("Read error: {}", e));
                                                is_error.set(true);
                                            }
                                        }
                                    }
                                });
                            },
                            "Load .dph"
                        }
                        button {
                            class: "btn",
                            style: "font-size: 12px; padding: 4px 12px;",
                            disabled: pid_for_scripts == 0 || scripts.iter().all(|s| s.hook_index.is_some()) || !driver_loaded || !hv_running,
                            onclick: {
                                move |_| {
                                    let pid_str = pid_input.read().clone();
                                    let pid = pid_str.trim().parse::<u32>().unwrap_or(0);
                                    if pid == 0 {
                                        status_message.set("Set PID first".to_string());
                                        is_error.set(true);
                                        return;
                                    }
                                    let count = dph_scripts.read().len();
                                    for i in 0..count {
                                        let already_applied = dph_scripts.read().get(i).map(|s| s.hook_index.is_some()).unwrap_or(true);
                                        if already_applied { continue; }
                                        apply_dph_script(i, pid, &mut dph_scripts, &mut detour_allocs, &mut ept_hooks_list, &mut status_message, &mut is_error);
                                    }
                                    persist_dph(&dph_scripts.read());
                                }
                            },
                            "Apply All"
                        }
                        if !scripts.is_empty() {
                            button {
                                class: "btn",
                                style: "font-size: 12px; padding: 4px 12px; color: #dc2626;",
                                onclick: move |_| {
                                    // Remove applied hooks first
                                    for script in DPH_SCRIPTS.read().iter() {
                                        if let Some(idx) = script.hook_index {
                                            if let Some((dpid, daddr)) = EPT_HOOK_DETOUR_ALLOCS.read().get(&idx).copied() {
                                                let _ = free_remote_memory(dpid, daddr);
                                            }
                                            EPT_HOOK_DETOUR_ALLOCS.write().remove(&idx);
                                            let _ = remove_ept_hook(idx);
                                        }
                                    }
                                    DPH_SCRIPTS.write().clear();
                                    persist_dph(&DPH_SCRIPTS.read());
                                    if let Ok(hooks) = list_ept_hooks() {
                                        EPT_HOOKS_LIST.write().clone_from(&hooks);
                                    }
                                },
                                "Clear All"
                            }
                        }
                        span { style: "color: var(--text-secondary); font-size: 12px; margin-left: auto;",
                            "No scripts loaded. Click \"Load .dph\" to add a hook script."
                        }
                    }

                    if scripts.is_empty() {
                        div {
                            style: "color: var(--text-secondary); text-align: center; padding: 40px;",
                            "No scripts loaded. Click \"Load .dph\" to add a hook script."
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
                }
            }

            // DPR Scripts tab
            if *active_sub_tab.read() == 1 {
                {
                    let scripts = dpr_scripts.read().clone();
                    let pid_str_clone = pid_input.read().clone();
                    let pid_for_scripts = pid_str_clone.trim().parse::<u32>().unwrap_or(0);
                    rsx! {
                div {
                    class: "process-table-container",
                    style: "max-height: calc(100vh - 300px);",

                    // Action buttons
                    div {
                        style: "display: flex; gap: 8px; align-items: center; margin-bottom: 12px; padding: 8px; background: var(--bg-secondary); border-radius: 4px; border-left: 3px solid #f59e0b;",
                        button {
                            class: "btn",
                            style: "font-size: 12px; padding: 4px 12px;",
                            onclick: move |_| {
                                spawn(async move {
                                    if let Some(file) = rfd::AsyncFileDialog::new()
                                        .add_filter("DioProcess Register Script", &["dpr"])
                                        .set_title("Load .dpr Script")
                                        .pick_file()
                                        .await
                                    {
                                        let path = file.path().to_string_lossy().to_string();
                                        match std::fs::read_to_string(file.path()) {
                                            Ok(content) => {
                                                match parse_dpr_script(&content, &path) {
                                                    Ok(script) => {
                                                        DPR_SCRIPTS.write().push(script);
                                                        persist_dpr(&DPR_SCRIPTS.read());
                                                        status_message.set("DPR script loaded".to_string());
                                                        is_error.set(false);
                                                    }
                                                    Err(e) => {
                                                        status_message.set(format!("Parse error: {}", e));
                                                        is_error.set(true);
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                status_message.set(format!("Read error: {}", e));
                                                is_error.set(true);
                                            }
                                        }
                                    }
                                });
                            },
                            "Load .dpr"
                        }
                        button {
                            class: "btn",
                            style: "font-size: 12px; padding: 4px 12px;",
                            disabled: pid_for_scripts == 0 || scripts.iter().all(|s| s.entry_index.is_some()) || !driver_loaded || !hv_running,
                            onclick: {
                                move |_| {
                                    let pid_str = pid_input.read().clone();
                                    let pid = pid_str.trim().parse::<u32>().unwrap_or(0);
                                    if pid == 0 {
                                        status_message.set("Set PID first".to_string());
                                        is_error.set(true);
                                        return;
                                    }
                                    let count = dpr_scripts.read().len();
                                    for i in 0..count {
                                        let already_applied = dpr_scripts.read().get(i).map(|s| s.entry_index.is_some()).unwrap_or(true);
                                        if already_applied { continue; }
                                        apply_dpr_script(i, pid, &mut dpr_scripts, &mut rc_list, &mut status_message, &mut is_error);
                                    }
                                    persist_dpr(&dpr_scripts.read());
                                }
                            },
                            "Apply All"
                        }
                        if !scripts.is_empty() {
                            button {
                                class: "btn",
                                style: "font-size: 12px; padding: 4px 12px; color: #dc2626;",
                                onclick: move |_| {
                                    // Remove applied reg changes first
                                    for script in DPR_SCRIPTS.read().iter() {
                                        if let Some(idx) = script.entry_index {
                                            let _ = remove_reg_change(idx);
                                        }
                                    }
                                    DPR_SCRIPTS.write().clear();
                                    persist_dpr(&DPR_SCRIPTS.read());
                                    if let Ok(list) = list_reg_changes() {
                                        REG_CHANGE_LIST.write().clone_from(&list);
                                    }
                                },
                                "Clear All"
                            }
                        }
                        span { style: "color: var(--text-secondary); font-size: 12px; margin-left: auto;",
                            "No .dpr scripts loaded. Click \"Load .dpr\" to add a register script."
                        }
                    }

                    if scripts.is_empty() {
                        div {
                            style: "color: var(--text-secondary); text-align: center; padding: 40px;",
                            "No .dpr scripts loaded. Click \"Load .dpr\" to add a register script."
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
