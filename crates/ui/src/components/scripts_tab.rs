//! Scripts tab — DPH and DPR script management with Memory Scanner-style layout

use callback::{hv_is_running, is_driver_loaded, list_ept_hooks, list_reg_changes, remove_ept_hook, remove_reg_change, REG_NAMES};
use dioxus::prelude::*;
use misc::free_remote_memory;

use crate::state::{
    DPH_SCRIPTS, DPR_SCRIPTS, EPT_HOOKS_LIST, EPT_HOOK_DETOUR_ALLOCS, REG_CHANGE_LIST, EptHookInputMode,
    EPT_HOOK_INPUT_MODE, EPT_HOOK_BYTES_INPUT, EPT_HOOK_ASM_INPUT, EPT_HOOK_DETOUR_ASM_INPUT, EPT_HOOK_DETOUR_STOLEN_BYTES,
};
use crate::components::memory_scanner_tab::{
    parse_dph_script, parse_dpr_script, persist_dph, persist_dpr, apply_dph_script, apply_dpr_script,
    reverse_resolve_address, build_dph_content, build_dpr_content,
};

#[component]
pub fn ScriptsTab() -> Element {
    let mut dph_scripts = DPH_SCRIPTS.signal();
    let mut detour_allocs = EPT_HOOK_DETOUR_ALLOCS.signal();
    let mut ept_hooks_list = EPT_HOOKS_LIST.signal();

    let mut status_message = use_signal(|| String::new());
    let mut is_error = use_signal(|| false);
    let mut pid_input = use_signal(|| String::new());

    let _driver_loaded = is_driver_loaded();
    let hv_running = hv_is_running();

    rsx! {
        div {
            class: "service-tab",

            // Header with PID input
            div {
                class: "controls",
                style: "border-left: 3px solid #8b5cf6;",
                div { style: "display: flex; align-items: center; gap: 12px;",
                    h2 { style: "color: var(--text-primary); font-size: 16px; font-weight: 600; margin: 0;", "Scripts" }
                    span {
                        class: "experimental-badge",
                        style: if hv_running { "background: #22c55e;" } else { "background: #6b7280;" },
                        if hv_running { "HV Active" } else { "HV Off" }
                    }
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
            }

            // Status message
            if !status_message.read().is_empty() {
                div {
                    class: if *is_error.read() { "status-bar status-error" } else { "status-bar status-success" },
                    "{status_message}"
                }
            }

            // Scrollable content
            div {
                style: "display: flex; flex-direction: column; flex: 1; overflow-y: auto; gap: 0;",

                // ============== DPH Scripts Panel ==============
                {
                    let scripts = dph_scripts.read().clone();
                    let pid_str_clone = pid_input.read().clone();
                    let pid_for_scripts = pid_str_clone.trim().parse::<u32>().unwrap_or(0);
                    rsx! {
                        div { class: "controls",
                            style: "border-left: 3px solid #f59e0b; margin-top: 4px;",

                            div { style: "display: flex; gap: 8px; align-items: center; margin-bottom: 8px;",
                                span { style: "color: var(--text-primary); font-weight: 600; font-size: 13px;",
                                    "DPH Scripts ({scripts.len()})"
                                }
                                button {
                                    class: "btn",
                                    style: "font-size: 12px; padding: 3px 12px;",
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
                                    style: "font-size: 12px; padding: 3px 12px;",
                                    disabled: pid_for_scripts == 0 || scripts.iter().all(|s| s.hook_index.is_some()),
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
                                        style: "font-size: 12px; padding: 3px 12px; color: #dc2626;",
                                        onclick: move |_| {
                                            dph_scripts.write().clear();
                                            persist_dph(&dph_scripts.read());
                                        },
                                        "Clear All"
                                    }
                                }
                            }

                            if scripts.is_empty() {
                                div { style: "color: var(--text-secondary); font-size: 13px; padding: 16px; text-align: center;",
                                    "No scripts loaded. Click \"Load .dph\" to add a hook script."
                                }
                            } else {
                                table { class: "process-table",
                                    style: "font-size: 12px;",
                                    thead { class: "table-header",
                                        tr {
                                            th { class: "th", style: "width: 180px;", "Name" }
                                            th { class: "th", style: "width: 220px;", "Target" }
                                            th { class: "th", style: "width: 80px;", "Mode" }
                                            th { class: "th", style: "width: 100px;", "Status" }
                                            th { class: "th", style: "width: 140px;", "" }
                                        }
                                    }
                                    tbody {
                                        for (si, script) in scripts.iter().enumerate() {
                                            {
                                                let s_name = script.name.clone();
                                                let s_target = script.target_expr.clone();
                                                let s_mode = match script.mode {
                                                    EptHookInputMode::Hex => "Hex",
                                                    EptHookInputMode::Assembly => "Assembly",
                                                    EptHookInputMode::Detour => "Detour",
                                                };
                                                let s_status = script.status.clone();
                                                let is_applied = script.hook_index.is_some();
                                                let status_color = if s_status == "Applied" { "color: #22c55e;" }
                                                    else if s_status.starts_with("Error") { "color: #dc2626;" }
                                                    else { "color: var(--text-secondary);" };
                                                rsx! {
                                                    tr { class: "process-row",
                                                        td { class: "cell", style: "width: 180px;", "{s_name}" }
                                                        td { class: "cell", style: "width: 220px; font-family: 'Consolas', monospace; font-size: 11px;", "{s_target}" }
                                                        td { class: "cell", style: "width: 80px;", "{s_mode}" }
                                                        td { class: "cell", style: "width: 100px; {status_color}", "{s_status}" }
                                                        td { class: "cell", style: "width: 140px; display: flex; gap: 4px;",
                                                            if !is_applied {
                                                                button {
                                                                    class: "btn",
                                                                    style: "font-size: 10px; padding: 1px 6px;",
                                                                    disabled: pid_for_scripts == 0,
                                                                    onclick: {
                                                                        move |_| {
                                                                            let pid_str = pid_input.read().clone();
                                                                            let pid = pid_str.trim().parse::<u32>().unwrap_or(0);
                                                                            if pid > 0 {
                                                                                apply_dph_script(si, pid, &mut dph_scripts, &mut detour_allocs, &mut ept_hooks_list, &mut status_message, &mut is_error);
                                                                                persist_dph(&dph_scripts.read());
                                                                            }
                                                                        }
                                                                    },
                                                                    "Apply"
                                                                }
                                                            }
                                                            button {
                                                                class: "btn",
                                                                style: "font-size: 10px; padding: 1px 6px; color: #dc2626;",
                                                                onclick: move |_| {
                                                                    if let Some(idx) = dph_scripts.read().get(si).and_then(|s| s.hook_index) {
                                                                        if let Some((dpid, daddr)) = detour_allocs.read().get(&idx).copied() {
                                                                            let _ = free_remote_memory(dpid, daddr);
                                                                        }
                                                                        detour_allocs.write().remove(&idx);
                                                                        let _ = remove_ept_hook(idx);
                                                                        if let Ok(h) = list_ept_hooks() {
                                                                            ept_hooks_list.set(h);
                                                                        }
                                                                    }
                                                                    dph_scripts.write().remove(si);
                                                                    persist_dph(&dph_scripts.read());
                                                                },
                                                                "Delete"
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

                // ============== Active EPT Hooks Panel ==============
                {
                    let hooks = ept_hooks_list.read().clone();
                    let has_hooks = !hooks.is_empty();
                    rsx! {
                        if has_hooks {
                            div { class: "controls",
                                style: "border-left: 3px solid #dc2626; margin-top: 4px;",
                                div { style: "display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;",
                                    span { style: "color: var(--text-primary); font-weight: 600; font-size: 13px;",
                                        "Active EPT Hooks ({hooks.len()})"
                                    }
                                    div { style: "display: flex; gap: 8px;",
                                        button {
                                            class: "btn",
                                            style: "font-size: 11px; padding: 2px 8px;",
                                            onclick: move |_| {
                                                if let Ok(h) = list_ept_hooks() {
                                                    ept_hooks_list.set(h);
                                                }
                                            },
                                            "Refresh"
                                        }
                                        button {
                                            class: "btn",
                                            style: "font-size: 11px; padding: 2px 8px; color: #dc2626;",
                                            onclick: move |_| {
                                                let allocs = detour_allocs.read().clone();
                                                for (_idx, (dpid, daddr)) in &allocs {
                                                    let _ = free_remote_memory(*dpid, *daddr);
                                                }
                                                detour_allocs.write().clear();
                                                let current = ept_hooks_list.read().clone();
                                                for hook in &current {
                                                    let _ = remove_ept_hook(hook.hook_index);
                                                }
                                                if let Ok(h) = list_ept_hooks() {
                                                    ept_hooks_list.set(h);
                                                }
                                            },
                                            "Remove All"
                                        }
                                    }
                                }
                                table { class: "process-table",
                                    style: "font-size: 12px;",
                                    thead { class: "table-header",
                                        tr {
                                            th { class: "th", style: "width: 50px;", "#" }
                                            th { class: "th", style: "width: 80px;", "PID" }
                                            th { class: "th", style: "width: 180px;", "Address" }
                                            th { class: "th", style: "width: 80px;", "Patch Size" }
                                            th { class: "th", style: "width: 140px;", "" }
                                        }
                                    }
                                    tbody {
                                        for hook in hooks.iter() {
                                            {
                                                let hook_idx = hook.hook_index;
                                                let hook_addr = hook.target_address;
                                                let hook_pid = hook.process_id;
                                                let hook_size = hook.patch_size;
                                                rsx! {
                                                    tr { class: "process-row",
                                                        td { class: "cell", style: "width: 50px;", "{hook_idx}" }
                                                        td { class: "cell", style: "width: 80px;", "{hook_pid}" }
                                                        td {
                                                            class: "cell",
                                                            style: "width: 180px; font-family: 'Consolas', monospace; color: var(--accent-primary);",
                                                            "0x{hook_addr:X}"
                                                        }
                                                        td { class: "cell", style: "width: 80px;", "{hook_size}" }
                                                        td { class: "cell", style: "width: 140px; display: flex; gap: 4px;",
                                                            button {
                                                                class: "btn",
                                                                style: "font-size: 10px; padding: 1px 6px;",
                                                                onclick: {
                                                                    move |_| {
                                                                        // Try to find the DPH script that created this hook
                                                                        let script_data = DPH_SCRIPTS.read().iter()
                                                                            .find(|s| s.hook_index == Some(hook_idx))
                                                                            .map(|s| (s.name.clone(), s.target_expr.clone(), s.mode, s.stolen_bytes, s.code.clone()));
                                                                        
                                                                        let (name, target_expr, mode, stolen, code) = if let Some((n, t, m, st, c)) = script_data {
                                                                            (n, t, m, st, c)
                                                                        } else {
                                                                            // Fallback: use modal's global state (for hooks created via modal, not from script)
                                                                            let target = reverse_resolve_address(hook_pid, hook_addr);
                                                                            let mode = *EPT_HOOK_INPUT_MODE.read();
                                                                            let code = match mode {
                                                                                EptHookInputMode::Hex => EPT_HOOK_BYTES_INPUT.read().clone(),
                                                                                EptHookInputMode::Assembly => EPT_HOOK_ASM_INPUT.read().clone(),
                                                                                EptHookInputMode::Detour => EPT_HOOK_DETOUR_ASM_INPUT.read().clone(),
                                                                            };
                                                                            let stolen: u32 = EPT_HOOK_DETOUR_STOLEN_BYTES.read().trim().parse().unwrap_or(6);
                                                                            (String::new(), target, mode, stolen, code)
                                                                        };
                                                                        
                                                                        let mode_str = match mode {
                                                                            EptHookInputMode::Hex => "hex",
                                                                            EptHookInputMode::Assembly => "assembly",
                                                                            EptHookInputMode::Detour => "detour",
                                                                        };
                                                                        let content = build_dph_content(&name, &target_expr, mode_str, stolen, &code);
                                                                        spawn(async move {
                                                                            if let Some(file) = rfd::AsyncFileDialog::new()
                                                                                .add_filter("DioProcess Hook Script", &["dph"])
                                                                                .set_file_name("hook.dph")
                                                                                .save_file()
                                                                                .await
                                                                            {
                                                                                let _ = std::fs::write(file.path(), content);
                                                                            }
                                                                        });
                                                                    }
                                                                },
                                                                "Save .dph"
                                                            }
                                                            button {
                                                                class: "btn",
                                                                style: "font-size: 10px; padding: 1px 6px; color: #dc2626;",
                                                                onclick: move |_| {
                                                                    if let Some((dpid, daddr)) = detour_allocs.read().get(&hook_idx).copied() {
                                                                        let _ = free_remote_memory(dpid, daddr);
                                                                    }
                                                                    detour_allocs.write().remove(&hook_idx);
                                                                    let _ = remove_ept_hook(hook_idx);
                                                                    if let Ok(h) = list_ept_hooks() {
                                                                        ept_hooks_list.set(h);
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

                // ============== Active Register Changes Panel ==============
                {
                    let reg_changes = REG_CHANGE_LIST.read().clone();
                    let has_reg_changes = !reg_changes.is_empty();
                    rsx! {
                        if has_reg_changes {
                            div { class: "controls",
                                style: "border-left: 3px solid #a855f7; margin-top: 4px;",
                                div { style: "display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;",
                                    span { style: "color: var(--text-primary); font-weight: 600; font-size: 13px;",
                                        "Active Register Changes ({reg_changes.len()})"
                                    }
                                    div { style: "display: flex; gap: 8px;",
                                        button {
                                            class: "btn",
                                            style: "font-size: 11px; padding: 2px 8px;",
                                            onclick: move |_| {
                                                if let Ok(list) = list_reg_changes() {
                                                    *REG_CHANGE_LIST.write() = list;
                                                }
                                            },
                                            "Refresh"
                                        }
                                        button {
                                            class: "btn",
                                            style: "font-size: 11px; padding: 2px 8px; color: #dc2626;",
                                            onclick: move |_| {
                                                let _ = callback::remove_all_reg_changes();
                                                if let Ok(list) = list_reg_changes() {
                                                    *REG_CHANGE_LIST.write() = list;
                                                }
                                            },
                                            "Remove All"
                                        }
                                    }
                                }
                                table { class: "process-table",
                                    style: "font-size: 12px;",
                                    thead { class: "table-header",
                                        tr {
                                            th { class: "th", style: "width: 50px;", "#" }
                                            th { class: "th", style: "width: 80px;", "PID" }
                                            th { class: "th", style: "width: 180px;", "Address" }
                                            th { class: "th", style: "width: 80px;", "Register" }
                                            th { class: "th", style: "width: 150px;", "Value" }
                                            th { class: "th", style: "width: 140px;", "" }
                                        }
                                    }
                                    tbody {
                                        for rc in reg_changes.iter() {
                                            {
                                                let rc_idx = rc.entry_index;
                                                let rc_pid = rc.process_id;
                                                let rc_addr = rc.target_address;
                                                let reg_name = REG_NAMES.get(rc.reg_index as usize).unwrap_or(&"???");
                                                let rc_val = rc.new_value;
                                                let is_flag = rc.reg_index >= 16;
                                                let val_display = if is_flag {
                                                    if rc_val != 0 { "Set".to_string() } else { "Clear".to_string() }
                                                } else {
                                                    format!("0x{:X}", rc_val)
                                                };
                                                rsx! {
                                                    tr { class: "process-row",
                                                        td { class: "cell", style: "width: 50px;", "{rc_idx}" }
                                                        td { class: "cell", style: "width: 80px;", "{rc_pid}" }
                                                        td {
                                                            class: "cell",
                                                            style: "width: 180px; font-family: 'Consolas', monospace; color: var(--accent-primary);",
                                                            "0x{rc_addr:X}"
                                                        }
                                                        td {
                                                            class: "cell",
                                                            style: "width: 80px; font-family: 'Consolas', monospace; color: #a855f7;",
                                                            "{reg_name}"
                                                        }
                                                        td {
                                                            class: "cell",
                                                            style: "width: 150px; font-family: 'Consolas', monospace;",
                                                            "{val_display}"
                                                        }
                                                        td { class: "cell", style: "width: 140px; display: flex; gap: 4px;",
                                                            button {
                                                                class: "btn",
                                                                style: "font-size: 10px; padding: 1px 6px;",
                                                                onclick: {
                                                                    let reg_name_str = reg_name.to_string();
                                                                    let val_str = if is_flag {
                                                                        if rc_val != 0 { "set".to_string() } else { "clear".to_string() }
                                                                    } else {
                                                                        format!("0x{:X}", rc_val)
                                                                    };
                                                                    move |_| {
                                                                        // Try to find the DPR script that created this register change
                                                                        let script_data = DPR_SCRIPTS.read().iter()
                                                                            .find(|s| s.entry_index == Some(rc_idx))
                                                                            .map(|s| (s.name.clone(), s.target_expr.clone(), s.register.clone(), s.value_expr.clone()));
                                                                        
                                                                        let (name, target_expr, reg, val) = if let Some((n, t, r, v)) = script_data {
                                                                            (n, t, r, v)
                                                                        } else {
                                                                            // Fallback: use raw data from register change entry
                                                                            let target = reverse_resolve_address(rc_pid, rc_addr);
                                                                            (String::new(), target, reg_name_str.clone(), val_str.clone())
                                                                        };
                                                                        
                                                                        let content = build_dpr_content(&name, &target_expr, &reg, &val, "");
                                                                        spawn(async move {
                                                                            if let Some(file) = rfd::AsyncFileDialog::new()
                                                                                .add_filter("DioProcess Register Script", &["dpr"])
                                                                                .set_file_name("register.dpr")
                                                                                .save_file()
                                                                                .await
                                                                            {
                                                                                let _ = std::fs::write(file.path(), content);
                                                                            }
                                                                        });
                                                                    }
                                                                },
                                                                "Save .dpr"
                                                            }
                                                            button {
                                                                class: "btn",
                                                                style: "font-size: 10px; padding: 1px 6px; color: #dc2626;",
                                                                onclick: move |_| {
                                                                    let _ = remove_reg_change(rc_idx);
                                                                    if let Ok(list) = list_reg_changes() {
                                                                        *REG_CHANGE_LIST.write() = list;
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

                // ============== DPR Scripts Panel ==============
                {
                    let dpr_scripts_list = DPR_SCRIPTS.read().clone();
                    let pid_str_for_dpr = pid_input.read().clone();
                    let pid_for_dpr = pid_str_for_dpr.trim().parse::<u32>().unwrap_or(0);
                    rsx! {
                        div { class: "controls",
                            style: "border-left: 3px solid #f59e0b; margin-top: 4px;",

                            div { style: "display: flex; gap: 8px; align-items: center; margin-bottom: 8px;",
                                span { style: "color: var(--text-primary); font-weight: 600; font-size: 13px;",
                                    "DPR Scripts ({dpr_scripts_list.len()})"
                                }
                                button {
                                    class: "btn",
                                    style: "font-size: 12px; padding: 3px 12px;",
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
                                    style: "font-size: 12px; padding: 3px 12px;",
                                    disabled: pid_for_dpr == 0 || dpr_scripts_list.iter().all(|s| s.entry_index.is_some()),
                                    onclick: {
                                        move |_| {
                                            let pid_str = pid_input.read().clone();
                                            let pid = pid_str.trim().parse::<u32>().unwrap_or(0);
                                            if pid == 0 {
                                                status_message.set("Set PID first".to_string());
                                                is_error.set(true);
                                                return;
                                            }
                                            let mut dpr = DPR_SCRIPTS.signal();
                                            let mut rc_list = REG_CHANGE_LIST.signal();
                                            let count = dpr.read().len();
                                            for i in 0..count {
                                                let already_applied = dpr.read().get(i).map(|s| s.entry_index.is_some()).unwrap_or(true);
                                                if already_applied { continue; }
                                                apply_dpr_script(i, pid, &mut dpr, &mut rc_list, &mut status_message, &mut is_error);
                                            }
                                            persist_dpr(&DPR_SCRIPTS.read());
                                        }
                                    },
                                    "Apply All"
                                }
                                if !dpr_scripts_list.is_empty() {
                                    button {
                                        class: "btn",
                                        style: "font-size: 12px; padding: 3px 12px; color: #dc2626;",
                                        onclick: move |_| {
                                            for script in DPR_SCRIPTS.read().iter() {
                                                if let Some(idx) = script.entry_index {
                                                    let _ = remove_reg_change(idx);
                                                }
                                            }
                                            DPR_SCRIPTS.write().clear();
                                            persist_dpr(&DPR_SCRIPTS.read());
                                            if let Ok(list) = list_reg_changes() {
                                                *REG_CHANGE_LIST.write() = list;
                                            }
                                        },
                                        "Clear All"
                                    }
                                }
                            }

                            if dpr_scripts_list.is_empty() {
                                div { style: "color: var(--text-secondary); font-size: 13px; padding: 8px; text-align: center;",
                                    "No .dpr scripts loaded. Click \"Load .dpr\" to add a register script."
                                }
                            } else {
                                table { class: "process-table",
                                    style: "font-size: 12px;",
                                    thead { class: "table-header",
                                        tr {
                                            th { class: "th", style: "width: 160px;", "Name" }
                                            th { class: "th", style: "width: 180px;", "Target" }
                                            th { class: "th", style: "width: 80px;", "Register" }
                                            th { class: "th", style: "width: 100px;", "Value" }
                                            th { class: "th", style: "width: 100px;", "Status" }
                                            th { class: "th", style: "width: 140px;", "" }
                                        }
                                    }
                                    tbody {
                                        for (si, script) in dpr_scripts_list.iter().enumerate() {
                                            {
                                                let s_name = script.name.clone();
                                                let s_target = script.target_expr.clone();
                                                let s_reg = script.register.clone();
                                                let s_val = script.value_expr.clone();
                                                let s_status = script.status.clone();
                                                let is_applied = script.entry_index.is_some();
                                                let status_color = if s_status == "Applied" { "color: #22c55e;" }
                                                    else if s_status.starts_with("Error") { "color: #dc2626;" }
                                                    else { "color: var(--text-secondary);" };
                                                rsx! {
                                                    tr { class: "process-row",
                                                        td { class: "cell", style: "width: 160px;", "{s_name}" }
                                                        td { class: "cell", style: "width: 180px; font-family: 'Consolas', monospace; font-size: 11px;", "{s_target}" }
                                                        td { class: "cell", style: "width: 80px; font-family: 'Consolas', monospace; color: #a855f7;", "{s_reg}" }
                                                        td { class: "cell", style: "width: 100px; font-family: 'Consolas', monospace;", "{s_val}" }
                                                        td { class: "cell", style: "width: 100px; {status_color}", "{s_status}" }
                                                        td { class: "cell", style: "width: 140px; display: flex; gap: 4px;",
                                                            if !is_applied {
                                                                button {
                                                                    class: "btn",
                                                                    style: "font-size: 10px; padding: 1px 6px;",
                                                                    disabled: pid_for_dpr == 0,
                                                                    onclick: {
                                                                        move |_| {
                                                                            let pid_str = pid_input.read().clone();
                                                                            let pid = pid_str.trim().parse::<u32>().unwrap_or(0);
                                                                            if pid > 0 {
                                                                                let mut dpr = DPR_SCRIPTS.signal();
                                                                                let mut rc_list = REG_CHANGE_LIST.signal();
                                                                                apply_dpr_script(si, pid, &mut dpr, &mut rc_list, &mut status_message, &mut is_error);
                                                                                persist_dpr(&DPR_SCRIPTS.read());
                                                                            }
                                                                        }
                                                                    },
                                                                    "Apply"
                                                                }
                                                            }
                                                            button {
                                                                class: "btn",
                                                                style: "font-size: 10px; padding: 1px 6px; color: #dc2626;",
                                                                onclick: move |_| {
                                                                    if let Some(idx) = DPR_SCRIPTS.read().get(si).and_then(|s| s.entry_index) {
                                                                        let _ = remove_reg_change(idx);
                                                                        if let Ok(list) = list_reg_changes() {
                                                                            *REG_CHANGE_LIST.write() = list;
                                                                        }
                                                                    }
                                                                    DPR_SCRIPTS.write().remove(si);
                                                                    persist_dpr(&DPR_SCRIPTS.read());
                                                                },
                                                                "Delete"
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
    }
}
