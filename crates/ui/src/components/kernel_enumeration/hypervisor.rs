//! Hypervisor control sub-tab
//!
//! Provides UI controls for managing the hypervisor and process protection.

use callback::{
    hv_clear_hidden_drivers, hv_hide_driver, hv_inject_dll, hv_inject_shellcode, hv_install_hooks,
    hv_list_hidden_drivers, hv_list_protected, hv_ping, hv_remove_hidden_driver, hv_remove_hooks,
    hv_start, hv_stop, hv_unprotect_process, is_driver_loaded, HvStatus,
};
use dioxus::prelude::*;
use std::collections::HashMap;

use crate::helpers::copy_to_clipboard;

/// Protected process info (PID + name)
#[derive(Clone, Debug)]
struct ProtectedProcess {
    pid: u32,
    name: String,
}

/// Context menu state for protected processes table
#[derive(Clone, Debug, Default)]
struct HvContextMenuState {
    visible: bool,
    x: i32,
    y: i32,
    pid: u32,
    name: String,
}

/// Hypervisor control component
#[component]
pub fn HypervisorTab() -> Element {
    let mut status = use_signal(|| HvStatus::default());
    let mut protected_processes = use_signal(Vec::<ProtectedProcess>::new);
    let mut status_message = use_signal(String::new);
    let mut context_menu = use_signal(HvContextMenuState::default);
    let mut selected_pid = use_signal(|| None::<u32>);
    let mut hidden_drivers = use_signal(Vec::<String>::new);
    let mut driver_name_input = use_signal(|| "dpdrv.sys".to_string());
    // Ring -1 injection state
    let mut inject_pid = use_signal(String::new);
    let mut inject_shellcode_path = use_signal(String::new);
    let mut inject_result = use_signal(|| None::<String>);
    let driver_loaded = is_driver_loaded();

    // Refresh status
    let mut refresh_status = move || {
        if !driver_loaded {
            status.set(HvStatus::default());
            protected_processes.set(Vec::new());
            hidden_drivers.set(Vec::new());
            return;
        }

        // Get list of hidden drivers
        if let Ok(drivers) = hv_list_hidden_drivers() {
            hidden_drivers.set(drivers);
        } else {
            hidden_drivers.set(Vec::new());
        }

        match hv_ping() {
            Ok(s) => {
                status.set(s.clone());
                if s.is_running {
                    if let Ok(pids) = hv_list_protected() {
                        // Build PID -> Name map from current processes
                        let all_procs = process::get_processes();
                        let name_map: HashMap<u32, String> = all_procs
                            .into_iter()
                            .map(|p| (p.pid, p.name))
                            .collect();

                        // Convert PIDs to ProtectedProcess with names
                        let procs: Vec<ProtectedProcess> = pids
                            .into_iter()
                            .map(|pid| ProtectedProcess {
                                pid,
                                name: name_map.get(&pid).cloned().unwrap_or_else(|| "<exited>".to_string()),
                            })
                            .collect();
                        protected_processes.set(procs);
                    }
                } else {
                    protected_processes.set(Vec::new());
                }
            }
            Err(_) => {
                status.set(HvStatus::default());
                protected_processes.set(Vec::new());
            }
        }
    };

    // Auto-refresh on mount
    use_effect(move || {
        refresh_status();
    });

    // Keyboard handler
    let handle_keydown = move |e: KeyboardEvent| {
        if e.key() == Key::Escape {
            context_menu.set(HvContextMenuState::default());
        } else if e.key() == Key::F5 {
            refresh_status();
        }
    };

    let current_status = status.read();
    let procs = protected_processes.read().clone();
    let ctx_menu = context_menu.read().clone();
    let msg = status_message.read().clone();

    rsx! {
        div {
            style: "display: flex; flex-direction: column; flex: 1; overflow: hidden;",
            tabindex: "0",
            onkeydown: handle_keydown,
            onclick: move |_| context_menu.set(HvContextMenuState::default()),

            // Controls bar - Status and buttons
            div { class: "controls",
                // Status indicators
                span {
                    class: if driver_loaded { "driver-status driver-status-loaded" } else { "driver-status driver-status-not-loaded" },
                    if driver_loaded { "Driver: Loaded" } else { "Driver: Not Loaded" }
                }
                span {
                    class: if current_status.is_running { "driver-status driver-status-loaded" } else { "driver-status driver-status-not-loaded" },
                    if current_status.is_running { "HV: Running" } else { "HV: Stopped" }
                }
                span {
                    class: if current_status.hooks_installed { "driver-status driver-status-loaded" } else { "driver-status driver-status-not-loaded" },
                    if current_status.hooks_installed { "Hooks: Installed" } else { "Hooks: Not Installed" }
                }

                // Separator
                div { style: "flex: 1;" }

                // Control buttons
                button {
                    class: "btn btn-primary",
                    disabled: !driver_loaded || current_status.is_running,
                    onclick: move |_| {
                        spawn(async move {
                            match hv_start() {
                                Ok(()) => {
                                    status_message.set("Hypervisor started successfully".to_string());
                                    refresh_status();
                                }
                                Err(e) => {
                                    status_message.set(format!("Failed to start: {}", e));
                                }
                            }
                            spawn(async move {
                                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                                status_message.set(String::new());
                            });
                        });
                    },
                    "Start HV"
                }

                button {
                    class: "btn btn-secondary",
                    disabled: !driver_loaded || !current_status.is_running,
                    onclick: move |_| {
                        spawn(async move {
                            match hv_stop() {
                                Ok(()) => {
                                    status_message.set("Hypervisor stopped".to_string());
                                    refresh_status();
                                }
                                Err(e) => {
                                    status_message.set(format!("Failed to stop: {}", e));
                                }
                            }
                            spawn(async move {
                                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                                status_message.set(String::new());
                            });
                        });
                    },
                    "Stop HV"
                }

                button {
                    class: "btn btn-primary",
                    disabled: !driver_loaded || !current_status.is_running || current_status.hooks_installed,
                    onclick: move |_| {
                        spawn(async move {
                            match hv_install_hooks() {
                                Ok(()) => {
                                    status_message.set("Protection hooks installed".to_string());
                                    refresh_status();
                                }
                                Err(e) => {
                                    status_message.set(format!("Failed to install hooks: {}", e));
                                }
                            }
                            spawn(async move {
                                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                                status_message.set(String::new());
                            });
                        });
                    },
                    "Install Hooks"
                }

                button {
                    class: "btn btn-secondary",
                    disabled: !driver_loaded || !current_status.hooks_installed,
                    onclick: move |_| {
                        spawn(async move {
                            match hv_remove_hooks() {
                                Ok(()) => {
                                    status_message.set("Hooks removed".to_string());
                                    refresh_status();
                                }
                                Err(e) => {
                                    status_message.set(format!("Failed to remove hooks: {}", e));
                                }
                            }
                            spawn(async move {
                                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                                status_message.set(String::new());
                            });
                        });
                    },
                    "Remove Hooks"
                }

                button {
                    class: "btn btn-secondary",
                    onclick: move |_| refresh_status(),
                    "Refresh"
                }

                if !msg.is_empty() {
                    span { class: "status-message", "{msg}" }
                }
            }

            // Driver Hiding Section
            div {
                class: "controls",
                style: "border-top: 1px solid var(--border-color); padding-top: 10px;",

                span { style: "font-weight: 600; margin-right: 15px;", "Driver Hiding:" }

                span {
                    class: if !hidden_drivers.read().is_empty() { "driver-status driver-status-loaded" } else { "driver-status driver-status-not-loaded" },
                    "{hidden_drivers.read().len()} hidden"
                }

                input {
                    r#type: "text",
                    placeholder: "Driver name (e.g., dpdrv.sys)",
                    value: "{driver_name_input}",
                    disabled: !driver_loaded || !current_status.hooks_installed,
                    oninput: move |e| driver_name_input.set(e.value()),
                    style: "padding: 6px 10px; border-radius: 4px; border: 1px solid var(--border-color); background: var(--bg-secondary); color: var(--text-primary); width: 180px; font-family: monospace;",
                }

                button {
                    class: "btn btn-primary",
                    disabled: !driver_loaded || !current_status.hooks_installed || driver_name_input.read().is_empty(),
                    onclick: move |_| {
                        let name = driver_name_input.read().clone();
                        spawn(async move {
                            match hv_hide_driver(&name) {
                                Ok(()) => {
                                    status_message.set(format!("Driver '{}' added to hide list", name));
                                    driver_name_input.set(String::new());
                                    refresh_status();
                                }
                                Err(e) => {
                                    status_message.set(format!("Failed to hide driver: {}", e));
                                }
                            }
                            spawn(async move {
                                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                                status_message.set(String::new());
                            });
                        });
                    },
                    "Add"
                }

                button {
                    class: "btn btn-secondary",
                    disabled: !driver_loaded || hidden_drivers.read().is_empty(),
                    onclick: move |_| {
                        spawn(async move {
                            match hv_clear_hidden_drivers() {
                                Ok(()) => {
                                    status_message.set("All hidden drivers cleared".to_string());
                                    refresh_status();
                                }
                                Err(e) => {
                                    status_message.set(format!("Failed: {}", e));
                                }
                            }
                            spawn(async move {
                                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                                status_message.set(String::new());
                            });
                        });
                    },
                    "Clear All"
                }

                // Show hidden drivers as tags
                for driver in hidden_drivers.read().iter() {
                    {
                        let driver_name = driver.clone();
                        let driver_display = driver.clone();
                        rsx! {
                            span {
                                class: "driver-status driver-status-loaded",
                                style: "display: inline-flex; align-items: center; gap: 5px; padding: 3px 8px;",
                                "{driver_display}"
                                button {
                                    style: "background: none; border: none; color: var(--text-primary); cursor: pointer; padding: 0; font-size: 12px; opacity: 0.7;",
                                    onclick: move |e| {
                                        e.stop_propagation();
                                        let name = driver_name.clone();
                                        spawn(async move {
                                            match hv_remove_hidden_driver(&name) {
                                                Ok(()) => {
                                                    status_message.set(format!("Driver '{}' removed from hide list", name));
                                                    refresh_status();
                                                }
                                                Err(e) => {
                                                    status_message.set(format!("Failed: {}", e));
                                                }
                                            }
                                            spawn(async move {
                                                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                                                status_message.set(String::new());
                                            });
                                        });
                                    },
                                    "×"
                                }
                            }
                        }
                    }
                }

                div { style: "flex: 1;" }

                span {
                    style: "font-size: 11px; color: var(--text-secondary);",
                    "Max 16 drivers"
                }
            }

            // Ring -1 Injection Section
            div {
                class: "controls",
                style: "border-top: 1px solid var(--border-color); padding-top: 10px;",

                span { style: "font-weight: 600; margin-right: 15px; color: var(--danger);", "Ring -1 Injection:" }

                input {
                    r#type: "text",
                    placeholder: "Target PID",
                    value: "{inject_pid}",
                    disabled: !driver_loaded || !current_status.is_running,
                    oninput: move |e| inject_pid.set(e.value()),
                    style: "padding: 6px 10px; border-radius: 4px; border: 1px solid var(--border-color); background: var(--bg-secondary); color: var(--text-primary); width: 80px; font-family: monospace;",
                }

                input {
                    r#type: "text",
                    placeholder: "Shellcode or DLL path...",
                    value: "{inject_shellcode_path}",
                    readonly: true,
                    style: "padding: 6px 10px; border-radius: 4px; border: 1px solid var(--border-color); background: var(--bg-secondary); color: var(--text-primary); width: 200px; font-family: monospace; font-size: 11px;",
                }

                button {
                    class: "btn btn-secondary",
                    disabled: !driver_loaded || !current_status.is_running,
                    onclick: move |_| {
                        spawn(async move {
                            let file = rfd::AsyncFileDialog::new()
                                .add_filter("Shellcode/DLL", &["bin", "raw", "sc", "dll"])
                                .add_filter("Shellcode", &["bin", "raw", "sc"])
                                .add_filter("DLL", &["dll"])
                                .add_filter("All files", &["*"])
                                .set_title("Select Shellcode or DLL File")
                                .pick_file()
                                .await;

                            if let Some(f) = file {
                                inject_shellcode_path.set(f.path().to_string_lossy().to_string());
                            }
                        });
                    },
                    "Browse"
                }

                button {
                    class: "btn btn-primary",
                    style: "background: var(--danger);",
                    disabled: !driver_loaded || !current_status.is_running || inject_pid.read().is_empty() || inject_shellcode_path.read().is_empty(),
                    onclick: move |_| {
                        let pid_str = inject_pid.read().clone();
                        let file_path = inject_shellcode_path.read().clone();

                        // Parse PID
                        let pid = match pid_str.parse::<u32>() {
                            Ok(p) => p,
                            Err(_) => {
                                inject_result.set(Some("Invalid PID".to_string()));
                                return;
                            }
                        };

                        // Detect file type by extension
                        let is_dll = file_path.to_lowercase().ends_with(".dll");

                        spawn(async move {
                            if is_dll {
                                // DLL injection via LoadLibraryW
                                match hv_inject_dll(pid, &file_path) {
                                    Ok(result) => {
                                        if result.success {
                                            inject_result.set(Some(format!(
                                                "DLL injected! Path @ 0x{:X}",
                                                result.path_address
                                            )));
                                            inject_pid.set(String::new());
                                            inject_shellcode_path.set(String::new());
                                        } else {
                                            inject_result.set(Some("DLL injection failed".to_string()));
                                        }
                                    }
                                    Err(e) => {
                                        inject_result.set(Some(format!("Error: {}", e)));
                                    }
                                }
                            } else {
                                // Shellcode injection
                                let shellcode = match tokio::fs::read(&file_path).await {
                                    Ok(data) => data,
                                    Err(e) => {
                                        inject_result.set(Some(format!("Failed to read file: {}", e)));
                                        return;
                                    }
                                };

                                if shellcode.is_empty() {
                                    inject_result.set(Some("Shellcode file is empty".to_string()));
                                    return;
                                }

                                match hv_inject_shellcode(pid, &shellcode) {
                                    Ok(result) => {
                                        if result.success {
                                            inject_result.set(Some(format!(
                                                "Success! 0x{:X} ({} bytes)",
                                                result.allocated_address, result.bytes_written
                                            )));
                                            inject_pid.set(String::new());
                                            inject_shellcode_path.set(String::new());
                                        } else {
                                            inject_result.set(Some("Injection failed".to_string()));
                                        }
                                    }
                                    Err(e) => {
                                        inject_result.set(Some(format!("Error: {}", e)));
                                    }
                                }
                            }
                            spawn(async move {
                                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                                inject_result.set(None);
                            });
                        });
                    },
                    "Inject"
                }

                if let Some(ref result) = *inject_result.read() {
                    span {
                        class: if result.starts_with("Success") || result.starts_with("DLL") { "driver-status driver-status-loaded" } else { "driver-status driver-status-not-loaded" },
                        style: "font-family: monospace;",
                        "{result}"
                    }
                }

                div { style: "flex: 1;" }

                span {
                    style: "font-size: 11px; color: var(--text-secondary);",
                    ".dll = LoadLibraryW | .bin/.raw/.sc = shellcode"
                }
            }

            // Table - Protected Processes
            div { class: "table-container",
                table { class: "process-table",
                    thead { class: "table-header",
                        tr {
                            th { class: "th", "PID" }
                            th { class: "th", "Name" }
                            th { class: "th", "Status" }
                            th { class: "th", "Actions" }
                        }
                    }

                    tbody {
                        if !current_status.is_running {
                            tr {
                                td { colspan: "4", class: "no-results",
                                    if driver_loaded {
                                        "Hypervisor not running. Click 'Start HV' to virtualize the system."
                                    } else {
                                        "Driver not loaded - Load DioProcess.sys to use hypervisor features"
                                    }
                                }
                            }
                        } else if !current_status.hooks_installed {
                            tr {
                                td { colspan: "4", class: "no-results",
                                    "Hooks not installed. Click 'Install Hooks' to enable process protection."
                                }
                            }
                        } else if procs.is_empty() {
                            tr {
                                td { colspan: "4", class: "no-results",
                                    "No processes are hidden. Right-click a process in the Process tab and select 'HV Hide Process'."
                                }
                            }
                        } else {
                            for proc in procs.iter() {
                                {
                                    let pid_val = proc.pid;
                                    let proc_name = proc.name.clone();
                                    let proc_name_ctx = proc.name.clone();
                                    rsx! {
                                        tr {
                                            key: "{pid_val}",
                                            class: if *selected_pid.read() == Some(pid_val) { "process-row selected" } else { "process-row" },
                                            onclick: move |_| {
                                                let current = *selected_pid.read();
                                                if current == Some(pid_val) {
                                                    selected_pid.set(None);
                                                } else {
                                                    selected_pid.set(Some(pid_val));
                                                }
                                            },
                                            oncontextmenu: {
                                                let name_for_ctx = proc_name_ctx.clone();
                                                move |e: MouseEvent| {
                                                    e.prevent_default();
                                                    selected_pid.set(Some(pid_val));
                                                    context_menu.set(HvContextMenuState {
                                                        visible: true,
                                                        x: e.page_coordinates().x as i32,
                                                        y: e.page_coordinates().y as i32,
                                                        pid: pid_val,
                                                        name: name_for_ctx.clone(),
                                                    });
                                                }
                                            },

                                            td { class: "cell mono", "{pid_val}" }
                                            td { class: "cell", "{proc_name}" }
                                            td { class: "cell",
                                                span { class: "cpu-low", style: "font-weight: 600;", "Hidden" }
                                            }
                                            td { class: "cell",
                                                button {
                                                    class: "btn btn-small btn-secondary",
                                                    onclick: move |e| {
                                                        e.stop_propagation();
                                                        spawn(async move {
                                                            match hv_unprotect_process(pid_val) {
                                                                Ok(()) => {
                                                                    status_message.set(format!("Process {} unhidden", pid_val));
                                                                    refresh_status();
                                                                }
                                                                Err(e) => {
                                                                    status_message.set(format!("Failed: {}", e));
                                                                }
                                                            }
                                                            spawn(async move {
                                                                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                                                                status_message.set(String::new());
                                                            });
                                                        });
                                                    },
                                                    "Unhide"
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

            // Info section at bottom
            div {
                class: "controls",
                style: "margin-top: auto; flex-direction: column; align-items: flex-start; gap: 8px; font-size: 12px; color: var(--text-secondary);",
                p { "The hypervisor runs at ring -1 (below the OS kernel) using Intel VT-x EPT hooks." }
                p { "Hidden processes are invisible to NtQuerySystemInformation (Task Manager, Process Explorer, Process Hacker)" }
                p { "Hidden drivers are invisible to SystemModuleInformation (driver enumeration tools, WinObjEx64)" }
                p {
                    style: "color: var(--danger);",
                    "Warning: Experimental feature. PatchGuard safe but use only on test systems."
                }
            }

            // Context menu
            if ctx_menu.visible {
                div {
                    class: "context-menu",
                    style: "left: {ctx_menu.x}px; top: {ctx_menu.y}px;",
                    oncontextmenu: move |e| e.prevent_default(),

                    button {
                        class: "context-menu-item",
                        onclick: move |_| {
                            copy_to_clipboard(&format!("{}", ctx_menu.pid));
                            context_menu.set(HvContextMenuState::default());
                        },
                        "Copy PID"
                    }
                    button {
                        class: "context-menu-item",
                        onclick: {
                            let name = ctx_menu.name.clone();
                            move |_| {
                                copy_to_clipboard(&name);
                                context_menu.set(HvContextMenuState::default());
                            }
                        },
                        "Copy Name"
                    }
                    button {
                        class: "context-menu-item",
                        onclick: move |_| {
                            let pid_val = ctx_menu.pid;
                            context_menu.set(HvContextMenuState::default());
                            spawn(async move {
                                match hv_unprotect_process(pid_val) {
                                    Ok(()) => {
                                        status_message.set(format!("Process {} unhidden", pid_val));
                                        refresh_status();
                                    }
                                    Err(e) => {
                                        status_message.set(format!("Failed: {}", e));
                                    }
                                }
                                spawn(async move {
                                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                                    status_message.set(String::new());
                                });
                            });
                        },
                        "Unhide Process"
                    }
                }
            }
        }
    }
}
