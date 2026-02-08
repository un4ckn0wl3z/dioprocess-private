//! Hypervisor control sub-tab
//!
//! Provides UI controls for managing the hypervisor and process protection.

use callback::{
    hv_install_hooks, hv_list_protected, hv_ping, hv_remove_hooks, hv_start,
    hv_stop, hv_unprotect_process, is_driver_loaded, HvStatus,
};
use dioxus::prelude::*;

use crate::helpers::copy_to_clipboard;

/// Context menu state for protected processes table
#[derive(Clone, Debug, Default)]
struct HvContextMenuState {
    visible: bool,
    x: i32,
    y: i32,
    pid: u32,
}

/// Hypervisor control component
#[component]
pub fn HypervisorTab() -> Element {
    let mut status = use_signal(|| HvStatus::default());
    let mut protected_pids = use_signal(Vec::<u32>::new);
    let mut status_message = use_signal(String::new);
    let mut context_menu = use_signal(HvContextMenuState::default);
    let mut selected_pid = use_signal(|| None::<u32>);
    let driver_loaded = is_driver_loaded();

    // Refresh status
    let mut refresh_status = move || {
        if !driver_loaded {
            status.set(HvStatus::default());
            protected_pids.set(Vec::new());
            return;
        }

        match hv_ping() {
            Ok(s) => {
                status.set(s.clone());
                if s.is_running {
                    if let Ok(pids) = hv_list_protected() {
                        protected_pids.set(pids);
                    }
                } else {
                    protected_pids.set(Vec::new());
                }
            }
            Err(_) => {
                status.set(HvStatus::default());
                protected_pids.set(Vec::new());
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
    let pids = protected_pids.read().clone();
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

            // Table - Protected Processes
            div { class: "table-container",
                table { class: "process-table",
                    thead { class: "table-header",
                        tr {
                            th { class: "th", "PID" }
                            th { class: "th", "Status" }
                            th { class: "th", "Actions" }
                        }
                    }

                    tbody {
                        if !current_status.is_running {
                            tr {
                                td { colspan: "3", class: "no-results",
                                    if driver_loaded {
                                        "Hypervisor not running. Click 'Start HV' to virtualize the system."
                                    } else {
                                        "Driver not loaded - Load DioProcess.sys to use hypervisor features"
                                    }
                                }
                            }
                        } else if !current_status.hooks_installed {
                            tr {
                                td { colspan: "3", class: "no-results",
                                    "Hooks not installed. Click 'Install Hooks' to enable process protection."
                                }
                            }
                        } else if pids.is_empty() {
                            tr {
                                td { colspan: "3", class: "no-results",
                                    "No processes are hidden. Right-click a process in the Process tab and select 'HV Hide Process'."
                                }
                            }
                        } else {
                            for pid in pids.iter() {
                                {
                                    let pid_val = *pid;
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
                                            oncontextmenu: move |e| {
                                                e.prevent_default();
                                                selected_pid.set(Some(pid_val));
                                                context_menu.set(HvContextMenuState {
                                                    visible: true,
                                                    x: e.page_coordinates().x as i32,
                                                    y: e.page_coordinates().y as i32,
                                                    pid: pid_val,
                                                });
                                            },

                                            td { class: "cell mono", "{pid_val}" }
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
                p { "Hidden processes are invisible to NtQuerySystemInformation (Task Manager, Process Explorer, etc.)" }
                p {
                    style: "color: var(--danger);",
                    "Warning: Experimental feature. Use only on test systems."
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
