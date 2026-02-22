//! Respawn Monitor sub-tab - Periodically scan and kill target processes

use dioxus::prelude::*;

use crate::config::get_config_storage;
use crate::helpers::copy_to_clipboard;
use crate::state::{
    RespawnTarget, RESPAWN_INITIALIZED, RESPAWN_IS_ERROR, RESPAWN_MONITORING_ACTIVE,
    RESPAWN_MONITOR_SEARCH_QUERY, RESPAWN_STATUS, RESPAWN_TARGETS,
};

/// Kill method display name
fn kill_method_name(method: u32) -> &'static str {
    match method {
        0 => "ZwTerminate",
        1 => "Unmap Section",
        2 => "PEB Corrupt",
        _ => "Unknown",
    }
}

/// Execute kill using the specified method
fn execute_kill(pid: u32, method: u32) -> Result<(), String> {
    match method {
        0 => callback::kill_process_terminate(pid).map_err(|e| e.to_string()),
        1 => callback::kill_process_unmap(pid).map_err(|e| e.to_string()),
        2 => callback::kill_process_peb_corrupt(pid).map_err(|e| e.to_string()),
        _ => Err("Unknown kill method".to_string()),
    }
}

/// Context menu state
#[derive(Clone, Debug, Default)]
struct RespawnContextMenu {
    visible: bool,
    x: i32,
    y: i32,
    process_name: String,
}

/// Respawn Monitor sub-tab component
#[component]
pub fn RespawnMonitorTab(driver_loaded: bool) -> Element {
    let mut name_input = use_signal(|| String::new());
    let mut kill_method = use_signal(|| 0u32);
    let mut scan_interval = use_signal(|| 2u32);
    let mut context_menu = use_signal(|| RespawnContextMenu::default());

    // On mount: load persisted targets from SQLite (once)
    use_effect(move || {
        if *RESPAWN_INITIALIZED.read() {
            return;
        }
        *RESPAWN_INITIALIZED.write() = true;

        spawn(async move {
            let stored = tokio::task::spawn_blocking(|| {
                get_config_storage().load_respawn_targets()
            })
            .await
            .unwrap_or_default();

            if !stored.is_empty() {
                let count = stored.len();
                *RESPAWN_TARGETS.write() = stored;
                *RESPAWN_STATUS.write() = format!("Loaded {} target(s) from config", count);
                *RESPAWN_IS_ERROR.write() = false;
            }
        });
    });

    // Monitoring coroutine — reads global signals so it works across tab switches
    let _monitor = use_coroutine(move |mut rx: UnboundedReceiver<bool>| async move {
        loop {
            // Wait for start signal or check current state
            if !*RESPAWN_MONITORING_ACTIVE.read() {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                continue;
            }

            let current_targets = RESPAWN_TARGETS.read().clone();
            if current_targets.is_empty() {
                *RESPAWN_MONITORING_ACTIVE.write() = false;
                continue;
            }

            // Find minimum interval across all targets
            let interval_secs = current_targets
                .iter()
                .map(|t| t.scan_interval)
                .min()
                .unwrap_or(2);

            // Sleep for interval
            tokio::time::sleep(std::time::Duration::from_secs(interval_secs as u64)).await;

            // Check if still active after sleep
            if !*RESPAWN_MONITORING_ACTIVE.read() {
                continue;
            }

            // Enumerate running processes
            let all_procs = tokio::task::spawn_blocking(|| process::get_processes())
                .await
                .unwrap_or_default();

            let mut updated_targets = RESPAWN_TARGETS.read().clone();
            let mut any_killed = false;

            for target in updated_targets.iter_mut() {
                // Find matching processes (case-insensitive)
                let matching: Vec<u32> = all_procs
                    .iter()
                    .filter(|p| p.name.eq_ignore_ascii_case(&target.process_name))
                    .map(|p| p.pid)
                    .collect();

                for pid in matching {
                    if driver_loaded {
                        match execute_kill(pid, target.kill_method) {
                            Ok(()) => {
                                target.kill_count += 1;
                                target.last_killed_pid = Some(pid);
                                any_killed = true;
                            }
                            Err(_) => {}
                        }
                    }
                }
            }

            if any_killed {
                *RESPAWN_TARGETS.write() = updated_targets;
            }

            // Drain any pending messages
            while let Ok(Some(_)) = rx.try_next() {}
        }
    });

    // Save targets to SQLite
    let save_targets = move || {
        let t = RESPAWN_TARGETS.read().clone();
        spawn(async move {
            let _ = tokio::task::spawn_blocking(move || {
                crate::config::save_respawn_targets(&t);
            })
            .await;
        });
    };

    // Add target handler
    let mut add_target = move || {
        let name = name_input.read().trim().to_string();
        if name.is_empty() {
            *RESPAWN_STATUS.write() = "Enter a process name".to_string();
            *RESPAWN_IS_ERROR.write() = true;
            return;
        }

        // Check for duplicate
        if RESPAWN_TARGETS
            .read()
            .iter()
            .any(|t| t.process_name.eq_ignore_ascii_case(&name))
        {
            *RESPAWN_STATUS.write() = format!("'{}' is already monitored", name);
            *RESPAWN_IS_ERROR.write() = true;
            return;
        }

        let new_target = RespawnTarget {
            process_name: name.clone(),
            kill_method: *kill_method.read(),
            scan_interval: *scan_interval.read(),
            kill_count: 0,
            last_killed_pid: None,
        };

        RESPAWN_TARGETS.write().push(new_target);
        name_input.set(String::new());
        *RESPAWN_STATUS.write() = format!("Added '{}' to respawn monitor", name);
        *RESPAWN_IS_ERROR.write() = false;
        save_targets();
    };

    // Remove target handler
    let remove_target = move |name: String| {
        RESPAWN_TARGETS.write().retain(|t| t.process_name != name);
        save_targets();
        *RESPAWN_STATUS.write() = format!("Removed '{}'", name);
        *RESPAWN_IS_ERROR.write() = false;
    };

    // Filter targets
    let search = RESPAWN_MONITOR_SEARCH_QUERY.read().to_lowercase();
    let filtered_targets: Vec<RespawnTarget> = RESPAWN_TARGETS
        .read()
        .iter()
        .filter(|t| {
            if search.is_empty() {
                return true;
            }
            t.process_name.to_lowercase().contains(&search)
                || kill_method_name(t.kill_method)
                    .to_lowercase()
                    .contains(&search)
        })
        .cloned()
        .collect();

    rsx! {
        div {
            class: "callback-content",
            onclick: move |_| {
                context_menu.set(RespawnContextMenu::default());
            },

            // Status message
            if !RESPAWN_STATUS.read().is_empty() {
                div {
                    class: if *RESPAWN_IS_ERROR.read() { "status-message error" } else { "status-message success" },
                    "{RESPAWN_STATUS}"
                }
            }

            // Add target section
            div {
                class: "controls",
                style: "gap: 8px; align-items: center; flex-wrap: wrap;",

                input {
                    class: "search-input",
                    style: "width: 200px;",
                    r#type: "text",
                    placeholder: "Process name (e.g. notepad.exe)",
                    value: "{name_input}",
                    oninput: move |evt| name_input.set(evt.value().clone()),
                    onkeypress: move |evt| {
                        if evt.key() == Key::Enter {
                            add_target();
                        }
                    },
                }

                select {
                    class: "search-input",
                    style: "width: 150px;",
                    value: "{kill_method}",
                    onchange: move |evt| {
                        if let Ok(v) = evt.value().parse::<u32>() {
                            kill_method.set(v);
                        }
                    },
                    option { value: "0", "ZwTerminate" }
                    option { value: "1", "Unmap Section" }
                    option { value: "2", "PEB Corrupt" }
                }

                select {
                    class: "search-input",
                    style: "width: 100px;",
                    value: "{scan_interval}",
                    onchange: move |evt| {
                        if let Ok(v) = evt.value().parse::<u32>() {
                            scan_interval.set(v);
                        }
                    },
                    option { value: "1", "1 sec" }
                    option { value: "2", "2 sec" }
                    option { value: "5", "5 sec" }
                    option { value: "10", "10 sec" }
                }

                button {
                    class: "btn btn-primary",
                    disabled: !driver_loaded,
                    onclick: move |_| add_target(),
                    "Add Target"
                }

                div { style: "flex: 1;" }

                button {
                    class: if *RESPAWN_MONITORING_ACTIVE.read() { "btn btn-danger" } else { "btn btn-primary" },
                    disabled: !driver_loaded || RESPAWN_TARGETS.read().is_empty(),
                    onclick: move |_| {
                        let new_state = !*RESPAWN_MONITORING_ACTIVE.read();
                        *RESPAWN_MONITORING_ACTIVE.write() = new_state;
                        if new_state {
                            *RESPAWN_STATUS.write() = "Monitoring started".to_string();
                        } else {
                            *RESPAWN_STATUS.write() = "Monitoring stopped".to_string();
                        }
                        *RESPAWN_IS_ERROR.write() = false;
                    },
                    if *RESPAWN_MONITORING_ACTIVE.read() { "Stop Monitoring" } else { "Start Monitoring" }
                }

                button {
                    class: "btn btn-secondary",
                    disabled: RESPAWN_TARGETS.read().is_empty(),
                    onclick: move |_| {
                        *RESPAWN_MONITORING_ACTIVE.write() = false;
                        RESPAWN_TARGETS.write().clear();
                        save_targets();
                        *RESPAWN_STATUS.write() = "All targets cleared".to_string();
                        *RESPAWN_IS_ERROR.write() = false;
                    },
                    "Clear All"
                }
            }

            // Search filter
            div {
                class: "controls",
                style: "padding-top: 0;",
                input {
                    class: "search-input",
                    r#type: "text",
                    placeholder: "Filter targets...",
                    value: "{RESPAWN_MONITOR_SEARCH_QUERY}",
                    oninput: move |evt| { *RESPAWN_MONITOR_SEARCH_QUERY.write() = evt.value().clone(); },
                }

                span {
                    class: "result-count",
                    "{filtered_targets.len()} target(s)"
                }

                if *RESPAWN_MONITORING_ACTIVE.read() {
                    span {
                        class: "driver-status driver-status-loaded",
                        style: "animation: pulse 1.5s infinite;",
                        "Monitoring Active"
                    }
                }
            }

            // Targets table
            div {
                class: "table-container",

                table {
                    class: "process-table",

                    thead {
                        class: "table-header",
                        tr {
                            th { class: "th", style: "width: 30%;", "Process Name" }
                            th { class: "th", style: "width: 15%;", "Kill Method" }
                            th { class: "th", style: "width: 10%;", "Interval" }
                            th { class: "th", style: "width: 12%;", "Kill Count" }
                            th { class: "th", style: "width: 15%;", "Last Killed PID" }
                            th { class: "th", style: "width: 18%;", "Actions" }
                        }
                    }

                    tbody {
                        if filtered_targets.is_empty() {
                            tr {
                                td {
                                    class: "cell",
                                    colspan: "6",
                                    style: "text-align: center; padding: 40px; color: var(--text-secondary);",
                                    if RESPAWN_TARGETS.read().is_empty() {
                                        "No targets configured. Add a process name to monitor."
                                    } else {
                                        "No targets match the filter."
                                    }
                                }
                            }
                        }

                        for target in filtered_targets.iter() {
                            {
                                let name = target.process_name.clone();
                                let name_for_ctx = target.process_name.clone();
                                let name_for_remove = target.process_name.clone();
                                let method = target.kill_method;
                                let interval = target.scan_interval;
                                let kill_count = target.kill_count;
                                let last_pid = target.last_killed_pid;

                                rsx! {
                                    tr {
                                        class: "process-row",
                                        oncontextmenu: move |evt| {
                                            evt.prevent_default();
                                            let coords = evt.client_coordinates();
                                            context_menu.set(RespawnContextMenu {
                                                visible: true,
                                                x: coords.x as i32,
                                                y: coords.y as i32,
                                                process_name: name_for_ctx.clone(),
                                            });
                                        },

                                        td {
                                            class: "cell",
                                            span { class: "process-name", "{name}" }
                                        }
                                        td { class: "cell", "{kill_method_name(method)}" }
                                        td { class: "cell", "{interval}s" }
                                        td {
                                            class: "cell",
                                            style: if kill_count > 0 { "color: var(--accent-danger); font-weight: bold;" } else { "" },
                                            "{kill_count}"
                                        }
                                        td {
                                            class: "cell mono",
                                            if let Some(pid) = last_pid {
                                                "{pid}"
                                            } else {
                                                "—"
                                            }
                                        }
                                        td {
                                            class: "cell",
                                            button {
                                                class: "btn btn-danger",
                                                style: "padding: 2px 8px; font-size: 11px;",
                                                onclick: move |_| {
                                                    remove_target(name_for_remove.clone());
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

            // Context menu
            if context_menu.read().visible {
                div {
                    class: "context-menu",
                    style: "position: fixed; left: {context_menu.read().x}px; top: {context_menu.read().y}px; z-index: 10000;",

                    button {
                        class: "context-menu-item",
                        onclick: move |_| {
                            let name = context_menu.read().process_name.clone();
                            copy_to_clipboard(&name);
                            context_menu.set(RespawnContextMenu::default());
                        },
                        "Copy Process Name"
                    }
                    button {
                        class: "context-menu-item",
                        onclick: move |_| {
                            let name = context_menu.read().process_name.clone();
                            remove_target(name);
                            context_menu.set(RespawnContextMenu::default());
                        },
                        "Remove Target"
                    }
                }
            }
        }
    }
}
