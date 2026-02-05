//! Memory Hook Scan window component

use dioxus::prelude::*;
use misc::{scan_process_hooks, HookScanResult, HookType};

use crate::helpers::copy_to_clipboard;
use crate::state::HOOK_SCAN_WINDOW_STATE;

/// Memory Hook Scan Window component
#[component]
pub fn HookScanWindow(pid: u32, process_name: String) -> Element {
    let mut scan_results = use_signal(|| Vec::<HookScanResult>::new());
    let mut status_message = use_signal(|| String::new());
    let mut is_scanning = use_signal(|| false);
    let mut filter_query = use_signal(|| String::new());
    let mut selected_index = use_signal(|| None::<usize>);
    let mut context_menu = use_signal(|| HookScanContextMenuState::default());

    // Trigger scan
    let trigger_scan = move |_| {
        is_scanning.set(true);
        status_message.set("🔍 Scanning IAT entries and comparing with disk DLLs...".to_string());
        scan_results.set(Vec::new());

        spawn(async move {
            match tokio::task::spawn_blocking(move || scan_process_hooks(pid)).await {
                Ok(Ok(results)) => {
                    let hook_count = results.len();
                    scan_results.set(results);
                    status_message.set(format!("✓ Scan complete: {} hook(s) detected", hook_count));
                    is_scanning.set(false);
                }
                Ok(Err(e)) => {
                    status_message.set(format!("✗ Scan failed: {}", e));
                    is_scanning.set(false);
                }
                Err(e) => {
                    status_message.set(format!("✗ Task error: {}", e));
                    is_scanning.set(false);
                }
            }
        });
    };

    // Filter results based on search query
    let filtered_results: Vec<(usize, HookScanResult)> = scan_results
        .read()
        .iter()
        .enumerate()
        .filter(|(_, result)| {
            let query = filter_query.read().to_lowercase();
            if query.is_empty() {
                return true;
            }
            result.module_name.to_lowercase().contains(&query)
                || result.description.to_lowercase().contains(&query)
                || format!("{:X}", result.memory_address).contains(&query.to_uppercase())
        })
        .map(|(i, r)| (i, r.clone()))
        .collect();

    let hook_count = scan_results.read().len();
    let filtered_count = filtered_results.len();

    rsx! {
        // Modal overlay
        div {
            class: "thread-modal-overlay",
            onclick: move |_| {
                *HOOK_SCAN_WINDOW_STATE.write() = None;
            },

            // Modal window
            div {
                class: "thread-modal handle-modal",
                onclick: move |e| e.stop_propagation(),

                // Header
                div {
                    class: "thread-modal-header",
                    div {
                        class: "thread-modal-title",
                        "🔍 Memory Hook Scan - {process_name} (PID: {pid})"
                    }
                    button {
                        class: "thread-modal-close",
                        onclick: move |_| {
                            *HOOK_SCAN_WINDOW_STATE.write() = None;
                        },
                        "✕"
                    }
                }

                // Controls
                div {
                    class: "thread-controls",
                    span {
                        class: "thread-count",
                        if filtered_count != hook_count {
                            "Hooks: {filtered_count}/{hook_count}"
                        } else {
                            "Hooks: {hook_count}"
                        }
                    }

                    input {
                        class: "create-process-input",
                        r#type: "text",
                        placeholder: "Filter by address or region...",
                        value: "{filter_query}",
                        oninput: move |e| filter_query.set(e.value().clone()),
                    }

                    button {
                        class: "btn btn-small btn-primary",
                        onclick: trigger_scan,
                        disabled: *is_scanning.read(),
                        if *is_scanning.read() {
                            "⏳ Scanning..."
                        } else {
                            "🔄 Scan"
                        }
                    }
                }

                // Status message
                if !status_message.read().is_empty() {
                    div {
                        class: "thread-status-message",
                        "{status_message}"
                    }
                }

                // Results table
                div {
                    class: "thread-table-container",
                    table {
                        class: "thread-table",
                        thead {
                            tr {
                                th { "Memory Region" }
                                th { "Address" }
                                th { "Bytes" }
                                th { "Hook Type" }
                                th { "Description" }
                            }
                        }
                        tbody {
                            if filtered_results.is_empty() && !*is_scanning.read() {
                                tr {
                                    td { colspan: 5, style: "text-align: center; padding: 20px;",
                                        if hook_count == 0 {
                                            "✓ No hook signatures detected in executable memory"
                                        } else {
                                            "No results match filter"
                                        }
                                    }
                                }
                            } else {
                                for (idx, result) in filtered_results.iter() {
                                    {
                                        let current_idx = *idx;
                                        let result_clone = result.clone();
                                        let is_selected = selected_index.read().as_ref().map(|s| *s == current_idx).unwrap_or(false);
                                        let row_class = if is_selected { "selected" } else { "" };
                                        let bytes_hex = result_clone.bytes_found.iter()
                                            .map(|b| format!("{:02X}", b))
                                            .collect::<Vec<_>>()
                                            .join(" ");
                                        
                                        rsx! {
                                            tr {
                                                key: "{current_idx}",
                                                class: "{row_class}",
                                                onclick: move |_| {
                                                    selected_index.set(Some(current_idx));
                                                },
                                                oncontextmenu: move |e| {
                                                    e.prevent_default();
                                                    selected_index.set(Some(current_idx));
                                                    let result_for_menu = result_clone.clone();
                                                    context_menu.set(HookScanContextMenuState {
                                                        visible: true,
                                                        x: e.client_coordinates().x as i32,
                                                        y: e.client_coordinates().y as i32,
                                                        index: current_idx,
                                                        module_name: result_for_menu.module_name,
                                                        description: result_for_menu.description,
                                                        memory_address: result_for_menu.memory_address,
                                                        bytes_found: result_for_menu.bytes_found,
                                                    });
                                                },
                                                
                                                td { "{result_clone.module_name}" }
                                                td { class: "mono", "0x{result_clone.memory_address:X}" }
                                                td { class: "mono status-hooked", "{bytes_hex}" }
                                                td { class: "status-hooked", "{get_hook_type_display(&result_clone.hook_type)}" }
                                                td { "{result_clone.description}" }
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
                        style: "left: {context_menu.read().x}px; top: clamp(5px, {context_menu.read().y}px, calc(100vh - 250px));",
                        onclick: move |e| e.stop_propagation(),

                        button {
                            class: "context-menu-item",
                            onclick: move |_| {
                                let menu = context_menu.read().clone();
                                let bytes_hex = menu.bytes_found.iter()
                                    .map(|b| format!("{:02X}", b))
                                    .collect::<Vec<_>>()
                                    .join(" ");
                                let text = format!(
                                    "Region: {}\nAddress: 0x{:X}\nBytes: {}\nDescription: {}",
                                    menu.module_name,
                                    menu.memory_address,
                                    bytes_hex,
                                    menu.description
                                );
                                copy_to_clipboard(&text);
                                context_menu.set(HookScanContextMenuState::default());
                            },
                            span { "📋" }
                            span { "Copy Details" }
                        }

                        button {
                            class: "context-menu-item",
                            onclick: move |_| {
                                let menu = context_menu.read().clone();
                                copy_to_clipboard(&format!("0x{:X}", menu.memory_address));
                                context_menu.set(HookScanContextMenuState::default());
                            },
                            span { "📋" }
                            span { "Copy Address" }
                        }

                        button {
                            class: "context-menu-item",
                            onclick: move |_| {
                                let menu = context_menu.read().clone();
                                let bytes_hex = menu.bytes_found.iter()
                                    .map(|b| format!("{:02X}", b))
                                    .collect::<Vec<_>>()
                                    .join(" ");
                                copy_to_clipboard(&bytes_hex);
                                context_menu.set(HookScanContextMenuState::default());
                            },
                            span { "📋" }
                            span { "Copy Bytes" }
                        }
                    }
                }
            }
        }

        // Click outside to close context menu
        if context_menu.read().visible {
            div {
                class: "context-menu-overlay",
                onclick: move |_| {
                    context_menu.set(HookScanContextMenuState::default());
                },
            }
        }
    }
}

/// Context menu state for hook scan results
#[derive(Clone, Debug, Default)]
pub struct HookScanContextMenuState {
    pub visible: bool,
    pub x: i32,
    pub y: i32,
    #[allow(dead_code)]
    pub index: usize,
    pub module_name: String,
    pub description: String,
    pub memory_address: usize,
    pub bytes_found: Vec<u8>,
}

/// Get display text for hook type
fn get_hook_type_display(hook_type: &HookType) -> &'static str {
    match hook_type {
        HookType::None => "None",
        HookType::IatHook => "IAT Hook",
    }
}
