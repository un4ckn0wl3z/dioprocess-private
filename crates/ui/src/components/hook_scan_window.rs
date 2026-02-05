//! Memory Hook Scan window component

use dioxus::prelude::*;
use misc::{scan_process_hooks, unhook_dll_remote_by_path, HookScanResult, HookType};
use std::path::Path;

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
                                th { style: "padding: 8px 12px;", "Memory Region" }
                                th { style: "padding: 8px 12px;", "Address" }
                                th { style: "padding: 8px 12px;", "Bytes" }
                                th { style: "padding: 8px 12px;", "Hook Type" }
                                th { style: "padding: 8px 12px;", "Description" }
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
                                        let result_for_ctx = result.clone();
                                        let is_selected = selected_index.read().as_ref().map(|s| *s == current_idx).unwrap_or(false);
                                        let row_class = if is_selected { "thread-row selected" } else { "thread-row" };
                                        let bytes_hex = result_clone.bytes_found.iter()
                                            .map(|b| format!("{:02X}", b))
                                            .collect::<Vec<_>>()
                                            .join(" ");
                                        let hook_type_class = get_hook_severity_class(&result_clone.hook_type);
                                        let hook_type_display = get_hook_type_display(&result_clone.hook_type);
                                        
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
                                                    // Extract target module from description (format: "[dll] module → target | ...")
                                                    let target = extract_target_module(&result_for_ctx.description);
                                                    context_menu.set(HookScanContextMenuState {
                                                        visible: true,
                                                        x: e.client_coordinates().x as i32,
                                                        y: e.client_coordinates().y as i32,
                                                        index: current_idx,
                                                        module_name: result_for_ctx.module_name.clone(),
                                                        target_module: target,
                                                        description: result_for_ctx.description.clone(),
                                                        memory_address: result_for_ctx.memory_address,
                                                        bytes_found: result_for_ctx.bytes_found.clone(),
                                                    });
                                                },
                                                
                                                td { style: "padding: 8px 12px;", "{result_clone.module_name}" }
                                                td { class: "mono", style: "padding: 8px 12px;", "0x{result_clone.memory_address:X}" }
                                                td { class: "mono", style: "padding: 8px 12px; color: #f87171;", "{bytes_hex}" }
                                                td { class: "{hook_type_class}", style: "padding: 8px 12px; font-weight: 600;", "{hook_type_display}" }
                                                td { style: "padding: 8px 12px; font-size: 12px; color: #9ca3af;", "{result_clone.description}" }
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

                        // Separator
                        div { style: "height: 1px; background: rgba(255,255,255,0.1); margin: 4px 0;" }

                        // Unhook option
                        button {
                            class: "context-menu-item context-menu-item-danger",
                            onclick: move |_| {
                                let menu = context_menu.read().clone();
                                let target_mod = menu.target_module.clone();
                                let mem_addr = menu.memory_address;
                                context_menu.set(HookScanContextMenuState::default());
                                
                                // Try to unhook the module
                                if !target_mod.is_empty() {
                                    status_message.set(format!("🔧 Attempting to unhook {}...", target_mod));
                                    let sys_dir = get_system_directory();
                                    let disk_path = format!("{}\\{}", sys_dir, target_mod);
                                    
                                    spawn(async move {
                                        // Find module base from the hooked address
                                        // For now, we need to use the scan results to get module info
                                        match tokio::task::spawn_blocking(move || {
                                            // Get module base by re-scanning to find it
                                            if let Ok(modules) = get_process_modules(pid) {
                                                for (name, base, size) in &modules {
                                                    if name.eq_ignore_ascii_case(&target_mod) 
                                                       || (mem_addr >= *base && mem_addr < (*base + *size)) {
                                                        return unhook_dll_remote_by_path(
                                                            pid,
                                                            Path::new(&disk_path),
                                                            &target_mod,
                                                            *base
                                                        );
                                                    }
                                                }
                                            }
                                            Err(misc::MiscError::FileNotFound(target_mod))
                                        }).await {
                                            Ok(Ok(result)) => {
                                                status_message.set(format!("✓ Unhooked: {} bytes restored in {}", result.bytes_replaced, result.dll_name));
                                            }
                                            Ok(Err(e)) => {
                                                status_message.set(format!("✗ Unhook failed: {}", e));
                                            }
                                            Err(e) => {
                                                status_message.set(format!("✗ Task error: {}", e));
                                            }
                                        }
                                    });
                                } else {
                                    status_message.set("✗ Cannot determine target module for unhook".to_string());
                                }
                            },
                            span { "🔓" }
                            span { "Unhook Module" }
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
    pub target_module: String,
    pub description: String,
    pub memory_address: usize,
    pub bytes_found: Vec<u8>,
}

/// Get display text for hook type
fn get_hook_type_display(hook_type: &HookType) -> &'static str {
    match hook_type {
        HookType::None => "None",
        HookType::InlineJmp => "⚠ E9 JMP",
        HookType::InlineCall => "⚠ E8 CALL",
        HookType::ShortJmp => "⚠ EB Short",
        HookType::IndirectJmp => "🔴 FF25 Indirect",
        HookType::MovJmp => "🔴 MOV+JMP x64",
    }
}

/// Get CSS class based on hook severity
fn get_hook_severity_class(hook_type: &HookType) -> &'static str {
    match hook_type {
        HookType::None => "status-clean",
        HookType::InlineJmp | HookType::InlineCall | HookType::ShortJmp => "status-hooked",
        HookType::IndirectJmp | HookType::MovJmp => "status-hooked",
    }
}

/// Extract target module name from hook description
/// Format: "[dll] module → target | ..." or "[dll] module → target hooked..."
fn extract_target_module(description: &str) -> String {
    // Try to find pattern "→ X |" or "→ X hooked"
    if let Some(arrow_pos) = description.find('→') {
        let after_arrow = &description[arrow_pos + '→'.len_utf8()..].trim_start();
        // Find the end of the module name (space, pipe, or end)
        let end_pos = after_arrow
            .find(|c: char| c == '|' || c == ' ')
            .unwrap_or(after_arrow.len());
        let module = after_arrow[..end_pos].trim();
        if !module.is_empty() {
            return module.to_string();
        }
    }
    String::new()
}

/// Get the system directory path
fn get_system_directory() -> String {
    // Use misc crate's internal function or inline the safe wrapper
    misc::get_system_directory_path()
}

/// Get process modules (name, base, size)
fn get_process_modules(pid: u32) -> Result<Vec<(String, usize, usize)>, misc::MiscError> {
    // Use the misc crate's module enumeration
    misc::enumerate_process_modules(pid)
}
