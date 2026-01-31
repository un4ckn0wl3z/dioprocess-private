//! Module window component

use dioxus::prelude::*;
use process::{get_module_imports, get_process_modules, ImportEntry, ModuleInfo};

use crate::helpers::copy_to_clipboard;
use crate::state::{ModuleContextMenuState, MODULE_WINDOW_STATE};

/// Module Window component
#[component]
pub fn ModuleWindow(pid: u32, process_name: String) -> Element {
    let mut modules = use_signal(|| get_process_modules(pid));
    let mut selected_module = use_signal(|| None::<usize>);
    let mut context_menu = use_signal(|| ModuleContextMenuState::default());
    let mut status_message = use_signal(|| String::new());
    let mut auto_refresh = use_signal(|| false);
    let mut filter_name = use_signal(|| String::new());
    let mut inspecting = use_signal(|| None::<(String, Vec<ImportEntry>)>);

    // Auto-refresh every 3 seconds (if enabled)
    use_future(move || async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            if *auto_refresh.read() {
                modules.set(get_process_modules(pid));
            }
        }
    });

    let ctx_menu = context_menu.read().clone();
    let filter = filter_name.read().clone();

    // Filter modules by name
    let module_list: Vec<ModuleInfo> = modules
        .read()
        .iter()
        .filter(|m| {
            if filter.is_empty() {
                true
            } else {
                m.name.to_lowercase().contains(&filter.to_lowercase())
                    || m.path.to_lowercase().contains(&filter.to_lowercase())
            }
        })
        .cloned()
        .collect();
    let module_count = module_list.len();
    let total_modules = modules.read().len();

    let inspect_state = inspecting.read().clone();

    rsx! {
        // Modal overlay
        div {
            class: "thread-modal-overlay",
            onclick: move |_| {
                *MODULE_WINDOW_STATE.write() = None;
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
                        "📦 Modules - {process_name} (PID: {pid})"
                    }
                    button {
                        class: "thread-modal-close",
                        onclick: move |_| {
                            *MODULE_WINDOW_STATE.write() = None;
                        },
                        "✕"
                    }
                }

                if let Some((ref module_name, ref import_entries)) = inspect_state {
                    // Import detail view
                    div {
                        class: "module-import-header",
                        button {
                            onclick: move |_| {
                                inspecting.set(None);
                            },
                            "← Back"
                        }
                        span { "Imports for {module_name}" }
                    }

                    div {
                        class: "thread-table-container",
                        if import_entries.is_empty() {
                            div {
                                style: "padding: 20px; color: #6b7280; text-align: center;",
                                "No imports found (or unable to parse PE file)"
                            }
                        }
                        for entry in import_entries.iter() {
                            {
                                let dll = entry.dll_name.clone();
                                let funcs = entry.functions.clone();
                                rsx! {
                                    div { class: "module-import-dll", "{dll}" }
                                    for func in funcs.iter() {
                                        div { class: "module-import-fn", "{func}" }
                                    }
                                }
                            }
                        }
                    }
                } else {
                    // Controls
                    div {
                        class: "thread-controls",
                        span { class: "thread-count", "Modules: {module_count}/{total_modules}" }

                        input {
                            class: "handle-filter-input",
                            r#type: "text",
                            placeholder: "Filter by name...",
                            value: "{filter_name}",
                            oninput: move |e| filter_name.set(e.value().clone()),
                        }

                        label { class: "checkbox-label",
                            input {
                                r#type: "checkbox",
                                class: "checkbox",
                                checked: *auto_refresh.read(),
                                onchange: move |e| auto_refresh.set(e.checked()),
                            }
                            span { "Auto-refresh" }
                        }

                        button {
                            class: "btn btn-small btn-primary",
                            onclick: move |_| {
                                modules.set(get_process_modules(pid));
                            },
                            "🔄 Refresh"
                        }
                    }

                    // Status message
                    if !status_message.read().is_empty() {
                        div { class: "thread-status-message", "{status_message}" }
                    }

                    // Module table
                    div {
                        class: "thread-table-container",
                        table {
                            class: "thread-table",
                            thead {
                                tr {
                                    th { class: "th", "Name" }
                                    th { class: "th", "Base Address" }
                                    th { class: "th", "Size" }
                                    th { class: "th", "Path" }
                                    th { class: "th", "Actions" }
                                }
                            }
                            tbody {
                                for module in module_list {
                                    {
                                        let base = module.base_address;
                                        let mod_name = module.name.clone();
                                        let mod_path = module.path.clone();
                                        let mod_path_ctx = module.path.clone();
                                        let mod_path_inspect = module.path.clone();
                                        let mod_name_inspect = module.name.clone();
                                        let is_selected = *selected_module.read() == Some(base);
                                        let row_class = if is_selected { "thread-row selected" } else { "thread-row" };
                                        let size_display = if module.size >= 1024 * 1024 {
                                            format!("{:.1} MB", module.size as f64 / (1024.0 * 1024.0))
                                        } else {
                                            format!("{:.1} KB", module.size as f64 / 1024.0)
                                        };

                                        rsx! {
                                            tr {
                                                key: "{base}",
                                                class: "{row_class}",
                                                onclick: move |_| {
                                                    let current = *selected_module.read();
                                                    if current == Some(base) {
                                                        selected_module.set(None);
                                                    } else {
                                                        selected_module.set(Some(base));
                                                    }
                                                },
                                                oncontextmenu: {
                                                    let ctx_path = mod_path_ctx.clone();
                                                    move |e: Event<MouseData>| {
                                                        e.prevent_default();
                                                        let coords = e.client_coordinates();
                                                        selected_module.set(Some(base));
                                                        context_menu.set(ModuleContextMenuState {
                                                            visible: true,
                                                            x: coords.x as i32,
                                                            y: coords.y as i32,
                                                            module_base: Some(base),
                                                            module_path: ctx_path.clone(),
                                                        });
                                                    }
                                                },
                                                td { class: "cell", style: "font-weight: 500;", "{mod_name}" }
                                                td { class: "cell cell-handle", "0x{base:X}" }
                                                td { class: "cell", style: "font-family: monospace; color: #9ca3af;", "{size_display}" }
                                                td { class: "cell cell-path", title: "{mod_path}", "{mod_path}" }
                                                td { class: "cell cell-actions",
                                                    button {
                                                        class: "action-btn action-btn-warning",
                                                        title: "Inspect Imports",
                                                        onclick: {
                                                            let path = mod_path_inspect.clone();
                                                            let name = mod_name_inspect.clone();
                                                            move |e: Event<MouseData>| {
                                                                e.stop_propagation();
                                                                let entries = get_module_imports(&path);
                                                                inspecting.set(Some((name.clone(), entries)));
                                                            }
                                                        },
                                                        "🔍"
                                                    }
                                                    button {
                                                        class: "action-btn action-btn-danger",
                                                        title: "Unload Module",
                                                        onclick: move |e: Event<MouseData>| {
                                                            e.stop_propagation();
                                                            match misc::unload_module(pid, base) {
                                                                Ok(()) => {
                                                                    status_message.set(format!("✓ Module at 0x{:X} unloaded", base));
                                                                    modules.set(get_process_modules(pid));
                                                                }
                                                                Err(err) => {
                                                                    status_message.set(format!("✗ Unload failed: {}", err));
                                                                }
                                                            }
                                                            spawn(async move {
                                                                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                                                                status_message.set(String::new());
                                                            });
                                                        },
                                                        "✕"
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Context menu for modules
                    if ctx_menu.visible {
                        div {
                            class: "context-menu",
                            style: "left: {ctx_menu.x}px; top: {ctx_menu.y}px;",
                            onclick: move |e| e.stop_propagation(),

                            button {
                                class: "context-menu-item context-menu-item-danger",
                                onclick: {
                                    let ctx_base = ctx_menu.module_base;
                                    move |_| {
                                        if let Some(base) = ctx_base {
                                            match misc::unload_module(pid, base) {
                                                Ok(()) => {
                                                    status_message.set(format!("✓ Module at 0x{:X} unloaded", base));
                                                    modules.set(get_process_modules(pid));
                                                }
                                                Err(err) => {
                                                    status_message.set(format!("✗ Unload failed: {}", err));
                                                }
                                            }
                                            spawn(async move {
                                                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                                                status_message.set(String::new());
                                            });
                                        }
                                        context_menu.set(ModuleContextMenuState::default());
                                    }
                                },
                                span { "✕" }
                                span { "Unload Module" }
                            }

                            button {
                                class: "context-menu-item",
                                onclick: {
                                    let ctx_path = ctx_menu.module_path.clone();
                                    move |_| {
                                        let entries = get_module_imports(&ctx_path);
                                        let name = ctx_path
                                            .rsplit('\\')
                                            .next()
                                            .unwrap_or(&ctx_path)
                                            .to_string();
                                        inspecting.set(Some((name, entries)));
                                        context_menu.set(ModuleContextMenuState::default());
                                    }
                                },
                                span { "🔍" }
                                span { "Inspect Imports" }
                            }

                            div { class: "context-menu-separator" }

                            button {
                                class: "context-menu-item",
                                onclick: {
                                    let ctx_path = ctx_menu.module_path.clone();
                                    move |_| {
                                        copy_to_clipboard(&ctx_path);
                                        status_message.set("📋 Path copied".to_string());
                                        spawn(async move {
                                            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                                            status_message.set(String::new());
                                        });
                                        context_menu.set(ModuleContextMenuState::default());
                                    }
                                },
                                span { "📝" }
                                span { "Copy Path" }
                            }

                            button {
                                class: "context-menu-item",
                                onclick: {
                                    let ctx_base = ctx_menu.module_base;
                                    move |_| {
                                        if let Some(base) = ctx_base {
                                            copy_to_clipboard(&format!("0x{:X}", base));
                                            status_message.set(format!("📋 Base address 0x{:X} copied", base));
                                            spawn(async move {
                                                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                                                status_message.set(String::new());
                                            });
                                        }
                                        context_menu.set(ModuleContextMenuState::default());
                                    }
                                },
                                span { "📋" }
                                span { "Copy Base Address" }
                            }
                        }
                    }
                }
            }
        }
    }
}
