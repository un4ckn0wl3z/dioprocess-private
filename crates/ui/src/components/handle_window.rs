//! Handle window component

use dioxus::prelude::*;
use process::{close_process_handle, get_handle_type_category, get_process_handles, HandleInfo};

use crate::helpers::copy_to_clipboard;
use crate::state::{HandleContextMenuState, HANDLE_WINDOW_STATE};

/// Handle Window component
#[component]
pub fn HandleWindow(pid: u32, process_name: String) -> Element {
    let mut handles = use_signal(|| get_process_handles(pid));
    let mut selected_handle = use_signal(|| None::<u16>);
    let mut context_menu = use_signal(|| HandleContextMenuState::default());
    let mut status_message = use_signal(|| String::new());
    let mut auto_refresh = use_signal(|| false); // Disabled by default - handle enumeration is expensive
    let mut filter_type = use_signal(|| String::new());

    // Auto-refresh every 3 seconds (if enabled)
    use_future(move || async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            if *auto_refresh.read() {
                handles.set(get_process_handles(pid));
            }
        }
    });

    let ctx_menu = context_menu.read().clone();
    let filter = filter_type.read().clone();

    // Filter handles by type
    let handle_list: Vec<HandleInfo> = handles
        .read()
        .iter()
        .filter(|h| {
            if filter.is_empty() {
                true
            } else {
                h.object_type_name
                    .to_lowercase()
                    .contains(&filter.to_lowercase())
            }
        })
        .cloned()
        .collect();
    let handle_count = handle_list.len();
    let total_handles = handles.read().len();

    rsx! {
        // Modal overlay
        div {
            class: "thread-modal-overlay",
            onclick: move |_| {
                *HANDLE_WINDOW_STATE.write() = None;
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
                        "🔗 Handles - {process_name} (PID: {pid})"
                    }
                    button {
                        class: "thread-modal-close",
                        onclick: move |_| {
                            *HANDLE_WINDOW_STATE.write() = None;
                        },
                        "✕"
                    }
                }

                // Controls
                div {
                    class: "thread-controls",
                    span { class: "thread-count", "Handles: {handle_count}/{total_handles}" }

                    input {
                        class: "handle-filter-input",
                        r#type: "text",
                        placeholder: "Filter by type...",
                        value: "{filter_type}",
                        oninput: move |e| filter_type.set(e.value().clone()),
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
                            handles.set(get_process_handles(pid));
                        },
                        "🔄 Refresh"
                    }
                }

                // Status message
                if !status_message.read().is_empty() {
                    div { class: "thread-status-message", "{status_message}" }
                }

                // Handle table
                div {
                    class: "thread-table-container",
                    table {
                        class: "thread-table",
                        thead {
                            tr {
                                th { class: "th", "Handle" }
                                th { class: "th", "Type" }
                                th { class: "th", "Access" }
                                th { class: "th", "Actions" }
                            }
                        }
                        tbody {
                            for handle in handle_list {
                                {
                                    let hval = handle.handle_value;
                                    let is_selected = *selected_handle.read() == Some(hval);
                                    let row_class = if is_selected { "thread-row selected" } else { "thread-row" };
                                    let type_category = get_handle_type_category(&handle.object_type_name);
                                    let type_class = format!("handle-type handle-type-{}", type_category);

                                    rsx! {
                                        tr {
                                            key: "{hval}",
                                            class: "{row_class}",
                                            onclick: move |_| {
                                                let current = *selected_handle.read();
                                                if current == Some(hval) {
                                                    selected_handle.set(None);
                                                } else {
                                                    selected_handle.set(Some(hval));
                                                }
                                            },
                                            oncontextmenu: move |e| {
                                                e.prevent_default();
                                                let coords = e.client_coordinates();
                                                selected_handle.set(Some(hval));
                                                context_menu.set(HandleContextMenuState {
                                                    visible: true,
                                                    x: coords.x as i32,
                                                    y: coords.y as i32,
                                                    handle_value: Some(hval),
                                                });
                                            },
                                            td { class: "cell cell-handle", "0x{handle.handle_value:04X}" }
                                            td { class: "cell {type_class}", "{handle.object_type_name}" }
                                            td { class: "cell cell-access", "0x{handle.granted_access:08X}" }
                                            td { class: "cell cell-actions",
                                                button {
                                                    class: "action-btn action-btn-danger",
                                                    title: "Close Handle (Dangerous!)",
                                                    onclick: move |e| {
                                                        e.stop_propagation();
                                                        if close_process_handle(pid, hval) {
                                                            status_message.set(format!("✓ Handle 0x{:04X} closed", hval));
                                                            handles.set(get_process_handles(pid));
                                                        } else {
                                                            status_message.set(format!("✗ Failed to close handle 0x{:04X}", hval));
                                                        }
                                                        spawn(async move {
                                                            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
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

                // Context menu for handles
                if ctx_menu.visible {
                    div {
                        class: "context-menu",
                        style: "left: {ctx_menu.x}px; top: {ctx_menu.y}px;",
                        onclick: move |e| e.stop_propagation(),

                        button {
                            class: "context-menu-item context-menu-item-danger",
                            onclick: move |_| {
                                if let Some(hval) = ctx_menu.handle_value {
                                    if close_process_handle(pid, hval) {
                                        status_message.set(format!("✓ Handle 0x{:04X} closed", hval));
                                        handles.set(get_process_handles(pid));
                                    } else {
                                        status_message.set(format!("✗ Failed to close handle 0x{:04X}", hval));
                                    }
                                    spawn(async move {
                                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                                        status_message.set(String::new());
                                    });
                                }
                                context_menu.set(HandleContextMenuState::default());
                            },
                            span { "✕" }
                            span { "Close Handle" }
                        }

                        div { class: "context-menu-separator" }

                        button {
                            class: "context-menu-item",
                            onclick: move |_| {
                                if let Some(hval) = ctx_menu.handle_value {
                                    copy_to_clipboard(&format!("0x{:04X}", hval));
                                    status_message.set(format!("📋 Handle 0x{:04X} copied", hval));
                                    spawn(async move {
                                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                                        status_message.set(String::new());
                                    });
                                }
                                context_menu.set(HandleContextMenuState::default());
                            },
                            span { "📋" }
                            span { "Copy Handle Value" }
                        }
                    }
                }
            }
        }
    }
}
