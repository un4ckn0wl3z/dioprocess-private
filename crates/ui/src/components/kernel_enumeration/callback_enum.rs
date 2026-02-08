//! Callback Enumeration sub-tab

use callback::{enumerate_object_callbacks, ObjectCallbackInfo, ObjectCallbackType};
use dioxus::prelude::*;
use rfd::AsyncFileDialog;

use super::SortOrder;
use crate::helpers::copy_to_clipboard;

/// Callback type selector
#[derive(Clone, Copy, PartialEq, Debug)]
enum CallbackType {
    Process,
    Thread,
    Image,
    Object,
}

/// Sort column for callback table
#[derive(Clone, Copy, PartialEq, Debug)]
enum CallbackSortColumn {
    Index,
    Address,
    Module,
}

/// Context menu state for callback table
#[derive(Clone, Debug, Default)]
struct CallbackContextMenuState {
    visible: bool,
    x: i32,
    y: i32,
    index: u32,
    address: u64,
    module: String,
}

/// Callback Enumeration sub-tab
#[component]
pub fn CallbackEnumTab(driver_loaded: bool) -> Element {
    let mut callback_type = use_signal(|| CallbackType::Process);
    let mut callbacks = use_signal(Vec::<callback::CallbackInfo>::new);
    let mut object_callbacks = use_signal(Vec::<ObjectCallbackInfo>::new);
    let mut is_enumerating = use_signal(|| false);
    let mut status_message = use_signal(|| String::new());
    let mut search_query = use_signal(|| String::new());
    let mut sort_column = use_signal(|| CallbackSortColumn::Index);
    let mut sort_order = use_signal(|| SortOrder::Ascending);
    let mut context_menu = use_signal(|| CallbackContextMenuState::default());
    let mut selected_index = use_signal(|| None::<u32>);

    // Handle enumerate button click
    let mut handle_enumerate = move |_| {
        let is_running = *is_enumerating.read();
        if is_running {
            return;
        }

        is_enumerating.set(true);
        status_message.set(String::new());
        let cb_type = *callback_type.read();

        spawn(async move {
            if cb_type == CallbackType::Object {
                // Handle Object callbacks separately
                let result = tokio::task::spawn_blocking(enumerate_object_callbacks).await;

                match result {
                    Ok(Ok(cb_list)) => {
                        let count = cb_list.len();
                        object_callbacks.set(cb_list);
                        callbacks.set(Vec::new()); // Clear regular callbacks
                        status_message.set(format!("✓ Found {} object callbacks", count));
                    }
                    Ok(Err(e)) => {
                        status_message.set(format!("✗ Error: {}", e));
                    }
                    Err(e) => {
                        status_message.set(format!("✗ Task error: {}", e));
                    }
                }
            } else {
                // Handle regular callbacks
                let result = tokio::task::spawn_blocking(move || match cb_type {
                    CallbackType::Process => callback::enumerate_process_callbacks(),
                    CallbackType::Thread => callback::enumerate_thread_callbacks(),
                    CallbackType::Image => callback::enumerate_image_callbacks(),
                    CallbackType::Object => unreachable!(),
                })
                .await;

                match result {
                    Ok(Ok(cb_list)) => {
                        let count = cb_list.len();
                        callbacks.set(cb_list);
                        object_callbacks.set(Vec::new()); // Clear object callbacks
                        status_message.set(format!("✓ Found {} active callbacks", count));
                    }
                    Ok(Err(e)) => {
                        status_message.set(format!("✗ Error: {}", e));
                    }
                    Err(e) => {
                        status_message.set(format!("✗ Task error: {}", e));
                    }
                }
            }

            is_enumerating.set(false);
        });
    };

    // Export CSV
    let export_csv = move |_| {
        let cb_type = *callback_type.read();
        let cb_list = callbacks.read().clone();
        let obj_cb_list = object_callbacks.read().clone();
        spawn(async move {
            if let Some(file) = AsyncFileDialog::new()
                .set_file_name("callbacks.csv")
                .add_filter("CSV", &["csv"])
                .save_file()
                .await
            {
                let csv = if cb_type == CallbackType::Object {
                    let mut csv =
                        String::from("Index,Type,PreOperation,PostOperation,Module,Altitude,Operations\n");
                    for cb in obj_cb_list.iter() {
                        csv.push_str(&format!(
                            "{},{},0x{:016X},0x{:016X},{},{},{}\n",
                            cb.index,
                            cb.object_type.as_str(),
                            cb.pre_operation_callback,
                            cb.post_operation_callback,
                            cb.module_name,
                            cb.altitude,
                            cb.operations.as_string()
                        ));
                    }
                    csv
                } else {
                    let mut csv = String::from("Index,Address,Module\n");
                    for cb in cb_list.iter() {
                        csv.push_str(&format!(
                            "{},0x{:016X},{}\n",
                            cb.index, cb.callback_address, cb.module_name
                        ));
                    }
                    csv
                };
                let _ = std::fs::write(file.path(), csv);
            }
        });
    };

    // Keyboard handler
    let handle_keydown = move |e: KeyboardEvent| {
        if e.key() == Key::Escape {
            context_menu.set(CallbackContextMenuState::default());
        } else if e.key() == Key::F5 {
            handle_enumerate(());
        }
    };

    // Get all the data we need before rsx!
    let callback_list = callbacks.read().clone();
    let object_callback_list = object_callbacks.read().clone();
    let query = search_query.read().to_lowercase();
    let col = *sort_column.read();
    let order = *sort_order.read();
    let current_type = *callback_type.read();

    // Filter and sort regular callbacks
    let mut filtered_list: Vec<callback::CallbackInfo> = callback_list
        .iter()
        .filter(|c| {
            if query.is_empty() {
                return true;
            }
            c.module_name.to_lowercase().contains(&query)
                || format!("{:016X}", c.callback_address)
                    .to_lowercase()
                    .contains(&query)
                || c.index.to_string().contains(&query)
        })
        .cloned()
        .collect();

    filtered_list.sort_by(|a, b| {
        let cmp = match col {
            CallbackSortColumn::Index => a.index.cmp(&b.index),
            CallbackSortColumn::Address => a.callback_address.cmp(&b.callback_address),
            CallbackSortColumn::Module => a
                .module_name
                .to_lowercase()
                .cmp(&b.module_name.to_lowercase()),
        };
        if order == SortOrder::Descending {
            cmp.reverse()
        } else {
            cmp
        }
    });

    // Filter and sort object callbacks
    let mut filtered_object_list: Vec<ObjectCallbackInfo> = object_callback_list
        .iter()
        .filter(|c| {
            if query.is_empty() {
                return true;
            }
            c.module_name.to_lowercase().contains(&query)
                || c.altitude.to_lowercase().contains(&query)
                || format!("{:016X}", c.pre_operation_callback)
                    .to_lowercase()
                    .contains(&query)
                || format!("{:016X}", c.post_operation_callback)
                    .to_lowercase()
                    .contains(&query)
                || c.object_type.as_str().to_lowercase().contains(&query)
        })
        .cloned()
        .collect();

    filtered_object_list.sort_by(|a, b| {
        let cmp = match col {
            CallbackSortColumn::Index => a.index.cmp(&b.index),
            CallbackSortColumn::Address => {
                a.pre_operation_callback.cmp(&b.pre_operation_callback)
            }
            CallbackSortColumn::Module => a
                .module_name
                .to_lowercase()
                .cmp(&b.module_name.to_lowercase()),
        };
        if order == SortOrder::Descending {
            cmp.reverse()
        } else {
            cmp
        }
    });

    let is_running = *is_enumerating.read();
    let status_msg = status_message.read().clone();
    let query_text = search_query.read().clone();
    let ctx_menu = context_menu.read().clone();
    let is_object_type = current_type == CallbackType::Object;
    let has_data = if is_object_type {
        !object_callback_list.is_empty()
    } else {
        !callback_list.is_empty()
    };

    // Sort indicator
    let sort_indicator = move |col_check: CallbackSortColumn| -> String {
        if *sort_column.read() == col_check {
            if *sort_order.read() == SortOrder::Ascending {
                " ▲".to_string()
            } else {
                " ▼".to_string()
            }
        } else {
            String::new()
        }
    };

    // Make sort handler
    let make_sort_handler = move |col: CallbackSortColumn| {
        move |_| {
            if *sort_column.read() == col {
                let new_order = if *sort_order.read() == SortOrder::Ascending {
                    SortOrder::Descending
                } else {
                    SortOrder::Ascending
                };
                sort_order.set(new_order);
            } else {
                sort_column.set(col);
                sort_order.set(SortOrder::Ascending);
            }
        }
    };

    rsx! {
        div {
            style: "display: flex; flex-direction: column; flex: 1; overflow: hidden;",
            tabindex: "0",
            onkeydown: handle_keydown,
            onclick: move |_| context_menu.set(CallbackContextMenuState::default()),

            // Controls
            div { class: "controls",
                // Callback type selector
                button {
                    class: if current_type == CallbackType::Process { "btn btn-secondary active" } else { "btn btn-secondary" },
                    onclick: move |_| {
                        callback_type.set(CallbackType::Process);
                        callbacks.set(Vec::new());
                        object_callbacks.set(Vec::new());
                        status_message.set(String::new());
                    },
                    "Process"
                }
                button {
                    class: if current_type == CallbackType::Thread { "btn btn-secondary active" } else { "btn btn-secondary" },
                    onclick: move |_| {
                        callback_type.set(CallbackType::Thread);
                        callbacks.set(Vec::new());
                        object_callbacks.set(Vec::new());
                        status_message.set(String::new());
                    },
                    "Thread"
                }
                button {
                    class: if current_type == CallbackType::Image { "btn btn-secondary active" } else { "btn btn-secondary" },
                    onclick: move |_| {
                        callback_type.set(CallbackType::Image);
                        callbacks.set(Vec::new());
                        object_callbacks.set(Vec::new());
                        status_message.set(String::new());
                    },
                    "Image Load"
                }
                button {
                    class: if current_type == CallbackType::Object { "btn btn-secondary active" } else { "btn btn-secondary" },
                    onclick: move |_| {
                        callback_type.set(CallbackType::Object);
                        callbacks.set(Vec::new());
                        object_callbacks.set(Vec::new());
                        status_message.set(String::new());
                    },
                    "Object"
                }

                // Search bar
                input {
                    class: "search-input",
                    r#type: "text",
                    placeholder: "Search callbacks...",
                    value: "{query_text}",
                    oninput: move |e| search_query.set(e.value().clone()),
                }

                // Action buttons
                button {
                    class: "btn btn-primary",
                    disabled: !driver_loaded || is_running,
                    onclick: move |_| handle_enumerate(()),
                    if is_running { "Enumerating..." } else { "Refresh" }
                }

                button {
                    class: "btn btn-secondary",
                    disabled: !has_data,
                    onclick: export_csv,
                    "Export CSV"
                }

                // Status message inline
                if !status_msg.is_empty() {
                    span { class: "status-message", "{status_msg}" }
                }
            }

            // Callback table - conditionally render based on type
            div { class: "table-container",
                if is_object_type {
                    // Object callback table
                    table { class: "process-table",
                        thead { class: "table-header",
                            tr {
                                th { class: "th", "Type" }
                                th {
                                    class: "th sortable",
                                    onclick: make_sort_handler(CallbackSortColumn::Address),
                                    "Pre-Operation{sort_indicator(CallbackSortColumn::Address)}"
                                }
                                th { class: "th", "Post-Operation" }
                                th {
                                    class: "th sortable",
                                    onclick: make_sort_handler(CallbackSortColumn::Module),
                                    "Module{sort_indicator(CallbackSortColumn::Module)}"
                                }
                                th { class: "th", "Altitude" }
                                th { class: "th", "Operations" }
                            }
                        }

                        tbody {
                            if filtered_object_list.is_empty() && !object_callback_list.is_empty() {
                                tr {
                                    td { colspan: "6", class: "no-results",
                                        "No callbacks match your search"
                                    }
                                }
                            } else if object_callback_list.is_empty() {
                                tr {
                                    td { colspan: "6", class: "no-results",
                                        if driver_loaded {
                                            "Click 'Refresh' to enumerate object callbacks"
                                        } else {
                                            "Driver not loaded - Load DioProcess.sys to use this feature"
                                        }
                                    }
                                }
                            } else {
                                for cb in filtered_object_list.into_iter() {
                                    tr {
                                        key: "{cb.index}",
                                        class: if *selected_index.read() == Some(cb.index) { "process-row selected" } else { "process-row" },
                                        onclick: move |_| {
                                            let current = *selected_index.read();
                                            if current == Some(cb.index) {
                                                selected_index.set(None);
                                            } else {
                                                selected_index.set(Some(cb.index));
                                            }
                                        },
                                        oncontextmenu: move |e| {
                                            e.prevent_default();
                                            selected_index.set(Some(cb.index));
                                            context_menu.set(CallbackContextMenuState {
                                                visible: true,
                                                x: e.page_coordinates().x as i32,
                                                y: e.page_coordinates().y as i32,
                                                index: cb.index,
                                                address: cb.pre_operation_callback,
                                                module: cb.module_name.clone(),
                                            });
                                        },

                                        td {
                                            class: "cell",
                                            span {
                                                class: if cb.object_type == ObjectCallbackType::Process { "cpu-low" } else { "" },
                                                style: "font-weight: 600;",
                                                "{cb.object_type.as_str()}"
                                            }
                                        }
                                        td { class: "cell mono",
                                            if cb.pre_operation_callback != 0 {
                                                "0x{cb.pre_operation_callback:016X}"
                                            } else {
                                                "—"
                                            }
                                        }
                                        td { class: "cell mono",
                                            if cb.post_operation_callback != 0 {
                                                "0x{cb.post_operation_callback:016X}"
                                            } else {
                                                "—"
                                            }
                                        }
                                        td { class: "cell", "{cb.module_name}" }
                                        td { class: "cell mono", "{cb.altitude}" }
                                        td { class: "cell", "{cb.operations.as_string()}" }
                                    }
                                }
                            }
                        }
                    }
                } else {
                    // Regular callback table
                    table { class: "process-table",
                        thead { class: "table-header",
                            tr {
                                th {
                                    class: "th sortable",
                                    onclick: make_sort_handler(CallbackSortColumn::Index),
                                    "Index{sort_indicator(CallbackSortColumn::Index)}"
                                }
                                th {
                                    class: "th sortable",
                                    onclick: make_sort_handler(CallbackSortColumn::Address),
                                    "Callback Address{sort_indicator(CallbackSortColumn::Address)}"
                                }
                                th {
                                    class: "th sortable",
                                    onclick: make_sort_handler(CallbackSortColumn::Module),
                                    "Driver Module{sort_indicator(CallbackSortColumn::Module)}"
                                }
                            }
                        }

                        tbody {
                            if filtered_list.is_empty() && !callback_list.is_empty() {
                                tr {
                                    td { colspan: "3", class: "no-results",
                                        "No callbacks match your search"
                                    }
                                }
                            } else if callback_list.is_empty() {
                                tr {
                                    td { colspan: "3", class: "no-results",
                                        if driver_loaded {
                                            "Click 'Refresh' to enumerate callbacks"
                                        } else {
                                            "Driver not loaded - Load DioProcess.sys to use this feature"
                                        }
                                    }
                                }
                            } else {
                                for cb in filtered_list.into_iter() {
                                    tr {
                                        key: "{cb.index}",
                                        class: if *selected_index.read() == Some(cb.index) { "process-row selected" } else { "process-row" },
                                        onclick: move |_| {
                                            let current = *selected_index.read();
                                            if current == Some(cb.index) {
                                                selected_index.set(None);
                                            } else {
                                                selected_index.set(Some(cb.index));
                                            }
                                        },
                                        oncontextmenu: move |e| {
                                            e.prevent_default();
                                            selected_index.set(Some(cb.index));
                                            context_menu.set(CallbackContextMenuState {
                                                visible: true,
                                                x: e.page_coordinates().x as i32,
                                                y: e.page_coordinates().y as i32,
                                                index: cb.index,
                                                address: cb.callback_address,
                                                module: cb.module_name.clone(),
                                            });
                                        },

                                        td { class: "cell", "{cb.index}" }
                                        td { class: "cell mono", "0x{cb.callback_address:016X}" }
                                        td { class: "cell", "{cb.module_name}" }
                                    }
                                }
                            }
                        }
                    }
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
                            copy_to_clipboard(&ctx_menu.index.to_string());
                            context_menu.set(CallbackContextMenuState::default());
                        },
                        "Copy Index"
                    }
                    button {
                        class: "context-menu-item",
                        onclick: move |_| {
                            copy_to_clipboard(&format!("0x{:016X}", ctx_menu.address));
                            context_menu.set(CallbackContextMenuState::default());
                        },
                        "Copy Address"
                    }
                    button {
                        class: "context-menu-item",
                        onclick: move |_| {
                            copy_to_clipboard(&ctx_menu.module);
                            context_menu.set(CallbackContextMenuState::default());
                        },
                        "Copy Module"
                    }
                }
            }
        }
    }
}
