//! Callback Enumeration sub-tab

use callback::{
    enumerate_object_callbacks, enumerate_registry_callbacks, remove_image_callback,
    remove_object_callback, remove_process_callback, remove_registry_callback,
    remove_thread_callback, restore_image_callback, restore_object_callback,
    restore_process_callback, restore_registry_callback, restore_thread_callback,
    ObjectCallbackInfo, ObjectCallbackType, RegistryCallbackInfo,
};
use dioxus::prelude::*;
use rfd::AsyncFileDialog;
use std::collections::HashMap;

use super::SortOrder;
use crate::helpers::copy_to_clipboard;
use crate::state::CALLBACK_ENUM_SEARCH_QUERY;

/// Callback type selector
#[derive(Clone, Copy, PartialEq, Debug)]
enum CallbackType {
    Process,
    Thread,
    Image,
    Object,
    Registry,
}

/// Sort column for callback table
#[derive(Clone, Copy, PartialEq, Debug)]
enum CallbackSortColumn {
    Index,
    Address,
    Module,
}

/// Tracks a removed callback for restoration (object callbacks only need Pre/Post state)
#[derive(Clone, Debug, Default)]
struct RemovedCallbackInfo {
    removed_pre: bool,
    removed_post: bool,
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
    object_type: Option<ObjectCallbackType>, // For object callbacks (OCKC style)
    has_pre_op: bool,                         // Whether callback has PreOperation
    has_post_op: bool,                        // Whether callback has PostOperation
    is_removed: bool,                         // Whether this callback was removed
}

/// Callback Enumeration sub-tab
#[component]
pub fn CallbackEnumTab(driver_loaded: bool) -> Element {
    let mut callback_type = use_signal(|| CallbackType::Process);
    let mut callbacks = use_signal(Vec::<callback::CallbackInfo>::new);
    let mut object_callbacks = use_signal(Vec::<ObjectCallbackInfo>::new);
    let mut registry_callbacks = use_signal(Vec::<RegistryCallbackInfo>::new);
    let mut is_enumerating = use_signal(|| false);
    let mut status_message = use_signal(|| String::new());
    let mut sort_column = use_signal(|| CallbackSortColumn::Index);
    let mut sort_order = use_signal(|| SortOrder::Ascending);
    let mut context_menu = use_signal(|| CallbackContextMenuState::default());
    let mut selected_index = use_signal(|| None::<u32>);

    // Track removed callbacks per type (keyed by index)
    let mut removed_process = use_signal(HashMap::<u32, RemovedCallbackInfo>::new);
    let mut removed_thread = use_signal(HashMap::<u32, RemovedCallbackInfo>::new);
    let mut removed_image = use_signal(HashMap::<u32, RemovedCallbackInfo>::new);
    let mut removed_object = use_signal(HashMap::<u32, RemovedCallbackInfo>::new);
    let mut removed_registry = use_signal(HashMap::<u32, RemovedCallbackInfo>::new);

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
                        callbacks.set(Vec::new());
                        registry_callbacks.set(Vec::new());
                        status_message.set(format!("✓ Found {} object callbacks", count));
                    }
                    Ok(Err(e)) => {
                        status_message.set(format!("✗ Error: {}", e));
                    }
                    Err(e) => {
                        status_message.set(format!("✗ Task error: {}", e));
                    }
                }
            } else if cb_type == CallbackType::Registry {
                // Handle Registry callbacks (RCK style)
                let result = tokio::task::spawn_blocking(enumerate_registry_callbacks).await;

                match result {
                    Ok(Ok(cb_list)) => {
                        let count = cb_list.len();
                        registry_callbacks.set(cb_list);
                        callbacks.set(Vec::new());
                        object_callbacks.set(Vec::new());
                        status_message.set(format!("✓ Found {} registry callbacks", count));
                    }
                    Ok(Err(e)) => {
                        status_message.set(format!("✗ Error: {}", e));
                    }
                    Err(e) => {
                        status_message.set(format!("✗ Task error: {}", e));
                    }
                }
            } else {
                // Handle regular callbacks (Process/Thread/Image)
                let result = tokio::task::spawn_blocking(move || match cb_type {
                    CallbackType::Process => callback::enumerate_process_callbacks(),
                    CallbackType::Thread => callback::enumerate_thread_callbacks(),
                    CallbackType::Image => callback::enumerate_image_callbacks(),
                    CallbackType::Object | CallbackType::Registry => unreachable!(),
                })
                .await;

                match result {
                    Ok(Ok(cb_list)) => {
                        let count = cb_list.len();
                        callbacks.set(cb_list);
                        object_callbacks.set(Vec::new());
                        registry_callbacks.set(Vec::new());
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
        let reg_cb_list = registry_callbacks.read().clone();
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
                } else if cb_type == CallbackType::Registry {
                    let mut csv = String::from("Index,Address,Module,ModuleBase,Offset,Altitude,Context\n");
                    for cb in reg_cb_list.iter() {
                        csv.push_str(&format!(
                            "{},0x{:016X},{},0x{:016X},0x{:X},{},0x{:016X}\n",
                            cb.index, cb.callback_address, cb.module_name,
                            cb.module_base, cb.module_offset, cb.altitude, cb.context
                        ));
                    }
                    csv
                } else {
                    let mut csv = String::from("Index,Address,Module,ModuleBase,Offset\n");
                    for cb in cb_list.iter() {
                        csv.push_str(&format!(
                            "{},0x{:016X},{},0x{:016X},0x{:X}\n",
                            cb.index, cb.callback_address, cb.module_name,
                            cb.module_base, cb.module_offset
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
    let registry_callback_list = registry_callbacks.read().clone();
    let query = CALLBACK_ENUM_SEARCH_QUERY.read().to_lowercase();
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

    // Filter and sort registry callbacks
    let mut filtered_registry_list: Vec<RegistryCallbackInfo> = registry_callback_list
        .iter()
        .filter(|c| {
            if query.is_empty() {
                return true;
            }
            c.module_name.to_lowercase().contains(&query)
                || c.altitude.to_lowercase().contains(&query)
                || format!("{:016X}", c.callback_address)
                    .to_lowercase()
                    .contains(&query)
                || c.index.to_string().contains(&query)
        })
        .cloned()
        .collect();

    filtered_registry_list.sort_by(|a, b| {
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

    let is_running = *is_enumerating.read();
    let status_msg = status_message.read().clone();
    let query_text = CALLBACK_ENUM_SEARCH_QUERY.read().clone();
    let ctx_menu = context_menu.read().clone();
    let is_object_type = current_type == CallbackType::Object;
    let is_registry_type = current_type == CallbackType::Registry;
    let has_data = if is_object_type {
        !object_callback_list.is_empty()
    } else if is_registry_type {
        !registry_callback_list.is_empty()
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

    // Handle remove callback
    let handle_remove = move |index: u32, module_name: String, _original_address: u64| {
        let cb_type = *callback_type.read();
        let module_clone = module_name.clone();

        spawn(async move {
            let result = tokio::task::spawn_blocking(move || match cb_type {
                CallbackType::Process => remove_process_callback(index),
                CallbackType::Thread => remove_thread_callback(index),
                CallbackType::Image => remove_image_callback(index),
                CallbackType::Registry => remove_registry_callback(index),
                CallbackType::Object => {
                    // Object callbacks cannot be removed this way - use handle_remove_object
                    Err(callback::CallbackError::IoctlFailed(0))
                }
            })
            .await;

            match result {
                Ok(Ok(())) => {
                    // Track the removed callback
                    let info = RemovedCallbackInfo::default();
                    match cb_type {
                        CallbackType::Process => {
                            removed_process.write().insert(index, info);
                        }
                        CallbackType::Thread => {
                            removed_thread.write().insert(index, info);
                        }
                        CallbackType::Image => {
                            removed_image.write().insert(index, info);
                        }
                        CallbackType::Registry => {
                            removed_registry.write().insert(index, info);
                        }
                        CallbackType::Object => {}
                    }
                    status_message.set(format!(
                        "Removed {} callback at index {} ({}) - can restore later",
                        match cb_type {
                            CallbackType::Process => "process",
                            CallbackType::Thread => "thread",
                            CallbackType::Image => "image",
                            CallbackType::Registry => "registry",
                            CallbackType::Object => "object",
                        },
                        index,
                        module_clone
                    ));
                }
                Ok(Err(e)) => {
                    status_message.set(format!("Failed to remove callback: {:?}", e));
                }
                Err(e) => {
                    status_message.set(format!("Task error: {}", e));
                }
            }
        });
    };

    // Handle remove object callback (OCKC style - uses InterlockedExchangePointer)
    let handle_remove_object =
        move |index: u32, obj_type: ObjectCallbackType, remove_pre: bool, remove_post: bool| {
            let module_name = {
                let ctx = context_menu.read();
                ctx.module.clone()
            };
            let module_clone = module_name.clone();

            spawn(async move {
                let result = tokio::task::spawn_blocking(move || {
                    remove_object_callback(index, obj_type, remove_pre, remove_post)
                })
                .await;

                match result {
                    Ok(Ok(())) => {
                        // Track the removed object callback
                        let mut map = removed_object.write();
                        let info = map.entry(index).or_insert(RemovedCallbackInfo::default());
                        if remove_pre {
                            info.removed_pre = true;
                        }
                        if remove_post {
                            info.removed_post = true;
                        }
                        drop(map);

                        let ops = match (remove_pre, remove_post) {
                            (true, true) => "Pre+Post",
                            (true, false) => "Pre",
                            (false, true) => "Post",
                            _ => "",
                        };
                        status_message.set(format!(
                            "Removed {} object callback {} at index {} ({}) - can restore later",
                            obj_type.as_str(),
                            ops,
                            index,
                            module_clone
                        ));
                    }
                    Ok(Err(e)) => {
                        status_message.set(format!("Failed to remove object callback: {:?}", e));
                    }
                    Err(e) => {
                        status_message.set(format!("Task error: {}", e));
                    }
                }
            });
        };

    // Handle restore callback (for Process/Thread/Image/Registry)
    let handle_restore = move |index: u32, module_name: String| {
        let cb_type = *callback_type.read();
        let module_clone = module_name.clone();

        spawn(async move {
            let result = tokio::task::spawn_blocking(move || match cb_type {
                CallbackType::Process => restore_process_callback(index),
                CallbackType::Thread => restore_thread_callback(index),
                CallbackType::Image => restore_image_callback(index),
                CallbackType::Registry => restore_registry_callback(index),
                CallbackType::Object => {
                    // Object callbacks use handle_restore_object
                    Err(callback::CallbackError::IoctlFailed(0))
                }
            })
            .await;

            match result {
                Ok(Ok(())) => {
                    // Remove from tracking
                    match cb_type {
                        CallbackType::Process => {
                            removed_process.write().remove(&index);
                        }
                        CallbackType::Thread => {
                            removed_thread.write().remove(&index);
                        }
                        CallbackType::Image => {
                            removed_image.write().remove(&index);
                        }
                        CallbackType::Registry => {
                            removed_registry.write().remove(&index);
                        }
                        CallbackType::Object => {}
                    }
                    status_message.set(format!(
                        "Restored {} callback at index {} ({})",
                        match cb_type {
                            CallbackType::Process => "process",
                            CallbackType::Thread => "thread",
                            CallbackType::Image => "image",
                            CallbackType::Registry => "registry",
                            CallbackType::Object => "object",
                        },
                        index,
                        module_clone
                    ));
                }
                Ok(Err(e)) => {
                    status_message.set(format!("Failed to restore callback: {:?}", e));
                }
                Err(e) => {
                    status_message.set(format!("Task error: {}", e));
                }
            }
        });
    };

    // Handle restore object callback
    let handle_restore_object =
        move |index: u32, obj_type: ObjectCallbackType, restore_pre: bool, restore_post: bool| {
            let module_name = {
                let ctx = context_menu.read();
                ctx.module.clone()
            };
            let module_clone = module_name.clone();

            spawn(async move {
                let result = tokio::task::spawn_blocking(move || {
                    restore_object_callback(index, obj_type, restore_pre, restore_post)
                })
                .await;

                match result {
                    Ok(Ok(())) => {
                        // Update tracking
                        let mut map = removed_object.write();
                        if let Some(info) = map.get_mut(&index) {
                            if restore_pre {
                                info.removed_pre = false;
                            }
                            if restore_post {
                                info.removed_post = false;
                            }
                            // If both restored, remove from tracking
                            if !info.removed_pre && !info.removed_post {
                                map.remove(&index);
                            }
                        }
                        drop(map);

                        let ops = match (restore_pre, restore_post) {
                            (true, true) => "Pre+Post",
                            (true, false) => "Pre",
                            (false, true) => "Post",
                            _ => "",
                        };
                        status_message.set(format!(
                            "Restored {} object callback {} at index {} ({})",
                            obj_type.as_str(),
                            ops,
                            index,
                            module_clone
                        ));
                    }
                    Ok(Err(e)) => {
                        status_message.set(format!("Failed to restore object callback: {:?}", e));
                    }
                    Err(e) => {
                        status_message.set(format!("Task error: {}", e));
                    }
                }
            });
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
                        registry_callbacks.set(Vec::new());
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
                        registry_callbacks.set(Vec::new());
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
                        registry_callbacks.set(Vec::new());
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
                        registry_callbacks.set(Vec::new());
                        status_message.set(String::new());
                    },
                    "Object"
                }
                button {
                    class: if current_type == CallbackType::Registry { "btn btn-secondary active" } else { "btn btn-secondary" },
                    onclick: move |_| {
                        callback_type.set(CallbackType::Registry);
                        callbacks.set(Vec::new());
                        object_callbacks.set(Vec::new());
                        registry_callbacks.set(Vec::new());
                        status_message.set(String::new());
                    },
                    "Registry"
                }

                // Search bar
                input {
                    class: "search-input",
                    r#type: "text",
                    placeholder: "Search callbacks...",
                    value: "{query_text}",
                    oninput: move |e| { *CALLBACK_ENUM_SEARCH_QUERY.write() = e.value().clone(); },
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
                                            let removed_info = removed_object.read().get(&cb.index).cloned();
                                            let is_removed = removed_info.is_some();
                                            context_menu.set(CallbackContextMenuState {
                                                visible: true,
                                                x: e.page_coordinates().x as i32,
                                                y: e.page_coordinates().y as i32,
                                                index: cb.index,
                                                address: cb.pre_operation_callback,
                                                module: cb.module_name.clone(),
                                                object_type: Some(cb.object_type),
                                                has_pre_op: cb.pre_operation_callback != 0,
                                                has_post_op: cb.post_operation_callback != 0,
                                                is_removed,
                                            });
                                        },

                                        td {
                                            class: "cell",
                                            span {
                                                class: if cb.object_type == ObjectCallbackType::Process { "cpu-low" } else { "" },
                                                style: "font-weight: 600;",
                                                "{cb.object_type.as_str()}"
                                            }
                                            {
                                                let removed_info = removed_object.read().get(&cb.index).cloned();
                                                if let Some(info) = removed_info {
                                                    if info.removed_pre && info.removed_post {
                                                        rsx! { span { class: "removed-badge", " (Both Removed)" } }
                                                    } else if info.removed_pre {
                                                        rsx! { span { class: "removed-badge", " (Pre Removed)" } }
                                                    } else if info.removed_post {
                                                        rsx! { span { class: "removed-badge", " (Post Removed)" } }
                                                    } else {
                                                        rsx! {}
                                                    }
                                                } else {
                                                    rsx! {}
                                                }
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
                } else if is_registry_type {
                    // Registry callback table (RCK style)
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
                                th { class: "th", "Altitude" }
                            }
                        }

                        tbody {
                            if filtered_registry_list.is_empty() && !registry_callback_list.is_empty() {
                                tr {
                                    td { colspan: "4", class: "no-results",
                                        "No callbacks match your search"
                                    }
                                }
                            } else if registry_callback_list.is_empty() {
                                tr {
                                    td { colspan: "4", class: "no-results",
                                        if driver_loaded {
                                            "Click 'Refresh' to enumerate registry callbacks"
                                        } else {
                                            "Driver not loaded - Load DioProcess.sys to use this feature"
                                        }
                                    }
                                }
                            } else {
                                for cb in filtered_registry_list.into_iter() {
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
                                            let is_removed = removed_registry.read().contains_key(&cb.index);
                                            context_menu.set(CallbackContextMenuState {
                                                visible: true,
                                                x: e.page_coordinates().x as i32,
                                                y: e.page_coordinates().y as i32,
                                                index: cb.index,
                                                address: cb.callback_address,
                                                module: cb.module_name.clone(),
                                                object_type: None,
                                                has_pre_op: false,
                                                has_post_op: false,
                                                is_removed,
                                            });
                                        },

                                        td { class: "cell",
                                            "{cb.index}"
                                            if removed_registry.read().contains_key(&cb.index) {
                                                span { class: "removed-badge", " (Removed)" }
                                            }
                                        }
                                        td { class: "cell mono", "0x{cb.callback_address:016X}" }
                                        td { class: "cell",
                                            if cb.module_offset > 0 {
                                                "{cb.module_name}+0x{cb.module_offset:X}"
                                            } else {
                                                "{cb.module_name}"
                                            }
                                        }
                                        td { class: "cell mono", "{cb.altitude}" }
                                    }
                                }
                            }
                        }
                    }
                } else {
                    // Regular callback table (Process/Thread/Image)
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
                                            let is_removed = match current_type {
                                                CallbackType::Process => removed_process.read().contains_key(&cb.index),
                                                CallbackType::Thread => removed_thread.read().contains_key(&cb.index),
                                                CallbackType::Image => removed_image.read().contains_key(&cb.index),
                                                _ => false,
                                            };
                                            context_menu.set(CallbackContextMenuState {
                                                visible: true,
                                                x: e.page_coordinates().x as i32,
                                                y: e.page_coordinates().y as i32,
                                                index: cb.index,
                                                address: cb.callback_address,
                                                module: cb.module_name.clone(),
                                                object_type: None,
                                                has_pre_op: false,
                                                has_post_op: false,
                                                is_removed,
                                            });
                                        },

                                        td { class: "cell",
                                            "{cb.index}"
                                            {
                                                let is_removed = match current_type {
                                                    CallbackType::Process => removed_process.read().contains_key(&cb.index),
                                                    CallbackType::Thread => removed_thread.read().contains_key(&cb.index),
                                                    CallbackType::Image => removed_image.read().contains_key(&cb.index),
                                                    _ => false,
                                                };
                                                if is_removed {
                                                    rsx! { span { class: "removed-badge", " (Removed)" } }
                                                } else {
                                                    rsx! {}
                                                }
                                            }
                                        }
                                        td { class: "cell mono", "0x{cb.callback_address:016X}" }
                                        td { class: "cell",
                                            // Show module+offset format like TCKC
                                            if cb.module_offset > 0 {
                                                "{cb.module_name}+0x{cb.module_offset:X}"
                                            } else {
                                                "{cb.module_name}"
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

                    // Divider and Remove/Restore buttons (only for Process/Thread/Image/Registry, not Object)
                    if current_type != CallbackType::Object {
                        div { class: "context-menu-divider" }
                        // Only show Remove if not already removed
                        if !ctx_menu.is_removed {
                            button {
                                class: "context-menu-item context-menu-danger",
                                onclick: {
                                    let idx = ctx_menu.index;
                                    let module = ctx_menu.module.clone();
                                    let addr = ctx_menu.address;
                                    move |_| {
                                        handle_remove(idx, module.clone(), addr);
                                        context_menu.set(CallbackContextMenuState::default());
                                    }
                                },
                                "Remove Callback"
                            }
                        }
                        // Always show Restore (kernel will error if not previously removed)
                        button {
                            class: "context-menu-item context-menu-restore",
                            onclick: {
                                let idx = ctx_menu.index;
                                let module = ctx_menu.module.clone();
                                move |_| {
                                    handle_restore(idx, module.clone());
                                    context_menu.set(CallbackContextMenuState::default());
                                }
                            },
                            "Restore Callback"
                        }
                    }

                    // Object callback removal/restore options (OCKC style)
                    if current_type == CallbackType::Object {
                        div { class: "context-menu-divider" }

                        // Remove PreOperation
                        if ctx_menu.has_pre_op {
                            button {
                                class: "context-menu-item context-menu-danger",
                                onclick: {
                                    let idx = ctx_menu.index;
                                    let obj_type = ctx_menu.object_type.unwrap_or(ObjectCallbackType::Process);
                                    move |_| {
                                        handle_remove_object(idx, obj_type, true, false);
                                        context_menu.set(CallbackContextMenuState::default());
                                    }
                                },
                                "Remove Pre-Operation"
                            }
                        }

                        // Remove PostOperation
                        if ctx_menu.has_post_op {
                            button {
                                class: "context-menu-item context-menu-danger",
                                onclick: {
                                    let idx = ctx_menu.index;
                                    let obj_type = ctx_menu.object_type.unwrap_or(ObjectCallbackType::Process);
                                    move |_| {
                                        handle_remove_object(idx, obj_type, false, true);
                                        context_menu.set(CallbackContextMenuState::default());
                                    }
                                },
                                "Remove Post-Operation"
                            }
                        }

                        // Remove Both
                        if ctx_menu.has_pre_op && ctx_menu.has_post_op {
                            button {
                                class: "context-menu-item context-menu-danger",
                                onclick: {
                                    let idx = ctx_menu.index;
                                    let obj_type = ctx_menu.object_type.unwrap_or(ObjectCallbackType::Process);
                                    move |_| {
                                        handle_remove_object(idx, obj_type, true, true);
                                        context_menu.set(CallbackContextMenuState::default());
                                    }
                                },
                                "Remove Both"
                            }
                        }

                        // Restore divider
                        div { class: "context-menu-divider" }

                        // Restore PreOperation
                        button {
                            class: "context-menu-item context-menu-restore",
                            onclick: {
                                let idx = ctx_menu.index;
                                let obj_type = ctx_menu.object_type.unwrap_or(ObjectCallbackType::Process);
                                move |_| {
                                    handle_restore_object(idx, obj_type, true, false);
                                    context_menu.set(CallbackContextMenuState::default());
                                }
                            },
                            "Restore Pre-Operation"
                        }

                        // Restore PostOperation
                        button {
                            class: "context-menu-item context-menu-restore",
                            onclick: {
                                let idx = ctx_menu.index;
                                let obj_type = ctx_menu.object_type.unwrap_or(ObjectCallbackType::Process);
                                move |_| {
                                    handle_restore_object(idx, obj_type, false, true);
                                    context_menu.set(CallbackContextMenuState::default());
                                }
                            },
                            "Restore Post-Operation"
                        }

                        // Restore Both
                        button {
                            class: "context-menu-item context-menu-restore",
                            onclick: {
                                let idx = ctx_menu.index;
                                let obj_type = ctx_menu.object_type.unwrap_or(ObjectCallbackType::Process);
                                move |_| {
                                    handle_restore_object(idx, obj_type, true, true);
                                    context_menu.set(CallbackContextMenuState::default());
                                }
                            },
                            "Restore Both"
                        }
                    }
                }
            }
        }
    }
}
