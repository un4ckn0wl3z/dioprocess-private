//! Kernel Utilities Tab - Advanced kernel-mode features with sub-tabs

use callback::{
    enumerate_minifilters, enumerate_object_callbacks, enumerate_pspcidtable, CidEntry,
    CidObjectType, MinifilterInfo, ObjectCallbackInfo, ObjectCallbackType,
};
use dioxus::prelude::*;
use rfd::AsyncFileDialog;

use crate::helpers::copy_to_clipboard;

/// Sub-tab selection
#[derive(Clone, Copy, PartialEq, Debug)]
enum KernelUtilityTab {
    CallbackEnum,
    PspCidTable,
    Minifilters,
}

/// Callback type selector
#[derive(Clone, Copy, PartialEq, Debug)]
enum CallbackType {
    Process,
    Thread,
    Image,
    Object, // ObRegisterCallbacks - handle operation monitoring
}

/// Sort column for callback table
#[derive(Clone, Copy, PartialEq, Debug)]
enum CallbackSortColumn {
    Index,
    Address,
    Module,
}

/// Sort column for PspCidTable
#[derive(Clone, Copy, PartialEq, Debug)]
enum CidSortColumn {
    Type,
    Id,
    ProcessName,
    ObjectAddress,
    ParentPid,
}

/// Sort order
#[derive(Clone, Copy, PartialEq, Debug)]
enum SortOrder {
    Ascending,
    Descending,
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

/// Context menu state for CID table
#[derive(Clone, Debug, Default)]
struct CidContextMenuState {
    visible: bool,
    x: i32,
    y: i32,
    id: u32,
    process_name: String,
    object_address: u64,
    parent_pid: u32,
}

/// Kernel Utilities tab component
#[component]
pub fn KernelUtilitiesTab() -> Element {
    let driver_loaded = callback::is_driver_loaded();
    let mut active_tab = use_signal(|| KernelUtilityTab::CallbackEnum);

    rsx! {
        div {
            class: "service-tab",
            tabindex: "0",

            // Header
            div { class: "header-box",
                h1 { class: "header-title", "Kernel Utilities" }
                div { class: "header-stats",
                    span {
                        class: if driver_loaded { "driver-status driver-status-loaded" } else { "driver-status driver-status-not-loaded" },
                        if driver_loaded {
                            "Driver: Loaded"
                        } else {
                            "Driver: Not Loaded"
                        }
                    }
                    span { class: "header-shortcuts", "F5: Refresh | Esc: Close menu" }
                }
            }

            // Sub-tabs (styled like controls bar)
            div {
                class: "controls",
                style: "border-bottom: 1px solid var(--border-secondary); padding-bottom: 12px;",
                button {
                    class: if *active_tab.read() == KernelUtilityTab::CallbackEnum { "btn btn-secondary active" } else { "btn btn-secondary" },
                    onclick: move |_| active_tab.set(KernelUtilityTab::CallbackEnum),
                    "Callback Enumeration"
                }

                button {
                    class: if *active_tab.read() == KernelUtilityTab::PspCidTable { "btn btn-secondary active" } else { "btn btn-secondary" },
                    onclick: move |_| active_tab.set(KernelUtilityTab::PspCidTable),
                    "PspCidTable"
                }

                button {
                    class: if *active_tab.read() == KernelUtilityTab::Minifilters { "btn btn-secondary active" } else { "btn btn-secondary" },
                    onclick: move |_| active_tab.set(KernelUtilityTab::Minifilters),
                    "Minifilters"
                }
            }

            // Tab content
            match *active_tab.read() {
                KernelUtilityTab::CallbackEnum => rsx! { CallbackEnumTab { driver_loaded } },
                KernelUtilityTab::PspCidTable => rsx! { PspCidTableTab { driver_loaded } },
                KernelUtilityTab::Minifilters => rsx! { MinifiltersTab { driver_loaded } },
            }
        }
    }
}

/// Callback Enumeration sub-tab
#[component]
fn CallbackEnumTab(driver_loaded: bool) -> Element {
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

/// PspCidTable Enumeration sub-tab
#[component]
fn PspCidTableTab(driver_loaded: bool) -> Element {
    let mut cid_entries = use_signal(|| Vec::<CidEntry>::new());
    let mut cid_status = use_signal(|| String::new());
    let mut cid_is_enumerating = use_signal(|| false);
    let mut search_query = use_signal(|| String::new());
    let mut sort_column = use_signal(|| CidSortColumn::Id);
    let mut sort_order = use_signal(|| SortOrder::Ascending);
    let mut context_menu = use_signal(|| CidContextMenuState::default());
    let mut selected_id = use_signal(|| None::<u32>);
    let mut type_filter = use_signal(|| String::new()); // "", "process", "thread"

    // Handle enumerate button click
    let mut handle_cid_enumerate = move |_| {
        let is_running = *cid_is_enumerating.read();
        if is_running {
            return;
        }

        cid_is_enumerating.set(true);
        cid_status.set(String::new());

        spawn(async move {
            let result = tokio::task::spawn_blocking(move || enumerate_pspcidtable()).await;

            match result {
                Ok(Ok(entries)) => {
                    let process_count = entries.iter().filter(|e| e.object_type == CidObjectType::Process).count();
                    let thread_count = entries.iter().filter(|e| e.object_type == CidObjectType::Thread).count();
                    cid_entries.set(entries);
                    cid_status.set(format!("✓ Found {} processes and {} threads ({} total)", process_count, thread_count, process_count + thread_count));
                }
                Ok(Err(e)) => {
                    cid_status.set(format!("✗ Error: {}", e));
                }
                Err(e) => {
                    cid_status.set(format!("✗ Task error: {}", e));
                }
            }

            cid_is_enumerating.set(false);
        });
    };

    // Export CSV
    let export_csv = move |_| {
        let entries = cid_entries.read().clone();
        spawn(async move {
            if let Some(file) = AsyncFileDialog::new()
                .set_file_name("pspcidtable.csv")
                .add_filter("CSV", &["csv"])
                .save_file()
                .await
            {
                let mut csv = String::from("Type,ID,ProcessName,ObjectAddress,ParentPID\n");
                for entry in entries.iter() {
                    let type_str = if entry.object_type == CidObjectType::Process { "Process" } else { "Thread" };
                    csv.push_str(&format!(
                        "{},{},{},0x{:016X},{}\n",
                        type_str, entry.id, entry.process_name_str(), entry.object_address, entry.parent_pid
                    ));
                }
                let _ = std::fs::write(file.path(), csv);
            }
        });
    };

    // Keyboard handler
    let handle_keydown = move |e: KeyboardEvent| {
        if e.key() == Key::Escape {
            context_menu.set(CidContextMenuState::default());
        } else if e.key() == Key::F5 {
            handle_cid_enumerate(());
        }
    };

    // Get all the data we need before rsx!
    let cid_list = cid_entries.read().clone();
    let query = search_query.read().to_lowercase();
    let filter_type = type_filter.read().clone();
    let col = *sort_column.read();
    let order = *sort_order.read();

    // Filter and sort
    let mut filtered_list: Vec<CidEntry> = cid_list
        .iter()
        .filter(|e| {
            // Type filter
            let type_match = match filter_type.as_str() {
                "process" => e.object_type == CidObjectType::Process,
                "thread" => e.object_type == CidObjectType::Thread,
                _ => true,
            };
            if !type_match {
                return false;
            }

            // Search filter
            if query.is_empty() {
                return true;
            }
            e.process_name_str().to_lowercase().contains(&query)
                || e.id.to_string().contains(&query)
                || format!("{:016X}", e.object_address).to_lowercase().contains(&query)
                || e.parent_pid.to_string().contains(&query)
        })
        .cloned()
        .collect();

    filtered_list.sort_by(|a, b| {
        let cmp = match col {
            CidSortColumn::Type => {
                let a_type = if a.object_type == CidObjectType::Process { 0 } else { 1 };
                let b_type = if b.object_type == CidObjectType::Process { 0 } else { 1 };
                a_type.cmp(&b_type)
            }
            CidSortColumn::Id => a.id.cmp(&b.id),
            CidSortColumn::ProcessName => a.process_name_str().to_lowercase().cmp(&b.process_name_str().to_lowercase()),
            CidSortColumn::ObjectAddress => a.object_address.cmp(&b.object_address),
            CidSortColumn::ParentPid => a.parent_pid.cmp(&b.parent_pid),
        };
        if order == SortOrder::Descending {
            cmp.reverse()
        } else {
            cmp
        }
    });

    let cid_is_running = *cid_is_enumerating.read();
    let cid_status_msg = cid_status.read().clone();
    let query_text = search_query.read().clone();
    let ctx_menu = context_menu.read().clone();
    let filter = type_filter.read().clone();

    // Sort indicator
    let sort_indicator = move |col_check: CidSortColumn| -> String {
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
    let make_sort_handler = move |col: CidSortColumn| {
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
            onclick: move |_| context_menu.set(CidContextMenuState::default()),

            // Controls
            div { class: "controls",
                // Type filter
                button {
                    class: if filter.is_empty() { "btn btn-secondary active" } else { "btn btn-secondary" },
                    onclick: move |_| type_filter.set(String::new()),
                    "All"
                }
                button {
                    class: if filter == "process" { "btn btn-secondary active" } else { "btn btn-secondary" },
                    onclick: move |_| type_filter.set("process".to_string()),
                    "Processes"
                }
                button {
                    class: if filter == "thread" { "btn btn-secondary active" } else { "btn btn-secondary" },
                    onclick: move |_| type_filter.set("thread".to_string()),
                    "Threads"
                }

                // Search bar
                input {
                    class: "search-input",
                    r#type: "text",
                    placeholder: "Search by name, ID, address...",
                    value: "{query_text}",
                    oninput: move |e| search_query.set(e.value().clone()),
                }

                // Action buttons
                button {
                    class: "btn btn-primary",
                    disabled: !driver_loaded || cid_is_running,
                    onclick: move |_| handle_cid_enumerate(()),
                    if cid_is_running { "Enumerating..." } else { "Refresh" }
                }

                button {
                    class: "btn btn-secondary",
                    disabled: cid_list.is_empty(),
                    onclick: export_csv,
                    "Export CSV"
                }

                // Status message inline
                if !cid_status_msg.is_empty() {
                    span { class: "status-message", "{cid_status_msg}" }
                }
            }

            // CID Table
            div { class: "table-container",
                table { class: "process-table",
                    thead { class: "table-header",
                        tr {
                            th {
                                class: "th sortable",
                                onclick: make_sort_handler(CidSortColumn::Type),
                                "Type{sort_indicator(CidSortColumn::Type)}"
                            }
                            th {
                                class: "th sortable",
                                onclick: make_sort_handler(CidSortColumn::Id),
                                "ID{sort_indicator(CidSortColumn::Id)}"
                            }
                            th {
                                class: "th sortable",
                                onclick: make_sort_handler(CidSortColumn::ProcessName),
                                "Process Name{sort_indicator(CidSortColumn::ProcessName)}"
                            }
                            th {
                                class: "th sortable",
                                onclick: make_sort_handler(CidSortColumn::ObjectAddress),
                                "Object Address{sort_indicator(CidSortColumn::ObjectAddress)}"
                            }
                            th {
                                class: "th sortable",
                                onclick: make_sort_handler(CidSortColumn::ParentPid),
                                "Parent/Owner PID{sort_indicator(CidSortColumn::ParentPid)}"
                            }
                        }
                    }

                    tbody {
                        if filtered_list.is_empty() && !cid_list.is_empty() {
                            tr {
                                td { colspan: "5", class: "no-results",
                                    "No entries match your filter/search"
                                }
                            }
                        } else if cid_list.is_empty() {
                            tr {
                                td { colspan: "5", class: "no-results",
                                    if driver_loaded {
                                        "Click 'Refresh' to enumerate PspCidTable"
                                    } else {
                                        "Driver not loaded - Load DioProcess.sys to use this feature"
                                    }
                                }
                            }
                        } else {
                            for entry in filtered_list.into_iter() {
                                tr {
                                    key: "{entry.id}-{entry.object_address}",
                                    class: if *selected_id.read() == Some(entry.id) { "process-row selected" } else { "process-row" },
                                    onclick: move |_| {
                                        let current = *selected_id.read();
                                        if current == Some(entry.id) {
                                            selected_id.set(None);
                                        } else {
                                            selected_id.set(Some(entry.id));
                                        }
                                    },
                                    oncontextmenu: move |e| {
                                        e.prevent_default();
                                        selected_id.set(Some(entry.id));
                                        context_menu.set(CidContextMenuState {
                                            visible: true,
                                            x: e.page_coordinates().x as i32,
                                            y: e.page_coordinates().y as i32,
                                            id: entry.id,
                                            process_name: entry.process_name_str(),
                                            object_address: entry.object_address,
                                            parent_pid: entry.parent_pid,
                                        });
                                    },

                                    td {
                                        class: "cell",
                                        if entry.object_type == CidObjectType::Process {
                                            span { class: "cpu-low", style: "font-weight: 600;", "Process" }
                                        } else {
                                            span { style: "color: #60a5fa; font-weight: 600;", "Thread" }
                                        }
                                    }
                                    td { class: "cell", "{entry.id}" }
                                    td { class: "cell cell-pid", "{entry.process_name_str()}" }
                                    td { class: "cell mono", "0x{entry.object_address:016X}" }
                                    td {
                                        class: "cell",
                                        if entry.parent_pid != 0 {
                                            "{entry.parent_pid}"
                                        } else {
                                            "—"
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
                            copy_to_clipboard(&ctx_menu.id.to_string());
                            context_menu.set(CidContextMenuState::default());
                        },
                        "Copy ID"
                    }
                    button {
                        class: "context-menu-item",
                        onclick: move |_| {
                            copy_to_clipboard(&ctx_menu.process_name);
                            context_menu.set(CidContextMenuState::default());
                        },
                        "Copy Process Name"
                    }
                    button {
                        class: "context-menu-item",
                        onclick: move |_| {
                            copy_to_clipboard(&format!("0x{:016X}", ctx_menu.object_address));
                            context_menu.set(CidContextMenuState::default());
                        },
                        "Copy Object Address"
                    }
                    button {
                        class: "context-menu-item",
                        onclick: move |_| {
                            copy_to_clipboard(&ctx_menu.parent_pid.to_string());
                            context_menu.set(CidContextMenuState::default());
                        },
                        "Copy Parent/Owner PID"
                    }
                }
            }
        }
    }
}

/// Sort column for Minifilters
#[derive(Clone, Copy, PartialEq, Debug)]
enum MinifilterSortColumn {
    Name,
    Altitude,
    Address,
    Instances,
}

/// Context menu state for minifilter table
#[derive(Clone, Debug, Default)]
struct MinifilterContextMenuState {
    visible: bool,
    x: i32,
    y: i32,
    filter_name: String,
    altitude: String,
    filter_address: u64,
    owner_module: String,
}

/// Minifilters Enumeration sub-tab
#[component]
fn MinifiltersTab(driver_loaded: bool) -> Element {
    let mut minifilters = use_signal(|| Vec::<MinifilterInfo>::new());
    let mut status_message = use_signal(|| String::new());
    let mut is_enumerating = use_signal(|| false);
    let mut search_query = use_signal(|| String::new());
    let mut sort_column = use_signal(|| MinifilterSortColumn::Altitude);
    let mut sort_order = use_signal(|| SortOrder::Descending); // Higher altitude = earlier in filter chain
    let mut context_menu = use_signal(|| MinifilterContextMenuState::default());
    let mut selected_index = use_signal(|| None::<u32>);

    // Handle enumerate button click
    let mut handle_enumerate = move |_| {
        let is_running = *is_enumerating.read();
        if is_running {
            return;
        }

        is_enumerating.set(true);
        status_message.set(String::new());

        spawn(async move {
            let result = tokio::task::spawn_blocking(enumerate_minifilters).await;

            match result {
                Ok(Ok(filters)) => {
                    let count = filters.len();
                    minifilters.set(filters);
                    status_message.set(format!("✓ Found {} minifilters", count));
                }
                Ok(Err(e)) => {
                    status_message.set(format!("✗ Error: {}", e));
                }
                Err(e) => {
                    status_message.set(format!("✗ Task error: {}", e));
                }
            }

            is_enumerating.set(false);
        });
    };

    // Export CSV
    let export_csv = move |_| {
        let filter_list = minifilters.read().clone();
        spawn(async move {
            if let Some(file) = AsyncFileDialog::new()
                .set_file_name("minifilters.csv")
                .add_filter("CSV", &["csv"])
                .save_file()
                .await
            {
                let mut csv = String::from(
                    "Name,Altitude,Address,Instances,Flags,PreCreate,PostCreate,PreRead,PostRead,PreWrite,PostWrite,Owner\n",
                );
                for f in filter_list.iter() {
                    csv.push_str(&format!(
                        "{},{},0x{:016X},{},{},0x{:X},0x{:X},0x{:X},0x{:X},0x{:X},0x{:X},{}\n",
                        f.filter_name,
                        f.altitude,
                        f.filter_address,
                        f.num_instances,
                        f.flags,
                        f.callbacks.pre_create,
                        f.callbacks.post_create,
                        f.callbacks.pre_read,
                        f.callbacks.post_read,
                        f.callbacks.pre_write,
                        f.callbacks.post_write,
                        f.owner_module
                    ));
                }
                let _ = std::fs::write(file.path(), csv);
            }
        });
    };

    // Keyboard handler
    let handle_keydown = move |e: KeyboardEvent| {
        if e.key() == Key::Escape {
            context_menu.set(MinifilterContextMenuState::default());
        } else if e.key() == Key::F5 {
            handle_enumerate(());
        }
    };

    // Get all the data we need before rsx!
    let filter_list = minifilters.read().clone();
    let query = search_query.read().to_lowercase();
    let col = *sort_column.read();
    let order = *sort_order.read();

    // Filter and sort
    let mut filtered_list: Vec<MinifilterInfo> = filter_list
        .iter()
        .filter(|f| {
            if query.is_empty() {
                return true;
            }
            f.filter_name.to_lowercase().contains(&query)
                || f.altitude.to_lowercase().contains(&query)
                || f.owner_module.to_lowercase().contains(&query)
                || format!("{:016X}", f.filter_address)
                    .to_lowercase()
                    .contains(&query)
        })
        .cloned()
        .collect();

    filtered_list.sort_by(|a, b| {
        let cmp = match col {
            MinifilterSortColumn::Name => a
                .filter_name
                .to_lowercase()
                .cmp(&b.filter_name.to_lowercase()),
            MinifilterSortColumn::Altitude => {
                // Parse altitude as float for proper numeric sorting
                let a_alt: f64 = a.altitude.parse().unwrap_or(0.0);
                let b_alt: f64 = b.altitude.parse().unwrap_or(0.0);
                a_alt.partial_cmp(&b_alt).unwrap_or(std::cmp::Ordering::Equal)
            }
            MinifilterSortColumn::Address => a.filter_address.cmp(&b.filter_address),
            MinifilterSortColumn::Instances => a.num_instances.cmp(&b.num_instances),
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
    let has_data = !filter_list.is_empty();

    // Sort indicator
    let sort_indicator = move |col_check: MinifilterSortColumn| -> String {
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
    let make_sort_handler = move |col: MinifilterSortColumn| {
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

    // Helper to format callback address
    let format_callback = |addr: u64| -> String {
        if addr != 0 {
            format!("0x{:X}", addr)
        } else {
            "—".to_string()
        }
    };

    rsx! {
        div {
            style: "display: flex; flex-direction: column; flex: 1; overflow: hidden;",
            tabindex: "0",
            onkeydown: handle_keydown,
            onclick: move |_| context_menu.set(MinifilterContextMenuState::default()),

            // Controls
            div { class: "controls",
                // Search bar
                input {
                    class: "search-input",
                    r#type: "text",
                    placeholder: "Search by name, altitude, owner...",
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

            // Minifilters table
            div { class: "table-container",
                table { class: "process-table",
                    thead { class: "table-header",
                        tr {
                            th {
                                class: "th sortable",
                                onclick: make_sort_handler(MinifilterSortColumn::Name),
                                "Filter Name{sort_indicator(MinifilterSortColumn::Name)}"
                            }
                            th {
                                class: "th sortable",
                                onclick: make_sort_handler(MinifilterSortColumn::Altitude),
                                "Altitude{sort_indicator(MinifilterSortColumn::Altitude)}"
                            }
                            th {
                                class: "th sortable",
                                onclick: make_sort_handler(MinifilterSortColumn::Address),
                                "Address{sort_indicator(MinifilterSortColumn::Address)}"
                            }
                            th {
                                class: "th sortable",
                                onclick: make_sort_handler(MinifilterSortColumn::Instances),
                                "Instances{sort_indicator(MinifilterSortColumn::Instances)}"
                            }
                            th { class: "th", "Pre/Post Create" }
                            th { class: "th", "Pre/Post Read" }
                            th { class: "th", "Pre/Post Write" }
                            th { class: "th", "Owner Module" }
                        }
                    }

                    tbody {
                        if filtered_list.is_empty() && !filter_list.is_empty() {
                            tr {
                                td { colspan: "8", class: "no-results",
                                    "No minifilters match your search"
                                }
                            }
                        } else if filter_list.is_empty() {
                            tr {
                                td { colspan: "8", class: "no-results",
                                    if driver_loaded {
                                        "Click 'Refresh' to enumerate minifilters"
                                    } else {
                                        "Driver not loaded - Load DioProcess.sys to use this feature"
                                    }
                                }
                            }
                        } else {
                            for f in filtered_list.into_iter() {
                                tr {
                                    key: "{f.index}",
                                    class: if *selected_index.read() == Some(f.index) { "process-row selected" } else { "process-row" },
                                    onclick: move |_| {
                                        let current = *selected_index.read();
                                        if current == Some(f.index) {
                                            selected_index.set(None);
                                        } else {
                                            selected_index.set(Some(f.index));
                                        }
                                    },
                                    oncontextmenu: move |e| {
                                        e.prevent_default();
                                        selected_index.set(Some(f.index));
                                        context_menu.set(MinifilterContextMenuState {
                                            visible: true,
                                            x: e.page_coordinates().x as i32,
                                            y: e.page_coordinates().y as i32,
                                            filter_name: f.filter_name.clone(),
                                            altitude: f.altitude.clone(),
                                            filter_address: f.filter_address,
                                            owner_module: f.owner_module.clone(),
                                        });
                                    },

                                    td { class: "cell", "{f.filter_name}" }
                                    td {
                                        class: "cell mono",
                                        style: "font-weight: 600; color: #fbbf24;",
                                        "{f.altitude}"
                                    }
                                    td { class: "cell mono", "0x{f.filter_address:016X}" }
                                    td { class: "cell", "{f.num_instances}" }
                                    td {
                                        class: "cell mono",
                                        style: "font-size: 11px;",
                                        "{format_callback(f.callbacks.pre_create)} / {format_callback(f.callbacks.post_create)}"
                                    }
                                    td {
                                        class: "cell mono",
                                        style: "font-size: 11px;",
                                        "{format_callback(f.callbacks.pre_read)} / {format_callback(f.callbacks.post_read)}"
                                    }
                                    td {
                                        class: "cell mono",
                                        style: "font-size: 11px;",
                                        "{format_callback(f.callbacks.pre_write)} / {format_callback(f.callbacks.post_write)}"
                                    }
                                    td { class: "cell", "{f.owner_module}" }
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
                            copy_to_clipboard(&ctx_menu.filter_name);
                            context_menu.set(MinifilterContextMenuState::default());
                        },
                        "Copy Filter Name"
                    }
                    button {
                        class: "context-menu-item",
                        onclick: move |_| {
                            copy_to_clipboard(&ctx_menu.altitude);
                            context_menu.set(MinifilterContextMenuState::default());
                        },
                        "Copy Altitude"
                    }
                    button {
                        class: "context-menu-item",
                        onclick: move |_| {
                            copy_to_clipboard(&format!("0x{:016X}", ctx_menu.filter_address));
                            context_menu.set(MinifilterContextMenuState::default());
                        },
                        "Copy Address"
                    }
                    button {
                        class: "context-menu-item",
                        onclick: move |_| {
                            copy_to_clipboard(&ctx_menu.owner_module);
                            context_menu.set(MinifilterContextMenuState::default());
                        },
                        "Copy Owner Module"
                    }
                }
            }
        }
    }
}
