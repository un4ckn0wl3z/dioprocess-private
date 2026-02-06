//! Kernel Utilities Tab - Advanced kernel-mode features with sub-tabs

use callback::{enumerate_pspcidtable, CidEntry, CidObjectType};
use dioxus::prelude::*;
use rfd::AsyncFileDialog;

use crate::helpers::copy_to_clipboard;

/// Sub-tab selection
#[derive(Clone, Copy, PartialEq, Debug)]
enum KernelUtilityTab {
    CallbackEnum,
    PspCidTable,
}

/// Callback type selector
#[derive(Clone, Copy, PartialEq, Debug)]
enum CallbackType {
    Process,
    Thread,
    Image,
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
                        if driver_loaded {
                            "🟢 Driver loaded — Advanced kernel features available"
                        } else {
                            "🔴 Driver not loaded — Load DioProcess.sys to enable features"
                        }
                    }
                }
            }

            // Sub-tabs
            div {
                class: "subtab-container",
                style: "display: flex; gap: 8px; padding: 16px 16px 0 16px; border-bottom: 2px solid rgba(0, 212, 255, 0.15);",

                button {
                    class: if *active_tab.read() == KernelUtilityTab::CallbackEnum { "subtab-button active" } else { "subtab-button" },
                    onclick: move |_| active_tab.set(KernelUtilityTab::CallbackEnum),
                    "Callback Enumeration"
                }

                button {
                    class: if *active_tab.read() == KernelUtilityTab::PspCidTable { "subtab-button active" } else { "subtab-button" },
                    onclick: move |_| active_tab.set(KernelUtilityTab::PspCidTable),
                    "PspCidTable"
                }
            }

            // Tab content
            match *active_tab.read() {
                KernelUtilityTab::CallbackEnum => rsx! { CallbackEnumTab { driver_loaded } },
                KernelUtilityTab::PspCidTable => rsx! { PspCidTableTab { driver_loaded } },
            }
        }
    }
}

/// Callback Enumeration sub-tab
#[component]
fn CallbackEnumTab(driver_loaded: bool) -> Element {
    let mut callback_type = use_signal(|| CallbackType::Process);
    let mut callbacks = use_signal(Vec::<callback::CallbackInfo>::new);
    let mut is_enumerating = use_signal(|| false);
    let mut status_message = use_signal(|| String::new());
    let mut search_query = use_signal(|| String::new());
    let mut sort_column = use_signal(|| CallbackSortColumn::Index);
    let mut sort_order = use_signal(|| SortOrder::Ascending);
    let mut context_menu = use_signal(|| CallbackContextMenuState::default());

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
            let result = tokio::task::spawn_blocking(move || match cb_type {
                CallbackType::Process => callback::enumerate_process_callbacks(),
                CallbackType::Thread => callback::enumerate_thread_callbacks(),
                CallbackType::Image => callback::enumerate_image_callbacks(),
            })
            .await;

            match result {
                Ok(Ok(cb_list)) => {
                    let count = cb_list.len();
                    callbacks.set(cb_list);
                    status_message.set(format!("✓ Found {} active callbacks", count));
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
        let cb_list = callbacks.read().clone();
        spawn(async move {
            if let Some(file) = AsyncFileDialog::new()
                .set_file_name("callbacks.csv")
                .add_filter("CSV", &["csv"])
                .save_file()
                .await
            {
                let mut csv = String::from("Index,Address,Module\n");
                for cb in cb_list.iter() {
                    csv.push_str(&format!(
                        "{},0x{:016X},{}\n",
                        cb.index, cb.callback_address, cb.module_name
                    ));
                }
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
    let query = search_query.read().to_lowercase();
    let col = *sort_column.read();
    let order = *sort_order.read();

    // Filter and sort
    let mut filtered_list: Vec<callback::CallbackInfo> = callback_list
        .iter()
        .filter(|c| {
            if query.is_empty() {
                return true;
            }
            c.module_name.to_lowercase().contains(&query)
                || format!("{:016X}", c.callback_address).to_lowercase().contains(&query)
                || c.index.to_string().contains(&query)
        })
        .cloned()
        .collect();

    filtered_list.sort_by(|a, b| {
        let cmp = match col {
            CallbackSortColumn::Index => a.index.cmp(&b.index),
            CallbackSortColumn::Address => a.callback_address.cmp(&b.callback_address),
            CallbackSortColumn::Module => a.module_name.to_lowercase().cmp(&b.module_name.to_lowercase()),
        };
        if order == SortOrder::Descending {
            cmp.reverse()
        } else {
            cmp
        }
    });
    let is_running = *is_enumerating.read();
    let status_msg = status_message.read().clone();
    let current_type = *callback_type.read();
    let query_text = search_query.read().clone();
    let ctx_menu = context_menu.read().clone();

    // Sort indicator
    let sort_indicator = move |col: CallbackSortColumn| -> String {
        if *sort_column.read() == col {
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
            class: "tab-content",
            tabindex: "0",
            onkeydown: handle_keydown,
            onclick: move |_| context_menu.set(CallbackContextMenuState::default()),

            // Description
            div {
                class: "tab-description",
                p {
                    "Enumerate registered kernel callbacks. Windows allows drivers to register notification callbacks for process creation/exit, thread creation/exit, and image (DLL/EXE) loading. This tool locates the internal kernel callback arrays and resolves callback addresses to their owning driver modules."
                }
            }

            // Toolbar
            div { class: "toolbar",
                // Callback type selector
                div {
                    style: "display: flex; gap: 8px; align-items: center;",
                    span { style: "color: #9ca3af; font-size: 13px;", "Type:" }
                    button {
                        class: if current_type == CallbackType::Process { "btn btn-small active" } else { "btn btn-small" },
                        onclick: move |_| {
                            callback_type.set(CallbackType::Process);
                            callbacks.set(Vec::new());
                            status_message.set(String::new());
                        },
                        "Process"
                    }
                    button {
                        class: if current_type == CallbackType::Thread { "btn btn-small active" } else { "btn btn-small" },
                        onclick: move |_| {
                            callback_type.set(CallbackType::Thread);
                            callbacks.set(Vec::new());
                            status_message.set(String::new());
                        },
                        "Thread"
                    }
                    button {
                        class: if current_type == CallbackType::Image { "btn btn-small active" } else { "btn btn-small" },
                        onclick: move |_| {
                            callback_type.set(CallbackType::Image);
                            callbacks.set(Vec::new());
                            status_message.set(String::new());
                        },
                        "Image Load"
                    }
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
                    if is_running { "Enumerating..." } else { "🔄 Refresh" }
                }

                button {
                    class: "btn btn-secondary",
                    disabled: callback_list.is_empty(),
                    onclick: export_csv,
                    "Export CSV"
                }
            }

            // Status message
            if !status_msg.is_empty() {
                div { class: "status-bar", "{status_msg}" }
            }

            // Callback table
            div { class: "table-container",
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
                                        "Driver not loaded"
                                    }
                                }
                            }
                        } else {
                            for cb in filtered_list.into_iter() {
                                tr {
                                    key: "{cb.index}",
                                    class: "table-row",
                                    oncontextmenu: move |e| {
                                        e.prevent_default();
                                        context_menu.set(CallbackContextMenuState {
                                            visible: true,
                                            x: e.page_coordinates().x as i32,
                                            y: e.page_coordinates().y as i32,
                                            index: cb.index,
                                            address: cb.callback_address,
                                            module: cb.module_name.clone(),
                                        });
                                    },

                                    td { class: "td", "{cb.index}" }
                                    td { class: "td mono", "0x{cb.callback_address:016X}" }
                                    td { class: "td", "{cb.module_name}" }
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
    let sort_indicator = move |col: CidSortColumn| -> String {
        if *sort_column.read() == col {
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
            class: "tab-content",
            tabindex: "0",
            onkeydown: handle_keydown,
            onclick: move |_| context_menu.set(CidContextMenuState::default()),

            // Description
            div {
                class: "tab-description",
                p {
                    "Enumerate all processes and threads by parsing the kernel's PspCidTable handle table. This table stores all EPROCESS (process) and ETHREAD (thread) objects indexed by PID/TID. Dynamically resolves Windows version-specific structure offsets to extract process names, parent PIDs, and thread owner information. Uses signature scanning to locate PspCidTable (no hardcoded addresses). Read-only operation — PatchGuard/KPP safe."
                }
            }

            // Toolbar
            div { class: "toolbar",
                // Type filter
                div {
                    style: "display: flex; gap: 8px; align-items: center;",
                    span { style: "color: #9ca3af; font-size: 13px;", "Filter:" }
                    button {
                        class: if filter.is_empty() { "btn btn-small active" } else { "btn btn-small" },
                        onclick: move |_| type_filter.set(String::new()),
                        "All"
                    }
                    button {
                        class: if filter == "process" { "btn btn-small active" } else { "btn btn-small" },
                        onclick: move |_| type_filter.set("process".to_string()),
                        "Processes"
                    }
                    button {
                        class: if filter == "thread" { "btn btn-small active" } else { "btn btn-small" },
                        onclick: move |_| type_filter.set("thread".to_string()),
                        "Threads"
                    }
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
                    if cid_is_running { "Enumerating..." } else { "🔄 Refresh" }
                }

                button {
                    class: "btn btn-secondary",
                    disabled: cid_list.is_empty(),
                    onclick: export_csv,
                    "Export CSV"
                }
            }

            // Status message
            if !cid_status_msg.is_empty() {
                div { class: "status-bar", "{cid_status_msg}" }
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
                                        "Driver not loaded"
                                    }
                                }
                            }
                        } else {
                            for entry in filtered_list.into_iter() {
                                tr {
                                    key: "{entry.id}-{entry.object_address}",
                                    class: "table-row",
                                    oncontextmenu: move |e| {
                                        e.prevent_default();
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
                                        class: "td",
                                        if entry.object_type == CidObjectType::Process {
                                            span { style: "color: #10b981; font-weight: 600;", "Process" }
                                        } else {
                                            span { style: "color: #3b82f6; font-weight: 600;", "Thread" }
                                        }
                                    }
                                    td { class: "td", "{entry.id}" }
                                    td { class: "td", style: "color: #fbbf24; font-family: monospace;", "{entry.process_name_str()}" }
                                    td { class: "td mono", "0x{entry.object_address:016X}" }
                                    td {
                                        class: "td",
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
