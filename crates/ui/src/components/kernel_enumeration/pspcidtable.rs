//! PspCidTable Enumeration sub-tab

use callback::{enumerate_pspcidtable, CidEntry, CidObjectType};
use dioxus::prelude::*;
use rfd::AsyncFileDialog;

use super::SortOrder;
use crate::helpers::copy_to_clipboard;

/// Sort column for PspCidTable
#[derive(Clone, Copy, PartialEq, Debug)]
enum CidSortColumn {
    Type,
    Id,
    ProcessName,
    ObjectAddress,
    ParentPid,
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

/// PspCidTable Enumeration sub-tab
#[component]
pub fn PspCidTableTab(driver_loaded: bool) -> Element {
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
