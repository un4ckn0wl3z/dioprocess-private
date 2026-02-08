//! Minifilters Enumeration sub-tab

use callback::{enumerate_minifilters, MinifilterInfo};
use dioxus::prelude::*;
use rfd::AsyncFileDialog;

use super::SortOrder;
use crate::helpers::copy_to_clipboard;

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
pub fn MinifiltersTab(driver_loaded: bool) -> Element {
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
