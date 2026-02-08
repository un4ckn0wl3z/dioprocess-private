//! Drivers Enumeration sub-tab

use callback::{enumerate_kernel_drivers, KernelDriverInfo};
use dioxus::prelude::*;
use rfd::AsyncFileDialog;

use super::SortOrder;
use crate::helpers::copy_to_clipboard;

/// Sort column for driver table
#[derive(Clone, Copy, PartialEq, Debug)]
enum DriverSortColumn {
    Name,
    BaseAddress,
    Size,
    EntryPoint,
    Path,
}

/// Context menu state for driver table
#[derive(Clone, Debug, Default)]
struct DriverContextMenuState {
    visible: bool,
    x: i32,
    y: i32,
    driver_name: String,
    base_address: u64,
    driver_path: String,
}

/// Drivers sub-tab - enumerate loaded kernel drivers
#[component]
pub fn DriversTab(driver_loaded: bool) -> Element {
    let mut drivers = use_signal(Vec::<KernelDriverInfo>::new);
    let mut is_enumerating = use_signal(|| false);
    let mut status_message = use_signal(|| String::new());
    let mut search_query = use_signal(|| String::new());
    let mut sort_column = use_signal(|| DriverSortColumn::BaseAddress);
    let mut sort_order = use_signal(|| SortOrder::Ascending);
    let mut context_menu = use_signal(DriverContextMenuState::default);
    let mut selected_index = use_signal(|| None::<u32>);

    // Handle enumerate button click
    let mut handle_enumerate = move |_| {
        if *is_enumerating.read() {
            return;
        }

        is_enumerating.set(true);
        status_message.set(String::new());

        spawn(async move {
            let result = tokio::task::spawn_blocking(enumerate_kernel_drivers).await;

            match result {
                Ok(Ok(entries)) => {
                    let count = entries.len();
                    drivers.set(entries);
                    status_message.set(format!("✓ Found {} loaded drivers", count));
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
        let driver_list = drivers.read().clone();
        spawn(async move {
            if let Some(file) = AsyncFileDialog::new()
                .set_file_name("kernel_drivers.csv")
                .add_filter("CSV", &["csv"])
                .save_file()
                .await
            {
                let mut csv = String::from("Name,BaseAddress,Size,EntryPoint,Flags,LoadCount,Path\n");
                for d in driver_list.iter() {
                    csv.push_str(&format!(
                        "{},0x{:016X},0x{:X},0x{:016X},0x{:X},{},{}\n",
                        d.driver_name,
                        d.base_address,
                        d.size,
                        d.entry_point,
                        d.flags,
                        d.load_count,
                        d.driver_path.replace(',', ";")
                    ));
                }
                let _ = std::fs::write(file.path(), csv);
            }
        });
    };

    // Keyboard handler
    let handle_keydown = move |e: KeyboardEvent| {
        if e.key() == Key::Escape {
            context_menu.set(DriverContextMenuState::default());
        } else if e.key() == Key::F5 {
            handle_enumerate(());
        }
    };

    // Get data for rendering
    let driver_list = drivers.read().clone();
    let query = search_query.read().to_lowercase();
    let col = *sort_column.read();
    let order = *sort_order.read();

    // Filter and sort
    let mut filtered_list: Vec<KernelDriverInfo> = driver_list
        .iter()
        .filter(|d| {
            if query.is_empty() {
                return true;
            }
            d.driver_name.to_lowercase().contains(&query)
                || format!("{:016X}", d.base_address).to_lowercase().contains(&query)
                || d.driver_path.to_lowercase().contains(&query)
        })
        .cloned()
        .collect();

    filtered_list.sort_by(|a, b| {
        let cmp = match col {
            DriverSortColumn::Name => a.driver_name.to_lowercase().cmp(&b.driver_name.to_lowercase()),
            DriverSortColumn::BaseAddress => a.base_address.cmp(&b.base_address),
            DriverSortColumn::Size => a.size.cmp(&b.size),
            DriverSortColumn::EntryPoint => a.entry_point.cmp(&b.entry_point),
            DriverSortColumn::Path => a.driver_path.to_lowercase().cmp(&b.driver_path.to_lowercase()),
        };
        if order == SortOrder::Descending { cmp.reverse() } else { cmp }
    });

    let is_running = *is_enumerating.read();
    let status_msg = status_message.read().clone();
    let query_text = search_query.read().clone();
    let ctx_menu = context_menu.read().clone();
    let has_data = !driver_list.is_empty();

    // Sort indicator helper
    let sort_indicator = move |col_check: DriverSortColumn| -> String {
        if *sort_column.read() == col_check {
            if *sort_order.read() == SortOrder::Ascending { " ▲".to_string() } else { " ▼".to_string() }
        } else {
            String::new()
        }
    };

    // Make sort handler
    let make_sort_handler = move |col: DriverSortColumn| {
        move |_| {
            if *sort_column.read() == col {
                sort_order.set(if *sort_order.read() == SortOrder::Ascending {
                    SortOrder::Descending
                } else {
                    SortOrder::Ascending
                });
            } else {
                sort_column.set(col);
                sort_order.set(SortOrder::Ascending);
            }
        }
    };

    // Format size helper
    let format_size = |size: u64| -> String {
        if size >= 1024 * 1024 {
            format!("{:.1} MB", size as f64 / (1024.0 * 1024.0))
        } else if size >= 1024 {
            format!("{:.1} KB", size as f64 / 1024.0)
        } else {
            format!("{} B", size)
        }
    };

    rsx! {
        div {
            style: "display: flex; flex-direction: column; flex: 1; overflow: hidden;",
            tabindex: "0",
            onkeydown: handle_keydown,
            onclick: move |_| context_menu.set(DriverContextMenuState::default()),

            // Controls
            div { class: "controls",
                input {
                    class: "search-input",
                    r#type: "text",
                    placeholder: "Search by name, address, path...",
                    value: "{query_text}",
                    oninput: move |e| search_query.set(e.value().clone()),
                }

                button {
                    class: "btn btn-primary",
                    disabled: !driver_loaded || is_running,
                    onclick: move |_| handle_enumerate(()),
                    if is_running { "Enumerating..." } else { "Enumerate" }
                }

                button {
                    class: "btn btn-secondary",
                    disabled: !has_data,
                    onclick: export_csv,
                    "Export CSV"
                }

                if !status_msg.is_empty() {
                    span { class: "status-message", "{status_msg}" }
                }
            }

            // Table
            div { class: "table-container",
                table { class: "process-table",
                    thead { class: "table-header",
                        tr {
                            th {
                                class: "th sortable",
                                onclick: make_sort_handler(DriverSortColumn::Name),
                                "Driver Name{sort_indicator(DriverSortColumn::Name)}"
                            }
                            th {
                                class: "th sortable",
                                onclick: make_sort_handler(DriverSortColumn::BaseAddress),
                                "Base Address{sort_indicator(DriverSortColumn::BaseAddress)}"
                            }
                            th {
                                class: "th sortable",
                                onclick: make_sort_handler(DriverSortColumn::Size),
                                "Size{sort_indicator(DriverSortColumn::Size)}"
                            }
                            th {
                                class: "th sortable",
                                onclick: make_sort_handler(DriverSortColumn::EntryPoint),
                                "Entry Point{sort_indicator(DriverSortColumn::EntryPoint)}"
                            }
                            th {
                                class: "th sortable",
                                onclick: make_sort_handler(DriverSortColumn::Path),
                                "Path{sort_indicator(DriverSortColumn::Path)}"
                            }
                        }
                    }

                    tbody {
                        if filtered_list.is_empty() && !driver_list.is_empty() {
                            tr {
                                td { colspan: "5", class: "no-results",
                                    "No drivers match your search"
                                }
                            }
                        } else if driver_list.is_empty() {
                            tr {
                                td { colspan: "5", class: "no-results",
                                    if driver_loaded {
                                        "Click 'Enumerate' to list loaded kernel drivers"
                                    } else {
                                        "Driver not loaded - Load DioProcess.sys to use this feature"
                                    }
                                }
                            }
                        } else {
                            for driver in filtered_list.into_iter() {
                                {
                                    let d = driver.clone();
                                    let idx = driver.index;

                                    // Highlight third-party drivers (non-Windows paths)
                                    let is_third_party = !d.driver_path.to_lowercase().contains("\\windows\\")
                                        && !d.driver_path.to_lowercase().contains("\\systemroot\\");

                                    rsx! {
                                        tr {
                                            key: "{idx}",
                                            class: if *selected_index.read() == Some(idx) { "process-row selected" } else { "process-row" },
                                            onclick: move |_| {
                                                let current = *selected_index.read();
                                                if current == Some(idx) {
                                                    selected_index.set(None);
                                                } else {
                                                    selected_index.set(Some(idx));
                                                }
                                            },
                                            oncontextmenu: move |e| {
                                                e.prevent_default();
                                                selected_index.set(Some(idx));
                                                context_menu.set(DriverContextMenuState {
                                                    visible: true,
                                                    x: e.page_coordinates().x as i32,
                                                    y: e.page_coordinates().y as i32,
                                                    driver_name: d.driver_name.clone(),
                                                    base_address: d.base_address,
                                                    driver_path: d.driver_path.clone(),
                                                });
                                            },

                                            td {
                                                class: "cell",
                                                style: if is_third_party { "color: #fbbf24; font-weight: 600;" } else { "" },
                                                "{driver.driver_name}"
                                            }
                                            td { class: "cell mono", "0x{driver.base_address:016X}" }
                                            td { class: "cell", "{format_size(driver.size)}" }
                                            td { class: "cell mono", "0x{driver.entry_point:016X}" }
                                            td {
                                                class: "cell",
                                                title: "{driver.driver_path}",
                                                // Show just the filename from path
                                                if let Some(pos) = driver.driver_path.rfind('\\') {
                                                    "{&driver.driver_path[pos+1..]}"
                                                } else {
                                                    "{driver.driver_path}"
                                                }
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
                            copy_to_clipboard(&ctx_menu.driver_name);
                            context_menu.set(DriverContextMenuState::default());
                        },
                        "Copy Name"
                    }
                    button {
                        class: "context-menu-item",
                        onclick: move |_| {
                            copy_to_clipboard(&format!("0x{:016X}", ctx_menu.base_address));
                            context_menu.set(DriverContextMenuState::default());
                        },
                        "Copy Base Address"
                    }
                    button {
                        class: "context-menu-item",
                        onclick: move |_| {
                            copy_to_clipboard(&ctx_menu.driver_path);
                            context_menu.set(DriverContextMenuState::default());
                        },
                        "Copy Path"
                    }
                }
            }
        }
    }
}
