//! Network connections tab component

use dioxus::prelude::*;
use network::{get_network_connections, NetworkConnection, Protocol, TcpState};
use process::{kill_process, open_file_location};

use crate::helpers::copy_to_clipboard;

/// Network context menu state
#[derive(Clone, Debug, Default)]
struct NetworkContextMenuState {
    visible: bool,
    x: i32,
    y: i32,
    pid: Option<u32>,
    exe_path: String,
    port: u16,
}

/// Sort column for network table
#[derive(Clone, Copy, PartialEq, Debug)]
enum NetworkSortColumn {
    Protocol,
    LocalAddr,
    LocalPort,
    RemoteAddr,
    RemotePort,
    State,
    Process,
    Pid,
}

/// Sort order
#[derive(Clone, Copy, PartialEq, Debug)]
enum SortOrder {
    Ascending,
    Descending,
}

/// Network Tab component
#[component]
pub fn NetworkTab() -> Element {
    let mut connections = use_signal(|| get_network_connections());
    let mut search_query = use_signal(|| String::new());
    let mut sort_column = use_signal(|| NetworkSortColumn::LocalPort);
    let mut sort_order = use_signal(|| SortOrder::Ascending);
    let mut auto_refresh = use_signal(|| true);
    let mut selected_row = use_signal(|| None::<(u32, u16)>); // (pid, port)
    let mut status_message = use_signal(|| String::new());
    let mut context_menu = use_signal(|| NetworkContextMenuState::default());
    let mut protocol_filter = use_signal(|| String::new()); // "", "tcp", "udp"
    let mut state_filter = use_signal(|| String::new()); // "", "listen", "established", etc.

    // Auto-refresh every 3 seconds
    use_future(move || async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            if *auto_refresh.read() {
                connections.set(get_network_connections());
            }
        }
    });

    // Keyboard shortcuts handler
    let handle_keydown = move |e: KeyboardEvent| {
        if e.key() == Key::Escape {
            context_menu.set(NetworkContextMenuState::default());
            return;
        }

        if e.key() == Key::F5 {
            connections.set(get_network_connections());
            return;
        }

        if e.key() == Key::Delete {
            let row_to_kill = *selected_row.read();
            if let Some((pid, _)) = row_to_kill {
                if kill_process(pid) {
                    status_message.set(format!("✓ Process {} terminated", pid));
                    connections.set(get_network_connections());
                    selected_row.set(None);
                } else {
                    status_message.set(format!("✗ Failed to terminate process {}", pid));
                }
                spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                    status_message.set(String::new());
                });
            }
        }
    };

    // Filter and sort connections
    let mut filtered_connections: Vec<NetworkConnection> = connections
        .read()
        .iter()
        .filter(|c| {
            // Protocol filter
            let proto_match = match protocol_filter.read().as_str() {
                "tcp" => c.protocol == Protocol::Tcp,
                "udp" => c.protocol == Protocol::Udp,
                "all" => true,
                _ => true,
            };

            // State filter
            let state_match = if state_filter.read().as_str() == "all" {
                true
            } else {
                match &c.state {
                    Some(state) => state
                        .to_string()
                        .to_lowercase()
                        .contains(&state_filter.read().to_lowercase()),
                    None => state_filter.read().is_empty(),
                }
            };

            // Search filter
            let query = search_query.read().to_lowercase();
            let search_match = if query.is_empty() {
                true
            } else {
                c.local_addr.to_lowercase().contains(&query)
                    || c.local_port.to_string().contains(&query)
                    || c.remote_addr.to_lowercase().contains(&query)
                    || c.remote_port.to_string().contains(&query)
                    || c.process_name.to_lowercase().contains(&query)
                    || c.pid.to_string().contains(&query)
            };

            proto_match && state_match && search_match
        })
        .cloned()
        .collect();

    // Sort
    filtered_connections.sort_by(|a, b| {
        let cmp = match *sort_column.read() {
            NetworkSortColumn::Protocol => a.protocol.to_string().cmp(&b.protocol.to_string()),
            NetworkSortColumn::LocalAddr => a.local_addr.cmp(&b.local_addr),
            NetworkSortColumn::LocalPort => a.local_port.cmp(&b.local_port),
            NetworkSortColumn::RemoteAddr => a.remote_addr.cmp(&b.remote_addr),
            NetworkSortColumn::RemotePort => a.remote_port.cmp(&b.remote_port),
            NetworkSortColumn::State => {
                let a_state = a.state.map(|s| s.to_string()).unwrap_or_default();
                let b_state = b.state.map(|s| s.to_string()).unwrap_or_default();
                a_state.cmp(&b_state)
            }
            NetworkSortColumn::Process => a
                .process_name
                .to_lowercase()
                .cmp(&b.process_name.to_lowercase()),
            NetworkSortColumn::Pid => a.pid.cmp(&b.pid),
        };
        match *sort_order.read() {
            SortOrder::Ascending => cmp,
            SortOrder::Descending => cmp.reverse(),
        }
    });

    let connection_count = filtered_connections.len();
    let total_count = connections.read().len();

    let current_sort_col = *sort_column.read();
    let current_sort_ord = *sort_order.read();
    let ctx_menu = context_menu.read().clone();
    let export_connections = filtered_connections.clone();

    let sort_indicator = |column: NetworkSortColumn| -> &'static str {
        if current_sort_col == column {
            match current_sort_ord {
                SortOrder::Ascending => " ▲",
                SortOrder::Descending => " ▼",
            }
        } else {
            ""
        }
    };

    rsx! {
        div {
            class: "network-tab",
            tabindex: "0",
            onkeydown: handle_keydown,
            onclick: move |_| context_menu.set(NetworkContextMenuState::default()),

            // Header
            div { class: "header-box",
                h1 { class: "header-title", "🌐 Network Connections" }
                div { class: "header-stats",
                    span { "Showing: {connection_count}/{total_count} connections" }
                    span { class: "header-shortcuts", "F5: Refresh | Del: Kill Process | Esc: Close menu" }
                }
                if !status_message.read().is_empty() {
                    div { class: "status-message", "{status_message}" }
                }
            }

            // Controls
            div { class: "controls",
                input {
                    class: "search-input",
                    r#type: "text",
                    placeholder: "Search by address, port, process...",
                    value: "{search_query}",
                    oninput: move |e| search_query.set(e.value().clone()),
                }

                select {
                    class: "filter-select",
                    value: "{protocol_filter}",
                    onchange: move |e| protocol_filter.set(e.value().clone()),
                    option { value: "all", "All Protocols" }
                    option { value: "tcp", "TCP" }
                    option { value: "udp", "UDP" }
                }

                select {
                    class: "filter-select",
                    value: "{state_filter}",
                    onchange: move |e| state_filter.set(e.value().clone()),
                    option { value: "all", "All States" }
                    option { value: "listen", "LISTEN" }
                    option { value: "established", "ESTABLISHED" }
                    option { value: "time_wait", "TIME_WAIT" }
                    option { value: "close_wait", "CLOSE_WAIT" }
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
                    class: "btn btn-primary",
                    onclick: move |_| {
                        connections.set(get_network_connections());
                    },
                    "🔄 Refresh"
                }

                button {
                    class: "btn btn-danger",
                    disabled: selected_row.read().is_none(),
                    onclick: move |_| {
                        let row_to_kill = *selected_row.read();
                        if let Some((pid, _)) = row_to_kill {
                            if kill_process(pid) {
                                status_message.set(format!("✓ Process {} terminated", pid));
                                connections.set(get_network_connections());
                                selected_row.set(None);
                            } else {
                                status_message.set(format!("✗ Failed to terminate process {}", pid));
                            }
                            spawn(async move {
                                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                                status_message.set(String::new());
                            });
                        }
                    },
                    "Kill Process"
                }

                button {
                    class: "btn btn-secondary",
                    onclick: {
                        let conns = export_connections.clone();
                        move |_| {
                            let conns = conns.clone();
                            spawn(async move {
                                let file = rfd::AsyncFileDialog::new()
                                    .add_filter("CSV", &["csv"])
                                    .set_file_name("network_connections.csv")
                                    .set_title("Export Network Connections")
                                    .save_file()
                                    .await;
                                if let Some(file) = file {
                                    let path = file.path().to_path_buf();
                                    let mut csv = String::from("Protocol,Local Address,Local Port,Remote Address,Remote Port,State,PID,Process\n");
                                    for c in &conns {
                                        let state_str = c.state.map(|s| s.to_string()).unwrap_or_default();
                                        csv.push_str(&format!(
                                            "{},{},{},{},{},{},{},\"{}\"\n",
                                            c.protocol,
                                            c.local_addr,
                                            c.local_port,
                                            c.remote_addr,
                                            c.remote_port,
                                            state_str,
                                            c.pid,
                                            c.process_name.replace('"', "\"\"")
                                        ));
                                    }
                                    match std::fs::write(&path, csv) {
                                        Ok(()) => {
                                            status_message.set(format!("Exported {} connections to {}", conns.len(), path.display()));
                                        }
                                        Err(e) => {
                                            status_message.set(format!("Export failed: {}", e));
                                        }
                                    }
                                    spawn(async move {
                                        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                                        status_message.set(String::new());
                                    });
                                }
                            });
                        }
                    },
                    "Export CSV"
                }
            }

            // Network table
            div { class: "table-container",
                table { class: "process-table network-table",
                    thead { class: "table-header",
                        tr {
                            th {
                                class: "th sortable",
                                onclick: move |_| {
                                    if *sort_column.read() == NetworkSortColumn::Protocol {
                                        let new_order = if *sort_order.read() == SortOrder::Ascending { SortOrder::Descending } else { SortOrder::Ascending };
                                        sort_order.set(new_order);
                                    } else {
                                        sort_column.set(NetworkSortColumn::Protocol);
                                        sort_order.set(SortOrder::Ascending);
                                    }
                                },
                                "Proto{sort_indicator(NetworkSortColumn::Protocol)}"
                            }
                            th {
                                class: "th sortable",
                                onclick: move |_| {
                                    if *sort_column.read() == NetworkSortColumn::LocalAddr {
                                        let new_order = if *sort_order.read() == SortOrder::Ascending { SortOrder::Descending } else { SortOrder::Ascending };
                                        sort_order.set(new_order);
                                    } else {
                                        sort_column.set(NetworkSortColumn::LocalAddr);
                                        sort_order.set(SortOrder::Ascending);
                                    }
                                },
                                "Local Address{sort_indicator(NetworkSortColumn::LocalAddr)}"
                            }
                            th {
                                class: "th sortable",
                                onclick: move |_| {
                                    if *sort_column.read() == NetworkSortColumn::LocalPort {
                                        let new_order = if *sort_order.read() == SortOrder::Ascending { SortOrder::Descending } else { SortOrder::Ascending };
                                        sort_order.set(new_order);
                                    } else {
                                        sort_column.set(NetworkSortColumn::LocalPort);
                                        sort_order.set(SortOrder::Ascending);
                                    }
                                },
                                "Port{sort_indicator(NetworkSortColumn::LocalPort)}"
                            }
                            th {
                                class: "th sortable",
                                onclick: move |_| {
                                    if *sort_column.read() == NetworkSortColumn::RemoteAddr {
                                        let new_order = if *sort_order.read() == SortOrder::Ascending { SortOrder::Descending } else { SortOrder::Ascending };
                                        sort_order.set(new_order);
                                    } else {
                                        sort_column.set(NetworkSortColumn::RemoteAddr);
                                        sort_order.set(SortOrder::Ascending);
                                    }
                                },
                                "Remote Address{sort_indicator(NetworkSortColumn::RemoteAddr)}"
                            }
                            th {
                                class: "th sortable",
                                onclick: move |_| {
                                    if *sort_column.read() == NetworkSortColumn::RemotePort {
                                        let new_order = if *sort_order.read() == SortOrder::Ascending { SortOrder::Descending } else { SortOrder::Ascending };
                                        sort_order.set(new_order);
                                    } else {
                                        sort_column.set(NetworkSortColumn::RemotePort);
                                        sort_order.set(SortOrder::Ascending);
                                    }
                                },
                                "Port{sort_indicator(NetworkSortColumn::RemotePort)}"
                            }
                            th {
                                class: "th sortable",
                                onclick: move |_| {
                                    if *sort_column.read() == NetworkSortColumn::State {
                                        let new_order = if *sort_order.read() == SortOrder::Ascending { SortOrder::Descending } else { SortOrder::Ascending };
                                        sort_order.set(new_order);
                                    } else {
                                        sort_column.set(NetworkSortColumn::State);
                                        sort_order.set(SortOrder::Ascending);
                                    }
                                },
                                "State{sort_indicator(NetworkSortColumn::State)}"
                            }
                            th {
                                class: "th sortable",
                                onclick: move |_| {
                                    if *sort_column.read() == NetworkSortColumn::Pid {
                                        let new_order = if *sort_order.read() == SortOrder::Ascending { SortOrder::Descending } else { SortOrder::Ascending };
                                        sort_order.set(new_order);
                                    } else {
                                        sort_column.set(NetworkSortColumn::Pid);
                                        sort_order.set(SortOrder::Ascending);
                                    }
                                },
                                "PID{sort_indicator(NetworkSortColumn::Pid)}"
                            }
                            th {
                                class: "th sortable",
                                onclick: move |_| {
                                    if *sort_column.read() == NetworkSortColumn::Process {
                                        let new_order = if *sort_order.read() == SortOrder::Ascending { SortOrder::Descending } else { SortOrder::Ascending };
                                        sort_order.set(new_order);
                                    } else {
                                        sort_column.set(NetworkSortColumn::Process);
                                        sort_order.set(SortOrder::Ascending);
                                    }
                                },
                                "Process{sort_indicator(NetworkSortColumn::Process)}"
                            }
                        }
                    }
                    tbody {
                        for conn in filtered_connections {
                            {
                                let pid = conn.pid;
                                let port = conn.local_port;
                                let exe_path = conn.exe_path.clone();
                                let exe_path_ctx = conn.exe_path.clone();
                                let is_selected = *selected_row.read() == Some((pid, port));
                                let row_class = if is_selected { "process-row selected" } else { "process-row" };
                                let proto_class = if conn.protocol == Protocol::Tcp { "proto-tcp" } else { "proto-udp" };
                                let state_str = conn.state.map(|s| s.to_string()).unwrap_or_else(|| "-".to_string());
                                let state_class = match conn.state {
                                    Some(TcpState::Listen) => "state-listen",
                                    Some(TcpState::Established) => "state-established",
                                    Some(TcpState::TimeWait) | Some(TcpState::CloseWait) => "state-waiting",
                                    _ => "state-other",
                                };

                                rsx! {
                                    tr {
                                        key: "{pid}-{port}-{conn.remote_port}",
                                        class: "{row_class}",
                                        onclick: move |_| {
                                            let current = *selected_row.read();
                                            if current == Some((pid, port)) {
                                                selected_row.set(None);
                                            } else {
                                                selected_row.set(Some((pid, port)));
                                            }
                                        },
                                        oncontextmenu: move |e| {
                                            e.prevent_default();
                                            let coords = e.client_coordinates();
                                            selected_row.set(Some((pid, port)));
                                            context_menu.set(NetworkContextMenuState {
                                                visible: true,
                                                x: coords.x as i32,
                                                y: coords.y as i32,
                                                pid: Some(pid),
                                                exe_path: exe_path_ctx.clone(),
                                                port,
                                            });
                                        },
                                        td { class: "cell cell-proto {proto_class}", "{conn.protocol}" }
                                        td { class: "cell cell-addr", "{conn.local_addr}" }
                                        td { class: "cell cell-port", "{conn.local_port}" }
                                        td { class: "cell cell-addr",
                                            if conn.remote_addr.is_empty() || conn.remote_addr == "0.0.0.0" {
                                                "-"
                                            } else {
                                                "{conn.remote_addr}"
                                            }
                                        }
                                        td { class: "cell cell-port",
                                            if conn.remote_port == 0 {
                                                "-"
                                            } else {
                                                "{conn.remote_port}"
                                            }
                                        }
                                        td { class: "cell cell-state {state_class}", "{state_str}" }
                                        td { class: "cell cell-pid", "{conn.pid}" }
                                        td { class: "cell cell-name", title: "{exe_path}", "{conn.process_name}" }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Context Menu
            if ctx_menu.visible {
                div {
                    class: "context-menu",
                    style: "left: {ctx_menu.x}px; top: {ctx_menu.y}px;",
                    onclick: move |e| e.stop_propagation(),

                    button {
                        class: "context-menu-item context-menu-item-danger",
                        onclick: move |_| {
                            if let Some(pid) = ctx_menu.pid {
                                if kill_process(pid) {
                                    status_message.set(format!("✓ Process {} terminated", pid));
                                    connections.set(get_network_connections());
                                    selected_row.set(None);
                                } else {
                                    status_message.set(format!("✗ Failed to terminate process {}", pid));
                                }
                                spawn(async move {
                                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                                    status_message.set(String::new());
                                });
                            }
                            context_menu.set(NetworkContextMenuState::default());
                        },
                        span { "☠️" }
                        span { "Kill Process" }
                    }

                    div { class: "context-menu-separator" }

                    button {
                        class: "context-menu-item",
                        disabled: ctx_menu.exe_path.is_empty(),
                        onclick: {
                            let path = ctx_menu.exe_path.clone();
                            move |_| {
                                open_file_location(&path);
                                context_menu.set(NetworkContextMenuState::default());
                            }
                        },
                        span { "📂" }
                        span { "Open File Location" }
                    }

                    button {
                        class: "context-menu-item",
                        onclick: move |_| {
                            if let Some(pid) = ctx_menu.pid {
                                copy_to_clipboard(&pid.to_string());
                                status_message.set(format!("📋 PID {} copied", pid));
                                spawn(async move {
                                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                                    status_message.set(String::new());
                                });
                            }
                            context_menu.set(NetworkContextMenuState::default());
                        },
                        span { "📋" }
                        span { "Copy PID" }
                    }

                    button {
                        class: "context-menu-item",
                        onclick: move |_| {
                            copy_to_clipboard(&ctx_menu.port.to_string());
                            status_message.set(format!("📋 Port {} copied", ctx_menu.port));
                            spawn(async move {
                                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                                status_message.set(String::new());
                            });
                            context_menu.set(NetworkContextMenuState::default());
                        },
                        span { "📋" }
                        span { "Copy Port" }
                    }

                    button {
                        class: "context-menu-item",
                        disabled: ctx_menu.exe_path.is_empty(),
                        onclick: {
                            let path = ctx_menu.exe_path.clone();
                            move |_| {
                                copy_to_clipboard(&path);
                                status_message.set("📋 Path copied".to_string());
                                spawn(async move {
                                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                                    status_message.set(String::new());
                                });
                                context_menu.set(NetworkContextMenuState::default());
                            }
                        },
                        span { "📝" }
                        span { "Copy Path" }
                    }
                }
            }
        }
    }
}
