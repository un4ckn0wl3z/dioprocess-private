//! Packet Capture tab — WFP-based per-process network packet capture

use callback::packet_capture::{
    add_packet_filter, clear_packet_buffer, clear_packet_filters, export_to_pcap,
    format_timestamp, get_capture_state, get_captured_packets, inject_packet,
    remove_packet_filter, start_packet_capture, stop_packet_capture,
    FilterAction, PacketDirection, PacketFilterRule, PacketProtocol,
};
use callback::packet_storage::get_packet_storage;
use callback::{hv_is_running, is_driver_loaded};
use crate::state::{
    PACKET_CAPTURE_PID, PACKET_CAPTURE_PACKETS, PACKET_CAPTURE_STATE,
    PACKET_CAPTURE_SELECTED, PACKET_CAPTURE_STATUS, PACKET_CAPTURE_IS_ERROR,
    PACKET_CAPTURE_AUTO_SCROLL, PACKET_CAPTURE_EDIT_MODE, PACKET_CAPTURE_EDIT_PAYLOAD,
    PACKET_CAPTURE_EDIT_ASCII, PACKET_CAPTURE_FILTER_RULES, PACKET_CAPTURE_VIEW_MODE,
    PACKET_CAPTURE_SORT_DESC,
    PACKET_MANAGER_PACKETS, PACKET_MANAGER_SELECTED, PACKET_MANAGER_SEARCH,
    PACKET_MANAGER_STATUS, PACKET_MANAGER_IS_ERROR, PACKET_MANAGER_SHOW_SAVE_MODAL,
    PACKET_MANAGER_SAVE_NAME, PACKET_MANAGER_SAVE_DESC, PACKET_MANAGER_SAVE_TAGS,
};
use dioxus::prelude::*;

fn direction_str(dir: PacketDirection) -> &'static str {
    match dir {
        PacketDirection::Outbound => "OUT",
        PacketDirection::Inbound => "IN",
    }
}

fn direction_class(dir: PacketDirection) -> &'static str {
    match dir {
        PacketDirection::Outbound => "dir-badge dir-badge-out",
        PacketDirection::Inbound => "dir-badge dir-badge-in",
    }
}

fn filter_action_str(action: FilterAction) -> &'static str {
    match action {
        FilterAction::Block => "Block",
        FilterAction::Allow => "Allow",
    }
}

fn filter_action_class(action: FilterAction) -> &'static str {
    match action {
        FilterAction::Block => "filter-tag-block",
        FilterAction::Allow => "filter-tag-allow",
    }
}

#[component]
pub fn PacketCaptureTab() -> Element {
    // Use global state for persistence across tab switches
    let mut pid_input = PACKET_CAPTURE_PID.signal();
    let mut packets = PACKET_CAPTURE_PACKETS.signal();
    let mut capture_state = PACKET_CAPTURE_STATE.signal();
    let mut selected_packet_idx = PACKET_CAPTURE_SELECTED.signal();
    let mut status_message = PACKET_CAPTURE_STATUS.signal();
    let mut is_error = PACKET_CAPTURE_IS_ERROR.signal();
    let mut auto_scroll = PACKET_CAPTURE_AUTO_SCROLL.signal();
    let mut filter_rules = PACKET_CAPTURE_FILTER_RULES.signal();
    let mut edit_mode = PACKET_CAPTURE_EDIT_MODE.signal();
    let mut edit_payload = PACKET_CAPTURE_EDIT_PAYLOAD.signal();
    let mut edit_ascii = PACKET_CAPTURE_EDIT_ASCII.signal();
    let mut sort_desc = PACKET_CAPTURE_SORT_DESC.signal();
    
    // Local state for filter input (doesn't need persistence)
    let mut new_filter_port = use_signal(|| String::new());
    let mut new_filter_action = use_signal(|| 0usize); // 0 = Block, 1 = Allow

    let driver_loaded = is_driver_loaded();
    let hv_running = hv_is_running();

    // Auto-refresh packets while capturing
    use_future(move || async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            if capture_state.read().is_capturing {
                // Get new packets
                if let Ok(new_packets) = get_captured_packets() {
                    let had_new = !new_packets.is_empty();
                    if had_new {
                        let mut current = packets.write();
                        current.extend(new_packets);
                        // Limit to 10000 packets
                        if current.len() > 10000 {
                            let excess = current.len() - 10000;
                            current.drain(0..excess);
                        }
                    }
                    // Auto-scroll if enabled and we got new packets
                    if had_new && *auto_scroll.read() && !*sort_desc.read() {
                        // Scroll to bottom (newest at bottom when ascending)
                        let _ = dioxus::document::eval(r#"
                            let container = document.getElementById('packet-table-container');
                            if (container) { container.scrollTop = container.scrollHeight; }
                        "#);
                    } else if had_new && *auto_scroll.read() && *sort_desc.read() {
                        // Scroll to top (newest at top when descending)
                        let _ = dioxus::document::eval(r#"
                            let container = document.getElementById('packet-table-container');
                            if (container) { container.scrollTop = 0; }
                        "#);
                    }
                }
                // Update state
                if let Ok(state) = get_capture_state() {
                    capture_state.set(state);
                }
            }
        }
    });

    let start_capture = move |_| {
        let pid_str = pid_input.read().clone();
        let pid: u32 = match pid_str.trim().parse() {
            Ok(p) => p,
            Err(_) => {
                status_message.set("Invalid PID".to_string());
                is_error.set(true);
                return;
            }
        };

        match start_packet_capture(pid) {
            Ok(()) => {
                status_message.set(format!("Capture started for PID {}", pid));
                is_error.set(false);
                packets.write().clear();
                if let Ok(state) = get_capture_state() {
                    capture_state.set(state);
                }
            }
            Err(e) => {
                status_message.set(format!("Failed to start capture: {:?}", e));
                is_error.set(true);
            }
        }
    };

    let stop_capture = move |_| {
        match stop_packet_capture() {
            Ok(()) => {
                status_message.set("Capture stopped".to_string());
                is_error.set(false);
                if let Ok(state) = get_capture_state() {
                    capture_state.set(state);
                }
            }
            Err(e) => {
                status_message.set(format!("Failed to stop capture: {:?}", e));
                is_error.set(true);
            }
        }
    };

    let clear_packets = move |_| {
        packets.write().clear();
        selected_packet_idx.set(None);
        let _ = clear_packet_buffer();
        status_message.set("Packets cleared".to_string());
        is_error.set(false);
    };

    let add_filter = move |_| {
        let port_str = new_filter_port.read().clone();
        let port: u16 = match port_str.trim().parse() {
            Ok(p) => p,
            Err(_) => {
                status_message.set("Invalid port number".to_string());
                is_error.set(true);
                return;
            }
        };

        let action = if *new_filter_action.read() == 0 {
            FilterAction::Block
        } else {
            FilterAction::Allow
        };

        let rule = PacketFilterRule {
            enabled: true,
            action,
            port,
            ip_address: 0,
            protocol: PacketProtocol::Tcp,
        };

        match add_packet_filter(&rule) {
            Ok(()) => {
                let idx = filter_rules.read().len();
                filter_rules.write().push((rule, idx));
                new_filter_port.set(String::new());
                status_message.set(format!("Filter added for port {}", port));
                is_error.set(false);
            }
            Err(e) => {
                status_message.set(format!("Failed to add filter: {:?}", e));
                is_error.set(true);
            }
        }
    };

    let export_pcap = move |_| {
        let packets_clone = packets.read().clone();
        spawn(async move {
            if let Some(file) = rfd::AsyncFileDialog::new()
                .add_filter("PCAP File", &["pcap"])
                .set_file_name("capture.pcap")
                .save_file()
                .await
            {
                match export_to_pcap(&packets_clone, file.path()) {
                    Ok(()) => {
                        // Can't update signals from here easily, but file is saved
                    }
                    Err(_) => {}
                }
            }
        });
    };

    let mut view_mode = PACKET_CAPTURE_VIEW_MODE.signal();
    let mut manager_packets = PACKET_MANAGER_PACKETS.signal();
    let mut manager_selected = PACKET_MANAGER_SELECTED.signal();
    let mut manager_search = PACKET_MANAGER_SEARCH.signal();
    let mut manager_status = PACKET_MANAGER_STATUS.signal();
    let mut manager_is_error = PACKET_MANAGER_IS_ERROR.signal();
    let mut show_save_modal = PACKET_MANAGER_SHOW_SAVE_MODAL.signal();
    let mut save_name = PACKET_MANAGER_SAVE_NAME.signal();
    let mut save_desc = PACKET_MANAGER_SAVE_DESC.signal();
    let mut save_tags = PACKET_MANAGER_SAVE_TAGS.signal();

    // Load saved packets on first render
    use_effect(move || {
        if let Some(storage) = get_packet_storage() {
            manager_packets.set(storage.get_all_packets());
        }
    });

    rsx! {
        div {
            class: "packet-capture-tab",

            // Header with view mode toggle
            div {
                class: "header-box",
                div {
                    class: "header-title-row",
                    h1 { class: "header-title", "📡 Packet Capture" }
                    div {
                        class: "view-mode-toggle",
                        button {
                            class: if *view_mode.read() == 0 { "btn btn-primary btn-small" } else { "btn btn-secondary btn-small" },
                            onclick: move |_| view_mode.set(0),
                            "Capture"
                        }
                        button {
                            class: if *view_mode.read() == 1 { "btn btn-primary btn-small" } else { "btn btn-secondary btn-small" },
                            onclick: move |_| {
                                view_mode.set(1);
                                // Refresh saved packets
                                if let Some(storage) = get_packet_storage() {
                                    manager_packets.set(storage.get_all_packets());
                                }
                            },
                            "Saved Packets"
                        }
                    }
                }
                div {
                    class: "header-stats",
                    if hv_running {
                        span {
                            class: "capture-status-badge capture-status-active",
                            "HV ACTIVE"
                        }
                    }
                    if !driver_loaded {
                        span {
                            class: "capture-status-badge capture-status-stopped",
                            "DRIVER NOT LOADED"
                        }
                    }
                }
                if !status_message.read().is_empty() {
                    div { class: "status-message", "{status_message}" }
                }
            }

            // View mode: 0 = Capture, 1 = Saved Packets
            if *view_mode.read() == 0 {

            // Controls
            div {
                class: "controls",
                input {
                    r#type: "text",
                    class: "pid-input",
                    placeholder: "PID",
                    value: "{pid_input}",
                    oninput: move |e| pid_input.set(e.value().clone()),
                }
                button {
                    class: "btn btn-primary",
                    disabled: capture_state.read().is_capturing,
                    onclick: start_capture,
                    "▶ Start"
                }
                button {
                    class: "btn btn-danger",
                    disabled: !capture_state.read().is_capturing,
                    onclick: stop_capture,
                    "⏹ Stop"
                }
                button {
                    class: "btn btn-secondary",
                    onclick: clear_packets,
                    "Clear"
                }
                button {
                    class: "btn btn-secondary",
                    onclick: export_pcap,
                    "Export PCAP"
                }
                label {
                    class: "checkbox-label",
                    input {
                        r#type: "checkbox",
                        class: "checkbox",
                        checked: *auto_scroll.read(),
                        onchange: move |e| auto_scroll.set(e.checked()),
                    }
                    span { "Auto-scroll" }
                }
            }

            // Capture stats
            {
                let state = capture_state.read();
                let status_class = if state.is_capturing { "capture-status-badge capture-status-active" } else { "capture-status-badge capture-status-stopped" };
                let status_str = if state.is_capturing { "Capturing" } else { "Stopped" };
                let pkt_count = packets.read().len();
                rsx! {
                    div {
                        class: "capture-stats",
                        span {
                            class: "{status_class}",
                            "{status_str}"
                        }
                        span { "Target PID: {state.target_pid}" }
                        span { "Packets: {pkt_count}" }
                        span { "Dropped: {state.dropped_count}" }
                    }
                }
            }

            // Filter rules
            div {
                class: "filter-panel",
                div {
                    class: "filter-panel-header",
                    span { class: "filter-panel-title", "Filters" }
                    input {
                        r#type: "text",
                        class: "pid-input",
                        placeholder: "Port",
                        value: "{new_filter_port}",
                        oninput: move |e| new_filter_port.set(e.value().clone()),
                    }
                    select {
                        class: "filter-select",
                        value: "{new_filter_action}",
                        onchange: move |e| {
                            if let Ok(v) = e.value().parse::<usize>() {
                                new_filter_action.set(v);
                            }
                        },
                        option { value: "0", "Block" }
                        option { value: "1", "Allow" }
                    }
                    button {
                        class: "btn btn-primary btn-small",
                        onclick: add_filter,
                        "+ Add"
                    }
                    button {
                        class: "btn btn-secondary btn-small",
                        onclick: move |_| {
                            let _ = clear_packet_filters();
                            filter_rules.write().clear();
                        },
                        "Clear All"
                    }
                }
                // Active filters
                div {
                    class: "filter-tags",
                    for (rule, idx) in filter_rules.read().iter() {
                        {
                            let tag_class = filter_action_class(rule.action);
                            let action_str = filter_action_str(rule.action);
                            let port = rule.port;
                            let idx_copy = *idx;
                            rsx! {
                                span {
                                    key: "{idx_copy}",
                                    class: "{tag_class}",
                                    "{action_str} :{port}"
                                    button {
                                        class: "filter-tag-remove",
                                        onclick: move |_| {
                                            let _ = remove_packet_filter(idx_copy as u32);
                                            filter_rules.write().retain(|(_, i)| *i != idx_copy);
                                        },
                                        "×"
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Packet list
            div {
                class: "packet-content",

                // Left: packet table
                div {
                    class: "packet-table-container",
                    id: "packet-table-container",
                    table {
                        class: "packet-table",
                        thead {
                            class: "table-header",
                            tr {
                                th { 
                                    class: "th th-sortable",
                                    onclick: move |_| {
                                        let current = *sort_desc.read();
                                        sort_desc.set(!current);
                                    },
                                    "#"
                                    span { 
                                        class: "sort-indicator",
                                        if *sort_desc.read() { " ▼" } else { " ▲" }
                                    }
                                }
                                th { class: "th", "Time" }
                                th { class: "th", "Dir" }
                                th { class: "th", "Proto" }
                                th { class: "th", "Source" }
                                th { class: "th", "Destination" }
                                th { class: "th", "Len" }
                            }
                        }
                        tbody {
                            {
                                let packets_list = packets.read();
                                let is_desc = *sort_desc.read();
                                let indices: Vec<usize> = if is_desc {
                                    (0..packets_list.len()).rev().collect()
                                } else {
                                    (0..packets_list.len()).collect()
                                };
                                rsx! {
                                    for idx in indices {
                                        {
                                            let packet = &packets_list[idx];
                                            let pkt_id = packet.id;
                                            let ts = format_timestamp(packet.timestamp);
                                            let dir = packet.direction;
                                            let dir_str = direction_str(dir);
                                            let dir_class = direction_class(dir);
                                            let proto = format!("{}", packet.protocol);
                                            let src = format!("{}:{}", packet.local_addr, packet.local_port);
                                            let dst = format!("{}:{}", packet.remote_addr, packet.remote_port);
                                            let plen = packet.payload.len();
                                            let payload_hex = packet.payload.iter()
                                                .map(|b| format!("{:02X}", b))
                                                .collect::<Vec<_>>()
                                                .join(" ");
                                            let is_selected = *selected_packet_idx.read() == Some(idx);
                                            let row_class = if is_selected { "process-row selected" } else { "process-row" };
                                            rsx! {
                                                tr {
                                                    key: "{pkt_id}",
                                                    class: "{row_class}",
                                                    onclick: move |_| {
                                                        selected_packet_idx.set(Some(idx));
                                                        edit_payload.set(payload_hex.clone());
                                                        edit_mode.set(false);
                                                    },
                                                    td { class: "cell cell-id", "{pkt_id}" }
                                                    td { class: "cell cell-time", "{ts}" }
                                                    td {
                                                        class: "cell cell-dir",
                                                        span { class: "{dir_class}", "{dir_str}" }
                                                    }
                                                    td { class: "cell cell-proto", "{proto}" }
                                                    td { class: "cell cell-addr", "{src}" }
                                                    td { class: "cell cell-addr", "{dst}" }
                                                    td { class: "cell cell-len", "{plen}" }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Right: packet details
                div {
                    class: "packet-details-panel",
                    {
                        let sel_idx = *selected_packet_idx.read();
                        let editing = *edit_mode.read();
                        if let Some(idx) = sel_idx {
                            if let Some(packet) = packets.read().get(idx).cloned() {
                                let pkt_id = packet.id;
                                let pkt_pid = packet.pid;
                                let dir_str = if packet.direction == PacketDirection::Outbound { "Outbound" } else { "Inbound" };
                                let proto_str = format!("{}", packet.protocol);
                                let local_str = format!("{}:{}", packet.local_addr, packet.local_port);
                                let remote_str = format!("{}:{}", packet.remote_addr, packet.remote_port);
                                let hex_display = packet.payload.iter()
                                    .map(|b| format!("{:02X}", b))
                                    .collect::<Vec<_>>()
                                    .chunks(16)
                                    .map(|chunk| chunk.join(" "))
                                    .collect::<Vec<_>>()
                                    .join("\n");
                                let ascii_display: String = packet.payload.iter()
                                    .map(|&b| if b >= 32 && b < 127 { b as char } else { '.' })
                                    .collect();
                                let edit_btn_text = if editing { "Cancel" } else { "Edit" };
                                let packet_clone = packet.clone();
                                rsx! {
                                    div {
                                        div {
                                            class: "packet-details-header",
                                            span { class: "packet-details-title", "Packet #{pkt_id}" }
                                            div {
                                                class: "packet-details-actions",
                                                button {
                                                    class: "btn btn-secondary btn-small",
                                                    onclick: move |_| {
                                                        let current = *edit_mode.read();
                                                        if !current {
                                                            // Entering edit mode - initialize payload
                                                            let hex_str = packet.payload.iter()
                                                                .map(|b| format!("{:02X}", b))
                                                                .collect::<Vec<_>>()
                                                                .join(" ");
                                                            edit_payload.set(hex_str);
                                                            edit_ascii.set(false); // Start in hex mode
                                                        }
                                                        edit_mode.set(!current);
                                                    },
                                                    "{edit_btn_text}"
                                                }
                                                button {
                                                    class: "btn btn-primary btn-small",
                                                    title: "Resend packet at network layer",
                                                    onclick: move |_| {
                                                        let mut p = packet_clone.clone();
                                                        if *edit_mode.read() {
                                                            let is_ascii = *edit_ascii.read();
                                                            let payload_str = edit_payload.read().clone();
                                                            let bytes: Vec<u8> = if is_ascii {
                                                                // ASCII mode - direct string to bytes
                                                                payload_str.into_bytes()
                                                            } else {
                                                                // Hex mode - parse hex string
                                                                payload_str
                                                                    .split_whitespace()
                                                                    .filter_map(|s| u8::from_str_radix(s, 16).ok())
                                                                    .collect()
                                                            };
                                                            p.payload = bytes;
                                                        }
                                                        match inject_packet(&p) {
                                                            Ok(()) => {
                                                                status_message.set("Packet injected successfully".to_string());
                                                                is_error.set(false);
                                                            }
                                                            Err(e) => {
                                                                status_message.set(format!("Resend failed: {:?}", e));
                                                                is_error.set(true);
                                                            }
                                                        }
                                                    },
                                                    "Resend"
                                                }
                                                button {
                                                    class: "btn btn-secondary btn-small",
                                                    title: "Save packet to library",
                                                    onclick: move |_| {
                                                        show_save_modal.set(true);
                                                    },
                                                    "Save"
                                                }
                                            }
                                        }
                                        div {
                                            class: "packet-details-info",
                                            div { "PID: ", span { "{pkt_pid}" } }
                                            div { "Direction: ", span { "{dir_str}" } }
                                            div { "Protocol: ", span { "{proto_str}" } }
                                            div { "Local: ", span { "{local_str}" } }
                                            div { "Remote: ", span { "{remote_str}" } }
                                        }
                                        if editing {
                                            div {
                                                class: "edit-mode-toggle",
                                                label {
                                                    class: "checkbox-label",
                                                    input {
                                                        r#type: "radio",
                                                        name: "edit_mode_type",
                                                        checked: !*edit_ascii.read(),
                                                        onchange: move |_| {
                                                            // Switch to hex mode - convert current payload
                                                            if *edit_ascii.read() {
                                                                let ascii_str = edit_payload.read().clone();
                                                                let hex_str = ascii_str.bytes()
                                                                    .map(|b| format!("{:02X}", b))
                                                                    .collect::<Vec<_>>()
                                                                    .join(" ");
                                                                edit_payload.set(hex_str);
                                                            }
                                                            edit_ascii.set(false);
                                                        },
                                                    }
                                                    span { "Hex" }
                                                }
                                                label {
                                                    class: "checkbox-label",
                                                    input {
                                                        r#type: "radio",
                                                        name: "edit_mode_type",
                                                        checked: *edit_ascii.read(),
                                                        onchange: move |_| {
                                                            // Switch to ASCII mode - convert current payload
                                                            if !*edit_ascii.read() {
                                                                let hex_str = edit_payload.read().clone();
                                                                let bytes: Vec<u8> = hex_str
                                                                    .split_whitespace()
                                                                    .filter_map(|s| u8::from_str_radix(s, 16).ok())
                                                                    .collect();
                                                                let ascii_str: String = bytes.iter()
                                                                    .map(|&b| if b >= 32 && b < 127 { b as char } else { '.' })
                                                                    .collect();
                                                                edit_payload.set(ascii_str);
                                                            }
                                                            edit_ascii.set(true);
                                                        },
                                                    }
                                                    span { "ASCII" }
                                                }
                                            }
                                            div {
                                                class: "hex-section",
                                                div { 
                                                    class: "hex-section-title", 
                                                    if *edit_ascii.read() { "ASCII (editable):" } else { "Hex (editable):" }
                                                }
                                                textarea {
                                                    class: "hex-edit-textarea",
                                                    value: "{edit_payload}",
                                                    oninput: move |e| edit_payload.set(e.value().clone()),
                                                }
                                            }
                                        } else {
                                            div {
                                                class: "hex-section",
                                                div { class: "hex-section-title", "Hex:" }
                                                pre {
                                                    class: "hex-display",
                                                    "{hex_display}"
                                                }
                                            }
                                            div {
                                                class: "hex-section",
                                                div { class: "hex-section-title", "ASCII:" }
                                                pre {
                                                    class: "hex-display",
                                                    "{ascii_display}"
                                                }
                                            }
                                        }
                                    }
                                }
                            } else {
                                rsx! {
                                    div {
                                        class: "packet-empty-state",
                                        "Select a packet to view details"
                                    }
                                }
                            }
                        } else {
                            rsx! {
                                div {
                                    class: "packet-empty-state",
                                    "Select a packet to view details"
                                }
                            }
                        }
                    }
                }
            }

            } // end if view_mode == 0

            // Saved Packets view (view_mode == 1)
            if *view_mode.read() == 1 {
                // Manager controls
                div {
                    class: "controls",
                    input {
                        r#type: "text",
                        class: "search-input",
                        placeholder: "Search saved packets...",
                        value: "{manager_search}",
                        oninput: move |e| {
                            manager_search.set(e.value().clone());
                            if let Some(storage) = get_packet_storage() {
                                let query = e.value();
                                if query.is_empty() {
                                    manager_packets.set(storage.get_all_packets());
                                } else {
                                    manager_packets.set(storage.search_packets(&query));
                                }
                            }
                        },
                    }
                    button {
                        class: "btn btn-secondary",
                        onclick: move |_| {
                            spawn(async move {
                                if let Some(file) = rfd::AsyncFileDialog::new()
                                    .add_filter("DioProcess Packet", &["dpp"])
                                    .pick_file()
                                    .await
                                {
                                    if let Some(storage) = get_packet_storage() {
                                        match storage.import_dpp(file.path()) {
                                            Ok(_) => {
                                                manager_packets.set(storage.get_all_packets());
                                                manager_status.set("Packet imported".to_string());
                                                manager_is_error.set(false);
                                            }
                                            Err(e) => {
                                                manager_status.set(format!("Import failed: {}", e));
                                                manager_is_error.set(true);
                                            }
                                        }
                                    }
                                }
                            });
                        },
                        "Import .dpp"
                    }
                    button {
                        class: "btn btn-secondary",
                        onclick: move |_| {
                            if let Some(storage) = get_packet_storage() {
                                manager_packets.set(storage.get_all_packets());
                            }
                        },
                        "Refresh"
                    }
                }

                if !manager_status.read().is_empty() {
                    div {
                        class: if *manager_is_error.read() { "status-message error" } else { "status-message" },
                        "{manager_status}"
                    }
                }

                // Saved packets list
                div {
                    class: "packet-content",
                    div {
                        class: "packet-table-container",
                        table {
                            class: "packet-table",
                            thead {
                                class: "table-header",
                                tr {
                                    th { class: "th", "Name" }
                                    th { class: "th", "Proto" }
                                    th { class: "th", "Destination" }
                                    th { class: "th", "Size" }
                                    th { class: "th", "Tags" }
                                }
                            }
                            tbody {
                                for saved in manager_packets.read().iter() {
                                    {
                                        let id = saved.id;
                                        let name = saved.name.clone();
                                        let proto = format!("{:?}", saved.protocol);
                                        let dest = format!("{}:{}", saved.remote_addr, saved.remote_port);
                                        let size = saved.payload.len();
                                        let tags = saved.tags.join(", ");
                                        let is_selected = *manager_selected.read() == Some(id);
                                        let row_class = if is_selected { "process-row selected" } else { "process-row" };
                                        rsx! {
                                            tr {
                                                key: "{id}",
                                                class: "{row_class}",
                                                onclick: move |_| manager_selected.set(Some(id)),
                                                td { class: "cell", "{name}" }
                                                td { class: "cell", "{proto}" }
                                                td { class: "cell", "{dest}" }
                                                td { class: "cell", "{size}" }
                                                td { class: "cell", "{tags}" }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Selected packet details
                    div {
                        class: "packet-details-panel",
                        {
                            let sel_id = *manager_selected.read();
                            if let Some(id) = sel_id {
                                if let Some(saved) = manager_packets.read().iter().find(|p| p.id == id).cloned() {
                                    let hex_display = saved.payload.iter()
                                        .map(|b| format!("{:02X}", b))
                                        .collect::<Vec<_>>()
                                        .chunks(16)
                                        .map(|chunk| chunk.join(" "))
                                        .collect::<Vec<_>>()
                                        .join("\n");
                                    let ascii_display: String = saved.payload.iter()
                                        .map(|&b| if b >= 32 && b < 127 { b as char } else { '.' })
                                        .collect();
                                    let saved_clone = saved.clone();
                                    let saved_for_inject = saved.clone();
                                    rsx! {
                                        div {
                                            div {
                                                class: "packet-details-header",
                                                span { class: "packet-details-title", "{saved.name}" }
                                                div {
                                                    class: "packet-details-actions",
                                                    button {
                                                        class: "btn btn-primary btn-small",
                                                        onclick: move |_| {
                                                            let packet = saved_for_inject.to_captured_packet();
                                                            match inject_packet(&packet) {
                                                                Ok(()) => {
                                                                    manager_status.set("Packet sent".to_string());
                                                                    manager_is_error.set(false);
                                                                }
                                                                Err(e) => {
                                                                    manager_status.set(format!("Send failed: {:?}", e));
                                                                    manager_is_error.set(true);
                                                                }
                                                            }
                                                        },
                                                        "Send"
                                                    }
                                                    button {
                                                        class: "btn btn-secondary btn-small",
                                                        onclick: move |_| {
                                                            let saved_id = saved_clone.id;
                                                            let saved_name = saved_clone.name.clone();
                                                            spawn(async move {
                                                                if let Some(file) = rfd::AsyncFileDialog::new()
                                                                    .add_filter("DioProcess Packet", &["dpp"])
                                                                    .set_file_name(&format!("{}.dpp", saved_name))
                                                                    .save_file()
                                                                    .await
                                                                {
                                                                    if let Some(storage) = get_packet_storage() {
                                                                        match storage.export_dpp(saved_id, file.path()) {
                                                                            Ok(()) => {}
                                                                            Err(_) => {}
                                                                        }
                                                                    }
                                                                }
                                                            });
                                                        },
                                                        "Export"
                                                    }
                                                    button {
                                                        class: "btn btn-danger btn-small",
                                                        onclick: move |_| {
                                                            if let Some(storage) = get_packet_storage() {
                                                                let _ = storage.delete_packet(id);
                                                                manager_packets.set(storage.get_all_packets());
                                                                manager_selected.set(None);
                                                            }
                                                        },
                                                        "Delete"
                                                    }
                                                }
                                            }
                                            div {
                                                class: "packet-details-info",
                                                div { "Description: ", span { "{saved.description}" } }
                                                div { "Protocol: ", span { "{saved.protocol:?}" } }
                                                div { "Direction: ", span { "{saved.direction:?}" } }
                                                div { "Local: ", span { "{saved.local_addr}:{saved.local_port}" } }
                                                div { "Remote: ", span { "{saved.remote_addr}:{saved.remote_port}" } }
                                                div { "Tags: ", span { "{saved.tags:?}" } }
                                            }
                                            div {
                                                class: "hex-section",
                                                div { class: "hex-section-title", "Hex:" }
                                                pre { class: "hex-display", "{hex_display}" }
                                            }
                                            div {
                                                class: "hex-section",
                                                div { class: "hex-section-title", "ASCII:" }
                                                pre { class: "hex-display", "{ascii_display}" }
                                            }
                                        }
                                    }
                                } else {
                                    rsx! { div { class: "packet-empty-state", "Select a saved packet" } }
                                }
                            } else {
                                rsx! { div { class: "packet-empty-state", "Select a saved packet" } }
                            }
                        }
                    }
                }
            } // end if view_mode == 1

            // Save packet modal
            if *show_save_modal.read() {
                div {
                    class: "modal-overlay",
                    onclick: move |_| show_save_modal.set(false),
                    div {
                        class: "modal-content",
                        onclick: move |e| e.stop_propagation(),
                        h2 { "Save Packet" }
                        div {
                            class: "form-group",
                            label { "Name:" }
                            input {
                                r#type: "text",
                                class: "form-input",
                                value: "{save_name}",
                                oninput: move |e| save_name.set(e.value().clone()),
                            }
                        }
                        div {
                            class: "form-group",
                            label { "Description:" }
                            textarea {
                                class: "form-input",
                                value: "{save_desc}",
                                oninput: move |e| save_desc.set(e.value().clone()),
                            }
                        }
                        div {
                            class: "form-group",
                            label { "Tags (comma-separated):" }
                            input {
                                r#type: "text",
                                class: "form-input",
                                placeholder: "tag1, tag2, tag3",
                                value: "{save_tags}",
                                oninput: move |e| save_tags.set(e.value().clone()),
                            }
                        }
                        div {
                            class: "modal-actions",
                            button {
                                class: "btn btn-secondary",
                                onclick: move |_| show_save_modal.set(false),
                                "Cancel"
                            }
                            button {
                                class: "btn btn-primary",
                                onclick: move |_| {
                                    if let Some(idx) = *selected_packet_idx.read() {
                                        if let Some(mut packet) = packets.read().get(idx).cloned() {
                                            // If in edit mode, use the edited payload
                                            if *edit_mode.read() {
                                                let is_ascii = *edit_ascii.read();
                                                let payload_str = edit_payload.read().clone();
                                                let bytes: Vec<u8> = if is_ascii {
                                                    payload_str.into_bytes()
                                                } else {
                                                    payload_str
                                                        .split_whitespace()
                                                        .filter_map(|s| u8::from_str_radix(s, 16).ok())
                                                        .collect()
                                                };
                                                packet.payload = bytes;
                                            }
                                            if let Some(storage) = get_packet_storage() {
                                                let name = save_name.read().clone();
                                                let desc = save_desc.read().clone();
                                                let tags: Vec<String> = save_tags.read()
                                                    .split(',')
                                                    .map(|s| s.trim().to_string())
                                                    .filter(|s| !s.is_empty())
                                                    .collect();
                                                match storage.save_packet(&name, &desc, &tags, &packet) {
                                                    Ok(_) => {
                                                        status_message.set(format!("Packet saved as '{}'", name));
                                                        is_error.set(false);
                                                        show_save_modal.set(false);
                                                        save_name.set(String::new());
                                                        save_desc.set(String::new());
                                                        save_tags.set(String::new());
                                                    }
                                                    Err(e) => {
                                                        status_message.set(format!("Save failed: {}", e));
                                                        is_error.set(true);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                },
                                "Save"
                            }
                        }
                    }
                }
            }
        }
    }
}
