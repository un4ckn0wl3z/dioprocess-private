//! Packet Capture tab — WFP-based per-process network packet capture

use callback::packet_capture::{
    add_packet_filter, clear_packet_buffer, clear_packet_filters, export_to_pcap,
    format_timestamp, get_capture_state, get_captured_packets, inject_packet,
    remove_packet_filter, start_packet_capture, stop_packet_capture,
    CapturedPacket, CaptureState, FilterAction, PacketDirection, PacketFilterRule, PacketProtocol,
};
use callback::{hv_is_running, is_driver_loaded};
use dioxus::prelude::*;

fn direction_str(dir: PacketDirection) -> &'static str {
    match dir {
        PacketDirection::Outbound => "OUT",
        PacketDirection::Inbound => "IN",
    }
}

fn direction_color(dir: PacketDirection) -> &'static str {
    match dir {
        PacketDirection::Outbound => "#2563eb",
        PacketDirection::Inbound => "#16a34a",
    }
}

fn filter_action_str(action: FilterAction) -> &'static str {
    match action {
        FilterAction::Block => "Block",
        FilterAction::Allow => "Allow",
    }
}

fn filter_action_bg(action: FilterAction) -> &'static str {
    match action {
        FilterAction::Block => "#fee2e2",
        FilterAction::Allow => "#dcfce7",
    }
}

#[component]
pub fn PacketCaptureTab() -> Element {
    let mut pid_input = use_signal(|| String::new());
    let mut packets = use_signal(|| Vec::<CapturedPacket>::new());
    let mut capture_state = use_signal(|| CaptureState {
        is_capturing: false,
        target_pid: 0,
        packet_count: 0,
        dropped_count: 0,
    });
    let mut selected_packet_idx = use_signal(|| None::<usize>);
    let mut status_message = use_signal(|| String::new());
    let mut is_error = use_signal(|| false);
    let mut auto_scroll = use_signal(|| true);
    let mut filter_rules = use_signal(|| Vec::<(PacketFilterRule, usize)>::new());
    let mut new_filter_port = use_signal(|| String::new());
    let mut new_filter_action = use_signal(|| 0usize); // 0 = Block, 1 = Allow
    let mut edit_mode = use_signal(|| false);
    let mut edit_payload = use_signal(|| String::new());

    let driver_loaded = is_driver_loaded();
    let hv_running = hv_is_running();

    // Auto-refresh packets while capturing
    use_future(move || async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            if capture_state.read().is_capturing {
                // Get new packets
                if let Ok(new_packets) = get_captured_packets() {
                    if !new_packets.is_empty() {
                        let mut current = packets.write();
                        current.extend(new_packets);
                        // Limit to 10000 packets
                        if current.len() > 10000 {
                            let excess = current.len() - 10000;
                            current.drain(0..excess);
                        }
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

    rsx! {
        div {
            class: "service-tab",
            style: "padding: 16px;",

            // Header
            div {
                class: "service-header",
                style: "display: flex; align-items: center; gap: 12px; margin-bottom: 16px;",
                h2 { style: "margin: 0;", "Packet Capture" }
                if hv_running {
                    span {
                        class: "badge",
                        style: "background: #22c55e; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px;",
                        "HV ACTIVE"
                    }
                }
                if !driver_loaded {
                    span {
                        class: "badge",
                        style: "background: #dc2626; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px;",
                        "DRIVER NOT LOADED"
                    }
                }
            }

            // Controls
            div {
                style: "display: flex; gap: 8px; align-items: center; margin-bottom: 12px;",
                label { "PID:" }
                input {
                    r#type: "text",
                    class: "input",
                    style: "width: 100px;",
                    placeholder: "Process ID",
                    value: "{pid_input}",
                    oninput: move |e| pid_input.set(e.value().clone()),
                }
                button {
                    class: "btn btn-primary",
                    disabled: capture_state.read().is_capturing,
                    onclick: start_capture,
                    "Start"
                }
                button {
                    class: "btn",
                    disabled: !capture_state.read().is_capturing,
                    onclick: stop_capture,
                    "Stop"
                }
                button {
                    class: "btn",
                    onclick: clear_packets,
                    "Clear"
                }
                button {
                    class: "btn",
                    onclick: export_pcap,
                    "Export PCAP"
                }
                div { style: "flex: 1;" }
                label {
                    style: "display: flex; align-items: center; gap: 4px;",
                    input {
                        r#type: "checkbox",
                        checked: *auto_scroll.read(),
                        onchange: move |e| auto_scroll.set(e.checked()),
                    }
                    "Auto-scroll"
                }
            }

            // Status
            if !status_message.read().is_empty() {
                {
                    let err = *is_error.read();
                    let bg = if err { "#fef2f2" } else { "#f0fdf4" };
                    let cls = if err { "status-error" } else { "status-success" };
                    rsx! {
                        div {
                            class: "{cls}",
                            style: "padding: 8px; margin-bottom: 12px; border-radius: 4px; background: {bg};",
                            "{status_message}"
                        }
                    }
                }
            }

            // Capture stats
            {
                let state = capture_state.read();
                let status_str = if state.is_capturing { "Capturing" } else { "Stopped" };
                let pkt_count = packets.read().len();
                rsx! {
                    div {
                        style: "display: flex; gap: 16px; margin-bottom: 12px; font-size: 12px; color: #666;",
                        span { "Status: {status_str}" }
                        span { "Target PID: {state.target_pid}" }
                        span { "Packets: {pkt_count}" }
                        span { "Dropped: {state.dropped_count}" }
                    }
                }
            }

            // Filter rules
            div {
                style: "margin-bottom: 12px; padding: 8px; background: #f8f9fa; border-radius: 4px;",
                div {
                    style: "display: flex; gap: 8px; align-items: center; margin-bottom: 8px;",
                    span { style: "font-weight: 500;", "Filters:" }
                    input {
                        r#type: "text",
                        class: "input",
                        style: "width: 80px;",
                        placeholder: "Port",
                        value: "{new_filter_port}",
                        oninput: move |e| new_filter_port.set(e.value().clone()),
                    }
                    select {
                        class: "input",
                        style: "width: 80px;",
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
                        class: "btn",
                        style: "font-size: 11px; padding: 2px 8px;",
                        onclick: add_filter,
                        "+ Add"
                    }
                    button {
                        class: "btn",
                        style: "font-size: 11px; padding: 2px 8px;",
                        onclick: move |_| {
                            let _ = clear_packet_filters();
                            filter_rules.write().clear();
                        },
                        "Clear All"
                    }
                }
                // Active filters
                div {
                    style: "display: flex; gap: 8px; flex-wrap: wrap;",
                    for (rule, idx) in filter_rules.read().iter() {
                        {
                            let bg = filter_action_bg(rule.action);
                            let action_str = filter_action_str(rule.action);
                            let port = rule.port;
                            let idx_copy = *idx;
                            rsx! {
                                span {
                                    key: "{idx_copy}",
                                    style: "background: {bg}; padding: 2px 8px; border-radius: 4px; font-size: 11px; display: flex; align-items: center; gap: 4px;",
                                    "{action_str} :{port}"
                                    button {
                                        style: "background: none; border: none; cursor: pointer; color: #666; padding: 0 4px;",
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
                style: "display: flex; gap: 12px; height: calc(100vh - 380px);",

                // Left: packet table
                div {
                    style: "flex: 1; overflow: auto; border: 1px solid #ddd; border-radius: 4px;",
                    table {
                        class: "data-table",
                        style: "width: 100%; font-size: 11px;",
                        thead {
                            tr {
                                th { style: "width: 50px;", "#" }
                                th { style: "width: 90px;", "Time" }
                                th { style: "width: 40px;", "Dir" }
                                th { style: "width: 40px;", "Proto" }
                                th { "Source" }
                                th { "Destination" }
                                th { style: "width: 50px;", "Len" }
                            }
                        }
                        tbody {
                            for (idx, packet) in packets.read().iter().enumerate() {
                                {
                                    let pkt_id = packet.id;
                                    let ts = format_timestamp(packet.timestamp);
                                    let dir = packet.direction;
                                    let dir_str = direction_str(dir);
                                    let dir_color = direction_color(dir);
                                    let proto = format!("{}", packet.protocol);
                                    let src = format!("{}:{}", packet.local_addr, packet.local_port);
                                    let dst = format!("{}:{}", packet.remote_addr, packet.remote_port);
                                    let plen = packet.payload.len();
                                    let payload_hex = packet.payload.iter()
                                        .map(|b| format!("{:02X}", b))
                                        .collect::<Vec<_>>()
                                        .join(" ");
                                    let is_selected = *selected_packet_idx.read() == Some(idx);
                                    let row_class = if is_selected { "selected" } else { "" };
                                    rsx! {
                                        tr {
                                            key: "{pkt_id}",
                                            class: "{row_class}",
                                            style: "cursor: pointer;",
                                            onclick: move |_| {
                                                selected_packet_idx.set(Some(idx));
                                                edit_payload.set(payload_hex.clone());
                                                edit_mode.set(false);
                                            },
                                            td { "{pkt_id}" }
                                            td { "{ts}" }
                                            td {
                                                style: "color: {dir_color};",
                                                "{dir_str}"
                                            }
                                            td { "{proto}" }
                                            td { "{src}" }
                                            td { "{dst}" }
                                            td { "{plen}" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Right: packet details
                div {
                    style: "width: 400px; border: 1px solid #ddd; border-radius: 4px; padding: 8px; overflow: auto;",
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
                                            style: "display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;",
                                            span { style: "font-weight: 500;", "Packet #{pkt_id}" }
                                            div {
                                                style: "display: flex; gap: 4px;",
                                                button {
                                                    class: "btn",
                                                    style: "font-size: 10px; padding: 2px 8px;",
                                                    onclick: move |_| {
                                                        let current = *edit_mode.read();
                                                        edit_mode.set(!current);
                                                    },
                                                    "{edit_btn_text}"
                                                }
                                                button {
                                                    class: "btn btn-primary",
                                                    style: "font-size: 10px; padding: 2px 8px;",
                                                    onclick: move |_| {
                                                        let mut p = packet_clone.clone();
                                                        if *edit_mode.read() {
                                                            let hex_str = edit_payload.read().clone();
                                                            let bytes: Vec<u8> = hex_str
                                                                .split_whitespace()
                                                                .filter_map(|s| u8::from_str_radix(s, 16).ok())
                                                                .collect();
                                                            p.payload = bytes;
                                                        }
                                                        match inject_packet(&p) {
                                                            Ok(()) => {
                                                                status_message.set("Packet resent".to_string());
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
                                            }
                                        }
                                        div {
                                            style: "font-size: 11px; margin-bottom: 8px; color: #666;",
                                            div { "PID: {pkt_pid}" }
                                            div { "Direction: {dir_str}" }
                                            div { "Protocol: {proto_str}" }
                                            div { "Local: {local_str}" }
                                            div { "Remote: {remote_str}" }
                                        }
                                        div {
                                            style: "margin-bottom: 8px;",
                                            div { style: "font-weight: 500; font-size: 11px; margin-bottom: 4px;", "Hex:" }
                                            if editing {
                                                textarea {
                                                    class: "input",
                                                    style: "width: 100%; height: 120px; font-family: monospace; font-size: 10px;",
                                                    value: "{edit_payload}",
                                                    oninput: move |e| edit_payload.set(e.value().clone()),
                                                }
                                            } else {
                                                pre {
                                                    style: "background: #f8f9fa; padding: 8px; border-radius: 4px; font-size: 10px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; max-height: 120px;",
                                                    "{hex_display}"
                                                }
                                            }
                                        }
                                        div {
                                            div { style: "font-weight: 500; font-size: 11px; margin-bottom: 4px;", "ASCII:" }
                                            pre {
                                                style: "background: #f8f9fa; padding: 8px; border-radius: 4px; font-size: 10px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; max-height: 120px;",
                                                "{ascii_display}"
                                            }
                                        }
                                    }
                                }
                            } else {
                                rsx! {
                                    div {
                                        style: "color: #666; text-align: center; padding: 20px;",
                                        "Select a packet to view details"
                                    }
                                }
                            }
                        } else {
                            rsx! {
                                div {
                                    style: "color: #666; text-align: center; padding: 20px;",
                                    "Select a packet to view details"
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
