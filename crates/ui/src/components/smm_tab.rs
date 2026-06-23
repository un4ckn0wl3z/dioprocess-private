//! SMM (System Management Mode) tab — Ring -2 memory operations via SMI

use dioxus::prelude::*;
use smm::{
    is_smm_driver_loaded, smm_cache_session, smm_escalate_privileges, smm_phys_read,
    smm_phys_write, smm_ping, smm_virtual_read, smm_virtual_write, smm_vtop,
};
use std::process::Command;

use crate::helpers::copy_to_clipboard;

const HEX_PAGE_SIZE: usize = 4096;

#[derive(Clone, PartialEq)]
enum SmmOperation {
    PhysRead,
    PhysWrite,
    VaRead,
    VaWrite,
    Vtop,
}

#[component]
pub fn SmmTab() -> Element {
    let mut smm_loaded = use_signal(|| is_smm_driver_loaded());
    let mut smi_available = use_signal(|| false);
    let mut session_cached = use_signal(|| false);
    let mut status_message = use_signal(|| String::new());
    let mut is_error = use_signal(|| false);

    let mut operation = use_signal(|| SmmOperation::PhysRead);
    let mut pid_input = use_signal(|| String::new());
    let mut address_input = use_signal(|| String::new());
    let mut length_input = use_signal(|| "256".to_string());
    let mut write_data_input = use_signal(|| String::new());
    let mut write_type = use_signal(|| "hex".to_string());

    let mut hex_data = use_signal(|| Vec::<u8>::new());
    let mut hex_base_address = use_signal(|| 0u64);
    let mut hex_page = use_signal(|| 0usize);
    let mut vtop_result = use_signal(|| None::<u64>);

    let mut refresh_status = move || {
        smm_loaded.set(is_smm_driver_loaded());
        if *smm_loaded.read() {
            match smm_ping() {
                Ok(()) => smi_available.set(true),
                Err(_) => smi_available.set(false),
            }
        } else {
            smi_available.set(false);
        }
    };

    let mut do_cache_session = move || {
        match smm_cache_session() {
            Ok(()) => {
                session_cached.set(true);
                status_message.set("Session cached successfully".to_string());
                is_error.set(false);
            }
            Err(e) => {
                status_message.set(format!("Failed to cache session: {}", e));
                is_error.set(true);
            }
        }
    };

    let mut do_ping = move || {
        match smm_ping() {
            Ok(()) => {
                smi_available.set(true);
                status_message.set("SMI handler responded successfully".to_string());
                is_error.set(false);
            }
            Err(e) => {
                smi_available.set(false);
                status_message.set(format!("SMI ping failed: {}", e));
                is_error.set(true);
            }
        }
    };

    let do_execute = move || {
        let op = operation.read().clone();
        let addr_str = address_input.read().clone();
        let len_str = length_input.read().clone();
        let pid_str = pid_input.read().clone();
        let write_str = write_data_input.read().clone();
        let wtype = write_type.read().clone();

        let address = parse_hex_or_dec(addr_str.trim());
        let length = len_str.trim().parse::<u32>().unwrap_or(256);
        let pid = pid_str.trim().parse::<u32>().unwrap_or(0);

        match op {
            SmmOperation::PhysRead => {
                if address == 0 {
                    status_message.set("Invalid address".to_string());
                    is_error.set(true);
                    return;
                }
                if length == 0 || length > 0x1000 {
                    status_message.set("Length must be 1-4096 bytes".to_string());
                    is_error.set(true);
                    return;
                }

                match smm_phys_read(address, length) {
                    Ok(data) => {
                        hex_base_address.set(address);
                        hex_data.set(data);
                        hex_page.set(0);
                        status_message.set(format!(
                            "Read {} bytes from PA 0x{:X}",
                            length, address
                        ));
                        is_error.set(false);
                    }
                    Err(e) => {
                        status_message.set(format!("Physical read failed: {}", e));
                        is_error.set(true);
                    }
                }
            }
            SmmOperation::VaRead => {
                if address == 0 || pid == 0 {
                    status_message.set("Invalid address or PID".to_string());
                    is_error.set(true);
                    return;
                }
                if length == 0 || length > 0x1000 {
                    status_message.set("Length must be 1-4096 bytes".to_string());
                    is_error.set(true);
                    return;
                }

                match smm_virtual_read(pid, address, length) {
                    Ok(data) => {
                        hex_base_address.set(address);
                        hex_data.set(data);
                        hex_page.set(0);
                        status_message.set(format!(
                            "Read {} bytes from VA 0x{:X} (PID {})",
                            length, address, pid
                        ));
                        is_error.set(false);
                    }
                    Err(e) => {
                        status_message.set(format!("Virtual read failed: {}", e));
                        is_error.set(true);
                    }
                }
            }
            SmmOperation::PhysWrite => {
                if address == 0 {
                    status_message.set("Invalid address".to_string());
                    is_error.set(true);
                    return;
                }

                let bytes = match encode_write_value(&wtype, &write_str) {
                    Ok(b) => b,
                    Err(msg) => {
                        status_message.set(msg);
                        is_error.set(true);
                        return;
                    }
                };

                if bytes.is_empty() {
                    status_message.set("No data to write".to_string());
                    is_error.set(true);
                    return;
                }

                match smm_phys_write(address, &bytes) {
                    Ok(_bytes_written) => {
                        status_message.set(format!(
                            "Wrote {} bytes to PA 0x{:X}",
                            bytes.len(),
                            address
                        ));
                        is_error.set(false);
                    }
                    Err(e) => {
                        status_message.set(format!("Physical write failed: {}", e));
                        is_error.set(true);
                    }
                }
            }
            SmmOperation::VaWrite => {
                if address == 0 || pid == 0 {
                    status_message.set("Invalid address or PID".to_string());
                    is_error.set(true);
                    return;
                }

                let bytes = match encode_write_value(&wtype, &write_str) {
                    Ok(b) => b,
                    Err(msg) => {
                        status_message.set(msg);
                        is_error.set(true);
                        return;
                    }
                };

                if bytes.is_empty() {
                    status_message.set("No data to write".to_string());
                    is_error.set(true);
                    return;
                }

                match smm_virtual_write(pid, address, &bytes) {
                    Ok(_bytes_written) => {
                        status_message.set(format!(
                            "Wrote {} bytes to VA 0x{:X} (PID {})",
                            bytes.len(),
                            address,
                            pid
                        ));
                        is_error.set(false);
                    }
                    Err(e) => {
                        status_message.set(format!("Virtual write failed: {}", e));
                        is_error.set(true);
                    }
                }
            }
            SmmOperation::Vtop => {
                if address == 0 || pid == 0 {
                    status_message.set("Invalid address or PID".to_string());
                    is_error.set(true);
                    return;
                }

                match smm_vtop(pid, address) {
                    Ok(pa) => {
                        vtop_result.set(Some(pa));
                        status_message.set(format!(
                            "VA 0x{:X} -> PA 0x{:X} (PID {})",
                            address, pa, pid
                        ));
                        is_error.set(false);
                    }
                    Err(e) => {
                        vtop_result.set(None);
                        status_message.set(format!("Translation failed: {}", e));
                        is_error.set(true);
                    }
                }
            }
        }
    };

    let mut do_priv_esc = move || {
        match smm_escalate_privileges() {
            Ok(()) => {
                status_message.set("Privileges escalated. Spawning elevated shell...".to_string());
                is_error.set(false);

                let _ = Command::new("cmd.exe")
                    .arg("/c")
                    .arg("start")
                    .arg("cmd.exe")
                    .spawn();
            }
            Err(e) => {
                status_message.set(format!("Privilege escalation failed: {}", e));
                is_error.set(true);
            }
        }
    };

    let handle_keydown = move |e: KeyboardEvent| {
        if e.key() == Key::F5 {
            refresh_status();
        } else if e.key() == Key::Escape {
            status_message.set(String::new());
        }
    };

    let driver_loaded = *smm_loaded.read();
    let smi_ok = *smi_available.read();
    let cached = *session_cached.read();
    let current_op = operation.read().clone();
    let status_msg = status_message.read().clone();
    let error_state = *is_error.read();
    let current_write_type = write_type.read().clone();
    let data = hex_data.read().clone();
    let base = *hex_base_address.read();
    let current_hex_page = *hex_page.read();
    let vtop = *vtop_result.read();

    let needs_pid = matches!(
        current_op,
        SmmOperation::VaRead | SmmOperation::VaWrite | SmmOperation::Vtop
    );
    let needs_length = matches!(current_op, SmmOperation::PhysRead | SmmOperation::VaRead);
    let needs_write_data = matches!(current_op, SmmOperation::PhysWrite | SmmOperation::VaWrite);

    rsx! {
        div {
            class: "service-tab",
            tabindex: "0",
            onkeydown: handle_keydown,

            // Header
            div { class: "header-box",
                h1 { class: "header-title",
                    "SMM Operations"
                    span { class: "experimental-badge", style: "background: #dc2626;", "Ring -2" }
                }
                div { class: "header-stats",
                    span {
                        class: if driver_loaded { "driver-status driver-status-loaded" } else { "driver-status driver-status-not-loaded" },
                        if driver_loaded { "SMM Driver: Loaded" } else { "SMM Driver: Not Loaded" }
                    }
                    span {
                        class: if smi_ok { "driver-status driver-status-loaded" } else { "driver-status driver-status-not-loaded" },
                        if smi_ok { "SMI: Available" } else { "SMI: Unavailable" }
                    }
                    span {
                        class: if cached { "driver-status driver-status-loaded" } else { "driver-status driver-status-not-loaded" },
                        if cached { "Session: Cached" } else { "Session: Not Cached" }
                    }
                    span { class: "header-shortcuts", "F5: Refresh | Esc: Clear status" }
                }
                if !status_msg.is_empty() {
                    div {
                        class: if error_state { "status-message status-error" } else { "status-message" },
                        "{status_msg}"
                    }
                }
            }

            div {
                style: "display: flex; flex-direction: column; flex: 1; overflow-y: auto; gap: 0;",

                // Session controls
                div { class: "controls",
                    div { style: "display: flex; gap: 8px; align-items: center; flex-wrap: wrap;",
                        button {
                            class: "btn btn-primary",
                            disabled: !driver_loaded,
                            onclick: move |_| do_ping(),
                            "Ping SMI"
                        }
                        button {
                            class: "btn btn-primary",
                            disabled: !driver_loaded || !smi_ok,
                            onclick: move |_| do_cache_session(),
                            "Cache Session"
                        }
                        button {
                            class: "btn btn-primary",
                            style: "background: #dc2626;",
                            disabled: !driver_loaded || !smi_ok || !cached,
                            onclick: move |_| do_priv_esc(),
                            "Escalate Privileges"
                        }
                        button {
                            class: "btn",
                            onclick: move |_| refresh_status(),
                            "Refresh Status"
                        }
                    }
                }

                // Operation selector
                div { class: "controls",
                    div { style: "display: flex; gap: 8px; align-items: center; flex-wrap: wrap;",
                        label { style: "color: var(--text-secondary); font-size: 13px;", "Operation:" }
                        select {
                            class: "handle-filter-input",
                            style: "width: 180px;",
                            value: match current_op {
                                SmmOperation::PhysRead => "physread",
                                SmmOperation::PhysWrite => "physwrite",
                                SmmOperation::VaRead => "varead",
                                SmmOperation::VaWrite => "vawrite",
                                SmmOperation::Vtop => "vtop",
                            },
                            onchange: move |e| {
                                let op = match e.value().as_str() {
                                    "physread" => SmmOperation::PhysRead,
                                    "physwrite" => SmmOperation::PhysWrite,
                                    "varead" => SmmOperation::VaRead,
                                    "vawrite" => SmmOperation::VaWrite,
                                    "vtop" => SmmOperation::Vtop,
                                    _ => SmmOperation::PhysRead,
                                };
                                operation.set(op);
                            },
                            option { value: "physread", "Physical Read" }
                            option { value: "physwrite", "Physical Write" }
                            option { value: "varead", "Virtual Read" }
                            option { value: "vawrite", "Virtual Write" }
                            option { value: "vtop", "VA to Physical" }
                        }

                        if needs_pid {
                            label { style: "color: var(--text-secondary); font-size: 13px;", "PID:" }
                            input {
                                class: "handle-filter-input",
                                r#type: "text",
                                placeholder: "Process ID",
                                style: "width: 100px;",
                                value: "{pid_input}",
                                oninput: move |e| pid_input.set(e.value()),
                            }
                        }

                        label { style: "color: var(--text-secondary); font-size: 13px;", "Address:" }
                        input {
                            class: "handle-filter-input",
                            r#type: "text",
                            placeholder: "0x...",
                            style: "width: 200px; font-family: 'Consolas', monospace;",
                            value: "{address_input}",
                            oninput: move |e| address_input.set(e.value()),
                        }

                        if needs_length {
                            label { style: "color: var(--text-secondary); font-size: 13px;", "Length:" }
                            input {
                                class: "handle-filter-input",
                                r#type: "text",
                                placeholder: "256",
                                style: "width: 80px;",
                                value: "{length_input}",
                                oninput: move |e| length_input.set(e.value()),
                            }
                        }

                        button {
                            class: "btn btn-primary",
                            disabled: !driver_loaded || !smi_ok || !cached,
                            onclick: {
                                let mut do_execute = do_execute.clone();
                                move |_| do_execute()
                            },
                            "Execute"
                        }
                    }
                }

                // Write data input (for write operations)
                if needs_write_data {
                    div { class: "controls",
                        div { style: "display: flex; gap: 8px; align-items: center; flex-wrap: wrap;",
                            label { style: "color: var(--text-secondary); font-size: 13px;", "Type:" }
                            select {
                                class: "handle-filter-input",
                                style: "width: 130px;",
                                value: "{current_write_type}",
                                onchange: move |e| write_type.set(e.value()),
                                option { value: "hex", "Hex Bytes" }
                                option { value: "u8", "Byte (u8)" }
                                option { value: "u32", "4 Bytes (u32)" }
                                option { value: "u64", "8 Bytes (u64)" }
                                option { value: "f32", "Float (f32)" }
                                option { value: "f64", "Double (f64)" }
                            }

                            label { style: "color: var(--text-secondary); font-size: 13px;", "Data:" }
                            input {
                                class: "handle-filter-input",
                                r#type: "text",
                                placeholder: "{write_placeholder(&current_write_type)}",
                                style: "width: 300px; font-family: 'Consolas', monospace;",
                                value: "{write_data_input}",
                                oninput: move |e| write_data_input.set(e.value()),
                            }
                        }
                    }
                }

                // VTOP result
                if let Some(pa) = vtop {
                    div { class: "controls",
                        div { style: "display: flex; gap: 8px; align-items: center;",
                            span {
                                style: "font-family: 'Consolas', monospace; font-size: 14px; color: var(--text-primary);",
                                "Physical Address: 0x{pa:X}"
                            }
                            button {
                                class: "btn btn-small btn-primary",
                                onclick: move |_| {
                                    copy_to_clipboard(&format!("0x{:X}", pa));
                                },
                                "Copy"
                            }
                            button {
                                class: "btn btn-small",
                                onclick: move |_| {
                                    address_input.set(format!("0x{:X}", pa));
                                    operation.set(SmmOperation::PhysRead);
                                },
                                "Read at PA"
                            }
                        }
                    }
                }

                // Hex dump
                if !data.is_empty() {
                    {render_hex_dump(data, base, current_hex_page, hex_page)}
                }

                // Info panel
                div { class: "controls",
                    div { style: "color: var(--text-muted); font-size: 12px;",
                        p { "SMM (System Management Mode) operates at Ring -2, below the hypervisor." }
                        p { "Operations are performed via SMI (System Management Interrupt) triggered by the kernel driver." }
                        p { style: "color: #f59e0b;",
                            "Warning: SMM memory operations bypass all OS protections. Use with extreme caution."
                        }
                    }
                }
            }
        }
    }
}

fn render_hex_dump(data: Vec<u8>, base: u64, current_page: usize, mut hex_page: Signal<usize>) -> Element {
    let data_len = data.len();
    let total_pages = (data_len + HEX_PAGE_SIZE - 1) / HEX_PAGE_SIZE;
    let page_start = current_page * HEX_PAGE_SIZE;
    let page_end = (page_start + HEX_PAGE_SIZE).min(data_len);
    let page_data = &data[page_start..page_end];

    let lines: Vec<(u64, Vec<u8>)> = page_data
        .chunks(16)
        .enumerate()
        .map(|(i, chunk)| {
            (base + page_start as u64 + (i * 16) as u64, chunk.to_vec())
        })
        .collect();

    rsx! {
        div { class: "controls",
            if total_pages > 1 {
                div {
                    class: "hex-pagination",
                    button {
                        disabled: current_page == 0,
                        onclick: move |_| {
                            let p = *hex_page.read();
                            if p > 0 { hex_page.set(p - 1); }
                        },
                        "\u{2190} Prev"
                    }
                    span { "Page {current_page + 1} / {total_pages}" }
                    button {
                        disabled: current_page + 1 >= total_pages,
                        onclick: move |_| {
                            let p = *hex_page.read();
                            hex_page.set(p + 1);
                        },
                        "Next \u{2192}"
                    }
                }
            }

            div {
                class: "hex-dump-container",
                div {
                    class: "hex-dump-header",
                    span { class: "hex-offset", "Address" }
                    span { class: "hex-bytes", "00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F" }
                    span { class: "hex-ascii", "ASCII" }
                }
                for (offset, bytes) in lines {
                    {
                        let hex_str = format_hex_line(&bytes);
                        let ascii_str = format_ascii_line(&bytes);
                        rsx! {
                            div {
                                class: "hex-dump-line",
                                key: "{offset}",
                                span { class: "hex-offset", "0x{offset:08X}" }
                                span { class: "hex-bytes", "{hex_str}" }
                                span { class: "hex-ascii", "{ascii_str}" }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn parse_hex_or_dec(s: &str) -> u64 {
    let s = s.trim();
    if s.starts_with("0x") || s.starts_with("0X") {
        u64::from_str_radix(s.trim_start_matches("0x").trim_start_matches("0X"), 16).unwrap_or(0)
    } else {
        s.parse::<u64>().unwrap_or(0)
    }
}

fn encode_write_value(wtype: &str, value: &str) -> Result<Vec<u8>, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("Value is empty".to_string());
    }

    match wtype {
        "hex" => {
            let bytes: Vec<u8> = value
                .split_whitespace()
                .filter_map(|s| u8::from_str_radix(s.trim_start_matches("0x").trim_start_matches("0X"), 16).ok())
                .collect();
            if bytes.is_empty() {
                Err("Invalid hex bytes (e.g. \"90 90 CC\")".to_string())
            } else {
                Ok(bytes)
            }
        }
        "u8" => {
            let v = parse_int::<u8>(value).map_err(|e| format!("Invalid u8: {}", e))?;
            Ok(vec![v])
        }
        "u32" => {
            let v = parse_int::<u32>(value).map_err(|e| format!("Invalid u32: {}", e))?;
            Ok(v.to_le_bytes().to_vec())
        }
        "u64" => {
            let v = parse_int::<u64>(value).map_err(|e| format!("Invalid u64: {}", e))?;
            Ok(v.to_le_bytes().to_vec())
        }
        "f32" => {
            let v: f32 = value.parse().map_err(|e| format!("Invalid float: {}", e))?;
            Ok(v.to_le_bytes().to_vec())
        }
        "f64" => {
            let v: f64 = value.parse().map_err(|e| format!("Invalid double: {}", e))?;
            Ok(v.to_le_bytes().to_vec())
        }
        _ => Err(format!("Unknown type: {}", wtype)),
    }
}

fn parse_int<T>(s: &str) -> Result<T, String>
where
    T: std::str::FromStr + TryFrom<u64>,
    <T as std::str::FromStr>::Err: std::fmt::Display,
    <T as TryFrom<u64>>::Error: std::fmt::Display,
{
    let s = s.trim();
    if s.starts_with("0x") || s.starts_with("0X") {
        let hex_str = s.trim_start_matches("0x").trim_start_matches("0X");
        let v = u64::from_str_radix(hex_str, 16).map_err(|e| e.to_string())?;
        T::try_from(v).map_err(|e| e.to_string())
    } else {
        s.parse::<T>().map_err(|e| e.to_string())
    }
}

fn write_placeholder(wtype: &str) -> &'static str {
    match wtype {
        "hex" => "90 90 CC",
        "u8" => "0-255 or 0xFF",
        "u32" => "0-4294967295 or 0xFFFFFFFF",
        "u64" => "integer or 0x...",
        "f32" => "3.14",
        "f64" => "3.14159265",
        _ => "",
    }
}

fn format_hex_line(bytes: &[u8]) -> String {
    let mut parts = Vec::new();
    for (i, byte) in bytes.iter().enumerate() {
        if i == 8 {
            parts.push(format!(" {:02X}", byte));
        } else {
            parts.push(format!("{:02X}", byte));
        }
    }
    let missing = 16usize.saturating_sub(bytes.len());
    for i in 0..missing {
        let idx = bytes.len() + i;
        if idx == 8 {
            parts.push("   ".to_string());
        } else {
            parts.push("  ".to_string());
        }
    }
    parts.join(" ")
}

fn format_ascii_line(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| {
            if (0x20..=0x7E).contains(&b) {
                b as char
            } else {
                '.'
            }
        })
        .collect()
}
