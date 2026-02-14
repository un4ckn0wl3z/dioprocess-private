//! Physical Memory tab — virtual address translation and physical memory viewer

use callback::{
    is_driver_loaded, read_physical_memory, translate_virtual_address, write_physical_memory,
    PageTableEntry, PageTableWalkResult,
};
use dioxus::prelude::*;

use crate::helpers::copy_to_clipboard;

const HEX_PAGE_SIZE: usize = 4096;

/// Physical Memory tab component
#[component]
pub fn MemoryTranslateTab() -> Element {
    let mut pid_input = use_signal(|| String::new());
    let mut va_input = use_signal(|| String::new());
    let mut walk_result = use_signal(|| None::<PageTableWalkResult>);
    let mut physical_page_data = use_signal(Vec::<u8>::new);
    let mut page_base_address = use_signal(|| 0u64);
    let mut write_offset_input = use_signal(|| String::new());
    let mut write_bytes_input = use_signal(|| String::new());
    let mut status_message = use_signal(|| String::new());
    let mut is_error = use_signal(|| false);
    let mut hex_page = use_signal(|| 0usize);

    let driver_loaded = is_driver_loaded();

    let do_translate = move || {
        let pid_str = pid_input.read().clone();
        let va_str = va_input.read().clone();

        let pid = pid_str.trim().parse::<u32>().unwrap_or(0);
        let va = if va_str.trim().starts_with("0x") || va_str.trim().starts_with("0X") {
            u64::from_str_radix(va_str.trim().trim_start_matches("0x").trim_start_matches("0X"), 16).unwrap_or(0)
        } else {
            va_str.trim().parse::<u64>().unwrap_or(0)
        };

        if pid == 0 {
            status_message.set("Invalid PID".to_string());
            is_error.set(true);
            return;
        }
        if va == 0 {
            status_message.set("Invalid virtual address".to_string());
            is_error.set(true);
            return;
        }

        match translate_virtual_address(pid, va) {
            Ok(result) => {
                let pa = result.physical_address;
                let page_size = result.page_size;
                let success = result.physical_address != 0;
                walk_result.set(Some(result));

                if success {
                    // Read the physical page
                    let page_base = pa & !0xFFFu64;
                    page_base_address.set(page_base);
                    hex_page.set(0);

                    let read_size = (page_size as usize).min(HEX_PAGE_SIZE);
                    match read_physical_memory(page_base, read_size) {
                        Ok(data) => {
                            physical_page_data.set(data);
                            status_message.set(format!(
                                "VA 0x{:X} -> PA 0x{:X} ({} page)",
                                va, pa, format_page_size(page_size)
                            ));
                            is_error.set(false);
                        }
                        Err(e) => {
                            physical_page_data.set(Vec::new());
                            status_message.set(format!("Translation OK, read failed: {}", e));
                            is_error.set(true);
                        }
                    }
                } else {
                    physical_page_data.set(Vec::new());
                    status_message.set("Page not present".to_string());
                    is_error.set(true);
                }
            }
            Err(e) => {
                walk_result.set(None);
                physical_page_data.set(Vec::new());
                status_message.set(format!("Translation failed: {}", e));
                is_error.set(true);
            }
        }
    };

    let do_write = move || {
        let offset_str = write_offset_input.read().clone();
        let bytes_str = write_bytes_input.read().clone();
        let base = *page_base_address.read();

        let offset = if offset_str.trim().starts_with("0x") || offset_str.trim().starts_with("0X") {
            u64::from_str_radix(offset_str.trim().trim_start_matches("0x").trim_start_matches("0X"), 16).unwrap_or(0)
        } else {
            offset_str.trim().parse::<u64>().unwrap_or(0)
        };

        // Parse hex bytes (e.g. "90 90 CC")
        let bytes: Vec<u8> = bytes_str
            .split_whitespace()
            .filter_map(|s| u8::from_str_radix(s, 16).ok())
            .collect();

        if bytes.is_empty() {
            status_message.set("No valid hex bytes to write".to_string());
            is_error.set(true);
            return;
        }

        let write_addr = base + offset;
        match write_physical_memory(write_addr, &bytes) {
            Ok(n) => {
                status_message.set(format!("Wrote {} bytes at PA 0x{:X}", n, write_addr));
                is_error.set(false);

                // Re-read the page to reflect changes
                let read_size = physical_page_data.read().len().max(HEX_PAGE_SIZE);
                if let Ok(data) = read_physical_memory(base, read_size.min(HEX_PAGE_SIZE)) {
                    physical_page_data.set(data);
                }
            }
            Err(e) => {
                status_message.set(format!("Write failed: {}", e));
                is_error.set(true);
            }
        }
    };

    // Keyboard handler
    let mut do_translate_clone = do_translate.clone();
    let handle_keydown = move |e: KeyboardEvent| {
        if e.key() == Key::F5 {
            do_translate_clone();
        } else if e.key() == Key::Escape {
            status_message.set(String::new());
        }
    };

    let walk = walk_result.read().clone();
    let page_data = physical_page_data.read().clone();
    let base = *page_base_address.read();
    let current_hex_page = *hex_page.read();
    let status_msg = status_message.read().clone();
    let error_state = *is_error.read();

    rsx! {
        div {
            class: "service-tab",
            tabindex: "0",
            onkeydown: handle_keydown,

            // Header
            div { class: "header-box",
                h1 { class: "header-title",
                    "Physical Memory"
                    span { class: "experimental-badge", style: "background: #7c3aed;", "Physical" }
                }
                div { class: "header-stats",
                    span {
                        class: if driver_loaded { "driver-status driver-status-loaded" } else { "driver-status driver-status-not-loaded" },
                        if driver_loaded { "Driver: Loaded" } else { "Driver: Not Loaded" }
                    }
                    span { class: "header-shortcuts", "F5: Translate | Esc: Clear status" }
                }
                if !status_msg.is_empty() {
                    div {
                        class: if error_state { "status-message status-error" } else { "status-message" },
                        "{status_msg}"
                    }
                }
            }

            // Scrollable content area
            div {
                style: "display: flex; flex-direction: column; flex: 1; overflow-y: auto; gap: 0;",

            // Input bar
            div { class: "controls",
                div { style: "display: flex; gap: 8px; align-items: center; flex-wrap: wrap;",
                    label { style: "color: var(--text-secondary); font-size: 13px;", "PID:" }
                    input {
                        class: "handle-filter-input",
                        r#type: "text",
                        placeholder: "Process ID",
                        style: "width: 100px;",
                        value: "{pid_input}",
                        oninput: move |e| pid_input.set(e.value()),
                    }
                    label { style: "color: var(--text-secondary); font-size: 13px;", "Virtual Address:" }
                    input {
                        class: "handle-filter-input",
                        r#type: "text",
                        placeholder: "0x7FF...",
                        style: "width: 200px; font-family: 'Consolas', monospace;",
                        value: "{va_input}",
                        oninput: move |e| va_input.set(e.value()),
                        onkeydown: {
                            let mut do_translate = do_translate.clone();
                            move |e: KeyboardEvent| {
                                if e.key() == Key::Enter {
                                    do_translate();
                                }
                            }
                        },
                    }
                    button {
                        class: "btn btn-primary",
                        disabled: !driver_loaded,
                        onclick: {
                            let mut do_translate = do_translate.clone();
                            move |_| do_translate()
                        },
                        "Translate"
                    }
                }
            }

            // Page Table Walk Graph
            if let Some(ref result) = walk {
                div {
                    class: "controls",
                    style: "overflow-x: auto;",

                    // Walk visualization as horizontal flow
                    div {
                        style: "display: flex; align-items: flex-start; gap: 4px; min-width: max-content;",

                        // CR3 box
                        div {
                            class: "pte-box",
                            style: "border-color: var(--accent-primary); background: rgba(139, 92, 246, 0.1);",
                            div { class: "pte-box-title", "CR3" }
                            div { class: "pte-box-value", "0x{result.cr3:X}" }
                        }

                        // Arrow
                        span { class: "pte-arrow", "→" }

                        // PML4E
                        {render_pte_box("PML4E", &result.pml4e, (va_input.read().clone(), 39))}

                        span { class: "pte-arrow", "→" }

                        // PDPTE
                        {render_pte_box("PDPTE", &result.pdpte, (va_input.read().clone(), 30))}

                        if result.walk_depth >= 2 && result.pdpte.large_page {
                            span { class: "pte-arrow-label", "1GB Page" }
                        }

                        if result.walk_depth >= 3 && !result.pdpte.large_page {
                            span { class: "pte-arrow", "→" }

                            // PDE
                            {render_pte_box("PDE", &result.pde, (va_input.read().clone(), 21))}

                            if result.pde.large_page {
                                span { class: "pte-arrow-label", "2MB Page" }
                            }
                        }

                        if let Some(ref pte) = result.pte {
                            span { class: "pte-arrow", "→" }

                            // PTE
                            {render_pte_box("PTE", pte, (va_input.read().clone(), 12))}
                        }
                    }

                    // Result line
                    if result.physical_address != 0 {
                        div {
                            style: "margin-top: 10px; display: flex; align-items: center; gap: 8px; font-family: 'Consolas', monospace; font-size: 13px; color: var(--text-primary);",
                            span {
                                "VA 0x{va_input} → PA 0x{result.physical_address:X} ({format_page_size(result.page_size)} page)"
                            }
                            button {
                                class: "btn btn-small btn-primary",
                                onclick: {
                                    let pa = result.physical_address;
                                    move |_| {
                                        copy_to_clipboard(&format!("0x{:X}", pa));
                                    }
                                },
                                "Copy PA"
                            }
                        }
                    }
                }
            }

            // Hex dump of physical page
            if !page_data.is_empty() {
                {render_hex_dump(page_data.clone(), base, current_hex_page, hex_page)}
            }

            // Write bar
            if base != 0 {
                div { class: "controls",
                    div { style: "display: flex; gap: 8px; align-items: center; flex-wrap: wrap;",
                        label { style: "color: var(--text-secondary); font-size: 13px;", "Offset:" }
                        input {
                            class: "handle-filter-input",
                            r#type: "text",
                            placeholder: "0x0",
                            style: "width: 100px; font-family: 'Consolas', monospace;",
                            value: "{write_offset_input}",
                            oninput: move |e| write_offset_input.set(e.value()),
                        }
                        label { style: "color: var(--text-secondary); font-size: 13px;", "Hex bytes:" }
                        input {
                            class: "handle-filter-input",
                            r#type: "text",
                            placeholder: "90 90 CC",
                            style: "width: 300px; font-family: 'Consolas', monospace;",
                            value: "{write_bytes_input}",
                            oninput: move |e| write_bytes_input.set(e.value()),
                            onkeydown: {
                                let mut do_write = do_write.clone();
                                move |e: KeyboardEvent| {
                                    if e.key() == Key::Enter {
                                        do_write();
                                    }
                                }
                            },
                        }
                        button {
                            class: "btn btn-primary",
                            style: "background: var(--bg-danger);",
                            disabled: !driver_loaded,
                            onclick: {
                                let mut do_write = do_write.clone();
                                move |_| do_write()
                            },
                            "Write"
                        }
                        span {
                            style: "color: var(--text-muted); font-size: 12px;",
                            "Base: 0x{base:X}"
                        }
                    }
                }
            }

            } // end scrollable content area
        }
    }
}

/// Render a single PTE box in the walk graph
fn render_pte_box(label: &str, entry: &PageTableEntry, va_info: (String, u32)) -> Element {
    let (_va_str, _shift) = va_info;
    let border_color = if entry.present {
        "var(--stat-green)"
    } else {
        "#ef4444"
    };

    let pfn = entry.physical_address >> 12;
    let p = if entry.present { 1 } else { 0 };
    let rw = if entry.read_write { 1 } else { 0 };
    let us = if entry.user_supervisor { 1 } else { 0 };
    let nx = if entry.no_execute { 1 } else { 0 };
    let a = if entry.accessed { 1 } else { 0 };
    let d = if entry.dirty { 1 } else { 0 };
    let raw = entry.raw_value;

    rsx! {
        div {
            class: "pte-box",
            style: "border-color: {border_color};",

            div { class: "pte-box-title", "{label}" }
            div { class: "pte-box-flags",
                span {
                    style: if entry.present { "color: var(--stat-green);" } else { "color: #ef4444;" },
                    "P:{p} "
                }
                span { "RW:{rw} " }
                span { "US:{us} " }
                span { "NX:{nx}" }
            }
            div { class: "pte-box-flags",
                span { "A:{a} " }
                span { "D:{d} " }
                if entry.large_page {
                    span { style: "color: #fbbf24;", "LP:1 " }
                }
                if entry.global {
                    span { "G:1 " }
                }
            }
            div { class: "pte-box-pfn", "PFN: 0x{pfn:X}" }
            div {
                class: "pte-box-raw",
                title: "Raw PTE value",
                "0x{raw:016X}"
            }
        }
    }
}

/// Render hex dump with pagination
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
            // Pagination
            if total_pages > 1 {
                div {
                    class: "hex-pagination",
                    button {
                        disabled: current_page == 0,
                        onclick: move |_| {
                            let p = *hex_page.read();
                            if p > 0 { hex_page.set(p - 1); }
                        },
                        "← Prev"
                    }
                    span { "Page {current_page + 1} / {total_pages}" }
                    button {
                        disabled: current_page + 1 >= total_pages,
                        onclick: move |_| {
                            let p = *hex_page.read();
                            hex_page.set(p + 1);
                        },
                        "Next →"
                    }
                }
            }

            // Hex dump content
            div {
                class: "hex-dump-container",
                div {
                    class: "hex-dump-header",
                    span { class: "hex-offset", "Phys Addr" }
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

fn format_page_size(size: u32) -> &'static str {
    match size {
        0x1000 => "4KB",
        0x200000 => "2MB",
        0x40000000 => "1GB",
        _ => "Unknown",
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
