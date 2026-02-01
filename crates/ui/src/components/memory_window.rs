//! Memory window component

use std::collections::HashMap;

use dioxus::prelude::*;
use process::{
    get_memory_protect_name, get_memory_state_name, get_memory_type_name,
    get_process_memory_regions, get_process_modules, read_process_memory, MemoryRegionInfo,
};

use crate::helpers::copy_to_clipboard;
use crate::state::{MemoryContextMenuState, MEMORY_WINDOW_STATE};

const HEX_PAGE_SIZE: usize = 4096;

/// Memory Window component
#[component]
pub fn MemoryWindow(pid: u32, process_name: String) -> Element {
    let mut regions = use_signal(|| get_process_memory_regions(pid));
    let mut modules = use_signal(|| get_process_modules(pid));
    let mut selected_region = use_signal(|| None::<usize>);
    let mut context_menu = use_signal(|| MemoryContextMenuState::default());
    let mut status_message = use_signal(|| String::new());
    let mut auto_refresh = use_signal(|| false);
    let mut filter_text = use_signal(|| String::new());
    let mut show_free = use_signal(|| false);
    let mut inspecting = use_signal(|| None::<(usize, Vec<u8>)>);
    let mut hex_page = use_signal(|| 0usize);

    // Auto-refresh every 3 seconds (if enabled)
    use_future(move || async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            if *auto_refresh.read() {
                regions.set(get_process_memory_regions(pid));
                modules.set(get_process_modules(pid));
            }
        }
    });

    let ctx_menu = context_menu.read().clone();
    let filter = filter_text.read().clone();
    let show_free_val = *show_free.read();

    // Build module map: base_address -> (name, path)
    let module_map: HashMap<usize, (String, String)> = modules
        .read()
        .iter()
        .map(|m| (m.base_address, (m.name.clone(), m.path.clone())))
        .collect();

    // Filter regions
    let region_list: Vec<MemoryRegionInfo> = regions
        .read()
        .iter()
        .filter(|r| {
            // Hide free regions unless show_free is checked
            if !show_free_val && r.state == 0x10000 {
                // MEM_FREE = 0x10000
                return false;
            }
            if filter.is_empty() {
                true
            } else {
                let addr_str = format!("0x{:X}", r.base_address).to_lowercase();
                let state_name = get_memory_state_name(r.state).to_lowercase();
                let type_name = get_memory_type_name(r.mem_type).to_lowercase();
                let protect_name = get_memory_protect_name(r.protect).to_lowercase();
                let query = filter.to_lowercase();
                // Include module name in filter matching
                let module_name = if r.mem_type == 0x1000000 {
                    module_map
                        .get(&r.allocation_base)
                        .map(|(n, _)| n.to_lowercase())
                        .unwrap_or_default()
                } else {
                    String::new()
                };
                addr_str.contains(&query)
                    || state_name.contains(&query)
                    || type_name.contains(&query)
                    || protect_name.contains(&query)
                    || module_name.contains(&query)
            }
        })
        .cloned()
        .collect();

    let region_count = region_list.len();
    let total_regions = regions.read().len();

    let inspect_state = inspecting.read().clone();

    rsx! {
        // Modal overlay
        div {
            class: "thread-modal-overlay",
            onclick: move |_| {
                *MEMORY_WINDOW_STATE.write() = None;
            },

            // Modal window
            div {
                class: "thread-modal memory-modal",
                onclick: move |e| e.stop_propagation(),

                // Header
                div {
                    class: "thread-modal-header",
                    div {
                        class: "thread-modal-title",
                        "🧠 Memory - {process_name} (PID: {pid})"
                    }
                    button {
                        class: "thread-modal-close",
                        onclick: move |_| {
                            *MEMORY_WINDOW_STATE.write() = None;
                        },
                        "✕"
                    }
                }

                if let Some((ref base_addr, ref data)) = inspect_state {
                    // Hex dump sub-view
                    {
                        let base_addr = *base_addr;
                        let data_len = data.len();
                        let current_page = *hex_page.read();
                        let total_pages = (data_len + HEX_PAGE_SIZE - 1) / HEX_PAGE_SIZE;
                        let page_start = current_page * HEX_PAGE_SIZE;
                        let page_end = (page_start + HEX_PAGE_SIZE).min(data_len);
                        let page_data = &data[page_start..page_end];

                        // Build hex dump lines (16 bytes per line)
                        let lines: Vec<(usize, Vec<u8>)> = page_data
                            .chunks(16)
                            .enumerate()
                            .map(|(i, chunk)| {
                                (base_addr + page_start + i * 16, chunk.to_vec())
                            })
                            .collect();

                        rsx! {
                            // Back button + dump button + info
                            div {
                                class: "module-import-header",
                                button {
                                    onclick: move |_| {
                                        inspecting.set(None);
                                        hex_page.set(0);
                                    },
                                    "← Back"
                                }
                                button {
                                    class: "btn btn-small btn-primary",
                                    title: "Dump entire region to .bin file",
                                    onclick: {
                                        let dump_data = data.clone();
                                        move |_| {
                                            let dump_data = dump_data.clone();
                                            spawn(async move {
                                                let file = rfd::AsyncFileDialog::new()
                                                    .add_filter("Binary", &["bin"])
                                                    .set_file_name(format!("memory_0x{:X}.bin", base_addr))
                                                    .set_title("Save memory dump")
                                                    .save_file()
                                                    .await;
                                                if let Some(file) = file {
                                                    let path = file.path().to_path_buf();
                                                    match std::fs::write(&path, &dump_data) {
                                                        Ok(()) => {
                                                            status_message.set(format!(
                                                                "✓ Dumped {} bytes to {}",
                                                                dump_data.len(),
                                                                path.display()
                                                            ));
                                                        }
                                                        Err(e) => {
                                                            status_message.set(format!(
                                                                "✗ Dump failed: {}",
                                                                e
                                                            ));
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
                                    "💾 Dump"
                                }
                                span { "0x{base_addr:X} — {data_len} bytes" }
                            }

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
                                    span {
                                        style: "margin-left: auto; color: #6b7280; font-size: 12px;",
                                        "Offset 0x{page_start:X}–0x{page_end:X}"
                                    }
                                }
                            }

                            // Hex dump content
                            div {
                                class: "hex-dump-container",
                                div {
                                    class: "hex-dump-header",
                                    span { class: "hex-offset", "Offset" }
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
                } else {
                    // Controls
                    div {
                        class: "thread-controls",
                        span { class: "thread-count", "Regions: {region_count}/{total_regions}" }

                        input {
                            class: "handle-filter-input",
                            r#type: "text",
                            placeholder: "Filter...",
                            value: "{filter_text}",
                            oninput: move |e| filter_text.set(e.value().clone()),
                        }

                        label { class: "checkbox-label",
                            input {
                                r#type: "checkbox",
                                class: "checkbox",
                                checked: *show_free.read(),
                                onchange: move |e| show_free.set(e.checked()),
                            }
                            span { "Show Free" }
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
                            class: "btn btn-small btn-primary",
                            onclick: move |_| {
                                regions.set(get_process_memory_regions(pid));
                                modules.set(get_process_modules(pid));
                            },
                            "🔄 Refresh"
                        }
                    }

                    // Status message
                    if !status_message.read().is_empty() {
                        div { class: "thread-status-message", "{status_message}" }
                    }

                    // Memory region table
                    div {
                        class: "thread-table-container",
                        table {
                            class: "thread-table",
                            thead {
                                tr {
                                    th { class: "th", "Base Address" }
                                    th { class: "th", "Size" }
                                    th { class: "th", "State" }
                                    th { class: "th", "Type" }
                                    th { class: "th", "Module" }
                                    th { class: "th", "Protection" }
                                    th { class: "th", "Actions" }
                                }
                            }
                            tbody {
                                for region in region_list {
                                    {
                                        let base = region.base_address;
                                        let alloc_base = region.allocation_base;
                                        let size = region.region_size;
                                        let state = region.state;
                                        let mem_type = region.mem_type;
                                        let protect = region.protect;

                                        let state_name = get_memory_state_name(state);
                                        let type_name = get_memory_type_name(mem_type);
                                        let protect_name = get_memory_protect_name(protect);

                                        let state_class = match state_name {
                                            "Commit" => "mem-state-commit",
                                            "Reserve" => "mem-state-reserve",
                                            "Free" => "mem-state-free",
                                            _ => "",
                                        };

                                        let type_class = match type_name {
                                            "Image" => "mem-type-image",
                                            "Mapped" => "mem-type-mapped",
                                            "Private" => "mem-type-private",
                                            _ => "",
                                        };

                                        let size_display = if size >= 1024 * 1024 {
                                            format!("{:.1} MB", size as f64 / (1024.0 * 1024.0))
                                        } else if size >= 1024 {
                                            format!("{:.1} KB", size as f64 / 1024.0)
                                        } else {
                                            format!("{} B", size)
                                        };

                                        let is_committed = state == 0x1000; // MEM_COMMIT
                                        let is_reserved = state == 0x2000; // MEM_RESERVE
                                        let is_free = state == 0x10000; // MEM_FREE
                                        let is_selected = *selected_region.read() == Some(base);
                                        let row_class = if is_selected { "thread-row selected" } else { "thread-row" };

                                        // Module name for MEM_IMAGE regions
                                        let (module_name, module_path) = if mem_type == 0x1000000 {
                                            module_map
                                                .get(&alloc_base)
                                                .map(|(n, p)| (n.clone(), p.clone()))
                                                .unwrap_or_default()
                                        } else {
                                            (String::new(), String::new())
                                        };

                                        rsx! {
                                            tr {
                                                key: "{base}",
                                                class: "{row_class}",
                                                onclick: move |_| {
                                                    let current = *selected_region.read();
                                                    if current == Some(base) {
                                                        selected_region.set(None);
                                                    } else {
                                                        selected_region.set(Some(base));
                                                    }
                                                },
                                                oncontextmenu: move |e: Event<MouseData>| {
                                                    e.prevent_default();
                                                    let coords = e.client_coordinates();
                                                    selected_region.set(Some(base));
                                                    context_menu.set(MemoryContextMenuState {
                                                        visible: true,
                                                        x: coords.x as i32,
                                                        y: coords.y as i32,
                                                        base_address: base,
                                                        allocation_base: alloc_base,
                                                        region_size: size,
                                                        state,
                                                    });
                                                },
                                                td { class: "cell cell-handle", "0x{base:X}" }
                                                td { class: "cell", style: "font-family: monospace; color: #9ca3af;", "{size_display}" }
                                                td { class: "cell {state_class}", style: "font-weight: 500;", "{state_name}" }
                                                td { class: "cell {type_class}", "{type_name}" }
                                                td {
                                                    class: "cell",
                                                    style: "font-size: 12px; color: #8b9cf7;",
                                                    title: "{module_path}",
                                                    {
                                                        let display = if module_name.is_empty() { "-".to_string() } else { module_name };
                                                        rsx! { "{display}" }
                                                    }
                                                }
                                                td { class: "cell", style: "font-size: 12px; color: #d1d5db;", "{protect_name}" }
                                                td { class: "cell cell-actions",
                                                    // Inspect button (committed only)
                                                    if is_committed {
                                                        button {
                                                            class: "action-btn action-btn-warning",
                                                            title: "Inspect Memory",
                                                            onclick: move |e: Event<MouseData>| {
                                                                e.stop_propagation();
                                                                let read_size = size.min(1024 * 1024);
                                                                let data = read_process_memory(pid, base, read_size);
                                                                if data.is_empty() {
                                                                    status_message.set(format!("✗ Failed to read memory at 0x{:X}", base));
                                                                    spawn(async move {
                                                                        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                                                                        status_message.set(String::new());
                                                                    });
                                                                } else {
                                                                    hex_page.set(0);
                                                                    inspecting.set(Some((base, data)));
                                                                }
                                                            },
                                                            "🔍"
                                                        }
                                                    }
                                                    // Dump button (committed only)
                                                    if is_committed {
                                                        button {
                                                            class: "action-btn action-btn-primary",
                                                            title: "Dump to .bin file",
                                                            onclick: move |e: Event<MouseData>| {
                                                                e.stop_propagation();
                                                                spawn(async move {
                                                                    let file = rfd::AsyncFileDialog::new()
                                                                        .add_filter("Binary", &["bin"])
                                                                        .set_file_name(format!("memory_0x{:X}.bin", base))
                                                                        .set_title("Save memory dump")
                                                                        .save_file()
                                                                        .await;
                                                                    if let Some(file) = file {
                                                                        let read_size = size.min(1024 * 1024);
                                                                        let data = read_process_memory(pid, base, read_size);
                                                                        if data.is_empty() {
                                                                            status_message.set(format!("✗ Failed to read memory at 0x{:X}", base));
                                                                        } else {
                                                                            let path = file.path().to_path_buf();
                                                                            match std::fs::write(&path, &data) {
                                                                                Ok(()) => {
                                                                                    status_message.set(format!(
                                                                                        "✓ Dumped {} bytes to {}",
                                                                                        data.len(),
                                                                                        path.display()
                                                                                    ));
                                                                                }
                                                                                Err(e) => {
                                                                                    status_message.set(format!(
                                                                                        "✗ Dump failed: {}",
                                                                                        e
                                                                                    ));
                                                                                }
                                                                            }
                                                                        }
                                                                        spawn(async move {
                                                                            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                                                                            status_message.set(String::new());
                                                                        });
                                                                    }
                                                                });
                                                            },
                                                            "💾"
                                                        }
                                                    }
                                                    // Commit button (reserved only)
                                                    if is_reserved {
                                                        button {
                                                            class: "action-btn action-btn-success",
                                                            title: "Commit Region",
                                                            onclick: move |e: Event<MouseData>| {
                                                                e.stop_propagation();
                                                                match misc::commit_memory(pid, base, size) {
                                                                    Ok(()) => {
                                                                        status_message.set(format!("✓ Committed 0x{:X}", base));
                                                                        regions.set(get_process_memory_regions(pid));
                                                                    }
                                                                    Err(err) => {
                                                                        status_message.set(format!("✗ Commit failed: {}", err));
                                                                    }
                                                                }
                                                                spawn(async move {
                                                                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                                                                    status_message.set(String::new());
                                                                });
                                                            },
                                                            "✓"
                                                        }
                                                    }
                                                    // Decommit button (committed only)
                                                    if is_committed {
                                                        button {
                                                            class: "action-btn action-btn-warning",
                                                            title: "Decommit Region",
                                                            onclick: move |e: Event<MouseData>| {
                                                                e.stop_propagation();
                                                                match misc::decommit_memory(pid, base, size) {
                                                                    Ok(()) => {
                                                                        status_message.set(format!("✓ Decommitted 0x{:X}", base));
                                                                        regions.set(get_process_memory_regions(pid));
                                                                    }
                                                                    Err(err) => {
                                                                        status_message.set(format!("✗ Decommit failed: {}", err));
                                                                    }
                                                                }
                                                                spawn(async move {
                                                                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                                                                    status_message.set(String::new());
                                                                });
                                                            },
                                                            "⬇"
                                                        }
                                                    }
                                                    // Free button (committed or reserved only)
                                                    if is_committed || is_reserved {
                                                        button {
                                                            class: "action-btn action-btn-danger",
                                                            title: "Free Region",
                                                            onclick: move |e: Event<MouseData>| {
                                                                e.stop_propagation();
                                                                match misc::free_memory(pid, alloc_base) {
                                                                    Ok(()) => {
                                                                        status_message.set(format!("✓ Freed allocation at 0x{:X}", alloc_base));
                                                                        regions.set(get_process_memory_regions(pid));
                                                                    }
                                                                    Err(err) => {
                                                                        status_message.set(format!("✗ Free failed: {}", err));
                                                                    }
                                                                }
                                                                spawn(async move {
                                                                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                                                                    status_message.set(String::new());
                                                                });
                                                            },
                                                            "✕"
                                                        }
                                                    }
                                                    if is_free {
                                                        span { style: "color: #4b5563; font-size: 12px;", "-" }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Context menu for memory regions
                    if ctx_menu.visible {
                        {
                            let ctx_base = ctx_menu.base_address;
                            let ctx_alloc_base = ctx_menu.allocation_base;
                            let ctx_size = ctx_menu.region_size;
                            let ctx_state = ctx_menu.state;
                            let ctx_is_committed = ctx_state == 0x1000;
                            let ctx_is_reserved = ctx_state == 0x2000;

                            rsx! {
                                div {
                                    class: "context-menu",
                                    style: "left: {ctx_menu.x}px; top: {ctx_menu.y}px;",
                                    onclick: move |e| e.stop_propagation(),

                                    if ctx_is_committed {
                                        button {
                                            class: "context-menu-item",
                                            onclick: move |_| {
                                                let read_size = ctx_size.min(1024 * 1024);
                                                let data = read_process_memory(pid, ctx_base, read_size);
                                                if data.is_empty() {
                                                    status_message.set(format!("✗ Failed to read memory at 0x{:X}", ctx_base));
                                                    spawn(async move {
                                                        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                                                        status_message.set(String::new());
                                                    });
                                                } else {
                                                    hex_page.set(0);
                                                    inspecting.set(Some((ctx_base, data)));
                                                }
                                                context_menu.set(MemoryContextMenuState::default());
                                            },
                                            span { "🔍" }
                                            span { "Inspect Memory" }
                                        }

                                        button {
                                            class: "context-menu-item",
                                            onclick: move |_| {
                                                context_menu.set(MemoryContextMenuState::default());
                                                spawn(async move {
                                                    let file = rfd::AsyncFileDialog::new()
                                                        .add_filter("Binary", &["bin"])
                                                        .set_file_name(format!("memory_0x{:X}.bin", ctx_base))
                                                        .set_title("Save memory dump")
                                                        .save_file()
                                                        .await;
                                                    if let Some(file) = file {
                                                        let read_size = ctx_size.min(1024 * 1024);
                                                        let data = read_process_memory(pid, ctx_base, read_size);
                                                        if data.is_empty() {
                                                            status_message.set(format!("✗ Failed to read memory at 0x{:X}", ctx_base));
                                                        } else {
                                                            let path = file.path().to_path_buf();
                                                            match std::fs::write(&path, &data) {
                                                                Ok(()) => {
                                                                    status_message.set(format!(
                                                                        "✓ Dumped {} bytes to {}",
                                                                        data.len(),
                                                                        path.display()
                                                                    ));
                                                                }
                                                                Err(e) => {
                                                                    status_message.set(format!(
                                                                        "✗ Dump failed: {}",
                                                                        e
                                                                    ));
                                                                }
                                                            }
                                                        }
                                                        spawn(async move {
                                                            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                                                            status_message.set(String::new());
                                                        });
                                                    }
                                                });
                                            },
                                            span { "💾" }
                                            span { "Dump to File" }
                                        }
                                    }

                                    if ctx_is_reserved {
                                        button {
                                            class: "context-menu-item context-menu-item-success",
                                            onclick: move |_| {
                                                match misc::commit_memory(pid, ctx_base, ctx_size) {
                                                    Ok(()) => {
                                                        status_message.set(format!("✓ Committed 0x{:X}", ctx_base));
                                                        regions.set(get_process_memory_regions(pid));
                                                    }
                                                    Err(err) => {
                                                        status_message.set(format!("✗ Commit failed: {}", err));
                                                    }
                                                }
                                                spawn(async move {
                                                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                                                    status_message.set(String::new());
                                                });
                                                context_menu.set(MemoryContextMenuState::default());
                                            },
                                            span { "✓" }
                                            span { "Commit Region" }
                                        }
                                    }

                                    if ctx_is_committed {
                                        button {
                                            class: "context-menu-item context-menu-item-warning",
                                            onclick: move |_| {
                                                match misc::decommit_memory(pid, ctx_base, ctx_size) {
                                                    Ok(()) => {
                                                        status_message.set(format!("✓ Decommitted 0x{:X}", ctx_base));
                                                        regions.set(get_process_memory_regions(pid));
                                                    }
                                                    Err(err) => {
                                                        status_message.set(format!("✗ Decommit failed: {}", err));
                                                    }
                                                }
                                                spawn(async move {
                                                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                                                    status_message.set(String::new());
                                                });
                                                context_menu.set(MemoryContextMenuState::default());
                                            },
                                            span { "⬇" }
                                            span { "Decommit Region" }
                                        }
                                    }

                                    if ctx_is_committed || ctx_is_reserved {
                                        button {
                                            class: "context-menu-item context-menu-item-danger",
                                            onclick: move |_| {
                                                match misc::free_memory(pid, ctx_alloc_base) {
                                                    Ok(()) => {
                                                        status_message.set(format!("✓ Freed allocation at 0x{:X}", ctx_alloc_base));
                                                        regions.set(get_process_memory_regions(pid));
                                                    }
                                                    Err(err) => {
                                                        status_message.set(format!("✗ Free failed: {}", err));
                                                    }
                                                }
                                                spawn(async move {
                                                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                                                    status_message.set(String::new());
                                                });
                                                context_menu.set(MemoryContextMenuState::default());
                                            },
                                            span { "✕" }
                                            span { "Free Region" }
                                        }

                                        div { class: "context-menu-separator" }
                                    }

                                    button {
                                        class: "context-menu-item",
                                        onclick: move |_| {
                                            copy_to_clipboard(&format!("0x{:X}", ctx_base));
                                            status_message.set(format!("📋 Address 0x{:X} copied", ctx_base));
                                            spawn(async move {
                                                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                                                status_message.set(String::new());
                                            });
                                            context_menu.set(MemoryContextMenuState::default());
                                        },
                                        span { "📋" }
                                        span { "Copy Address" }
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

/// Format a chunk of bytes as hex string with gap after byte 8
fn format_hex_line(bytes: &[u8]) -> String {
    let mut parts = Vec::new();
    for (i, byte) in bytes.iter().enumerate() {
        if i == 8 {
            parts.push(format!(" {:02X}", byte));
        } else {
            parts.push(format!("{:02X}", byte));
        }
    }
    // Pad if less than 16 bytes
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

/// Format bytes as ASCII (printable or '.')
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
