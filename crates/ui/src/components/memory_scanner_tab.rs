//! Memory Scanner tab — Cheat Engine-like memory scanner via physical memory (CR3 walk)

use callback::{
    assemble, first_scan, format_bytes_hex, hv_is_running, install_ept_hook, is_driver_loaded,
    list_ept_hooks, next_scan, parse_aob_pattern, parse_scan_value, remove_ept_hook,
    write_scan_value, ScanDataType, ScanRegion, ScanResult, ScanType,
};
use dioxus::prelude::*;
use misc::{allocate_near_address, free_remote_memory, write_process_memory_bytes};
use process::{get_process_arch, ProcessArch};

use crate::helpers::copy_to_clipboard;
use crate::state::{
    EPT_HOOKS_LIST, EPT_HOOK_ASM_ERROR, EPT_HOOK_ASM_INPUT, EPT_HOOK_ASM_PREVIEW,
    EPT_HOOK_BYTES_INPUT, EPT_HOOK_DETOUR_ALLOCS, EPT_HOOK_DETOUR_ASM_ERROR,
    EPT_HOOK_DETOUR_ASM_INPUT, EPT_HOOK_DETOUR_ASM_PREVIEW, EPT_HOOK_DETOUR_STOLEN_BYTES,
    EPT_HOOK_INPUT_MODE, EPT_HOOK_IS_ERROR, EPT_HOOK_SHOW_MODAL, EPT_HOOK_STATUS,
    EPT_HOOK_TARGET_ADDR, EptHookInputMode, SCANNER_DATA_TYPE_IDX, SCANNER_EDIT_VALUE,
    SCANNER_EDITING_IDX, SCANNER_HAS_SCANNED, SCANNER_IS_ERROR, SCANNER_IS_SCANNING,
    SCANNER_PAGE, SCANNER_PID, SCANNER_RESULTS, SCANNER_SCAN_TYPE_IDX, SCANNER_SELECTED,
    SCANNER_STATUS, SCANNER_VALUE, SCANNER_VALUE2, SCANNER_WRITE_VALUE,
};

const RESULTS_PER_PAGE: usize = 500;

#[component]
pub fn MemoryScannerTab() -> Element {
    let mut pid_input = SCANNER_PID.signal();
    let mut value_input = SCANNER_VALUE.signal();
    let mut value2_input = SCANNER_VALUE2.signal();
    let mut data_type_idx = SCANNER_DATA_TYPE_IDX.signal();
    let mut scan_type_idx = SCANNER_SCAN_TYPE_IDX.signal();
    let mut scan_results = SCANNER_RESULTS.signal();
    let mut has_scanned = SCANNER_HAS_SCANNED.signal();
    let mut is_scanning = SCANNER_IS_SCANNING.signal();
    let mut status_message = SCANNER_STATUS.signal();
    let mut is_error = SCANNER_IS_ERROR.signal();
    let mut result_page = SCANNER_PAGE.signal();
    let mut selected_idx = SCANNER_SELECTED.signal();
    let mut write_value_input = SCANNER_WRITE_VALUE.signal();
    let mut context_menu = use_signal(|| None::<(i32, i32, usize)>); // transient, no need to persist
    let mut editing_idx = SCANNER_EDITING_IDX.signal();
    let mut edit_value_input = SCANNER_EDIT_VALUE.signal();

    // EPT Hook state
    let mut ept_hook_bytes = EPT_HOOK_BYTES_INPUT.signal();
    let mut ept_hook_target = EPT_HOOK_TARGET_ADDR.signal();
    let mut ept_hook_show_modal = EPT_HOOK_SHOW_MODAL.signal();
    let mut ept_hooks_list = EPT_HOOKS_LIST.signal();
    let mut ept_hook_status = EPT_HOOK_STATUS.signal();
    let mut ept_hook_is_error = EPT_HOOK_IS_ERROR.signal();
    // Assembly mode state
    let mut ept_hook_input_mode = EPT_HOOK_INPUT_MODE.signal();
    let mut ept_hook_asm_input = EPT_HOOK_ASM_INPUT.signal();
    let mut ept_hook_asm_preview = EPT_HOOK_ASM_PREVIEW.signal();
    let mut ept_hook_asm_error = EPT_HOOK_ASM_ERROR.signal();
    // Detour mode state
    let mut detour_asm_input = EPT_HOOK_DETOUR_ASM_INPUT.signal();
    let mut detour_asm_preview = EPT_HOOK_DETOUR_ASM_PREVIEW.signal();
    let mut detour_asm_error = EPT_HOOK_DETOUR_ASM_ERROR.signal();
    let mut detour_stolen_bytes = EPT_HOOK_DETOUR_STOLEN_BYTES.signal();
    let mut detour_allocs = EPT_HOOK_DETOUR_ALLOCS.signal();

    let driver_loaded = is_driver_loaded();
    let scanned = *has_scanned.read();
    let scanning = *is_scanning.read();

    let all_data_types = ScanDataType::all();
    let current_dt_idx = *data_type_idx.read();
    let current_data_type = all_data_types[current_dt_idx];

    let scan_types = if scanned {
        ScanType::next_scan_types()
    } else {
        ScanType::first_scan_types()
    };
    let current_st_idx = *scan_type_idx.read();
    let current_scan_type = if current_st_idx < scan_types.len() {
        scan_types[current_st_idx]
    } else {
        scan_types[0]
    };

    let do_first_scan = move || {
        let pid_str = pid_input.read().clone();
        let val_str = value_input.read().clone();
        let dt = all_data_types[*data_type_idx.read()];
        let st_idx = *scan_type_idx.read();
        let first_types = ScanType::first_scan_types();
        let st = if st_idx < first_types.len() {
            first_types[st_idx]
        } else {
            first_types[0]
        };

        let pid = pid_str.trim().parse::<u32>().unwrap_or(0);
        if pid == 0 {
            status_message.set("Invalid PID".to_string());
            is_error.set(true);
            return;
        }

        let target_bytes = if st.needs_value() {
            match parse_scan_value(&val_str, dt) {
                Ok(b) => b,
                Err(msg) => {
                    status_message.set(msg);
                    is_error.set(true);
                    return;
                }
            }
        } else {
            vec![]
        };

        // Parse AOB pattern with wildcard mask if AOB type
        let aob_pat = if dt.is_aob() && st.needs_value() {
            match parse_aob_pattern(&val_str) {
                Ok(p) => Some(p),
                Err(msg) => {
                    status_message.set(msg);
                    is_error.set(true);
                    return;
                }
            }
        } else {
            None
        };

        is_scanning.set(true);
        status_message.set("Scanning...".to_string());
        is_error.set(false);

        spawn(async move {
            let result = tokio::task::spawn_blocking(move || {
                let raw_regions = process::get_process_memory_regions(pid);
                let regions: Vec<ScanRegion> = raw_regions
                    .iter()
                    .map(|r| ScanRegion {
                        base_address: r.base_address as u64,
                        region_size: r.region_size as u64,
                        state: r.state,
                        protect: r.protect,
                    })
                    .collect();

                first_scan(pid, &regions, &target_bytes, dt, st, aob_pat.as_ref())
            })
            .await;

            is_scanning.set(false);

            match result {
                Ok(Ok(results)) => {
                    let count = results.len();
                    scan_results.set(results);
                    has_scanned.set(true);
                    result_page.set(0);
                    selected_idx.set(None);
                    editing_idx.set(None);
                    scan_type_idx.set(0);
                    status_message.set(format!("Found {} results", count));
                    is_error.set(false);
                }
                Ok(Err(e)) => {
                    status_message.set(format!("Scan failed: {}", e));
                    is_error.set(true);
                }
                Err(e) => {
                    status_message.set(format!("Scan task failed: {}", e));
                    is_error.set(true);
                }
            }
        });
    };

    let do_next_scan = move || {
        let pid_str = pid_input.read().clone();
        let val_str = value_input.read().clone();
        let dt = all_data_types[*data_type_idx.read()];
        let st_idx = *scan_type_idx.read();
        let next_types = ScanType::next_scan_types();
        let st = if st_idx < next_types.len() {
            next_types[st_idx]
        } else {
            next_types[0]
        };

        let pid = pid_str.trim().parse::<u32>().unwrap_or(0);
        if pid == 0 {
            status_message.set("Invalid PID".to_string());
            is_error.set(true);
            return;
        }

        let target_bytes = if st.needs_value() {
            match parse_scan_value(&val_str, dt) {
                Ok(b) => b,
                Err(msg) => {
                    status_message.set(msg);
                    is_error.set(true);
                    return;
                }
            }
        } else {
            vec![]
        };

        // Parse AOB pattern with wildcard mask if AOB type
        let aob_pat = if dt.is_aob() && st.needs_value() {
            match parse_aob_pattern(&val_str) {
                Ok(p) => Some(p),
                Err(msg) => {
                    status_message.set(msg);
                    is_error.set(true);
                    return;
                }
            }
        } else {
            None
        };

        let prev_results = scan_results.read().clone();

        is_scanning.set(true);
        status_message.set("Scanning...".to_string());
        is_error.set(false);

        spawn(async move {
            let result = tokio::task::spawn_blocking(move || {
                next_scan(pid, &prev_results, &target_bytes, dt, st, aob_pat.as_ref())
            })
            .await;

            is_scanning.set(false);

            match result {
                Ok(Ok(results)) => {
                    let count = results.len();
                    scan_results.set(results);
                    result_page.set(0);
                    selected_idx.set(None);
                    editing_idx.set(None);
                    status_message.set(format!("Filtered to {} results", count));
                    is_error.set(false);
                }
                Ok(Err(e)) => {
                    status_message.set(format!("Next scan failed: {}", e));
                    is_error.set(true);
                }
                Err(e) => {
                    status_message.set(format!("Scan task failed: {}", e));
                    is_error.set(true);
                }
            }
        });
    };

    let do_reset = move || {
        scan_results.set(Vec::new());
        has_scanned.set(false);
        result_page.set(0);
        selected_idx.set(None);
        editing_idx.set(None);
        scan_type_idx.set(0);
        status_message.set("Scan reset".to_string());
        is_error.set(false);
    };

    let do_write = move || {
        let sel = *selected_idx.read();
        if sel.is_none() {
            status_message.set("No address selected".to_string());
            is_error.set(true);
            return;
        }
        let sel = sel.unwrap();
        let results = scan_results.read();
        if sel >= results.len() {
            return;
        }

        let pid_str = pid_input.read().clone();
        let pid = pid_str.trim().parse::<u32>().unwrap_or(0);
        let address = results[sel].address;
        let dt = all_data_types[*data_type_idx.read()];
        let val_str = write_value_input.read().clone();

        drop(results);

        let bytes = match parse_scan_value(&val_str, dt) {
            Ok(b) => b,
            Err(msg) => {
                status_message.set(msg);
                is_error.set(true);
                return;
            }
        };

        match write_scan_value(pid, address, &bytes) {
            Ok(()) => {
                status_message.set(format!(
                    "Wrote {} bytes to 0x{:X}",
                    bytes.len(),
                    address
                ));
                is_error.set(false);
            }
            Err(e) => {
                status_message.set(format!("Write failed: {}", e));
                is_error.set(true);
            }
        }
    };

    // Inline edit write (from the table row edit field)
    let do_inline_write = move |idx: usize| {
        let results = scan_results.read();
        if idx >= results.len() {
            return;
        }

        let pid_str = pid_input.read().clone();
        let pid = pid_str.trim().parse::<u32>().unwrap_or(0);
        let address = results[idx].address;
        let dt = all_data_types[*data_type_idx.read()];
        let val_str = edit_value_input.read().clone();

        drop(results);

        let bytes = match parse_scan_value(&val_str, dt) {
            Ok(b) => b,
            Err(msg) => {
                status_message.set(msg);
                is_error.set(true);
                return;
            }
        };

        match write_scan_value(pid, address, &bytes) {
            Ok(()) => {
                status_message.set(format!(
                    "Wrote {} bytes to 0x{:X}",
                    bytes.len(),
                    address
                ));
                is_error.set(false);
                editing_idx.set(None);
            }
            Err(e) => {
                status_message.set(format!("Write failed: {}", e));
                is_error.set(true);
            }
        }
    };

    // Keyboard handler
    let mut do_first_scan_clone = do_first_scan.clone();
    let mut do_next_scan_clone = do_next_scan.clone();
    let handle_keydown = move |e: KeyboardEvent| {
        if e.key() == Key::F5 {
            if *has_scanned.read() {
                do_next_scan_clone();
            } else {
                do_first_scan_clone();
            }
        } else if e.key() == Key::Escape {
            context_menu.set(None);
            editing_idx.set(None);
        }
    };

    // Read state for rendering
    let results = scan_results.read().clone();
    let total_results = results.len();
    let total_pages = if total_results == 0 {
        0
    } else {
        (total_results + RESULTS_PER_PAGE - 1) / RESULTS_PER_PAGE
    };
    let page = *result_page.read();
    let page_start = page * RESULTS_PER_PAGE;
    let page_end = (page_start + RESULTS_PER_PAGE).min(total_results);
    let page_results: Vec<(usize, &ScanResult)> = if total_results > 0 {
        results[page_start..page_end]
            .iter()
            .enumerate()
            .map(|(i, r)| (page_start + i, r))
            .collect()
    } else {
        vec![]
    };
    let sel = *selected_idx.read();
    let edit_idx = *editing_idx.read();
    let status_msg = status_message.read().clone();
    let error_state = *is_error.read();
    let ctx_menu = context_menu.read().clone();

    // Get context menu data
    let ctx_addr = ctx_menu.map(|(_, _, idx)| {
        if idx < total_results { results[idx].address } else { 0 }
    });
    let ctx_val = ctx_menu.map(|(_, _, idx)| {
        if idx < total_results {
            results[idx].format_value(current_data_type)
        } else {
            String::new()
        }
    });

    rsx! {
        div {
            class: "service-tab",
            tabindex: "0",
            onkeydown: handle_keydown,
            onclick: move |_| {
                context_menu.set(None);
            },

            // Header
            div { class: "header-box",
                h1 { class: "header-title",
                    "Memory Scanner"
                    span { class: "experimental-badge", style: "background: #dc2626;", "Scanner" }
                }
                div { class: "header-stats",
                    span {
                        class: if driver_loaded { "driver-status driver-status-loaded" } else { "driver-status driver-status-not-loaded" },
                        if driver_loaded { "Driver: Loaded" } else { "Driver: Not Loaded" }
                    }
                    if total_results > 0 {
                        span { class: "header-stat", "{total_results} results" }
                    }
                    span { class: "header-shortcuts", "F5: Scan | Esc: Close menu/edit" }
                }
                if !status_msg.is_empty() {
                    div {
                        class: if error_state { "status-message status-error" } else { "status-message" },
                        "{status_msg}"
                    }
                }
            }

            // Scrollable content
            div {
                style: "display: flex; flex-direction: column; flex: 1; overflow-y: auto; gap: 0;",

                // Controls bar
                div { class: "controls",
                    div { style: "display: flex; gap: 8px; align-items: center; flex-wrap: wrap;",
                        label { style: "color: var(--text-secondary); font-size: 13px;", "PID:" }
                        input {
                            class: "handle-filter-input",
                            r#type: "text",
                            placeholder: "Process ID",
                            style: "width: 100px;",
                            value: "{pid_input}",
                            disabled: scanning,
                            oninput: move |e| pid_input.set(e.value()),
                        }

                        label { style: "color: var(--text-secondary); font-size: 13px;", "Value:" }
                        input {
                            class: "handle-filter-input",
                            r#type: "text",
                            placeholder: { let p: &str = if !current_scan_type.needs_value() { "(not needed)" } else if current_data_type.is_aob() { "48 8B ?? 04 ..." } else { "Search value" }; p },
                            style: "width: 160px; font-family: 'Consolas', monospace;",
                            value: "{value_input}",
                            disabled: scanning || !current_scan_type.needs_value(),
                            oninput: move |e| value_input.set(e.value()),
                            onkeydown: {
                                let mut first = do_first_scan.clone();
                                let mut next = do_next_scan.clone();
                                move |e: KeyboardEvent| {
                                    if e.key() == Key::Enter {
                                        if *has_scanned.read() {
                                            next();
                                        } else {
                                            first();
                                        }
                                    }
                                }
                            },
                        }

                        if current_scan_type == ScanType::Between {
                            label { style: "color: var(--text-secondary); font-size: 13px;", "to:" }
                            input {
                                class: "handle-filter-input",
                                r#type: "text",
                                placeholder: "Max value",
                                style: "width: 120px; font-family: 'Consolas', monospace;",
                                value: "{value2_input}",
                                disabled: scanning,
                                oninput: move |e| value2_input.set(e.value()),
                            }
                        }

                        label { style: "color: var(--text-secondary); font-size: 13px;", "Type:" }
                        select {
                            class: "handle-filter-input",
                            style: "width: 140px;",
                            value: "{current_dt_idx}",
                            disabled: scanned || scanning,
                            onchange: move |e| {
                                if let Ok(v) = e.value().parse::<usize>() {
                                    data_type_idx.set(v);
                                }
                            },
                            for (i, dt) in all_data_types.iter().enumerate() {
                                option {
                                    key: "{i}",
                                    value: "{i}",
                                    selected: i == current_dt_idx,
                                    "{dt.label()}"
                                }
                            }
                        }

                        label { style: "color: var(--text-secondary); font-size: 13px;", "Scan:" }
                        select {
                            class: "handle-filter-input",
                            style: "width: 160px;",
                            value: "{current_st_idx}",
                            disabled: scanning,
                            onchange: move |e| {
                                if let Ok(v) = e.value().parse::<usize>() {
                                    scan_type_idx.set(v);
                                }
                            },
                            for (i, st) in scan_types.iter().enumerate() {
                                option {
                                    key: "{i}",
                                    value: "{i}",
                                    selected: i == current_st_idx,
                                    "{st.label()}"
                                }
                            }
                        }
                    }

                    // Action buttons
                    div { style: "display: flex; gap: 8px; align-items: center; margin-top: 8px;",
                        if !scanned {
                            button {
                                class: "btn btn-primary",
                                disabled: !driver_loaded || scanning,
                                onclick: {
                                    let mut first = do_first_scan.clone();
                                    move |_| first()
                                },
                                if scanning { "Scanning..." } else { "First Scan" }
                            }
                        } else {
                            button {
                                class: "btn btn-primary",
                                disabled: !driver_loaded || scanning,
                                onclick: {
                                    let mut next = do_next_scan.clone();
                                    move |_| next()
                                },
                                if scanning { "Scanning..." } else { "Next Scan" }
                            }
                        }

                        button {
                            class: "btn",
                            disabled: scanning,
                            onclick: {
                                let mut reset = do_reset.clone();
                                move |_| reset()
                            },
                            "New Scan"
                        }
                    }
                }

                // Write bar (when an address is selected via write bar)
                if sel.is_some() {
                    div { class: "controls",
                        style: "border-left: 3px solid var(--accent-primary);",
                        div { style: "display: flex; gap: 8px; align-items: center; flex-wrap: wrap;",
                            {
                                let sel_idx = sel.unwrap();
                                let addr = if sel_idx < total_results { results[sel_idx].address } else { 0 };
                                rsx! {
                                    span {
                                        style: "color: var(--accent-primary); font-family: 'Consolas', monospace; font-size: 13px;",
                                        "Write to 0x{addr:X}:"
                                    }
                                }
                            }
                            input {
                                class: "handle-filter-input",
                                r#type: "text",
                                placeholder: "New value",
                                style: "width: 180px; font-family: 'Consolas', monospace;",
                                value: "{write_value_input}",
                                oninput: move |e| write_value_input.set(e.value()),
                                onkeydown: {
                                    let mut w = do_write.clone();
                                    move |e: KeyboardEvent| {
                                        if e.key() == Key::Enter {
                                            w();
                                        }
                                    }
                                },
                            }
                            span {
                                style: "color: var(--text-secondary); font-size: 12px;",
                                "({current_data_type.label()})"
                            }
                            button {
                                class: "btn btn-primary",
                                disabled: !driver_loaded,
                                onclick: {
                                    let mut w = do_write.clone();
                                    move |_| w()
                                },
                                "Write"
                            }
                        }
                    }
                }

                // Results table
                if total_results > 0 || scanned {
                    table { class: "process-table",
                        thead { class: "table-header",
                            tr {
                                th { class: "th", style: "width: 180px; min-width: 180px;", "Address" }
                                th { class: "th", style: "width: 200px; min-width: 140px;", "Value" }
                                th { class: "th", style: "width: 200px; min-width: 140px;", "Previous" }
                                th { class: "th", style: "width: 100px; min-width: 80px;", "Type" }
                            }
                        }
                        tbody {
                            if total_results == 0 && scanned {
                                tr {
                                    td {
                                        colspan: "4",
                                        style: "padding: 20px; text-align: center; color: var(--text-secondary);",
                                        "No results found"
                                    }
                                }
                            }
                            for (global_i, result) in page_results.iter() {
                                {
                                    let global_i = *global_i;
                                    let is_selected = sel == Some(global_i);
                                    let is_editing = edit_idx == Some(global_i);
                                    let addr = result.address;
                                    let current_val = result.format_value(current_data_type);
                                    let prev_val = result.format_previous(current_data_type);
                                    let changed = result.current_bytes != result.previous_bytes;
                                    let dt_label = current_data_type.label();
                                    rsx! {
                                        tr {
                                            key: "{global_i}",
                                            class: if is_selected { "process-row selected" } else { "process-row" },
                                            onclick: move |_| {
                                                selected_idx.set(Some(global_i));
                                                context_menu.set(None);
                                            },
                                            ondoubleclick: {
                                                let cv = current_val.clone();
                                                move |_| {
                                                    editing_idx.set(Some(global_i));
                                                    edit_value_input.set(cv.clone());
                                                }
                                            },
                                            oncontextmenu: move |e| {
                                                e.prevent_default();
                                                let coords = e.client_coordinates();
                                                selected_idx.set(Some(global_i));
                                                context_menu.set(Some((coords.x as i32, coords.y as i32, global_i)));
                                            },
                                            td {
                                                class: "cell",
                                                style: "width: 180px; min-width: 180px; font-family: 'Consolas', monospace; color: var(--accent-primary);",
                                                "0x{addr:X}"
                                            }
                                            td {
                                                class: "cell",
                                                style: if changed {
                                                    "width: 200px; min-width: 140px; font-family: 'Consolas', monospace; color: #ef4444;"
                                                } else {
                                                    "width: 200px; min-width: 140px; font-family: 'Consolas', monospace;"
                                                },
                                                if is_editing {
                                                    input {
                                                        class: "handle-filter-input",
                                                        r#type: "text",
                                                        style: "width: 120px; font-family: 'Consolas', monospace; font-size: 12px; padding: 2px 4px;",
                                                        value: "{edit_value_input}",
                                                        oninput: move |e| edit_value_input.set(e.value()),
                                                        onclick: move |e| e.stop_propagation(),
                                                        onkeydown: {
                                                            let mut do_iw = do_inline_write.clone();
                                                            move |e: KeyboardEvent| {
                                                                if e.key() == Key::Enter {
                                                                    do_iw(global_i);
                                                                } else if e.key() == Key::Escape {
                                                                    editing_idx.set(None);
                                                                }
                                                            }
                                                        },
                                                    }
                                                } else {
                                                    "{current_val}"
                                                }
                                            }
                                            td {
                                                class: "cell",
                                                style: "width: 200px; min-width: 140px; font-family: 'Consolas', monospace; color: var(--text-secondary);",
                                                "{prev_val}"
                                            }
                                            td {
                                                class: "cell",
                                                style: "width: 100px; min-width: 80px; font-size: 11px; color: var(--text-secondary);",
                                                "{dt_label}"
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Pagination
                    if total_pages > 1 {
                        div {
                            class: "pagination",
                            button {
                                class: "btn",
                                disabled: page == 0,
                                onclick: move |_| result_page.set(0),
                                "<<"
                            }
                            button {
                                class: "btn",
                                disabled: page == 0,
                                onclick: move |_| result_page.set(page.saturating_sub(1)),
                                "<"
                            }
                            span {
                                style: "color: var(--text-secondary); font-size: 13px;",
                                "Page {page + 1} / {total_pages}"
                            }
                            button {
                                class: "btn",
                                disabled: page + 1 >= total_pages,
                                onclick: move |_| result_page.set(page + 1),
                                ">"
                            }
                            button {
                                class: "btn",
                                disabled: page + 1 >= total_pages,
                                onclick: move |_| result_page.set(total_pages - 1),
                                ">>"
                            }
                        }
                    }
                }

                // ============== EPT Hooks Panel ==============
                {
                    let hooks = ept_hooks_list.read().clone();
                    let has_hooks = !hooks.is_empty();
                    rsx! {
                        if has_hooks {
                            div { class: "controls",
                                style: "border-left: 3px solid #dc2626; margin-top: 4px;",
                                div { style: "display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;",
                                    span { style: "color: var(--text-primary); font-weight: 600; font-size: 13px;",
                                        "Active EPT Hooks ({hooks.len()})"
                                    }
                                    div { style: "display: flex; gap: 8px;",
                                        button {
                                            class: "btn",
                                            style: "font-size: 11px; padding: 2px 8px;",
                                            onclick: move |_| {
                                                if let Ok(h) = list_ept_hooks() {
                                                    ept_hooks_list.set(h);
                                                }
                                            },
                                            "Refresh"
                                        }
                                        button {
                                            class: "btn",
                                            style: "font-size: 11px; padding: 2px 8px; color: #dc2626;",
                                            onclick: move |_| {
                                                // Free all detour allocations first
                                                let allocs = detour_allocs.read().clone();
                                                for (_idx, (dpid, daddr)) in &allocs {
                                                    let _ = free_remote_memory(*dpid, *daddr);
                                                }
                                                detour_allocs.write().clear();
                                                let current = ept_hooks_list.read().clone();
                                                for hook in &current {
                                                    let _ = remove_ept_hook(hook.hook_index);
                                                }
                                                if let Ok(h) = list_ept_hooks() {
                                                    ept_hooks_list.set(h);
                                                }
                                            },
                                            "Remove All"
                                        }
                                    }
                                }
                                table { class: "process-table",
                                    style: "font-size: 12px;",
                                    thead { class: "table-header",
                                        tr {
                                            th { class: "th", style: "width: 50px;", "#" }
                                            th { class: "th", style: "width: 80px;", "PID" }
                                            th { class: "th", style: "width: 180px;", "Address" }
                                            th { class: "th", style: "width: 80px;", "Patch Size" }
                                            th { class: "th", style: "width: 80px;", "" }
                                        }
                                    }
                                    tbody {
                                        for hook in hooks.iter() {
                                            {
                                                let hook_idx = hook.hook_index;
                                                let hook_addr = hook.target_address;
                                                let hook_pid = hook.process_id;
                                                let hook_size = hook.patch_size;
                                                rsx! {
                                                    tr { class: "process-row",
                                                        td { class: "cell", style: "width: 50px;", "{hook_idx}" }
                                                        td { class: "cell", style: "width: 80px;", "{hook_pid}" }
                                                        td {
                                                            class: "cell",
                                                            style: "width: 180px; font-family: 'Consolas', monospace; color: var(--accent-primary);",
                                                            "0x{hook_addr:X}"
                                                        }
                                                        td { class: "cell", style: "width: 80px;", "{hook_size}" }
                                                        td { class: "cell", style: "width: 80px;",
                                                            button {
                                                                class: "btn",
                                                                style: "font-size: 10px; padding: 1px 6px; color: #dc2626;",
                                                                onclick: move |_| {
                                                                    // Free detour allocation if this hook has one
                                                                    if let Some((dpid, daddr)) = detour_allocs.read().get(&hook_idx).copied() {
                                                                        let _ = free_remote_memory(dpid, daddr);
                                                                    }
                                                                    detour_allocs.write().remove(&hook_idx);
                                                                    let _ = remove_ept_hook(hook_idx);
                                                                    if let Ok(h) = list_ept_hooks() {
                                                                        ept_hooks_list.set(h);
                                                                    }
                                                                },
                                                                "Remove"
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
                    }
                }
            }

            // Context menu
            if let Some((x, y, idx)) = ctx_menu {
                {
                    let addr = ctx_addr.unwrap_or(0);
                    let val = ctx_val.clone().unwrap_or_default();
                    let addr_hex = format!("0x{:X}", addr);
                    rsx! {
                        div {
                            class: "context-menu",
                            style: "left: clamp(0px, {x}px, calc(100vw - 200px)); top: clamp(0px, {y}px, calc(100vh - 200px));",
                            onclick: move |e| e.stop_propagation(),

                            // Edit Value
                            button {
                                class: "context-menu-item",
                                onclick: {
                                    let v = val.clone();
                                    move |_| {
                                        editing_idx.set(Some(idx));
                                        edit_value_input.set(v.clone());
                                        context_menu.set(None);
                                    }
                                },
                                span { "Edit Value" }
                            }

                            // Write Value (using the write bar)
                            button {
                                class: "context-menu-item",
                                onclick: move |_| {
                                    selected_idx.set(Some(idx));
                                    context_menu.set(None);
                                },
                                span { "Select for Write Bar" }
                            }

                            div { class: "context-menu-separator" }

                            // Copy Address
                            button {
                                class: "context-menu-item",
                                onclick: {
                                    let a = addr_hex.clone();
                                    move |_| {
                                        copy_to_clipboard(&a);
                                        context_menu.set(None);
                                    }
                                },
                                span { "Copy Address" }
                            }

                            // Copy Value
                            button {
                                class: "context-menu-item",
                                onclick: {
                                    let v = val.clone();
                                    move |_| {
                                        copy_to_clipboard(&v);
                                        context_menu.set(None);
                                    }
                                },
                                span { "Copy Value" }
                            }

                            // Copy Row
                            button {
                                class: "context-menu-item",
                                onclick: {
                                    let row = format!("{}\t{}", addr_hex, val);
                                    move |_| {
                                        copy_to_clipboard(&row);
                                        context_menu.set(None);
                                    }
                                },
                                span { "Copy Row" }
                            }

                            div { class: "context-menu-separator" }

                            // Install EPT Hook
                            button {
                                class: "context-menu-item",
                                disabled: !driver_loaded || !hv_is_running(),
                                onclick: move |_| {
                                    ept_hook_target.set(Some(addr));
                                    ept_hook_bytes.set(String::new());
                                    ept_hook_show_modal.set(true);
                                    ept_hook_status.set(String::new());
                                    ept_hook_is_error.set(false);
                                    context_menu.set(None);
                                },
                                span { "Install EPT Hook" }
                                if !hv_is_running() {
                                    span { style: "color: var(--text-secondary); font-size: 10px; margin-left: 4px;", "(HV off)" }
                                }
                            }
                        }
                    }
                }
            }

            // ============== EPT Hook Install Modal ==============
            if *ept_hook_show_modal.read() {
                {
                    let target_addr = ept_hook_target.read().unwrap_or(0);
                    let hook_status = ept_hook_status.read().clone();
                    let hook_error = *ept_hook_is_error.read();
                    let input_mode = *ept_hook_input_mode.read();
                    let asm_preview = ept_hook_asm_preview.read().clone();
                    let asm_error = ept_hook_asm_error.read().clone();
                    let detour_preview = detour_asm_preview.read().clone();
                    let detour_error = detour_asm_error.read().clone();

                    // Get process architecture for assembly
                    let pid_str = pid_input.read().clone();
                    let pid = pid_str.trim().parse::<u32>().unwrap_or(0);
                    let proc_arch = if pid > 0 { get_process_arch(pid) } else { ProcessArch::Unknown };
                    let arch_label = match proc_arch {
                        ProcessArch::X64 => "x64",
                        ProcessArch::X86 => "x86",
                        ProcessArch::Unknown => "?",
                    };
                    let arch_badge_style = match proc_arch {
                        ProcessArch::X64 => "background: #22c55e;",
                        ProcessArch::X86 => "background: #eab308;",
                        ProcessArch::Unknown => "background: #6b7280;",
                    };

                    rsx! {
                        div {
                            class: "modal-overlay",
                            onclick: move |_| ept_hook_show_modal.set(false),
                            div {
                                class: "modal-content",
                                style: "max-width: 600px; min-height: 400px;",
                                onclick: move |e| e.stop_propagation(),

                                // Header with title and arch badge
                                div { style: "display: flex; align-items: center; gap: 8px; margin-bottom: 12px;",
                                    h3 { style: "margin: 0; color: var(--text-primary);",
                                        "Install EPT Hook"
                                    }
                                    span {
                                        class: "experimental-badge",
                                        style: "{arch_badge_style}",
                                        "{arch_label}"
                                    }
                                }

                                div { style: "margin-bottom: 12px; color: var(--text-secondary); font-size: 12px;",
                                    "EPT split-page hook: reads see original bytes, execution uses patched bytes."
                                }

                                // Target address (read-only)
                                div { style: "display: flex; gap: 8px; align-items: center; margin-bottom: 12px;",
                                    label { style: "color: var(--text-secondary); font-size: 13px; min-width: 80px;", "Address:" }
                                    span {
                                        style: "font-family: 'Consolas', monospace; color: var(--accent-primary); font-size: 13px;",
                                        "0x{target_addr:X}"
                                    }
                                }

                                // Input mode toggle
                                div { style: "display: flex; gap: 4px; margin-bottom: 12px;",
                                    button {
                                        class: if input_mode == EptHookInputMode::Hex { "btn btn-primary" } else { "btn" },
                                        style: "font-size: 12px; padding: 4px 12px;",
                                        onclick: move |_| {
                                            ept_hook_input_mode.set(EptHookInputMode::Hex);
                                            ept_hook_asm_error.set(String::new());
                                        },
                                        "Hex Bytes"
                                    }
                                    button {
                                        class: if input_mode == EptHookInputMode::Assembly { "btn btn-primary" } else { "btn" },
                                        style: "font-size: 12px; padding: 4px 12px;",
                                        onclick: move |_| {
                                            ept_hook_input_mode.set(EptHookInputMode::Assembly);
                                            ept_hook_status.set(String::new());
                                        },
                                        "Assembly"
                                    }
                                    button {
                                        class: if input_mode == EptHookInputMode::Detour { "btn btn-primary" } else { "btn" },
                                        style: "font-size: 12px; padding: 4px 12px;",
                                        onclick: move |_| {
                                            ept_hook_input_mode.set(EptHookInputMode::Detour);
                                            ept_hook_status.set(String::new());
                                        },
                                        "Detour"
                                    }
                                }

                                // Hex bytes input mode
                                if input_mode == EptHookInputMode::Hex {
                                    div { style: "display: flex; gap: 8px; align-items: center; margin-bottom: 8px;",
                                        label { style: "color: var(--text-secondary); font-size: 13px; min-width: 80px;", "Hook bytes:" }
                                        input {
                                            class: "handle-filter-input",
                                            r#type: "text",
                                            placeholder: "e.g. 90 90 90 or C3 or 48B8... (hex)",
                                            style: "flex: 1; font-family: 'Consolas', monospace;",
                                            value: "{ept_hook_bytes}",
                                            oninput: move |e| ept_hook_bytes.set(e.value()),
                                            onkeydown: {
                                                move |e: KeyboardEvent| {
                                                    if e.key() == Key::Escape {
                                                        ept_hook_show_modal.set(false);
                                                    }
                                                }
                                            },
                                        }
                                    }
                                    div { style: "color: var(--text-secondary); font-size: 11px; margin-bottom: 12px;",
                                        "Enter replacement bytes in hex (space-separated or continuous). Max 256 bytes."
                                    }
                                }

                                // Assembly input mode
                                if input_mode == EptHookInputMode::Assembly {
                                    div { style: "margin-bottom: 8px;",
                                        label { style: "color: var(--text-secondary); font-size: 13px; display: block; margin-bottom: 4px;",
                                            "Assembly code (Intel syntax):"
                                        }
                                        textarea {
                                            class: "handle-filter-input",
                                            placeholder: "nop\nmov rax, 0x1234\nret",
                                            style: "width: 100%; height: 120px; font-family: 'Consolas', monospace; font-size: 13px; resize: vertical; background: var(--bg-tertiary); color: var(--text-primary); border: 1px solid var(--border-color); border-radius: 4px; padding: 8px;",
                                            value: "{ept_hook_asm_input}",
                                            oninput: {
                                                move |e: Event<FormData>| {
                                                    let code = e.value();
                                                    ept_hook_asm_input.set(code.clone());
                                                    
                                                    // Live preview assembly
                                                    if !code.trim().is_empty() && pid > 0 {
                                                        match assemble(&code, proc_arch, target_addr) {
                                                            Ok(bytes) => {
                                                                ept_hook_asm_preview.set(format_bytes_hex(&bytes));
                                                                ept_hook_asm_error.set(String::new());
                                                            }
                                                            Err(e) => {
                                                                ept_hook_asm_preview.set(String::new());
                                                                ept_hook_asm_error.set(e.to_string());
                                                            }
                                                        }
                                                    } else {
                                                        ept_hook_asm_preview.set(String::new());
                                                        ept_hook_asm_error.set(String::new());
                                                    }
                                                }
                                            },
                                            onkeydown: {
                                                move |e: KeyboardEvent| {
                                                    if e.key() == Key::Escape {
                                                        ept_hook_show_modal.set(false);
                                                    }
                                                }
                                            },
                                        }
                                    }

                                    // Assembly error display
                                    if !asm_error.is_empty() {
                                        div {
                                            style: "color: #ef4444; font-size: 12px; font-family: 'Consolas', monospace; margin-bottom: 8px; padding: 6px; background: rgba(239, 68, 68, 0.1); border-radius: 4px;",
                                            "⚠ {asm_error}"
                                        }
                                    }

                                    // Assembled bytes preview
                                    if !asm_preview.is_empty() {
                                        div { style: "margin-bottom: 12px;",
                                            label { style: "color: var(--text-secondary); font-size: 12px; display: block; margin-bottom: 4px;",
                                                "Assembled bytes:"
                                            }
                                            div {
                                                style: "font-family: 'Consolas', monospace; font-size: 13px; color: #22c55e; background: var(--bg-tertiary); padding: 8px; border-radius: 4px; word-break: break-all;",
                                                "{asm_preview}"
                                            }
                                        }
                                    }

                                    div { style: "color: var(--text-secondary); font-size: 11px; margin-bottom: 8px;",
                                        "Use Intel syntax. Separate instructions with newlines or semicolons."
                                    }

                                    // Save/Load buttons for .aa files
                                    div { style: "display: flex; gap: 8px; margin-bottom: 12px;",
                                        button {
                                            class: "btn",
                                            style: "font-size: 11px; padding: 3px 10px;",
                                            onclick: {
                                                move |_| {
                                                    let code = ept_hook_asm_input.read().clone();
                                                    spawn(async move {
                                                        if let Some(file) = rfd::AsyncFileDialog::new()
                                                            .add_filter("Auto Assemble Script", &["aa"])
                                                            .set_file_name("hook.aa")
                                                            .save_file()
                                                            .await
                                                        {
                                                            let _ = std::fs::write(file.path(), code);
                                                        }
                                                    });
                                                }
                                            },
                                            "Save .aa"
                                        }
                                        button {
                                            class: "btn",
                                            style: "font-size: 11px; padding: 3px 10px;",
                                            onclick: {
                                                move |_| {
                                                    spawn(async move {
                                                        if let Some(file) = rfd::AsyncFileDialog::new()
                                                            .add_filter("Auto Assemble Script", &["aa"])
                                                            .pick_file()
                                                            .await
                                                        {
                                                            if let Ok(content) = std::fs::read_to_string(file.path()) {
                                                                ept_hook_asm_input.set(content.clone());
                                                                // Trigger preview update
                                                                let pid_str = pid_input.read().clone();
                                                                let pid = pid_str.trim().parse::<u32>().unwrap_or(0);
                                                                let target_addr = ept_hook_target.read().unwrap_or(0);
                                                                if pid > 0 {
                                                                    let proc_arch = get_process_arch(pid);
                                                                    match assemble(&content, proc_arch, target_addr) {
                                                                        Ok(bytes) => {
                                                                            ept_hook_asm_preview.set(format_bytes_hex(&bytes));
                                                                            ept_hook_asm_error.set(String::new());
                                                                        }
                                                                        Err(e) => {
                                                                            ept_hook_asm_preview.set(String::new());
                                                                            ept_hook_asm_error.set(e.to_string());
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    });
                                                }
                                            },
                                            "Load .aa"
                                        }
                                    }
                                }

                                // Detour input mode
                                if input_mode == EptHookInputMode::Detour {
                                    div { style: "margin-bottom: 8px; padding: 8px; background: var(--bg-tertiary); border-radius: 4px; border: 1px solid var(--border-color);",
                                        div { style: "color: var(--text-secondary); font-size: 11px; margin-bottom: 8px;",
                                            "Allocates RWX memory near the hook point, writes detour code there, and places a JMP on the EPT exec page. Return jump is auto-appended."
                                        }

                                        // Stolen bytes input
                                        div { style: "display: flex; gap: 8px; align-items: center; margin-bottom: 8px;",
                                            label { style: "color: var(--text-secondary); font-size: 12px; min-width: 100px;", "Stolen bytes:" }
                                            input {
                                                class: "handle-filter-input",
                                                r#type: "text",
                                                placeholder: "6",
                                                style: "width: 60px; font-family: 'Consolas', monospace; font-size: 12px;",
                                                value: "{detour_stolen_bytes}",
                                                oninput: move |e| detour_stolen_bytes.set(e.value()),
                                            }
                                            span { style: "color: var(--text-secondary); font-size: 11px;",
                                                "(min 5 — bytes overwritten by JMP + NOP padding)"
                                            }
                                        }
                                    }

                                    // Detour assembly textarea
                                    div { style: "margin-bottom: 8px;",
                                        label { style: "color: var(--text-secondary); font-size: 13px; display: block; margin-bottom: 4px;",
                                            "Detour assembly code (Intel syntax):"
                                        }
                                        textarea {
                                            class: "handle-filter-input",
                                            placeholder: "; Your detour code here\n; Return jump is auto-appended\nadd [rbx+0x7F8], edx",
                                            style: "width: 100%; height: 160px; font-family: 'Consolas', monospace; font-size: 13px; resize: vertical; background: var(--bg-tertiary); color: var(--text-primary); border: 1px solid var(--border-color); border-radius: 4px; padding: 8px;",
                                            value: "{detour_asm_input}",
                                            oninput: {
                                                move |e: Event<FormData>| {
                                                    let code = e.value();
                                                    detour_asm_input.set(code.clone());

                                                    if !code.trim().is_empty() && pid > 0 {
                                                        // Preview: assemble at address 0 (final address determined at install time)
                                                        match assemble(&code, proc_arch, 0) {
                                                            Ok(bytes) => {
                                                                detour_asm_preview.set(format_bytes_hex(&bytes));
                                                                detour_asm_error.set(String::new());
                                                            }
                                                            Err(e) => {
                                                                detour_asm_preview.set(String::new());
                                                                detour_asm_error.set(e.to_string());
                                                            }
                                                        }
                                                    } else {
                                                        detour_asm_preview.set(String::new());
                                                        detour_asm_error.set(String::new());
                                                    }
                                                }
                                            },
                                            onkeydown: {
                                                move |e: KeyboardEvent| {
                                                    if e.key() == Key::Escape {
                                                        ept_hook_show_modal.set(false);
                                                    }
                                                }
                                            },
                                        }
                                    }

                                    // Error display
                                    if !detour_error.is_empty() {
                                        div {
                                            style: "color: #ef4444; font-size: 12px; font-family: 'Consolas', monospace; margin-bottom: 8px; padding: 6px; background: rgba(239, 68, 68, 0.1); border-radius: 4px;",
                                            "{detour_error}"
                                        }
                                    }

                                    // Assembled bytes preview
                                    if !detour_preview.is_empty() {
                                        {
                                            let byte_count = detour_preview.split_whitespace().count();
                                            let info = format!("Assembled detour ({} bytes + 14 return JMP = {} total):", byte_count, byte_count + 14);
                                            rsx! {
                                                div { style: "margin-bottom: 8px;",
                                                    label { style: "color: var(--text-secondary); font-size: 12px; display: block; margin-bottom: 4px;",
                                                        "{info}"
                                                    }
                                                    div {
                                                        style: "font-family: 'Consolas', monospace; font-size: 12px; color: #22c55e; background: var(--bg-tertiary); padding: 8px; border-radius: 4px; word-break: break-all; max-height: 80px; overflow-y: auto;",
                                                        "{detour_preview}"
                                                    }
                                                }
                                            }
                                        }
                                    }

                                    div { style: "color: var(--text-secondary); font-size: 11px; margin-bottom: 8px; padding: 6px; background: var(--bg-secondary); border-radius: 4px;",
                                        "Flow: hook_addr → [EPT JMP rel32] → allocated cave → your code → [auto JMP back] → hook_addr + stolen"
                                    }

                                    // Save/Load buttons
                                    div { style: "display: flex; gap: 8px; margin-bottom: 8px;",
                                        button {
                                            class: "btn",
                                            style: "font-size: 11px; padding: 3px 10px;",
                                            onclick: {
                                                move |_| {
                                                    let code = detour_asm_input.read().clone();
                                                    spawn(async move {
                                                        if let Some(file) = rfd::AsyncFileDialog::new()
                                                            .add_filter("Auto Assemble Script", &["aa"])
                                                            .set_file_name("detour.aa")
                                                            .save_file()
                                                            .await
                                                        {
                                                            let _ = std::fs::write(file.path(), code);
                                                        }
                                                    });
                                                }
                                            },
                                            "Save .aa"
                                        }
                                        button {
                                            class: "btn",
                                            style: "font-size: 11px; padding: 3px 10px;",
                                            onclick: {
                                                move |_| {
                                                    spawn(async move {
                                                        if let Some(file) = rfd::AsyncFileDialog::new()
                                                            .add_filter("Auto Assemble Script", &["aa"])
                                                            .pick_file()
                                                            .await
                                                        {
                                                            if let Ok(content) = std::fs::read_to_string(file.path()) {
                                                                detour_asm_input.set(content.clone());
                                                                let pid_str = pid_input.read().clone();
                                                                let pid = pid_str.trim().parse::<u32>().unwrap_or(0);
                                                                if pid > 0 {
                                                                    let proc_arch = get_process_arch(pid);
                                                                    match assemble(&content, proc_arch, 0) {
                                                                        Ok(bytes) => {
                                                                            detour_asm_preview.set(format_bytes_hex(&bytes));
                                                                            detour_asm_error.set(String::new());
                                                                        }
                                                                        Err(e) => {
                                                                            detour_asm_preview.set(String::new());
                                                                            detour_asm_error.set(e.to_string());
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    });
                                                }
                                            },
                                            "Load .aa"
                                        }
                                    }
                                }

                                if !hook_status.is_empty() {
                                    div {
                                        class: if hook_error { "status-message status-error" } else { "status-message" },
                                        style: "margin-bottom: 8px;",
                                        "{hook_status}"
                                    }
                                }

                                // Buttons
                                div { style: "display: flex; gap: 8px; justify-content: flex-end;",
                                    button {
                                        class: "btn",
                                        onclick: move |_| ept_hook_show_modal.set(false),
                                        "Cancel"
                                    }
                                    button {
                                        class: "btn btn-primary",
                                        disabled: !driver_loaded || !hv_is_running()
                                            || (input_mode == EptHookInputMode::Assembly && !asm_error.is_empty())
                                            || (input_mode == EptHookInputMode::Detour && !detour_error.is_empty()),
                                        onclick: {
                                            move |_| {
                                                let pid_str = pid_input.read().clone();
                                                let pid = pid_str.trim().parse::<u32>().unwrap_or(0);
                                                if pid == 0 {
                                                    ept_hook_status.set("Invalid PID".to_string());
                                                    ept_hook_is_error.set(true);
                                                    return;
                                                }

                                                let addr = ept_hook_target.read().unwrap_or(0);
                                                if addr == 0 {
                                                    ept_hook_status.set("Invalid address".to_string());
                                                    ept_hook_is_error.set(true);
                                                    return;
                                                }

                                                let input_mode = *ept_hook_input_mode.read();

                                                // Detour mode: allocate RWX near hook, write detour+return JMP, EPT hook with JMP patch
                                                if input_mode == EptHookInputMode::Detour {
                                                    let asm_code = detour_asm_input.read().clone();
                                                    let proc_arch = get_process_arch(pid);

                                                    // Parse stolen bytes (minimum 5 for JMP rel32)
                                                    let stolen: u32 = detour_stolen_bytes.read().trim().parse().unwrap_or(6);
                                                    if stolen < 5 {
                                                        ept_hook_status.set("Stolen bytes must be >= 5".to_string());
                                                        ept_hook_is_error.set(true);
                                                        return;
                                                    }

                                                    // Step 1: Allocate RWX memory near the hook point (within ±2GB for JMP rel32)
                                                    let alloc_addr = match allocate_near_address(pid, addr, 0x1000) {
                                                        Ok(a) => a,
                                                        Err(e) => {
                                                            ept_hook_status.set(format!("Alloc failed: {}", e));
                                                            ept_hook_is_error.set(true);
                                                            return;
                                                        }
                                                    };

                                                    // Step 2: Assemble detour code at allocated address
                                                    let detour_bytes = match assemble(&asm_code, proc_arch, alloc_addr) {
                                                        Ok(b) => b,
                                                        Err(e) => {
                                                            let _ = free_remote_memory(pid, alloc_addr);
                                                            ept_hook_status.set(format!("Assembly error: {}", e));
                                                            ept_hook_is_error.set(true);
                                                            return;
                                                        }
                                                    };

                                                    if detour_bytes.is_empty() || detour_bytes.len() > 3800 {
                                                        let _ = free_remote_memory(pid, alloc_addr);
                                                        ept_hook_status.set("Detour code must be 1-3800 bytes".to_string());
                                                        ept_hook_is_error.set(true);
                                                        return;
                                                    }

                                                    // Step 3: Build full payload = detour code + return JMP back to hook_point + stolen_bytes
                                                    // Return JMP uses FF 25 00 00 00 00 [8-byte abs addr] (14 bytes, no register clobber)
                                                    let return_addr = addr + stolen as u64;
                                                    let mut full_code = detour_bytes.clone();
                                                    full_code.extend_from_slice(&[0xFF, 0x25, 0x00, 0x00, 0x00, 0x00]);
                                                    full_code.extend_from_slice(&return_addr.to_le_bytes());

                                                    // Step 4: Write detour code to allocated memory
                                                    if let Err(e) = write_process_memory_bytes(pid, alloc_addr, &full_code) {
                                                        let _ = free_remote_memory(pid, alloc_addr);
                                                        ept_hook_status.set(format!("Write failed: {}", e));
                                                        ept_hook_is_error.set(true);
                                                        return;
                                                    }

                                                    // Step 5: Build JMP rel32 patch (E9 + offset) + NOP padding for stolen bytes
                                                    let jmp_target = alloc_addr as i64;
                                                    let jmp_from = (addr + 5) as i64; // E9 + 4 bytes = 5
                                                    let rel32 = (jmp_target - jmp_from) as i32;
                                                    let mut jmp_patch: Vec<u8> = Vec::with_capacity(stolen as usize);
                                                    jmp_patch.push(0xE9);
                                                    jmp_patch.extend_from_slice(&rel32.to_le_bytes());
                                                    // Fill remaining stolen bytes with NOPs
                                                    for _ in 5..stolen {
                                                        jmp_patch.push(0x90);
                                                    }

                                                    // Step 6: Install EPT hook with JMP patch bytes
                                                    match install_ept_hook(pid, addr, &jmp_patch) {
                                                        Ok(idx) => {
                                                            // Track allocation for cleanup on removal
                                                            detour_allocs.write().insert(idx, (pid, alloc_addr));
                                                            ept_hook_status.set(format!(
                                                                "Detour hook #{} installed: JMP@0x{:X} -> 0x{:X} ({} bytes detour)",
                                                                idx, addr, alloc_addr, detour_bytes.len()
                                                            ));
                                                            ept_hook_is_error.set(false);
                                                            if let Ok(hooks) = list_ept_hooks() {
                                                                ept_hooks_list.set(hooks);
                                                            }
                                                        }
                                                        Err(e) => {
                                                            let _ = free_remote_memory(pid, alloc_addr);
                                                            ept_hook_status.set(format!("Failed: {}", e));
                                                            ept_hook_is_error.set(true);
                                                        }
                                                    }
                                                    return;
                                                }

                                                // Hex / Assembly modes: use install_ept_hook
                                                let bytes = match input_mode {
                                                    EptHookInputMode::Hex => {
                                                        let hex_str = ept_hook_bytes.read().clone();
                                                        match parse_hex_bytes(&hex_str) {
                                                            Ok(b) => b,
                                                            Err(msg) => {
                                                                ept_hook_status.set(msg);
                                                                ept_hook_is_error.set(true);
                                                                return;
                                                            }
                                                        }
                                                    }
                                                    EptHookInputMode::Assembly => {
                                                        let asm_code = ept_hook_asm_input.read().clone();
                                                        let proc_arch = get_process_arch(pid);
                                                        match assemble(&asm_code, proc_arch, addr) {
                                                            Ok(b) => b,
                                                            Err(e) => {
                                                                ept_hook_status.set(format!("Assembly error: {}", e));
                                                                ept_hook_is_error.set(true);
                                                                return;
                                                            }
                                                        }
                                                    }
                                                    EptHookInputMode::Detour => unreachable!(),
                                                };

                                                if bytes.is_empty() || bytes.len() > 256 {
                                                    ept_hook_status.set("Patch bytes must be 1-256 bytes".to_string());
                                                    ept_hook_is_error.set(true);
                                                    return;
                                                }

                                                match install_ept_hook(pid, addr, &bytes) {
                                                    Ok(idx) => {
                                                        ept_hook_status.set(format!(
                                                            "EPT hook #{} installed at 0x{:X} ({} bytes)",
                                                            idx, addr, bytes.len()
                                                        ));
                                                        ept_hook_is_error.set(false);
                                                        if let Ok(hooks) = list_ept_hooks() {
                                                            ept_hooks_list.set(hooks);
                                                        }
                                                    }
                                                    Err(e) => {
                                                        ept_hook_status.set(format!("Failed: {}", e));
                                                        ept_hook_is_error.set(true);
                                                    }
                                                }
                                            }
                                        },
                                        "Install"
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

/// Parse a hex byte string like "90 90 90", "909090", "0x90 0x90", etc.
fn parse_hex_bytes(input: &str) -> Result<Vec<u8>, String> {
    let cleaned = input.trim();
    if cleaned.is_empty() {
        return Err("No bytes provided".to_string());
    }

    let mut bytes = Vec::new();

    // Try space-separated first
    if cleaned.contains(' ') {
        for part in cleaned.split_whitespace() {
            let hex = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")).unwrap_or(part);
            let val = u8::from_str_radix(hex, 16)
                .map_err(|_| format!("Invalid hex byte: '{}'", part))?;
            bytes.push(val);
        }
    } else {
        // Continuous hex string
        let hex = cleaned.strip_prefix("0x").or_else(|| cleaned.strip_prefix("0X")).unwrap_or(cleaned);
        if hex.len() % 2 != 0 {
            return Err("Hex string must have even number of digits".to_string());
        }
        for i in (0..hex.len()).step_by(2) {
            let val = u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|_| format!("Invalid hex at position {}: '{}'", i, &hex[i..i + 2]))?;
            bytes.push(val);
        }
    }

    Ok(bytes)
}
