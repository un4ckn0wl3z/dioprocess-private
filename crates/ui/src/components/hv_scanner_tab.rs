//! HV Scanner tab — Ring -1 memory scanner via hypervisor hypercalls

use callback::{
    enum_vm_regions, hv_first_scan, hv_is_running, hv_next_scan, hv_write_scan_value,
    is_driver_loaded, parse_aob_pattern, parse_scan_value, ScanDataType, ScanResult, ScanType,
};
use dioxus::prelude::*;

use crate::helpers::copy_to_clipboard;

use crate::state::{
    HV_SCANNER_DATA_TYPE_IDX, HV_SCANNER_EDIT_VALUE, HV_SCANNER_EDITING_IDX,
    HV_SCANNER_HAS_SCANNED, HV_SCANNER_IS_ERROR, HV_SCANNER_IS_SCANNING, HV_SCANNER_PAGE,
    HV_SCANNER_PID, HV_SCANNER_RESULTS, HV_SCANNER_SCAN_TYPE_IDX, HV_SCANNER_SELECTED,
    HV_SCANNER_STATUS, HV_SCANNER_VALUE, HV_SCANNER_VALUE2, HV_SCANNER_WRITE_VALUE,
};

const RESULTS_PER_PAGE: usize = 500;

#[component]
pub fn HvScannerTab() -> Element {
    let mut pid_input = HV_SCANNER_PID.signal();
    let mut value_input = HV_SCANNER_VALUE.signal();
    let _value2_input = HV_SCANNER_VALUE2.signal();
    let mut data_type_idx = HV_SCANNER_DATA_TYPE_IDX.signal();
    let mut scan_type_idx = HV_SCANNER_SCAN_TYPE_IDX.signal();
    let mut scan_results = HV_SCANNER_RESULTS.signal();
    let mut has_scanned = HV_SCANNER_HAS_SCANNED.signal();
    let mut is_scanning = HV_SCANNER_IS_SCANNING.signal();
    let mut status_message = HV_SCANNER_STATUS.signal();
    let mut is_error = HV_SCANNER_IS_ERROR.signal();
    let mut result_page = HV_SCANNER_PAGE.signal();
    let mut selected_idx = HV_SCANNER_SELECTED.signal();
    let mut write_value_input = HV_SCANNER_WRITE_VALUE.signal();
    let mut context_menu = use_signal(|| None::<(i32, i32, usize)>);
    let mut editing_idx = HV_SCANNER_EDITING_IDX.signal();
    let mut edit_value_input = HV_SCANNER_EDIT_VALUE.signal();

    let driver_loaded = is_driver_loaded();
    let hv_running = hv_is_running();
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

    let mut do_first_scan = move || {
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
        status_message.set("Scanning via Hypervisor...".to_string());
        is_error.set(false);

        spawn(async move {
            let result = tokio::task::spawn_blocking(move || {
                let regions = enum_vm_regions(pid)?;
                hv_first_scan(pid, &regions, &target_bytes, dt, st, aob_pat.as_ref())
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
                    status_message.set(format!("Found {} results (Ring -1)", count));
                    is_error.set(false);
                }
                Ok(Err(e)) => {
                    status_message.set(format!("HV Scan failed: {}", e));
                    is_error.set(true);
                }
                Err(e) => {
                    status_message.set(format!("HV Scan task failed: {}", e));
                    is_error.set(true);
                }
            }
        });
    };

    let mut do_next_scan = move || {
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
        status_message.set("Scanning via Hypervisor...".to_string());
        is_error.set(false);

        spawn(async move {
            let result = tokio::task::spawn_blocking(move || {
                hv_next_scan(pid, &prev_results, &target_bytes, dt, st, aob_pat.as_ref())
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
                    status_message.set(format!("Filtered to {} results (Ring -1)", count));
                    is_error.set(false);
                }
                Ok(Err(e)) => {
                    status_message.set(format!("HV Next scan failed: {}", e));
                    is_error.set(true);
                }
                Err(e) => {
                    status_message.set(format!("HV Scan task failed: {}", e));
                    is_error.set(true);
                }
            }
        });
    };

    let mut do_reset = move || {
        scan_results.set(Vec::new());
        has_scanned.set(false);
        result_page.set(0);
        selected_idx.set(None);
        editing_idx.set(None);
        scan_type_idx.set(0);
        status_message.set("Scan reset".to_string());
        is_error.set(false);
    };

    let mut do_write = move || {
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

        match hv_write_scan_value(pid, address, &bytes) {
            Ok(()) => {
                status_message.set(format!(
                    "Wrote {} bytes to 0x{:X} (Ring -1)",
                    bytes.len(),
                    address
                ));
                is_error.set(false);
            }
            Err(e) => {
                status_message.set(format!("HV Write failed: {}", e));
                is_error.set(true);
            }
        }
    };

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

        match hv_write_scan_value(pid, address, &bytes) {
            Ok(()) => {
                status_message.set(format!(
                    "Wrote {} bytes to 0x{:X} (Ring -1)",
                    bytes.len(),
                    address
                ));
                is_error.set(false);
                editing_idx.set(None);
            }
            Err(e) => {
                status_message.set(format!("HV Write failed: {}", e));
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
    let page_results: Vec<(usize, ScanResult)> = if total_results > 0 {
        results[page_start..page_end]
            .iter()
            .cloned()
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

            // Header with Ring -1 badge
            div { class: "header-box",
                div { style: "display: flex; align-items: center; gap: 12px;",
                    h2 { style: "margin: 0;", "HV Scanner" }
                    span {
                        style: "background: linear-gradient(135deg, #22c55e, #16a34a); color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;",
                        "Ring -1"
                    }
                }
                p { style: "margin: 4px 0 0 0; color: var(--text-secondary); font-size: 13px;",
                    "Memory scanner using hypervisor-level access — bypasses all Ring 0 protections"
                }
            }

            // Status bar
            if !driver_loaded {
                div { class: "status-bar",
                    style: "background: rgba(239, 68, 68, 0.1); border-left: 3px solid #ef4444; padding: 8px 12px; margin-bottom: 12px; color: #ef4444;",
                    "Driver not loaded"
                }
            } else if !hv_running {
                div { class: "status-bar",
                    style: "background: rgba(239, 68, 68, 0.1); border-left: 3px solid #ef4444; padding: 8px 12px; margin-bottom: 12px; color: #ef4444;",
                    "Hypervisor not running — Start HV from Hypervisor tab first"
                }
            } else if !status_msg.is_empty() {
                div { class: "status-bar",
                    style: if error_state {
                        "background: rgba(239, 68, 68, 0.1); border-left: 3px solid #ef4444; padding: 8px 12px; margin-bottom: 12px; color: #ef4444;"
                    } else {
                        "background: rgba(34, 197, 94, 0.1); border-left: 3px solid #22c55e; padding: 8px 12px; margin-bottom: 12px; color: #22c55e;"
                    },
                    "{status_msg}"
                }
            }

            // Controls bar (matching Memory Scanner style)
            div { class: "controls",
                div { style: "display: flex; gap: 8px; align-items: center; flex-wrap: wrap;",
                    label { style: "color: var(--text-secondary); font-size: 13px;", "PID:" }
                    input {
                        class: "handle-filter-input",
                        r#type: "text",
                        placeholder: "Process ID",
                        style: "width: 100px;",
                        value: "{pid_input}",
                        disabled: !hv_running || scanning,
                        oninput: move |e| pid_input.set(e.value()),
                    }

                    label { style: "color: var(--text-secondary); font-size: 13px;", "Value:" }
                    input {
                        class: "handle-filter-input",
                        r#type: "text",
                        placeholder: if current_data_type.is_aob() { "48 8B ?? 04 ..." } else { "Search value" },
                        style: "width: 160px; font-family: 'Consolas', monospace;",
                        value: "{value_input}",
                        disabled: !hv_running || scanning || !current_scan_type.needs_value(),
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

                    label { style: "color: var(--text-secondary); font-size: 13px;", "Type:" }
                    select {
                        class: "handle-filter-input",
                        style: "width: 140px;",
                        value: "{current_dt_idx}",
                        disabled: !hv_running || scanned || scanning,
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
                        disabled: !hv_running || scanning,
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
                            disabled: !hv_running || scanning,
                            onclick: {
                                let mut first = do_first_scan.clone();
                                move |_| first()
                            },
                            if scanning { "Scanning..." } else { "First Scan" }
                        }
                    } else {
                        button {
                            class: "btn btn-primary",
                            disabled: !hv_running || scanning,
                            onclick: {
                                let mut next = do_next_scan.clone();
                                move |_| next()
                            },
                            if scanning { "Scanning..." } else { "Next Scan" }
                        }
                    }

                    button {
                        class: "btn",
                        disabled: !hv_running || scanning,
                        onclick: {
                            let mut reset = do_reset.clone();
                            move |_| reset()
                        },
                        "New Scan"
                    }
                }
            }

            // Write bar (when an address is selected)
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
                            disabled: !hv_running,
                            onclick: {
                                let mut w = do_write.clone();
                                move |_| w()
                            },
                            "Write (Ring -1)"
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
            }

            // Pagination
            if total_pages > 1 {
                div { class: "pagination",
                    style: "display: flex; gap: 8px; align-items: center; justify-content: center; padding: 12px;",
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
                    span { style: "color: var(--text-secondary); font-size: 13px;",
                        "Page {page + 1} of {total_pages}"
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
                        onclick: move |_| result_page.set(total_pages.saturating_sub(1)),
                        ">>"
                    }
                    span { style: "color: var(--text-secondary); font-size: 12px; margin-left: 12px;",
                        "({total_results} total)"
                    }
                }
            }

            // Context menu
            if let Some((x, y, ctx_idx)) = ctx_menu {
                div {
                    class: "context-menu",
                    style: "position: fixed; left: {x}px; top: {y}px; z-index: 1000; background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 6px; box-shadow: 0 4px 12px rgba(0,0,0,0.3); padding: 4px 0; min-width: 140px;",
                    onclick: move |e| e.stop_propagation(),
                    div {
                        class: "context-menu-item",
                        style: "padding: 6px 12px; cursor: pointer; font-size: 13px;",
                        onmouseenter: |e| { let _ = e; },
                        onclick: {
                            let addr = ctx_addr.unwrap_or(0);
                            move |_| {
                                copy_to_clipboard(&format!("0x{:X}", addr));
                                context_menu.set(None);
                            }
                        },
                        "Copy Address"
                    }
                    div {
                        class: "context-menu-item",
                        style: "padding: 6px 12px; cursor: pointer; font-size: 13px;",
                        onclick: {
                            let val = ctx_val.clone().unwrap_or_default();
                            move |_| {
                                copy_to_clipboard(&val);
                                context_menu.set(None);
                            }
                        },
                        "Copy Value"
                    }
                }
            }
        }
    }
}
