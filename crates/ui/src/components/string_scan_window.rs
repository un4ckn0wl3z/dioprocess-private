//! String Scan window component

use dioxus::prelude::*;
use process::{scan_process_strings, StringEncoding, StringResult, StringScanConfig};

use crate::helpers::copy_to_clipboard;
use crate::state::STRING_SCAN_WINDOW_STATE;

/// String Scan Window component
#[component]
pub fn StringScanWindow(pid: u32, process_name: String) -> Element {
    let mut scan_results = use_signal(|| Vec::<StringResult>::new());
    let mut status_message = use_signal(|| String::new());
    let mut is_scanning = use_signal(|| false);
    let mut filter_query = use_signal(|| String::new());
    let mut selected_index = use_signal(|| None::<usize>);
    let mut context_menu = use_signal(|| StringScanContextMenuState::default());
    let mut min_length = use_signal(|| 4usize);
    let mut encoding_filter = use_signal(|| EncodingFilter::All);

    // Trigger scan
    let trigger_scan = move |_| {
        is_scanning.set(true);
        status_message.set("Scanning process memory for strings...".to_string());
        scan_results.set(Vec::new());

        let min_len = *min_length.read();

        spawn(async move {
            match tokio::task::spawn_blocking(move || {
                let config = StringScanConfig {
                    min_length: min_len,
                    scan_ascii: true,
                    scan_utf16: true,
                    max_string_length: 512,
                };
                scan_process_strings(pid, &config)
            })
            .await
            {
                Ok(results) => {
                    let count = results.len();
                    scan_results.set(results);
                    status_message.set(format!("Scan complete: {} string(s) found", count));
                    is_scanning.set(false);
                }
                Err(e) => {
                    status_message.set(format!("Scan failed: {}", e));
                    is_scanning.set(false);
                }
            }
        });
    };

    // Filter results based on search query and encoding filter
    let filtered_results: Vec<(usize, StringResult)> = scan_results
        .read()
        .iter()
        .enumerate()
        .filter(|(_, result)| {
            // Encoding filter
            let encoding_match = match *encoding_filter.read() {
                EncodingFilter::All => true,
                EncodingFilter::AsciiOnly => result.encoding == StringEncoding::Ascii,
                EncodingFilter::Utf16Only => result.encoding == StringEncoding::Utf16,
            };
            if !encoding_match {
                return false;
            }

            // Text filter
            let query = filter_query.read().to_lowercase();
            if query.is_empty() {
                return true;
            }
            result.value.to_lowercase().contains(&query)
                || format!("{:X}", result.address).contains(&query.to_uppercase())
        })
        .map(|(i, r)| (i, r.clone()))
        .collect();

    let total_count = scan_results.read().len();
    let filtered_count = filtered_results.len();

    // Export function
    let export_results = {
        let results = filtered_results.clone();
        let proc_name = process_name.clone();
        move |_| {
            let results = results.clone();
            let proc_name = proc_name.clone();
            spawn(async move {
                let file = rfd::AsyncFileDialog::new()
                    .add_filter("Text Files", &["txt"])
                    .set_file_name(&format!("{}_strings.txt", proc_name))
                    .set_title("Export Strings")
                    .save_file()
                    .await;

                if let Some(file) = file {
                    let path = file.path().to_path_buf();
                    let mut content = format!(
                        "String Scan Results for {} (PID: {})\n",
                        proc_name, pid
                    );
                    content.push_str(&format!("Total: {} strings\n\n", results.len()));
                    content.push_str("Address\t\tEncoding\tLength\tRegion\t\tString\n");
                    content.push_str(&"-".repeat(100));
                    content.push('\n');

                    for (_, result) in &results {
                        content.push_str(&format!(
                            "0x{:016X}\t{}\t\t{}\t{}\t\t{}\n",
                            result.address,
                            result.encoding,
                            result.length,
                            result.region_type,
                            result.value.replace('\n', "\\n").replace('\r', "\\r").replace('\t', "\\t")
                        ));
                    }

                    match std::fs::write(&path, content) {
                        Ok(()) => {
                            status_message.set(format!(
                                "Exported {} strings to {}",
                                results.len(),
                                path.display()
                            ));
                        }
                        Err(e) => {
                            status_message.set(format!("Export failed: {}", e));
                        }
                    }
                }
            });
        }
    };

    rsx! {
        // Modal overlay
        div {
            class: "thread-modal-overlay",
            onclick: move |_| {
                *STRING_SCAN_WINDOW_STATE.write() = None;
            },

            // Modal window
            div {
                class: "thread-modal string-scan-modal",
                onclick: move |e| e.stop_propagation(),

                // Header
                div {
                    class: "thread-modal-header",
                    div {
                        class: "thread-modal-title",
                        "Abc String Scan - {process_name} (PID: {pid})"
                    }
                    button {
                        class: "thread-modal-close",
                        onclick: move |_| {
                            *STRING_SCAN_WINDOW_STATE.write() = None;
                        },
                        "X"
                    }
                }

                // Controls
                div {
                    class: "thread-controls",
                    span {
                        class: "thread-count",
                        if filtered_count != total_count {
                            "Strings: {filtered_count}/{total_count}"
                        } else {
                            "Strings: {total_count}"
                        }
                    }

                    // Min length input
                    div {
                        class: "min-length-container",
                        style: "display: flex; align-items: center; gap: 6px;",
                        span { style: "color: #9ca3af; font-size: 13px;", "Min length:" }
                        input {
                            class: "min-length-input",
                            r#type: "number",
                            min: "1",
                            max: "100",
                            value: "{min_length}",
                            oninput: move |e| {
                                if let Ok(val) = e.value().parse::<usize>() {
                                    if val >= 1 && val <= 100 {
                                        min_length.set(val);
                                    }
                                }
                            },
                        }
                    }

                    // Encoding filter
                    select {
                        class: "filter-select",
                        style: "min-width: 100px;",
                        value: match *encoding_filter.read() {
                            EncodingFilter::All => "all",
                            EncodingFilter::AsciiOnly => "ascii",
                            EncodingFilter::Utf16Only => "utf16",
                        },
                        onchange: move |e| {
                            match e.value().as_str() {
                                "ascii" => encoding_filter.set(EncodingFilter::AsciiOnly),
                                "utf16" => encoding_filter.set(EncodingFilter::Utf16Only),
                                _ => encoding_filter.set(EncodingFilter::All),
                            }
                        },
                        option { value: "all", "All Encodings" }
                        option { value: "ascii", "ASCII Only" }
                        option { value: "utf16", "UTF-16 Only" }
                    }

                    input {
                        class: "create-process-input",
                        style: "flex: 1; min-width: 150px;",
                        r#type: "text",
                        placeholder: "Filter strings...",
                        value: "{filter_query}",
                        oninput: move |e| filter_query.set(e.value().clone()),
                    }

                    button {
                        class: "btn btn-small btn-primary",
                        onclick: trigger_scan,
                        disabled: *is_scanning.read(),
                        if *is_scanning.read() {
                            "Scanning..."
                        } else {
                            "Scan"
                        }
                    }

                    button {
                        class: "btn btn-small btn-secondary",
                        onclick: export_results,
                        disabled: filtered_results.is_empty(),
                        "Export"
                    }
                }

                // Status message
                if !status_message.read().is_empty() {
                    div {
                        class: "thread-status-message",
                        "{status_message}"
                    }
                }

                // Results table
                div {
                    class: "thread-table-container",
                    table {
                        class: "thread-table",
                        thead {
                            tr {
                                th { style: "padding: 8px 12px; width: 140px;", "Address" }
                                th { style: "padding: 8px 12px; width: 80px;", "Encoding" }
                                th { style: "padding: 8px 12px; width: 60px;", "Length" }
                                th { style: "padding: 8px 12px; width: 80px;", "Region" }
                                th { style: "padding: 8px 12px;", "String" }
                            }
                        }
                        tbody {
                            if filtered_results.is_empty() && !*is_scanning.read() {
                                tr {
                                    td { colspan: 5, style: "text-align: center; padding: 20px;",
                                        if total_count == 0 {
                                            "Click 'Scan' to search for strings in process memory"
                                        } else {
                                            "No results match filter"
                                        }
                                    }
                                }
                            } else {
                                for (idx, result) in filtered_results.iter() {
                                    {
                                        let current_idx = *idx;
                                        let result_clone = result.clone();
                                        let result_for_ctx = result.clone();
                                        let is_selected = selected_index.read().as_ref().map(|s| *s == current_idx).unwrap_or(false);
                                        let row_class = if is_selected { "thread-row selected" } else { "thread-row" };
                                        let encoding_class = match result_clone.encoding {
                                            StringEncoding::Ascii => "encoding-badge encoding-ascii",
                                            StringEncoding::Utf16 => "encoding-badge encoding-utf16",
                                        };
                                        let display_value = escape_display_string(&result_clone.value);

                                        rsx! {
                                            tr {
                                                key: "{current_idx}",
                                                class: "{row_class}",
                                                onclick: move |_| {
                                                    selected_index.set(Some(current_idx));
                                                },
                                                oncontextmenu: move |e| {
                                                    e.prevent_default();
                                                    selected_index.set(Some(current_idx));
                                                    context_menu.set(StringScanContextMenuState {
                                                        visible: true,
                                                        x: e.client_coordinates().x as i32,
                                                        y: e.client_coordinates().y as i32,
                                                        address: result_for_ctx.address,
                                                        value: result_for_ctx.value.clone(),
                                                        encoding: result_for_ctx.encoding,
                                                        length: result_for_ctx.length,
                                                        region_type: result_for_ctx.region_type.clone(),
                                                    });
                                                },

                                                td { class: "mono", style: "padding: 8px 12px;", "0x{result_clone.address:X}" }
                                                td { style: "padding: 8px 12px;",
                                                    span { class: "{encoding_class}", "{result_clone.encoding}" }
                                                }
                                                td { style: "padding: 8px 12px; text-align: center; color: #9ca3af;", "{result_clone.length}" }
                                                td { style: "padding: 8px 12px; color: #fb923c;", "{result_clone.region_type}" }
                                                td { class: "cell-string-value", style: "padding: 8px 12px;", "{display_value}" }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Context menu
                if context_menu.read().visible {
                    div {
                        class: "context-menu",
                        style: "left: {context_menu.read().x}px; top: clamp(5px, {context_menu.read().y}px, calc(100vh - 200px));",
                        onclick: move |e| e.stop_propagation(),

                        button {
                            class: "context-menu-item",
                            onclick: move |_| {
                                let menu = context_menu.read().clone();
                                copy_to_clipboard(&menu.value);
                                context_menu.set(StringScanContextMenuState::default());
                            },
                            span { "Copy String" }
                        }

                        button {
                            class: "context-menu-item",
                            onclick: move |_| {
                                let menu = context_menu.read().clone();
                                copy_to_clipboard(&format!("0x{:X}", menu.address));
                                context_menu.set(StringScanContextMenuState::default());
                            },
                            span { "Copy Address" }
                        }

                        button {
                            class: "context-menu-item",
                            onclick: move |_| {
                                let menu = context_menu.read().clone();
                                let text = format!(
                                    "Address: 0x{:X}\nEncoding: {}\nLength: {}\nRegion: {}\nString: {}",
                                    menu.address,
                                    menu.encoding,
                                    menu.length,
                                    menu.region_type,
                                    menu.value
                                );
                                copy_to_clipboard(&text);
                                context_menu.set(StringScanContextMenuState::default());
                            },
                            span { "Copy Row" }
                        }
                    }
                }
            }
        }

        // Click outside to close context menu
        if context_menu.read().visible {
            div {
                class: "context-menu-overlay",
                onclick: move |_| {
                    context_menu.set(StringScanContextMenuState::default());
                },
            }
        }
    }
}

/// Encoding filter options
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum EncodingFilter {
    All,
    AsciiOnly,
    Utf16Only,
}

/// Context menu state for string scan results
#[derive(Clone, Debug)]
pub struct StringScanContextMenuState {
    pub visible: bool,
    pub x: i32,
    pub y: i32,
    pub address: usize,
    pub value: String,
    pub encoding: StringEncoding,
    pub length: usize,
    pub region_type: String,
}

impl Default for StringScanContextMenuState {
    fn default() -> Self {
        Self {
            visible: false,
            x: 0,
            y: 0,
            address: 0,
            value: String::new(),
            encoding: StringEncoding::Ascii,
            length: 0,
            region_type: String::new(),
        }
    }
}

/// Escape control characters for display
fn escape_display_string(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '\n' => "\\n".to_string(),
            '\r' => "\\r".to_string(),
            '\t' => "\\t".to_string(),
            c if c.is_control() => format!("\\x{:02X}", c as u32),
            c => c.to_string(),
        })
        .collect()
}
