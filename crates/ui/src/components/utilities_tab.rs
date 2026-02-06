//! Utilities tab component

use dioxus::prelude::*;
use misc::ghostly_hollow_process;

/// Bloating method
#[derive(Clone, Copy, PartialEq, Debug)]
enum BloatMethod {
    NullBytes,
    RandomData,
}

/// Utilities Tab component
#[component]
pub fn UtilitiesTab() -> Element {
    // ---- File Bloating state ----
    let mut source_path = use_signal(|| String::new());
    let mut output_path = use_signal(|| String::new());
    let mut bloat_method = use_signal(|| BloatMethod::NullBytes);
    let mut size_mb = use_signal(|| "200".to_string());
    let mut status_message = use_signal(|| String::new());
    let mut status_is_error = use_signal(|| false);
    let mut is_running = use_signal(|| false);

    // ---- Ghostly Hollowing state ----
    let mut gh_host_path = use_signal(|| String::new());
    let mut gh_payload_path = use_signal(|| String::new());
    let mut gh_status_message = use_signal(|| String::new());
    let mut gh_status_is_error = use_signal(|| false);
    let mut gh_is_running = use_signal(|| false);

    // ---- File Bloating handlers ----

    let browse_source = move |_| {
        spawn(async move {
            let file = rfd::AsyncFileDialog::new()
                .add_filter("All Files", &["*"])
                .set_title("Select Source File")
                .pick_file()
                .await;

            if let Some(file) = file {
                source_path.set(file.path().to_string_lossy().to_string());
            }
        });
    };

    let browse_output = move |_| {
        spawn(async move {
            let file = rfd::AsyncFileDialog::new()
                .add_filter("All Files", &["*"])
                .set_title("Save Bloated File As")
                .save_file()
                .await;

            if let Some(file) = file {
                output_path.set(file.path().to_string_lossy().to_string());
            }
        });
    };

    let handle_bloat = move |_| {
        if *is_running.read() {
            return;
        }

        let src = source_path.read().clone();
        let dst = output_path.read().clone();
        let method = *bloat_method.read();
        let size_str = size_mb.read().clone();

        if src.is_empty() {
            status_message.set("Please select a source file".to_string());
            status_is_error.set(true);
            return;
        }

        if dst.is_empty() {
            status_message.set("Please select an output path".to_string());
            status_is_error.set(true);
            return;
        }

        let size: u64 = match size_str.parse() {
            Ok(v) if (1..=2000).contains(&v) => v,
            _ => {
                status_message.set("Size must be between 1 and 2000 MB".to_string());
                status_is_error.set(true);
                return;
            }
        };

        is_running.set(true);
        status_message.set(String::new());

        spawn(async move {
            let result = tokio::task::spawn_blocking(move || {
                // Copy source to output
                std::fs::copy(&src, &dst)?;

                // Open in append mode and write bloat data
                use std::io::Write;
                let mut file = std::fs::OpenOptions::new().append(true).open(&dst)?;

                let chunk_size: usize = 1024 * 1024; // 1 MB
                let total_bytes = size * 1024 * 1024;
                let fill_byte: u8 = match method {
                    BloatMethod::NullBytes => 0x00,
                    BloatMethod::RandomData => 0xFF,
                };
                let chunk = vec![fill_byte; chunk_size];

                let mut written: u64 = 0;
                while written < total_bytes {
                    let to_write = std::cmp::min(chunk_size as u64, total_bytes - written) as usize;
                    file.write_all(&chunk[..to_write])?;
                    written += to_write as u64;
                }

                file.flush()?;
                Ok::<_, std::io::Error>(())
            })
            .await;

            match result {
                Ok(Ok(())) => {
                    let method_name = match method {
                        BloatMethod::NullBytes => "null bytes",
                        BloatMethod::RandomData => "random data (0xFF)",
                    };
                    status_message.set(format!(
                        "File bloated successfully with {} MB of {}",
                        size, method_name
                    ));
                    status_is_error.set(false);
                }
                Ok(Err(e)) => {
                    status_message.set(format!("Error: {}", e));
                    status_is_error.set(true);
                }
                Err(e) => {
                    status_message.set(format!("Task error: {}", e));
                    status_is_error.set(true);
                }
            }

            is_running.set(false);

            if !*status_is_error.read() {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                status_message.set(String::new());
            }
        });
    };

    // ---- Ghostly Hollowing handlers ----

    let browse_gh_host = move |_| {
        spawn(async move {
            let file = rfd::AsyncFileDialog::new()
                .add_filter("Executables", &["exe"])
                .add_filter("All Files", &["*"])
                .set_title("Select Legitimate Host Executable")
                .pick_file()
                .await;

            if let Some(file) = file {
                gh_host_path.set(file.path().to_string_lossy().to_string());
            }
        });
    };

    let browse_gh_payload = move |_| {
        spawn(async move {
            let file = rfd::AsyncFileDialog::new()
                .add_filter("Executables", &["exe"])
                .add_filter("All Files", &["*"])
                .set_title("Select PE Payload (64-bit)")
                .pick_file()
                .await;

            if let Some(file) = file {
                gh_payload_path.set(file.path().to_string_lossy().to_string());
            }
        });
    };

    let handle_ghostly_hollow = move |_| {
        if *gh_is_running.read() {
            return;
        }

        let host = gh_host_path.read().clone();
        let payload = gh_payload_path.read().clone();

        if host.is_empty() {
            gh_status_message.set("Please select a host executable".to_string());
            gh_status_is_error.set(true);
            return;
        }

        if payload.is_empty() {
            gh_status_message.set("Please select a PE payload".to_string());
            gh_status_is_error.set(true);
            return;
        }

        gh_is_running.set(true);
        gh_status_message.set(String::new());

        spawn(async move {
            let result =
                tokio::task::spawn_blocking(move || ghostly_hollow_process(&host, &payload)).await;

            match result {
                Ok(Ok(pid)) => {
                    gh_status_message.set(format!(
                        "Ghostly hollowing successful — PID: {}",
                        pid
                    ));
                    gh_status_is_error.set(false);
                }
                Ok(Err(e)) => {
                    gh_status_message.set(format!("Error: {}", e));
                    gh_status_is_error.set(true);
                }
                Err(e) => {
                    gh_status_message.set(format!("Task error: {}", e));
                    gh_status_is_error.set(true);
                }
            }

            gh_is_running.set(false);

            if !*gh_status_is_error.read() {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                gh_status_message.set(String::new());
            }
        });
    };

    let status_msg = status_message.read().clone();
    let is_error = *status_is_error.read();
    let running = *is_running.read();

    let gh_status_msg = gh_status_message.read().clone();
    let gh_is_error = *gh_status_is_error.read();
    let gh_running = *gh_is_running.read();

    rsx! {
        div {
            class: "service-tab",
            tabindex: "0",

            // Header
            div { class: "header-box",
                h1 { class: "header-title", "Utilities" }
                div { class: "header-stats",
                    span { "Tools and utilities for security research" }
                }
            }

            div {
                style: "padding: 16px; display: flex; flex-direction: column; gap: 16px; flex: 1; overflow-y: auto;",

                // File Bloating section
                div {
                    style: "background: rgba(0, 0, 0, 0.3); border: 1px solid rgba(0, 212, 255, 0.15); border-radius: 8px; padding: 20px;",

                    h2 {
                        style: "color: #00d4ff; margin-bottom: 4px; font-size: 16px;",
                        "File Bloating"
                    }
                    p {
                        style: "color: #9ca3af; font-size: 12px; margin-bottom: 16px;",
                        "Inflate file size by appending data. Used to test security scanner file size limits."
                    }

                    // Source file
                    div { class: "create-process-field",
                        label { class: "create-process-label", "Source File" }
                        div { class: "create-process-path-row",
                            input {
                                class: "create-process-input",
                                r#type: "text",
                                placeholder: "Path to source file...",
                                value: "{source_path}",
                                oninput: move |e| source_path.set(e.value().clone()),
                            }
                            button {
                                class: "create-process-btn-browse",
                                onclick: browse_source,
                                "Browse"
                            }
                        }
                    }

                    // Output file
                    div { class: "create-process-field",
                        label { class: "create-process-label", "Output File" }
                        div { class: "create-process-path-row",
                            input {
                                class: "create-process-input",
                                r#type: "text",
                                placeholder: "Path for bloated output file...",
                                value: "{output_path}",
                                oninput: move |e| output_path.set(e.value().clone()),
                            }
                            button {
                                class: "create-process-btn-browse",
                                onclick: browse_output,
                                "Browse"
                            }
                        }
                    }

                    // Method + Size row
                    div {
                        style: "display: flex; gap: 16px; align-items: flex-end;",

                        div { class: "create-process-field",
                            label { class: "create-process-label", "Method" }
                            select {
                                class: "filter-select",
                                value: if *bloat_method.read() == BloatMethod::NullBytes { "null" } else { "random" },
                                onchange: move |e| {
                                    bloat_method.set(if e.value() == "null" {
                                        BloatMethod::NullBytes
                                    } else {
                                        BloatMethod::RandomData
                                    });
                                },
                                option { value: "null", "Append Null Bytes (0x00)" }
                                option { value: "random", "Large Metadata / Random Data (0xFF)" }
                            }
                        }

                        div { class: "create-process-field",
                            label { class: "create-process-label", "Size (MB)" }
                            input {
                                class: "create-process-input",
                                r#type: "number",
                                min: "1",
                                max: "2000",
                                value: "{size_mb}",
                                oninput: move |e| size_mb.set(e.value().clone()),
                                style: "width: 100px;",
                            }
                        }

                        button {
                            class: "btn btn-primary",
                            disabled: running,
                            onclick: handle_bloat,
                            if running {
                                "Bloating..."
                            } else {
                                "Bloat File"
                            }
                        }
                    }

                    // Status message
                    if !status_msg.is_empty() {
                        div {
                            class: if is_error { "create-process-status create-process-status-error" } else { "create-process-status create-process-status-success" },
                            "{status_msg}"
                        }
                    }
                }

                // Ghostly Hollowing section
                div {
                    style: "background: rgba(0, 0, 0, 0.3); border: 1px solid rgba(0, 212, 255, 0.15); border-radius: 8px; padding: 20px;",

                    h2 {
                        style: "color: #00d4ff; margin-bottom: 4px; font-size: 16px;",
                        "Ghostly Hollowing"
                    }
                    p {
                        style: "color: #9ca3af; font-size: 12px; margin-bottom: 16px;",
                        "Create a ghost section from payload PE (file deleted, section survives), then map it into a suspended legitimate process and hijack execution. Combines process ghosting + hollowing."
                    }

                    // Host executable
                    div { class: "create-process-field",
                        label { class: "create-process-label", "Host Executable (Legitimate)" }
                        div { class: "create-process-path-row",
                            input {
                                class: "create-process-input",
                                r#type: "text",
                                placeholder: "e.g. C:\\Windows\\system32\\RuntimeBroker.exe",
                                value: "{gh_host_path}",
                                oninput: move |e| gh_host_path.set(e.value().clone()),
                            }
                            button {
                                class: "create-process-btn-browse",
                                onclick: browse_gh_host,
                                "Browse"
                            }
                        }
                    }

                    // PE Payload
                    div { class: "create-process-field",
                        label { class: "create-process-label", "PE Payload (64-bit)" }
                        div { class: "create-process-path-row",
                            input {
                                class: "create-process-input",
                                r#type: "text",
                                placeholder: "Path to 64-bit PE payload...",
                                value: "{gh_payload_path}",
                                oninput: move |e| gh_payload_path.set(e.value().clone()),
                            }
                            button {
                                class: "create-process-btn-browse",
                                onclick: browse_gh_payload,
                                "Browse"
                            }
                        }
                    }

                    // Execute button
                    div {
                        style: "display: flex; gap: 16px; align-items: flex-end;",

                        button {
                            class: "btn btn-primary",
                            disabled: gh_running,
                            onclick: handle_ghostly_hollow,
                            if gh_running {
                                "Executing..."
                            } else {
                                "Execute Ghostly Hollowing"
                            }
                        }
                    }

                    // Status message
                    if !gh_status_msg.is_empty() {
                        div {
                            class: if gh_is_error { "create-process-status create-process-status-error" } else { "create-process-status create-process-status-success" },
                            "{gh_status_msg}"
                        }
                    }
                }
            }
        }
    }
}
