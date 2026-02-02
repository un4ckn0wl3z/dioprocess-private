//! Create Process Window component

use dioxus::prelude::*;
use misc::{create_process, hollow_process};

use crate::state::CREATE_PROCESS_WINDOW_STATE;

/// Create Process Window modal component
#[component]
pub fn CreateProcessWindow() -> Element {
    let mut technique = use_signal(|| "normal".to_string());
    let mut exe_path = use_signal(|| String::new());
    let mut payload_path = use_signal(|| String::new());
    let mut args = use_signal(|| String::new());
    let mut suspended = use_signal(|| false);
    let mut status_message = use_signal(|| String::new());
    let mut status_is_error = use_signal(|| false);
    let mut is_running = use_signal(|| false);

    let close_window = move |_| {
        *CREATE_PROCESS_WINDOW_STATE.write() = false;
    };

    let handle_create = move |_| {
        if *is_running.read() {
            return;
        }

        let current_technique = technique.read().clone();
        let current_exe = exe_path.read().clone();
        let current_payload = payload_path.read().clone();
        let current_args = args.read().clone();
        let current_suspended = *suspended.read();

        // Validate inputs
        if current_exe.is_empty() {
            status_message.set("Please select an executable".to_string());
            status_is_error.set(true);
            return;
        }

        if current_technique == "hollowing" && current_payload.is_empty() {
            status_message.set("Please select a payload PE for hollowing".to_string());
            status_is_error.set(true);
            return;
        }

        is_running.set(true);
        status_message.set(String::new());

        spawn(async move {
            let result = if current_technique == "normal" {
                create_process(&current_exe, &current_args, current_suspended)
                    .map(|(pid, tid)| {
                        if current_suspended {
                            format!("Process created (suspended): PID {} TID {}", pid, tid)
                        } else {
                            format!("Process created: PID {} TID {}", pid, tid)
                        }
                    })
            } else {
                hollow_process(&current_exe, &current_payload)
                    .map(|pid| format!("Process hollowed successfully: PID {}", pid))
            };

            match result {
                Ok(msg) => {
                    status_message.set(msg);
                    status_is_error.set(false);
                }
                Err(e) => {
                    status_message.set(format!("Error: {}", e));
                    status_is_error.set(true);
                }
            }

            is_running.set(false);

            // Auto-dismiss success messages after 5 seconds
            if !*status_is_error.read() {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                status_message.set(String::new());
            }
        });
    };

    let browse_exe = move |_| {
        spawn(async move {
            let file = rfd::AsyncFileDialog::new()
                .add_filter("Executable", &["exe"])
                .set_title("Select Executable")
                .pick_file()
                .await;

            if let Some(file) = file {
                exe_path.set(file.path().to_string_lossy().to_string());
            }
        });
    };

    let browse_payload = move |_| {
        spawn(async move {
            let file = rfd::AsyncFileDialog::new()
                .add_filter("Executable", &["exe"])
                .set_title("Select Payload PE")
                .pick_file()
                .await;

            if let Some(file) = file {
                payload_path.set(file.path().to_string_lossy().to_string());
            }
        });
    };

    let current_technique = technique.read().clone();
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
                    span { class: "create-process-modal-title", "Create Process" }
                    button {
                        class: "create-process-modal-close",
                        onclick: close_window,
                        "X"
                    }
                }

                // Body
                div { class: "create-process-form",
                    // Technique selector
                    div { class: "create-process-field",
                        label { class: "create-process-label", "Technique" }
                        div { class: "create-process-radio-group",
                            label { class: "create-process-radio-label",
                                input {
                                    r#type: "radio",
                                    name: "technique",
                                    value: "normal",
                                    checked: current_technique == "normal",
                                    onchange: move |_| technique.set("normal".to_string()),
                                }
                                span { "Normal (CreateProcess)" }
                            }
                            label { class: "create-process-radio-label",
                                input {
                                    r#type: "radio",
                                    name: "technique",
                                    value: "hollowing",
                                    checked: current_technique == "hollowing",
                                    onchange: move |_| technique.set("hollowing".to_string()),
                                }
                                span { "Process Hollowing" }
                            }
                        }
                    }

                    // Executable path
                    div { class: "create-process-field",
                        label { class: "create-process-label",
                            if current_technique == "hollowing" {
                                "Host Executable"
                            } else {
                                "Executable Path"
                            }
                        }
                        div { class: "create-process-path-row",
                            input {
                                class: "create-process-input",
                                r#type: "text",
                                placeholder: "Path to executable...",
                                value: "{exe_path}",
                                oninput: move |e| exe_path.set(e.value().clone()),
                            }
                            button {
                                class: "create-process-btn-browse",
                                onclick: browse_exe,
                                "Browse"
                            }
                        }
                    }

                    // Payload path (only for hollowing)
                    if current_technique == "hollowing" {
                        div { class: "create-process-field",
                            label { class: "create-process-label", "Payload PE" }
                            div { class: "create-process-path-row",
                                input {
                                    class: "create-process-input",
                                    r#type: "text",
                                    placeholder: "Path to payload executable...",
                                    value: "{payload_path}",
                                    oninput: move |e| payload_path.set(e.value().clone()),
                                }
                                button {
                                    class: "create-process-btn-browse",
                                    onclick: browse_payload,
                                    "Browse"
                                }
                            }
                        }
                    }

                    // Arguments
                    div { class: "create-process-field",
                        label { class: "create-process-label", "Arguments" }
                        input {
                            class: "create-process-input",
                            r#type: "text",
                            placeholder: "Command line arguments (optional)...",
                            value: "{args}",
                            oninput: move |e| args.set(e.value().clone()),
                        }
                    }

                    // Suspended checkbox (only for normal mode)
                    if current_technique == "normal" {
                        div { class: "create-process-field",
                            label { class: "create-process-checkbox-label",
                                input {
                                    r#type: "checkbox",
                                    class: "checkbox",
                                    checked: *suspended.read(),
                                    onchange: move |e| suspended.set(e.checked()),
                                }
                                span { "Create suspended" }
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
                        onclick: handle_create,
                        if running {
                            "Creating..."
                        } else {
                            "Create"
                        }
                    }
                }
            }
        }
    }
}
