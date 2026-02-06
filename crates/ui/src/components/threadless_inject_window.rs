//! Threadless Inject Window component

use dioxus::prelude::*;
use misc::inject_shellcode_threadless;

use crate::state::THREADLESS_INJECT_WINDOW_STATE;

/// Threadless Inject Window modal component
#[component]
pub fn ThreadlessInjectWindow(pid: u32, process_name: String) -> Element {
    let mut shellcode_path = use_signal(|| String::new());
    let mut target_dll = use_signal(|| "USER32".to_string());
    let mut target_func = use_signal(|| "MessageBoxW".to_string());
    let mut status_message = use_signal(|| String::new());
    let mut status_is_error = use_signal(|| false);
    let mut is_running = use_signal(|| false);

    let close_window = move |_| {
        *THREADLESS_INJECT_WINDOW_STATE.write() = None;
    };

    let target_pid = pid;

    let handle_inject = move |_| {
        if *is_running.read() {
            return;
        }

        let sc_path = shellcode_path.read().clone();
        let dll = target_dll.read().clone();
        let func = target_func.read().clone();

        if sc_path.is_empty() {
            status_message.set("Please select a shellcode file".to_string());
            status_is_error.set(true);
            return;
        }

        if dll.is_empty() || func.is_empty() {
            status_message.set("Target DLL and function name are required".to_string());
            status_is_error.set(true);
            return;
        }

        is_running.set(true);
        status_message.set(String::new());

        spawn(async move {
            let result = inject_shellcode_threadless(target_pid, &sc_path, &dll, &func);

            match result {
                Ok(()) => {
                    status_message.set(format!(
                        "Threadless injection installed on {}!{} in PID {} — payload fires when function is called",
                        dll, func, target_pid
                    ));
                    status_is_error.set(false);
                }
                Err(e) => {
                    status_message.set(format!("Error: {}", e));
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

    let browse_shellcode = move |_| {
        spawn(async move {
            let file = rfd::AsyncFileDialog::new()
                .add_filter("Shellcode Binary", &["bin"])
                .add_filter("All Files", &["*"])
                .set_title("Select Shellcode (.bin)")
                .pick_file()
                .await;

            if let Some(file) = file {
                shellcode_path.set(file.path().to_string_lossy().to_string());
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
                        "Threadless Injection - {process_name} (PID {pid})"
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
                            value: "Hook an exported function — payload fires when the target process calls it (no new threads)",
                        }
                    }

                    // Shellcode file
                    div { class: "create-process-field",
                        label { class: "create-process-label", "Shellcode File" }
                        div { class: "create-process-path-row",
                            input {
                                class: "create-process-input",
                                r#type: "text",
                                placeholder: "Path to shellcode .bin...",
                                value: "{shellcode_path}",
                                oninput: move |e| shellcode_path.set(e.value().clone()),
                            }
                            button {
                                class: "create-process-btn-browse",
                                onclick: browse_shellcode,
                                "Browse"
                            }
                        }
                    }

                    // Target DLL
                    div { class: "create-process-field",
                        label { class: "create-process-label", "Target DLL" }
                        input {
                            class: "create-process-input",
                            r#type: "text",
                            placeholder: "e.g. USER32",
                            value: "{target_dll}",
                            oninput: move |e| target_dll.set(e.value().clone()),
                        }
                    }

                    // Target Function
                    div { class: "create-process-field",
                        label { class: "create-process-label", "Target Function" }
                        input {
                            class: "create-process-input",
                            r#type: "text",
                            placeholder: "e.g. MessageBoxW",
                            value: "{target_func}",
                            oninput: move |e| target_func.set(e.value().clone()),
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
                            "Installing Hook..."
                        } else {
                            "Inject"
                        }
                    }
                }
            }
        }
    }
}
