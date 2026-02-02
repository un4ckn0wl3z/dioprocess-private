//! Ghost Process Window component

use dioxus::prelude::*;
use misc::ghost_process;

use crate::state::GHOST_PROCESS_WINDOW_STATE;

/// Ghost Process Window modal component
#[component]
pub fn GhostProcessWindow() -> Element {
    let mut exe_path = use_signal(|| String::new());
    let mut status_message = use_signal(|| String::new());
    let mut status_is_error = use_signal(|| false);
    let mut is_running = use_signal(|| false);

    let close_window = move |_| {
        *GHOST_PROCESS_WINDOW_STATE.write() = false;
    };

    let handle_ghost = move |_| {
        if *is_running.read() {
            return;
        }

        let current_exe = exe_path.read().clone();

        if current_exe.is_empty() {
            status_message.set("Please select a payload executable".to_string());
            status_is_error.set(true);
            return;
        }

        is_running.set(true);
        status_message.set(String::new());

        spawn(async move {
            let result = ghost_process(&current_exe);

            match result {
                Ok(pid) => {
                    status_message.set(format!("Ghost process created: PID {}", pid));
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

    let browse_exe = move |_| {
        spawn(async move {
            let file = rfd::AsyncFileDialog::new()
                .add_filter("Executable", &["exe"])
                .set_title("Select Payload Executable")
                .pick_file()
                .await;

            if let Some(file) = file {
                exe_path.set(file.path().to_string_lossy().to_string());
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
                    span { class: "create-process-modal-title", "Process Ghost" }
                    button {
                        class: "create-process-modal-close",
                        onclick: close_window,
                        "X"
                    }
                }

                // Body
                div { class: "create-process-form",
                    // Info text
                    div { class: "create-process-field",
                        label { class: "create-process-label", "Description" }
                        input {
                            class: "create-process-input",
                            r#type: "text",
                            readonly: true,
                            value: "Creates a process whose backing file is deleted from disk",
                        }
                    }

                    // Executable path
                    div { class: "create-process-field",
                        label { class: "create-process-label", "Payload Executable" }
                        div { class: "create-process-path-row",
                            input {
                                class: "create-process-input",
                                r#type: "text",
                                placeholder: "Path to 64-bit executable...",
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
                        onclick: handle_ghost,
                        if running {
                            "Ghosting..."
                        } else {
                            "Ghost"
                        }
                    }
                }
            }
        }
    }
}
