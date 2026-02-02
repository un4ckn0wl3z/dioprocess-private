//! Token Thief Window component

use dioxus::prelude::*;
use misc::steal_token;

use crate::state::TOKEN_THIEF_WINDOW_STATE;

/// Token Thief Window modal component
#[component]
pub fn TokenThiefWindow(pid: u32, process_name: String) -> Element {
    let mut exe_path = use_signal(|| String::new());
    let mut args = use_signal(|| String::new());
    let mut status_message = use_signal(|| String::new());
    let mut status_is_error = use_signal(|| false);
    let mut is_running = use_signal(|| false);

    let close_window = move |_| {
        *TOKEN_THIEF_WINDOW_STATE.write() = None;
    };

    let target_pid = pid;

    let handle_steal = move |_| {
        if *is_running.read() {
            return;
        }

        let current_exe = exe_path.read().clone();
        let current_args = args.read().clone();

        if current_exe.is_empty() {
            status_message.set("Please select an executable".to_string());
            status_is_error.set(true);
            return;
        }

        is_running.set(true);
        status_message.set(String::new());

        spawn(async move {
            let result = steal_token(target_pid, &current_exe, &current_args);

            match result {
                Ok((new_pid, new_tid)) => {
                    status_message.set(format!(
                        "Process created with stolen token: PID {} TID {}",
                        new_pid, new_tid
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

    let browse_exe = move |_| {
        spawn(async move {
            let file = rfd::AsyncFileDialog::new()
                .add_filter("Executable", &["exe"])
                .set_title("Select Executable to Launch")
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
                    span { class: "create-process-modal-title",
                        "Steal Token - {process_name} (PID {pid})"
                    }
                    button {
                        class: "create-process-modal-close",
                        onclick: close_window,
                        "X"
                    }
                }

                // Body
                div { class: "create-process-form",
                    // Info
                    div { class: "create-process-field",
                        label { class: "create-process-label", "Source Process" }
                        input {
                            class: "create-process-input",
                            r#type: "text",
                            readonly: true,
                            value: "{process_name} (PID {pid})",
                        }
                    }

                    // Executable path
                    div { class: "create-process-field",
                        label { class: "create-process-label", "Executable to Launch" }
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
                        onclick: handle_steal,
                        if running {
                            "Stealing..."
                        } else {
                            "Steal & Run"
                        }
                    }
                }
            }
        }
    }
}
