//! Function Stomping Window component

use dioxus::prelude::*;
use misc::inject_dll_function_stomping;

use crate::state::FUNCTION_STOMPING_WINDOW_STATE;

/// Function Stomping Window modal component
#[component]
pub fn FunctionStompingWindow(pid: u32, process_name: String) -> Element {
    let mut dll_path = use_signal(|| String::new());
    let mut sacrificial_dll = use_signal(|| "setupapi.dll".to_string());
    let mut sacrificial_func = use_signal(|| "SetupScanFileQueueA".to_string());
    let mut status_message = use_signal(|| String::new());
    let mut status_is_error = use_signal(|| false);
    let mut is_running = use_signal(|| false);

    let close_window = move |_| {
        *FUNCTION_STOMPING_WINDOW_STATE.write() = None;
    };

    let target_pid = pid;

    let handle_inject = move |_| {
        if *is_running.read() {
            return;
        }

        let current_dll = dll_path.read().clone();
        let current_sac_dll = sacrificial_dll.read().clone();
        let current_sac_func = sacrificial_func.read().clone();

        if current_dll.is_empty() {
            status_message.set("Please select a DLL to inject".to_string());
            status_is_error.set(true);
            return;
        }

        if current_sac_dll.is_empty() || current_sac_func.is_empty() {
            status_message.set("Sacrificial DLL and function name are required".to_string());
            status_is_error.set(true);
            return;
        }

        is_running.set(true);
        status_message.set(String::new());

        spawn(async move {
            let result = inject_dll_function_stomping(
                target_pid,
                &current_dll,
                &current_sac_dll,
                &current_sac_func,
            );

            match result {
                Ok(()) => {
                    status_message.set(format!(
                        "DLL injected into process {} (Function Stomping via {}!{})",
                        target_pid, current_sac_dll, current_sac_func
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

    let browse_dll = move |_| {
        spawn(async move {
            let file = rfd::AsyncFileDialog::new()
                .add_filter("DLL Files", &["dll"])
                .set_title("Select DLL to inject (Function Stomping)")
                .pick_file()
                .await;

            if let Some(file) = file {
                dll_path.set(file.path().to_string_lossy().to_string());
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
                        "Function Stomping - {process_name} (PID {pid})"
                    }
                    button {
                        class: "create-process-modal-close",
                        onclick: close_window,
                        "X"
                    }
                }

                // Body
                div { class: "create-process-form",
                    // DLL to inject
                    div { class: "create-process-field",
                        label { class: "create-process-label", "DLL to Inject" }
                        div { class: "create-process-path-row",
                            input {
                                class: "create-process-input",
                                r#type: "text",
                                placeholder: "Path to DLL...",
                                value: "{dll_path}",
                                oninput: move |e| dll_path.set(e.value().clone()),
                            }
                            button {
                                class: "create-process-btn-browse",
                                onclick: browse_dll,
                                "Browse"
                            }
                        }
                    }

                    // Sacrificial DLL
                    div { class: "create-process-field",
                        label { class: "create-process-label", "Sacrificial DLL" }
                        input {
                            class: "create-process-input",
                            r#type: "text",
                            placeholder: "e.g. setupapi.dll",
                            value: "{sacrificial_dll}",
                            oninput: move |e| sacrificial_dll.set(e.value().clone()),
                        }
                    }

                    // Sacrificial Function
                    div { class: "create-process-field",
                        label { class: "create-process-label", "Sacrificial Function" }
                        input {
                            class: "create-process-input",
                            r#type: "text",
                            placeholder: "e.g. SetupScanFileQueueA",
                            value: "{sacrificial_func}",
                            oninput: move |e| sacrificial_func.set(e.value().clone()),
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
                            "Injecting..."
                        } else {
                            "Inject"
                        }
                    }
                }
            }
        }
    }
}
