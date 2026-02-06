//! Kernel Utilities Tab - Advanced kernel-mode features

use dioxus::prelude::*;

/// Callback type selector
#[derive(Clone, Copy, PartialEq, Debug)]
enum CallbackType {
    Process,
    Thread,
    Image,
}

/// Kernel Utilities tab component
#[component]
pub fn KernelUtilitiesTab() -> Element {
    let driver_loaded = callback::is_driver_loaded();
    let mut callback_type = use_signal(|| CallbackType::Process);
    let mut callbacks = use_signal(Vec::<callback::CallbackInfo>::new);
    let mut is_enumerating = use_signal(|| false);
    let mut status_message = use_signal(|| String::new());
    let mut status_is_error = use_signal(|| false);

    // Handle enumerate button click
    let handle_enumerate = move |_| {
        let is_running = *is_enumerating.read();
        if is_running {
            return;
        }

        is_enumerating.set(true);
        status_message.set(String::new());
        let cb_type = *callback_type.read();

        spawn(async move {
            let result = tokio::task::spawn_blocking(move || match cb_type {
                CallbackType::Process => callback::enumerate_process_callbacks(),
                CallbackType::Thread => callback::enumerate_thread_callbacks(),
                CallbackType::Image => callback::enumerate_image_callbacks(),
            })
            .await;

            match result {
                Ok(Ok(cb_list)) => {
                    let count = cb_list.len();
                    callbacks.set(cb_list);
                    status_message.set(format!("Found {} active callbacks", count));
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

            is_enumerating.set(false);
        });
    };

    let callback_list = callbacks.read().clone();
    let is_running = *is_enumerating.read();
    let status_msg = status_message.read().clone();
    let is_error = *status_is_error.read();
    let current_type = *callback_type.read();

    rsx! {
        div {
            class: "service-tab",
            tabindex: "0",

            // Header
            div { class: "header-box",
                h1 { class: "header-title", "Kernel Utilities" }
                div { class: "header-stats",
                    span { "Advanced kernel-mode features and callback enumeration" }
                }
            }

            div {
                style: "padding: 16px; display: flex; flex-direction: column; gap: 16px; flex: 1; overflow-y: auto;",

                // Driver warning banner
                if !driver_loaded {
                    div {
                        class: "create-process-status create-process-status-error",
                        style: "margin-bottom: 0;",
                        "⚠️ Driver not loaded — Kernel callback enumeration requires the DioProcess kernel driver to be loaded."
                    }
                }

                // Kernel Callback Enumeration section
                div {
                    style: "background: rgba(0, 0, 0, 0.3); border: 1px solid rgba(0, 212, 255, 0.15); border-radius: 8px; padding: 20px;",

                    h2 {
                        style: "color: #00d4ff; margin-bottom: 4px; font-size: 16px;",
                        "Kernel Callback Enumeration"
                    }
                    p {
                        style: "color: #9ca3af; font-size: 12px; margin-bottom: 16px;",
                        "Enumerate registered kernel callbacks. Windows allows drivers to register notification callbacks for process creation/exit, thread creation/exit, and image (DLL/EXE) loading. This tool locates the internal kernel callback arrays and resolves callback addresses to their owning driver modules."
                    }

                    // Callback type selector
                    div { class: "create-process-field",
                        label { class: "create-process-label", "Callback Type" }
                        div {
                            style: "display: flex; gap: 12px;",

                            button {
                                class: if current_type == CallbackType::Process { "btn btn-secondary active" } else { "btn btn-secondary" },
                                onclick: move |_| {
                                    callback_type.set(CallbackType::Process);
                                    callbacks.set(Vec::new());
                                    status_message.set(String::new());
                                },
                                "Process Callbacks"
                            }
                            button {
                                class: if current_type == CallbackType::Thread { "btn btn-secondary active" } else { "btn btn-secondary" },
                                onclick: move |_| {
                                    callback_type.set(CallbackType::Thread);
                                    callbacks.set(Vec::new());
                                    status_message.set(String::new());
                                },
                                "Thread Callbacks"
                            }
                            button {
                                class: if current_type == CallbackType::Image { "btn btn-secondary active" } else { "btn btn-secondary" },
                                onclick: move |_| {
                                    callback_type.set(CallbackType::Image);
                                    callbacks.set(Vec::new());
                                    status_message.set(String::new());
                                },
                                "Image Load Callbacks"
                            }
                        }
                    }

                    // Enumerate button
                    div {
                        style: "display: flex; gap: 16px; align-items: flex-end; margin-top: 8px;",
                        button {
                            class: "btn btn-primary",
                            disabled: !driver_loaded || is_running,
                            onclick: handle_enumerate,
                            if is_running {
                                "Enumerating..."
                            } else {
                                "Enumerate Callbacks"
                            }
                        }
                    }

                    // Status message
                    if !status_msg.is_empty() {
                        div {
                            class: if is_error { "create-process-status create-process-status-error" } else { "create-process-status create-process-status-success" },
                            style: "margin-top: 16px;",
                            "{status_msg}"
                        }
                    }

                    // Results table
                    if !callback_list.is_empty() {
                        div {
                            style: "margin-top: 20px;",

                            // Table header
                            div {
                                style: "display: grid; grid-template-columns: 80px 180px 1fr; gap: 12px; padding: 12px 16px; background: rgba(34, 211, 238, 0.1); border: 1px solid rgba(34, 211, 238, 0.2); border-radius: 8px 8px 0 0; font-weight: 600; font-size: 13px; color: #22d3ee;",
                                div { "Index" }
                                div { "Callback Address" }
                                div { "Driver Module" }
                            }

                            // Table rows
                            for cb in callback_list.iter() {
                                div {
                                    key: "{cb.index}",
                                    style: "display: grid; grid-template-columns: 80px 180px 1fr; gap: 12px; padding: 12px 16px; background: rgba(0, 0, 0, 0.2); border: 1px solid rgba(0, 212, 255, 0.1); border-top: none; font-size: 13px; color: #d1d5db; transition: background 0.15s;",
                                    onmouseenter: move |_| {},
                                    onmouseleave: move |_| {},

                                    div { style: "color: #9ca3af;", "{cb.index}" }
                                    div { style: "font-family: 'Courier New', monospace; color: #22d3ee;", "0x{cb.callback_address:016X}" }
                                    div { style: "color: #e2e8f0;", "{cb.module_name}" }
                                }
                            }

                            // Last row border fix
                            div {
                                style: "height: 1px; background: rgba(34, 211, 238, 0.2);",
                            }
                        }
                    }

                    // Empty state
                    if callback_list.is_empty() && !is_running && !status_msg.is_empty() && !is_error {
                        div {
                            style: "text-align: center; padding: 40px; color: #6b7280; margin-top: 20px; background: rgba(0, 0, 0, 0.2); border: 1px solid rgba(0, 212, 255, 0.1); border-radius: 8px;",
                            "No active callbacks found for this type"
                        }
                    }
                }
            }
        }
    }
}
