//! Early Injection Window component

use callback::{
    arm_early_injection, disarm_early_injection, get_early_injection_status, is_driver_loaded,
    EarlyInjectionMethod,
};
use dioxus::prelude::*;

use crate::state::EARLY_INJECTION_WINDOW_STATE;

/// Early Injection Window modal component
#[component]
pub fn EarlyInjectionWindow() -> Element {
    let mut target_process = use_signal(|| String::new());
    let mut dll_path = use_signal(|| String::new());
    let mut method = use_signal(|| EarlyInjectionMethod::Trampoline);
    let mut one_shot = use_signal(|| true);
    let mut status_message = use_signal(|| String::new());
    let mut status_is_error = use_signal(|| false);
    let mut is_running = use_signal(|| false);

    // Status from driver
    let mut armed = use_signal(|| false);
    let mut injection_count = use_signal(|| 0u32);
    let mut last_injected_pid = use_signal(|| 0u32);
    let mut last_status = use_signal(|| 0i32);
    let mut driver_available = use_signal(|| false);

    // Check driver status and fetch early injection status on mount
    use_effect(move || {
        spawn(async move {
            let available = is_driver_loaded();
            driver_available.set(available);

            if available {
                match get_early_injection_status() {
                    Ok(status) => {
                        armed.set(status.armed);
                        if status.armed {
                            target_process.set(status.target_process_name);
                            dll_path.set(status.dll_path);
                            method.set(status.method);
                            one_shot.set(status.one_shot);
                        }
                        injection_count.set(status.injection_count);
                        last_injected_pid.set(status.last_injected_pid);
                        last_status.set(status.last_status);
                    }
                    Err(_) => {}
                }
            }
        });
    });

    // Auto-refresh status every 2 seconds when armed
    use_effect(move || {
        if *armed.read() && *driver_available.read() {
            spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    if !*armed.read() || !*driver_available.read() {
                        break;
                    }
                    if let Ok(status) = get_early_injection_status() {
                        // Check if driver disarmed (one-shot triggered) BEFORE updating local state
                        let was_armed = *armed.read();
                        if was_armed && !status.armed {
                            status_message.set("Injection complete - disarmed".to_string());
                            status_is_error.set(false);
                        }
                        // Update local state
                        armed.set(status.armed);
                        injection_count.set(status.injection_count);
                        last_injected_pid.set(status.last_injected_pid);
                        last_status.set(status.last_status);
                    }
                }
            });
        }
    });

    let close_window = move |_| {
        *EARLY_INJECTION_WINDOW_STATE.write() = false;
    };

    let handle_arm = move |_| {
        if *is_running.read() {
            return;
        }

        let current_target = target_process.read().clone();
        let current_dll = dll_path.read().clone();
        let current_method = *method.read();
        let current_one_shot = *one_shot.read();

        if current_target.is_empty() {
            status_message.set("Please enter a target process name".to_string());
            status_is_error.set(true);
            return;
        }

        if current_dll.is_empty() {
            status_message.set("Please select a DLL to inject".to_string());
            status_is_error.set(true);
            return;
        }

        is_running.set(true);
        status_message.set(String::new());

        spawn(async move {
            let result =
                arm_early_injection(&current_target, &current_dll, current_method, current_one_shot);

            match result {
                Ok(()) => {
                    armed.set(true);
                    status_message.set(format!(
                        "Armed: waiting for {} ({})",
                        current_target,
                        current_method.as_str()
                    ));
                    status_is_error.set(false);
                }
                Err(e) => {
                    status_message.set(format!("Error: {}", e));
                    status_is_error.set(true);
                }
            }

            is_running.set(false);
        });
    };

    let handle_disarm = move |_| {
        if *is_running.read() {
            return;
        }

        is_running.set(true);
        status_message.set(String::new());

        spawn(async move {
            let result = disarm_early_injection();

            match result {
                Ok(()) => {
                    armed.set(false);
                    status_message.set("Disarmed".to_string());
                    status_is_error.set(false);
                }
                Err(e) => {
                    status_message.set(format!("Error: {}", e));
                    status_is_error.set(true);
                }
            }

            is_running.set(false);

            // Auto-dismiss success messages after 3 seconds
            if !*status_is_error.read() {
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                status_message.set(String::new());
            }
        });
    };

    let browse_dll = move |_| {
        spawn(async move {
            let file = rfd::AsyncFileDialog::new()
                .add_filter("DLL", &["dll"])
                .set_title("Select DLL to Inject")
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
    let is_armed = *armed.read();
    let driver_ok = *driver_available.read();
    let count = *injection_count.read();
    let last_pid = *last_injected_pid.read();
    let last_st = *last_status.read();

    rsx! {
        div {
            class: "create-process-modal-overlay",
            onclick: close_window,

            div {
                class: "create-process-modal",
                onclick: move |e| e.stop_propagation(),
                style: "max-width: 550px;",

                // Header
                div { class: "create-process-modal-header",
                    span { class: "create-process-modal-title", "Early Injection" }
                    button {
                        class: "create-process-modal-close",
                        onclick: close_window,
                        "X"
                    }
                }

                // Body
                div { class: "create-process-form",
                    // Driver status
                    div { class: "create-process-field",
                        label { class: "create-process-label", "Driver Status" }
                        div {
                            class: if driver_ok { "create-process-status create-process-status-success" } else { "create-process-status create-process-status-error" },
                            style: "margin-bottom: 8px;",
                            if driver_ok {
                                "Driver loaded"
                            } else {
                                "Driver not loaded - early injection unavailable"
                            }
                        }
                    }

                    // Description
                    div { class: "create-process-field",
                        label { class: "create-process-label", "Description" }
                        input {
                            class: "create-process-input",
                            r#type: "text",
                            readonly: true,
                            value: "Inject DLL before any user code executes in target process",
                        }
                    }

                    // Target process name
                    div { class: "create-process-field",
                        label { class: "create-process-label", "Target Process Name" }
                        input {
                            class: "create-process-input",
                            r#type: "text",
                            placeholder: "e.g., notepad.exe",
                            value: "{target_process}",
                            disabled: !driver_ok || is_armed,
                            oninput: move |e| target_process.set(e.value().clone()),
                        }
                    }

                    // DLL path
                    div { class: "create-process-field",
                        label { class: "create-process-label", "DLL to Inject" }
                        div { class: "create-process-path-row",
                            input {
                                class: "create-process-input",
                                r#type: "text",
                                placeholder: "Path to DLL...",
                                value: "{dll_path}",
                                disabled: !driver_ok || is_armed,
                                oninput: move |e| dll_path.set(e.value().clone()),
                            }
                            button {
                                class: "create-process-btn-browse",
                                disabled: !driver_ok || is_armed,
                                onclick: browse_dll,
                                "Browse"
                            }
                        }
                    }

                    // Method selector
                    div { class: "create-process-field",
                        label { class: "create-process-label", "Injection Method" }
                        select {
                            class: "create-process-select",
                            disabled: !driver_ok || is_armed,
                            value: if *method.read() == EarlyInjectionMethod::Trampoline { "trampoline" } else { "apc" },
                            onchange: move |e| {
                                let val = e.value();
                                method.set(if val == "trampoline" {
                                    EarlyInjectionMethod::Trampoline
                                } else {
                                    EarlyInjectionMethod::ApcCallback
                                });
                            },
                            option { value: "trampoline", "Trampoline (Hook LdrLoadDll at process creation)" }
                            option { value: "apc", "APC Callback (Queue APC when kernel32.dll loads)" }
                        }
                    }

                    // One-shot checkbox
                    div { class: "create-process-field",
                        label { class: "create-process-checkbox-label",
                            input {
                                r#type: "checkbox",
                                checked: *one_shot.read(),
                                disabled: !driver_ok || is_armed,
                                onchange: move |e| one_shot.set(e.checked()),
                            }
                            " One-shot mode (disarm after first injection)"
                        }
                    }

                    // Armed status indicator
                    div { class: "create-process-field",
                        label { class: "create-process-label", "Status" }
                        div {
                            style: "display: flex; gap: 16px; align-items: center; flex-wrap: wrap;",
                            span {
                                class: if is_armed { "create-process-status create-process-status-success" } else { "create-process-status" },
                                style: "min-width: 80px; text-align: center;",
                                if is_armed { "ARMED" } else { "DISARMED" }
                            }
                            span { style: "color: var(--text-muted);", "Injections: {count}" }
                            if last_pid > 0 {
                                span { style: "color: var(--text-muted);", "Last PID: {last_pid}" }
                            }
                            if last_st != 0 {
                                span {
                                    style: if last_st == 0 { "color: var(--color-success);" } else { "color: var(--color-error);" },
                                    "Last status: 0x{last_st:08X}"
                                }
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
                        "Close"
                    }
                    if is_armed {
                        button {
                            class: "btn btn-danger",
                            disabled: running || !driver_ok,
                            onclick: handle_disarm,
                            if running {
                                "Disarming..."
                            } else {
                                "Disarm"
                            }
                        }
                    } else {
                        button {
                            class: "btn btn-primary",
                            disabled: running || !driver_ok,
                            onclick: handle_arm,
                            if running {
                                "Arming..."
                            } else {
                                "Arm"
                            }
                        }
                    }
                }
            }
        }
    }
}
