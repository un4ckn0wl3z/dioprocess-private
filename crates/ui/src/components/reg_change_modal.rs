//! Shared Register Change Modal - works from any tab

use callback::{hv_is_running, install_reg_change, is_driver_loaded, list_reg_changes};
use dioxus::prelude::*;

use crate::state::{
    REG_CHANGE_IS_ERROR, REG_CHANGE_LIST, REG_CHANGE_SHOW_MODAL, REG_CHANGE_STATUS,
    REG_CHANGE_TARGET_ADDR, SCANNER_PID,
};

/// Register names for the dropdown
const REGISTER_NAMES: &[&str] = &[
    "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP",
    "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
    "RIP", "RFLAGS", "ZF", "CF", "SF", "OF", "PF", "AF",
];

/// Shared Register Change Modal component
#[component]
pub fn RegChangeModal() -> Element {
    let mut rc_show_modal = REG_CHANGE_SHOW_MODAL.signal();
    let rc_target_addr = REG_CHANGE_TARGET_ADDR.signal();
    let mut rc_status = REG_CHANGE_STATUS.signal();
    let mut rc_is_error = REG_CHANGE_IS_ERROR.signal();
    let mut rc_list = REG_CHANGE_LIST.signal();
    let pid_input = SCANNER_PID.signal();

    let mut selected_reg_idx = use_signal(|| 0usize);
    let mut new_value_input = use_signal(|| String::new());
    let mut use_set_clear = use_signal(|| false);
    let mut set_clear_mode = use_signal(|| 0usize); // 0 = set, 1 = clear

    let driver_loaded = is_driver_loaded();
    let hv_running = hv_is_running();

    if !*rc_show_modal.read() {
        return rsx! {};
    }

    let target_addr = rc_target_addr.read().unwrap_or(0);
    let status = rc_status.read().clone();
    let is_error = *rc_is_error.read();
    let reg_idx = *selected_reg_idx.read();
    let reg_name = REGISTER_NAMES.get(reg_idx).unwrap_or(&"RAX");

    let pid_str = pid_input.read().clone();
    let pid = pid_str.trim().parse::<u32>().unwrap_or(0);

    // Check if selected register is a flag (ZF, CF, SF, OF, PF, AF)
    let is_flag = reg_idx >= 18;

    rsx! {
        div {
            class: "create-process-modal-overlay",
            onclick: move |_| rc_show_modal.set(false),
            div {
                class: "create-process-modal",
                style: "max-width: 500px;",
                onclick: move |e| e.stop_propagation(),

                // Header
                div { class: "create-process-modal-header",
                    div { style: "display: flex; align-items: center; gap: 8px;",
                        span { class: "create-process-modal-title", "Change Register Value" }
                        if hv_running {
                            span {
                                class: "experimental-badge",
                                style: "background: #059669;",
                                "Ring -1"
                            }
                        }
                    }
                    button {
                        class: "create-process-modal-close",
                        onclick: move |_| rc_show_modal.set(false),
                        "X"
                    }
                }

                // Body
                div { class: "create-process-form",

                    div { style: "margin-bottom: 12px; color: var(--text-secondary); font-size: 12px;",
                        "Set register value when execution reaches this address (via EPT hook)."
                    }

                    // Target address
                    div { class: "create-process-field",
                        label { class: "create-process-label", "Address:" }
                        span {
                            style: "font-family: 'Consolas', monospace; color: var(--accent-primary); font-size: 13px;",
                            "0x{target_addr:X}"
                        }
                    }

                    // Register selection
                    div { style: "display: flex; gap: 8px; align-items: center; margin-bottom: 12px;",
                        label { style: "color: var(--text-secondary); font-size: 13px; min-width: 80px;", "Register:" }
                        select {
                            class: "handle-filter-input",
                            style: "width: 120px; font-family: 'Consolas', monospace;",
                            value: "{reg_idx}",
                            onchange: move |e| {
                                if let Ok(idx) = e.value().parse::<usize>() {
                                    selected_reg_idx.set(idx);
                                    // Reset value input when switching registers
                                    if idx >= 18 {
                                        use_set_clear.set(true);
                                    }
                                }
                            },
                            for (idx, name) in REGISTER_NAMES.iter().enumerate() {
                                option {
                                    value: "{idx}",
                                    selected: idx == reg_idx,
                                    "{name}"
                                }
                            }
                        }
                    }

                    // Value input (for non-flag registers)
                    if !is_flag {
                        div { style: "display: flex; gap: 8px; align-items: center; margin-bottom: 12px;",
                            label { style: "color: var(--text-secondary); font-size: 13px; min-width: 80px;", "New value:" }
                            input {
                                class: "handle-filter-input",
                                r#type: "text",
                                placeholder: "0x1234 or 1234",
                                style: "flex: 1; font-family: 'Consolas', monospace;",
                                value: "{new_value_input}",
                                oninput: move |e| new_value_input.set(e.value()),
                            }
                        }
                        div { style: "color: var(--text-secondary); font-size: 11px; margin-bottom: 12px;",
                            "Enter value in hex (0x prefix) or decimal."
                        }
                    }

                    // Set/Clear toggle (for flag registers)
                    if is_flag {
                        div { style: "display: flex; gap: 8px; align-items: center; margin-bottom: 12px;",
                            label { style: "color: var(--text-secondary); font-size: 13px; min-width: 80px;", "Action:" }
                            button {
                                class: if *set_clear_mode.read() == 0 { "btn btn-primary" } else { "btn" },
                                style: "font-size: 12px; padding: 4px 16px;",
                                onclick: move |_| set_clear_mode.set(0),
                                "Set (1)"
                            }
                            button {
                                class: if *set_clear_mode.read() == 1 { "btn btn-primary" } else { "btn" },
                                style: "font-size: 12px; padding: 4px 16px;",
                                onclick: move |_| set_clear_mode.set(1),
                                "Clear (0)"
                            }
                        }
                    }

                    // Status message
                    if !status.is_empty() {
                        div {
                            style: if is_error {
                                "color: #ef4444; font-size: 12px; margin-bottom: 12px; padding: 8px; background: rgba(239, 68, 68, 0.1); border-radius: 4px;"
                            } else {
                                "color: #22c55e; font-size: 12px; margin-bottom: 12px; padding: 8px; background: rgba(34, 197, 94, 0.1); border-radius: 4px;"
                            },
                            "{status}"
                        }
                    }

                    // Install button
                    div { style: "display: flex; gap: 8px; justify-content: flex-end;",
                        button {
                            class: "btn",
                            onclick: move |_| rc_show_modal.set(false),
                            "Cancel"
                        }
                        button {
                            class: "btn btn-primary",
                            disabled: !driver_loaded || !hv_running,
                            onclick: move |_| {
                                let addr = rc_target_addr.read().unwrap_or(0);
                                let reg = reg_idx as u32;
                                
                                let value: u64 = if is_flag {
                                    if *set_clear_mode.read() == 0 { 1 } else { 0 }
                                } else {
                                    let val_str = new_value_input.read().clone();
                                    let val_str = val_str.trim();
                                    if val_str.starts_with("0x") || val_str.starts_with("0X") {
                                        u64::from_str_radix(&val_str[2..], 16).unwrap_or(0)
                                    } else {
                                        val_str.parse::<u64>().unwrap_or(0)
                                    }
                                };

                                match install_reg_change(pid, addr, reg, value) {
                                    Ok(idx) => {
                                        rc_status.set(format!(
                                            "Register change #{} installed: {} = 0x{:X} at 0x{:X}",
                                            idx, reg_name, value, addr
                                        ));
                                        rc_is_error.set(false);
                                        if let Ok(list) = list_reg_changes() {
                                            rc_list.set(list);
                                        }
                                    }
                                    Err(e) => {
                                        rc_status.set(format!("Failed: {}", e));
                                        rc_is_error.set(true);
                                    }
                                }
                            },
                            "Install"
                        }
                    }
                }
            }
        }
    }
}
