//! Shared EPT Hook Modal - works from any tab (Memory Scanner, HV Scanner, etc.)

use callback::{
    assemble, format_bytes_hex, hv_alloc_write_near, hv_is_running, hv_write_virtual_memory,
    install_ept_hook, is_driver_loaded, list_ept_hooks,
};
use dioxus::prelude::*;
use misc::free_remote_memory;
use process::{get_process_arch, ProcessArch};

use crate::state::{
    EptHookInputMode, EPT_HOOKS_LIST, EPT_HOOK_ASM_ERROR, EPT_HOOK_ASM_INPUT, EPT_HOOK_ASM_PREVIEW,
    EPT_HOOK_BYTES_INPUT, EPT_HOOK_DETOUR_ALLOCS, EPT_HOOK_DETOUR_ASM_ERROR,
    EPT_HOOK_DETOUR_ASM_INPUT, EPT_HOOK_DETOUR_ASM_PREVIEW, EPT_HOOK_DETOUR_STOLEN_BYTES,
    EPT_HOOK_INPUT_MODE, EPT_HOOK_IS_ERROR, EPT_HOOK_SHOW_MODAL, EPT_HOOK_STATUS,
    EPT_HOOK_TARGET_ADDR, SCANNER_PID,
};

/// Shared EPT Hook Modal component - renders when EPT_HOOK_SHOW_MODAL is true
#[component]
pub fn EptHookModal() -> Element {
    let mut ept_hook_show_modal = EPT_HOOK_SHOW_MODAL.signal();
    let ept_hook_target = EPT_HOOK_TARGET_ADDR.signal();
    let mut ept_hook_bytes = EPT_HOOK_BYTES_INPUT.signal();
    let mut ept_hook_status = EPT_HOOK_STATUS.signal();
    let mut ept_hook_is_error = EPT_HOOK_IS_ERROR.signal();
    let mut ept_hook_input_mode = EPT_HOOK_INPUT_MODE.signal();
    let mut ept_hook_asm_input = EPT_HOOK_ASM_INPUT.signal();
    let mut ept_hook_asm_preview = EPT_HOOK_ASM_PREVIEW.signal();
    let mut ept_hook_asm_error = EPT_HOOK_ASM_ERROR.signal();
    let mut detour_asm_input = EPT_HOOK_DETOUR_ASM_INPUT.signal();
    let mut detour_asm_preview = EPT_HOOK_DETOUR_ASM_PREVIEW.signal();
    let mut detour_asm_error = EPT_HOOK_DETOUR_ASM_ERROR.signal();
    let mut detour_stolen_bytes = EPT_HOOK_DETOUR_STOLEN_BYTES.signal();
    let mut detour_allocs = EPT_HOOK_DETOUR_ALLOCS.signal();
    let mut ept_hooks_list = EPT_HOOKS_LIST.signal();
    let pid_input = SCANNER_PID.signal();

    let driver_loaded = is_driver_loaded();
    let hv_running = hv_is_running();

    if !*ept_hook_show_modal.read() {
        return rsx! {};
    }

    let target_addr = ept_hook_target.read().unwrap_or(0);
    let hook_status = ept_hook_status.read().clone();
    let hook_error = *ept_hook_is_error.read();
    let input_mode = *ept_hook_input_mode.read();
    let asm_preview = ept_hook_asm_preview.read().clone();
    let asm_error = ept_hook_asm_error.read().clone();
    let detour_preview = detour_asm_preview.read().clone();
    let detour_error = detour_asm_error.read().clone();

    // Get process architecture
    let pid_str = pid_input.read().clone();
    let pid = pid_str.trim().parse::<u32>().unwrap_or(0);
    let proc_arch = if pid > 0 { get_process_arch(pid) } else { ProcessArch::Unknown };
    let arch_label = match proc_arch {
        ProcessArch::X64 => "x64",
        ProcessArch::X86 => "x86",
        ProcessArch::Unknown => "?",
    };
    let arch_badge_style = match proc_arch {
        ProcessArch::X64 => "background: #22c55e;",
        ProcessArch::X86 => "background: #eab308;",
        ProcessArch::Unknown => "background: #6b7280;",
    };

    rsx! {
        div {
            class: "create-process-modal-overlay",
            onclick: move |_| ept_hook_show_modal.set(false),
            div {
                class: "create-process-modal",
                style: "max-width: 600px; min-height: 400px;",
                onclick: move |e| e.stop_propagation(),

                // Header
                div { class: "create-process-modal-header",
                    div { style: "display: flex; align-items: center; gap: 8px;",
                        span { class: "create-process-modal-title", "Install EPT Hook" }
                        span {
                            class: "experimental-badge",
                            style: "{arch_badge_style}",
                            "{arch_label}"
                        }
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
                        onclick: move |_| ept_hook_show_modal.set(false),
                        "X"
                    }
                }

                // Body
                div { class: "create-process-form",

                    div { style: "margin-bottom: 12px; color: var(--text-secondary); font-size: 12px;",
                        "EPT split-page hook: reads see original bytes, execution uses patched bytes."
                    }

                    // Target address
                    div { class: "create-process-field",
                        label { class: "create-process-label", "Address:" }
                        span {
                            style: "font-family: 'Consolas', monospace; color: var(--accent-primary); font-size: 13px;",
                            "0x{target_addr:X}"
                        }
                    }

                    // Input mode toggle
                    div { style: "display: flex; gap: 4px; margin-bottom: 12px;",
                        button {
                            class: if input_mode == EptHookInputMode::Hex { "btn btn-primary" } else { "btn" },
                            style: "font-size: 12px; padding: 4px 12px;",
                            onclick: move |_| {
                                ept_hook_input_mode.set(EptHookInputMode::Hex);
                                ept_hook_asm_error.set(String::new());
                            },
                            "Hex Bytes"
                        }
                        button {
                            class: if input_mode == EptHookInputMode::Assembly { "btn btn-primary" } else { "btn" },
                            style: "font-size: 12px; padding: 4px 12px;",
                            onclick: move |_| {
                                ept_hook_input_mode.set(EptHookInputMode::Assembly);
                                ept_hook_status.set(String::new());
                            },
                            "Assembly"
                        }
                        button {
                            class: if input_mode == EptHookInputMode::Detour { "btn btn-primary" } else { "btn" },
                            style: "font-size: 12px; padding: 4px 12px;",
                            onclick: move |_| {
                                ept_hook_input_mode.set(EptHookInputMode::Detour);
                                ept_hook_status.set(String::new());
                            },
                            "Detour"
                        }
                    }

                    // Hex bytes input mode
                    if input_mode == EptHookInputMode::Hex {
                        div { style: "display: flex; gap: 8px; align-items: center; margin-bottom: 8px;",
                            label { style: "color: var(--text-secondary); font-size: 13px; min-width: 80px;", "Hook bytes:" }
                            input {
                                class: "handle-filter-input",
                                r#type: "text",
                                placeholder: "e.g. 90 90 90 or C3 or 48B8... (hex)",
                                style: "flex: 1; font-family: 'Consolas', monospace;",
                                value: "{ept_hook_bytes}",
                                oninput: move |e| ept_hook_bytes.set(e.value()),
                            }
                        }
                        div { style: "color: var(--text-secondary); font-size: 11px; margin-bottom: 12px;",
                            "Enter replacement bytes in hex (space-separated or continuous). Max 256 bytes."
                        }
                    }

                    // Assembly input mode
                    if input_mode == EptHookInputMode::Assembly {
                        div { style: "margin-bottom: 8px;",
                            label { style: "color: var(--text-secondary); font-size: 13px; display: block; margin-bottom: 4px;",
                                "Assembly code (Intel syntax):"
                            }
                            textarea {
                                class: "handle-filter-input",
                                placeholder: "nop\nmov rax, 0x1234\nret",
                                style: "width: 100%; height: 120px; font-family: 'Consolas', monospace; font-size: 13px; resize: vertical; background: var(--bg-tertiary); color: var(--text-primary); border: 1px solid var(--border-primary); border-radius: 4px; padding: 8px;",
                                value: "{ept_hook_asm_input}",
                                oninput: {
                                    move |e: Event<FormData>| {
                                        let code = e.value();
                                        ept_hook_asm_input.set(code.clone());
                                        
                                        if !code.trim().is_empty() && pid > 0 {
                                            match assemble(&code, proc_arch, target_addr) {
                                                Ok(bytes) => {
                                                    ept_hook_asm_preview.set(format_bytes_hex(&bytes));
                                                    ept_hook_asm_error.set(String::new());
                                                }
                                                Err(e) => {
                                                    ept_hook_asm_preview.set(String::new());
                                                    ept_hook_asm_error.set(e.to_string());
                                                }
                                            }
                                        } else {
                                            ept_hook_asm_preview.set(String::new());
                                            ept_hook_asm_error.set(String::new());
                                        }
                                    }
                                },
                            }
                        }

                        if !asm_error.is_empty() {
                            div {
                                style: "color: #ef4444; font-size: 12px; font-family: 'Consolas', monospace; margin-bottom: 8px; padding: 6px; background: rgba(239, 68, 68, 0.1); border-radius: 4px;",
                                "⚠ {asm_error}"
                            }
                        }

                        if !asm_preview.is_empty() {
                            div { style: "margin-bottom: 12px;",
                                label { style: "color: var(--text-secondary); font-size: 12px; display: block; margin-bottom: 4px;",
                                    "Assembled bytes:"
                                }
                                div {
                                    style: "font-family: 'Consolas', monospace; font-size: 13px; color: #22c55e; background: var(--bg-tertiary); padding: 8px; border-radius: 4px; word-break: break-all;",
                                    "{asm_preview}"
                                }
                            }
                        }
                    }

                    // Detour mode
                    if input_mode == EptHookInputMode::Detour {
                        div { style: "margin-bottom: 8px;",
                            div { style: "display: flex; gap: 8px; align-items: center; margin-bottom: 8px;",
                                label { style: "color: var(--text-secondary); font-size: 13px; min-width: 100px;", "Stolen bytes:" }
                                input {
                                    class: "handle-filter-input",
                                    r#type: "text",
                                    placeholder: "6",
                                    style: "width: 60px; font-family: 'Consolas', monospace;",
                                    value: "{detour_stolen_bytes}",
                                    oninput: move |e| detour_stolen_bytes.set(e.value()),
                                }
                                span { style: "color: var(--text-secondary); font-size: 11px;", "(min 5 for JMP rel32)" }
                            }
                            label { style: "color: var(--text-secondary); font-size: 13px; display: block; margin-bottom: 4px;",
                                "Detour code (Intel syntax):"
                            }
                            textarea {
                                class: "handle-filter-input",
                                placeholder: "; Your detour code here\n; Return JMP is auto-appended",
                                style: "width: 100%; height: 120px; font-family: 'Consolas', monospace; font-size: 13px; resize: vertical; background: var(--bg-tertiary); color: var(--text-primary); border: 1px solid var(--border-primary); border-radius: 4px; padding: 8px;",
                                value: "{detour_asm_input}",
                                oninput: {
                                    move |e: Event<FormData>| {
                                        let code = e.value();
                                        detour_asm_input.set(code.clone());
                                        
                                        if !code.trim().is_empty() && pid > 0 {
                                            match assemble(&code, proc_arch, target_addr) {
                                                Ok(bytes) => {
                                                    detour_asm_preview.set(format_bytes_hex(&bytes));
                                                    detour_asm_error.set(String::new());
                                                }
                                                Err(e) => {
                                                    detour_asm_preview.set(String::new());
                                                    detour_asm_error.set(e.to_string());
                                                }
                                            }
                                        } else {
                                            detour_asm_preview.set(String::new());
                                            detour_asm_error.set(String::new());
                                        }
                                    }
                                },
                            }
                        }

                        if !detour_error.is_empty() {
                            div {
                                style: "color: #ef4444; font-size: 12px; font-family: 'Consolas', monospace; margin-bottom: 8px; padding: 6px; background: rgba(239, 68, 68, 0.1); border-radius: 4px;",
                                "⚠ {detour_error}"
                            }
                        }

                        if !detour_preview.is_empty() {
                            div { style: "margin-bottom: 12px;",
                                label { style: "color: var(--text-secondary); font-size: 12px; display: block; margin-bottom: 4px;",
                                    "Detour bytes preview:"
                                }
                                div {
                                    style: "font-family: 'Consolas', monospace; font-size: 13px; color: #22c55e; background: var(--bg-tertiary); padding: 8px; border-radius: 4px; word-break: break-all;",
                                    "{detour_preview}"
                                }
                            }
                        }

                        div { style: "color: var(--text-secondary); font-size: 11px; margin-bottom: 8px;",
                            "Detour mode: Allocates RWX memory near hook, writes your code + return JMP, patches original with JMP to detour."
                        }
                    }

                    // Status message
                    if !hook_status.is_empty() {
                        div {
                            style: if hook_error {
                                "color: #ef4444; font-size: 12px; margin-bottom: 12px; padding: 8px; background: rgba(239, 68, 68, 0.1); border-radius: 4px;"
                            } else {
                                "color: #22c55e; font-size: 12px; margin-bottom: 12px; padding: 8px; background: rgba(34, 197, 94, 0.1); border-radius: 4px;"
                            },
                            "{hook_status}"
                        }
                    }

                    // Install button
                    div { style: "display: flex; gap: 8px; justify-content: flex-end;",
                        button {
                            class: "btn",
                            onclick: move |_| ept_hook_show_modal.set(false),
                            "Cancel"
                        }
                        button {
                            class: "btn btn-primary",
                            disabled: !driver_loaded || !hv_running,
                            onclick: move |_| {
                                let addr = ept_hook_target.read().unwrap_or(0);
                                let mode = *ept_hook_input_mode.read();

                                match mode {
                                    EptHookInputMode::Hex => {
                                        // Parse hex bytes
                                        let hex_str = ept_hook_bytes.read().clone();
                                        let hex_clean: String = hex_str.chars().filter(|c| !c.is_whitespace()).collect();
                                        if hex_clean.is_empty() || hex_clean.len() % 2 != 0 {
                                            ept_hook_status.set("Invalid hex bytes".to_string());
                                            ept_hook_is_error.set(true);
                                            return;
                                        }
                                        let bytes: Result<Vec<u8>, _> = (0..hex_clean.len())
                                            .step_by(2)
                                            .map(|i| u8::from_str_radix(&hex_clean[i..i+2], 16))
                                            .collect();
                                        match bytes {
                                            Ok(b) if !b.is_empty() => {
                                                match install_ept_hook(pid, addr, &b) {
                                                    Ok(idx) => {
                                                        ept_hook_status.set(format!("Hook #{} installed at 0x{:X}", idx, addr));
                                                        ept_hook_is_error.set(false);
                                                        if let Ok(hooks) = list_ept_hooks() {
                                                            ept_hooks_list.set(hooks);
                                                        }
                                                    }
                                                    Err(e) => {
                                                        ept_hook_status.set(format!("Failed: {}", e));
                                                        ept_hook_is_error.set(true);
                                                    }
                                                }
                                            }
                                            _ => {
                                                ept_hook_status.set("Invalid hex bytes".to_string());
                                                ept_hook_is_error.set(true);
                                            }
                                        }
                                    }
                                    EptHookInputMode::Assembly => {
                                        let code = ept_hook_asm_input.read().clone();
                                        match assemble(&code, proc_arch, addr) {
                                            Ok(bytes) if !bytes.is_empty() => {
                                                match install_ept_hook(pid, addr, &bytes) {
                                                    Ok(idx) => {
                                                        ept_hook_status.set(format!("Hook #{} installed at 0x{:X}", idx, addr));
                                                        ept_hook_is_error.set(false);
                                                        if let Ok(hooks) = list_ept_hooks() {
                                                            ept_hooks_list.set(hooks);
                                                        }
                                                    }
                                                    Err(e) => {
                                                        ept_hook_status.set(format!("Failed: {}", e));
                                                        ept_hook_is_error.set(true);
                                                    }
                                                }
                                            }
                                            Ok(_) => {
                                                ept_hook_status.set("Assembly produced no bytes".to_string());
                                                ept_hook_is_error.set(true);
                                            }
                                            Err(e) => {
                                                ept_hook_status.set(format!("Assembly error: {}", e));
                                                ept_hook_is_error.set(true);
                                            }
                                        }
                                    }
                                    EptHookInputMode::Detour => {
                                        let asm_code = detour_asm_input.read().clone();
                                        let stolen: u32 = detour_stolen_bytes.read().trim().parse().unwrap_or(6);
                                        
                                        if stolen < 5 {
                                            ept_hook_status.set("Stolen bytes must be >= 5".to_string());
                                            ept_hook_is_error.set(true);
                                            return;
                                        }

                                        // Use HV alloc+write (pure kernel/HV, no usermode API)
                                        if hv_running {
                                            let estimated_addr = addr.saturating_sub(0x1000) & !0xFFF;
                                            let detour_bytes = match assemble(&asm_code, proc_arch, estimated_addr) {
                                                Ok(b) => b,
                                                Err(e) => {
                                                    ept_hook_status.set(format!("Assembly error: {}", e));
                                                    ept_hook_is_error.set(true);
                                                    return;
                                                }
                                            };

                                            if detour_bytes.is_empty() || detour_bytes.len() > 3800 {
                                                ept_hook_status.set("Detour code must be 1-3800 bytes".to_string());
                                                ept_hook_is_error.set(true);
                                                return;
                                            }

                                            let return_addr = addr + stolen as u64;
                                            let mut full_code = detour_bytes.clone();
                                            full_code.extend_from_slice(&[0xFF, 0x25, 0x00, 0x00, 0x00, 0x00]);
                                            full_code.extend_from_slice(&return_addr.to_le_bytes());

                                            match hv_alloc_write_near(pid, addr, &full_code) {
                                                Ok(result) if result.success => {
                                                    let alloc_addr = result.allocated_address;
                                                    
                                                    // Re-assemble at actual address if different
                                                    if alloc_addr != estimated_addr {
                                                        let detour_bytes = match assemble(&asm_code, proc_arch, alloc_addr) {
                                                            Ok(b) => b,
                                                            Err(e) => {
                                                                ept_hook_status.set(format!("Re-assembly error: {}", e));
                                                                ept_hook_is_error.set(true);
                                                                return;
                                                            }
                                                        };
                                                        let mut full_code = detour_bytes;
                                                        full_code.extend_from_slice(&[0xFF, 0x25, 0x00, 0x00, 0x00, 0x00]);
                                                        full_code.extend_from_slice(&return_addr.to_le_bytes());
                                                        if let Err(e) = hv_write_virtual_memory(pid, alloc_addr, &full_code) {
                                                            ept_hook_status.set(format!("HV re-write failed: {}", e));
                                                            ept_hook_is_error.set(true);
                                                            return;
                                                        }
                                                    }

                                                    // Build JMP patch
                                                    let jmp_target = alloc_addr as i64;
                                                    let jmp_from = (addr + 5) as i64;
                                                    let rel32 = (jmp_target - jmp_from) as i32;
                                                    let mut jmp_patch: Vec<u8> = Vec::with_capacity(stolen as usize);
                                                    jmp_patch.push(0xE9);
                                                    jmp_patch.extend_from_slice(&rel32.to_le_bytes());
                                                    for _ in 5..stolen {
                                                        jmp_patch.push(0x90);
                                                    }

                                                    match install_ept_hook(pid, addr, &jmp_patch) {
                                                        Ok(idx) => {
                                                            detour_allocs.write().insert(idx, (pid, alloc_addr));
                                                            ept_hook_status.set(format!(
                                                                "Detour hook #{} via Kernel+HV: JMP@0x{:X} -> 0x{:X}",
                                                                idx, addr, alloc_addr
                                                            ));
                                                            ept_hook_is_error.set(false);
                                                            if let Ok(hooks) = list_ept_hooks() {
                                                                ept_hooks_list.set(hooks);
                                                            }
                                                        }
                                                        Err(e) => {
                                                            let _ = free_remote_memory(pid, alloc_addr);
                                                            ept_hook_status.set(format!("Failed: {}", e));
                                                            ept_hook_is_error.set(true);
                                                        }
                                                    }
                                                }
                                                Ok(_) => {
                                                    ept_hook_status.set("HV alloc+write failed".to_string());
                                                    ept_hook_is_error.set(true);
                                                }
                                                Err(e) => {
                                                    ept_hook_status.set(format!("HV alloc+write error: {}", e));
                                                    ept_hook_is_error.set(true);
                                                }
                                            }
                                        } else {
                                            ept_hook_status.set("Hypervisor not running".to_string());
                                            ept_hook_is_error.set(true);
                                        }
                                    }
                                }
                            },
                            "Install Hook"
                        }
                    }
                }
            }
        }
    }
}
