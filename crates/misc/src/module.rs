use std::ffi::CString;

use windows::core::PCSTR;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::Win32::System::Threading::{
    CreateRemoteThread, OpenProcess, WaitForSingleObject, PROCESS_CREATE_THREAD,
    PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
};

use crate::error::MiscError;

/// Unload a DLL from a target process by calling FreeLibrary remotely.
///
/// Uses `OpenProcess` -> `CreateRemoteThread` + `FreeLibrary` with the module
/// base address as the HMODULE argument.
///
/// # Safety
/// This function uses unsafe Windows API calls to manipulate another process.
pub fn unload_module(pid: u32, base_address: usize) -> Result<(), MiscError> {
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

        // Resolve FreeLibrary address from kernel32.dll
        let kernel32_name = CString::new("kernel32.dll").unwrap();
        let kernel32 =
            GetModuleHandleA(PCSTR(kernel32_name.as_ptr() as *const u8)).map_err(|_| {
                let _ = CloseHandle(process_handle);
                MiscError::GetModuleHandleFailed
            })?;

        let free_library_name = CString::new("FreeLibrary").unwrap();
        let free_library_addr =
            GetProcAddress(kernel32, PCSTR(free_library_name.as_ptr() as *const u8));

        let free_library_addr = match free_library_addr {
            Some(addr) => addr,
            None => {
                let _ = CloseHandle(process_handle);
                return Err(MiscError::GetProcAddressFailed);
            }
        };

        // Cast FreeLibrary address to the thread start routine type
        let thread_start: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32 =
            std::mem::transmute(free_library_addr);

        // Create a remote thread that calls FreeLibrary with the module base address
        let thread_handle = CreateRemoteThread(
            process_handle,
            None,
            0,
            Some(thread_start),
            Some(base_address as *const std::ffi::c_void),
            0,
            None,
        )
        .map_err(|_| {
            let _ = CloseHandle(process_handle);
            MiscError::CreateRemoteThreadFailed
        })?;

        // Wait for the remote thread to finish (10 second timeout)
        let wait_result = WaitForSingleObject(thread_handle, 10_000);

        let _ = CloseHandle(thread_handle);
        let _ = CloseHandle(process_handle);

        if wait_result.0 != 0 {
            return Err(MiscError::Timeout);
        }

        Ok(())
    }
}
