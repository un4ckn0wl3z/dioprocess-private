use std::ffi::CString;
use std::path::Path;

use windows::core::PCSTR;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAllocEx, VirtualFreeEx,
};
use windows::Win32::System::Threading::{
    CreateRemoteThread, OpenProcess, QueueUserAPC, ResumeThread, WaitForSingleObject,
    CREATE_SUSPENDED, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
    PROCESS_VM_READ, PROCESS_VM_WRITE,
};

use crate::error::MiscError;

/// Inject a DLL into a target process using the EarlyBird APC technique.
///
/// Creates a remote thread in suspended state, queues an APC with `LoadLibraryW`
/// before the thread runs, then resumes it. The APC fires during thread initialization
/// (in `LdrInitializeThunk`) before the entry point executes, guaranteeing execution
/// without waiting for an alertable wait state.
///
/// # Safety
/// This function uses unsafe Windows API calls to manipulate another process.
pub fn inject_dll_earlybird(pid: u32, dll_path: &str) -> Result<(), MiscError> {
    // Validate DLL exists
    if !Path::new(dll_path).exists() {
        return Err(MiscError::FileNotFound(dll_path.to_string()));
    }

    // Encode DLL path as wide string (UTF-16) with null terminator
    let wide_path: Vec<u16> = dll_path.encode_utf16().chain(std::iter::once(0)).collect();
    let wide_path_bytes = wide_path.len() * std::mem::size_of::<u16>();

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

        // Allocate memory in target process for the DLL path
        let remote_mem = VirtualAllocEx(
            process_handle,
            Some(std::ptr::null()),
            wide_path_bytes,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if remote_mem.is_null() {
            let _ = CloseHandle(process_handle);
            return Err(MiscError::AllocFailed);
        }

        // Write the DLL path into the allocated memory
        if WriteProcessMemory(
            process_handle,
            remote_mem,
            wide_path.as_ptr() as *const _,
            wide_path_bytes,
            None,
        )
        .is_err()
        {
            let _ = VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
            let _ = CloseHandle(process_handle);
            return Err(MiscError::WriteFailed);
        }

        // Resolve kernel32.dll function addresses
        let kernel32_name = CString::new("kernel32.dll").unwrap();
        let kernel32 =
            GetModuleHandleA(PCSTR(kernel32_name.as_ptr() as *const u8)).map_err(|_| {
                let _ = VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
                let _ = CloseHandle(process_handle);
                MiscError::GetModuleHandleFailed
            })?;

        // Resolve LoadLibraryW (APC callback)
        let load_library_name = CString::new("LoadLibraryW").unwrap();
        let load_library_addr =
            GetProcAddress(kernel32, PCSTR(load_library_name.as_ptr() as *const u8));

        let load_library_addr = match load_library_addr {
            Some(addr) => addr,
            None => {
                let _ = VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
                let _ = CloseHandle(process_handle);
                return Err(MiscError::GetProcAddressFailed);
            }
        };

        // Resolve ExitThread (benign thread entry point — thread exits after APC fires)
        let exit_thread_name = CString::new("ExitThread").unwrap();
        let exit_thread_addr =
            GetProcAddress(kernel32, PCSTR(exit_thread_name.as_ptr() as *const u8));

        let exit_thread_addr = match exit_thread_addr {
            Some(addr) => addr,
            None => {
                let _ = VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
                let _ = CloseHandle(process_handle);
                return Err(MiscError::GetProcAddressFailed);
            }
        };

        // Create a remote thread in SUSPENDED state with ExitThread as entry point.
        // The actual DLL load happens via the APC queued below, which fires during
        // thread initialization before the entry point executes.
        let thread_start: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32 =
            std::mem::transmute(exit_thread_addr);

        let thread_handle = CreateRemoteThread(
            process_handle,
            None,
            0,
            Some(thread_start),
            None, // ExitThread(0)
            CREATE_SUSPENDED.0, // Thread starts suspended
            None,
        )
        .map_err(|_| {
            let _ = VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
            let _ = CloseHandle(process_handle);
            MiscError::CreateRemoteThreadFailed
        })?;

        // Queue APC with LoadLibraryW on the suspended thread.
        // When the thread resumes, LdrInitializeThunk processes the APC queue
        // before reaching the entry point, triggering LoadLibraryW(dll_path).
        let apc_func: unsafe extern "system" fn(usize) =
            std::mem::transmute(load_library_addr as usize);

        if QueueUserAPC(Some(apc_func), thread_handle, remote_mem as usize) == 0 {
            // APC queue failed — resume and discard the thread
            let _ = ResumeThread(thread_handle);
            let _ = CloseHandle(thread_handle);
            let _ = VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
            let _ = CloseHandle(process_handle);
            return Err(MiscError::QueueApcFailed);
        }

        // Resume the thread — APC fires during thread initialization
        if ResumeThread(thread_handle) == u32::MAX {
            let _ = CloseHandle(thread_handle);
            let _ = CloseHandle(process_handle);
            return Err(MiscError::ResumeThreadFailed(0));
        }

        // Wait for the thread to finish (LoadLibraryW via APC, then ExitThread)
        let wait_result = WaitForSingleObject(thread_handle, 10_000);

        let _ = CloseHandle(thread_handle);
        let _ = VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
        let _ = CloseHandle(process_handle);

        if wait_result.0 != 0 {
            return Err(MiscError::Timeout);
        }

        Ok(())
    }
}
