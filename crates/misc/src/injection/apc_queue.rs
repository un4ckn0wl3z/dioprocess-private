use std::ffi::CString;
use std::path::Path;

use windows::core::PCSTR;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAllocEx, VirtualFreeEx,
};
use windows::Win32::System::Threading::{
    OpenProcess, OpenThread, QueueUserAPC, PROCESS_VM_OPERATION, PROCESS_VM_READ,
    PROCESS_VM_WRITE, THREAD_SET_CONTEXT,
};

use crate::error::MiscError;

/// Inject a DLL into a target process using APC queue.
///
/// Writes the DLL path into the target process, resolves `LoadLibraryW`, then
/// queues an APC on every thread belonging to the process. The DLL loads when
/// any queued thread enters an alertable wait state.
///
/// # Safety
/// This function uses unsafe Windows API calls to manipulate another process.
pub fn inject_dll_apc_queue(pid: u32, dll_path: &str) -> Result<(), MiscError> {
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
            PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
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

        // Resolve LoadLibraryW address from kernel32.dll
        let kernel32_name = CString::new("kernel32.dll").unwrap();
        let kernel32 =
            GetModuleHandleA(PCSTR(kernel32_name.as_ptr() as *const u8)).map_err(|_| {
                let _ = VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
                let _ = CloseHandle(process_handle);
                MiscError::GetModuleHandleFailed
            })?;

        let load_library_name = CString::new("LoadLibraryW").unwrap();
        let load_library_addr =
            GetProcAddress(kernel32, PCSTR(load_library_name.as_ptr() as *const u8));

        let load_library_addr = match load_library_addr {
            Some(addr) => addr as usize,
            None => {
                let _ = VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
                let _ = CloseHandle(process_handle);
                return Err(MiscError::GetProcAddressFailed);
            }
        };

        // Enumerate all threads via CreateToolhelp32Snapshot
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0).map_err(|_| {
            let _ = VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
            let _ = CloseHandle(process_handle);
            MiscError::ThreadEnumerationFailed
        })?;

        let mut thread_entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };

        let mut queued_count: u32 = 0;

        if Thread32First(snapshot, &mut thread_entry).is_ok() {
            loop {
                if thread_entry.th32OwnerProcessID == pid {
                    if let Ok(thread_handle) =
                        OpenThread(THREAD_SET_CONTEXT, false, thread_entry.th32ThreadID)
                    {
                        // Cast LoadLibraryW to the APC function type
                        let apc_func: unsafe extern "system" fn(usize) =
                            std::mem::transmute(load_library_addr);

                        if QueueUserAPC(
                            Some(apc_func),
                            thread_handle,
                            remote_mem as usize,
                        ) != 0
                        {
                            queued_count += 1;
                        }
                        let _ = CloseHandle(thread_handle);
                    }
                }
                thread_entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
                if Thread32Next(snapshot, &mut thread_entry).is_err() {
                    break;
                }
            }
        }

        let _ = CloseHandle(snapshot);

        if queued_count == 0 {
            let _ = VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
            let _ = CloseHandle(process_handle);
            return Err(MiscError::QueueApcFailed);
        }

        // NOTE: We intentionally do NOT free remote_mem here.
        // The DLL path must persist in the target process until an APC fires
        // and LoadLibraryW reads the path string.
        let _ = CloseHandle(process_handle);

        Ok(())
    }
}
