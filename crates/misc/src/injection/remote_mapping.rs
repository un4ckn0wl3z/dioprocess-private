use std::ffi::CString;
use std::path::Path;

use ntapi::ntmmapi::NtMapViewOfSection;
use windows::core::PCSTR;
use windows::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::Win32::System::Memory::{
    CreateFileMappingW, FILE_MAP_WRITE, MapViewOfFile, PAGE_READWRITE, UnmapViewOfFile,
};
use windows::Win32::System::Threading::{
    CreateRemoteThread, OpenProcess, WaitForSingleObject, PROCESS_CREATE_THREAD,
    PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
};

use crate::error::MiscError;

/// Inject a DLL into a target process using remote mapping injection.
///
/// Creates an anonymous file mapping, maps it locally to write the DLL path, then
/// maps the same section into the remote process via `NtMapViewOfSection`. This avoids
/// `VirtualAllocEx` / `WriteProcessMemory` entirely — the DLL path is shared through
/// a memory-mapped section. A remote thread then calls `LoadLibraryW` on the mapped address.
///
/// # Safety
/// This function uses unsafe Windows API calls to manipulate another process.
pub fn inject_dll_remote_mapping(pid: u32, dll_path: &str) -> Result<(), MiscError> {
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
                | PROCESS_VM_OPERATION,
            false,
            pid,
        )
        .map_err(|_| MiscError::OpenProcessFailed(pid))?;

        // Create an anonymous file mapping (backed by the page file, not a real file)
        let mapping_handle = CreateFileMappingW(
            INVALID_HANDLE_VALUE, // anonymous mapping
            None,                 // default security
            PAGE_READWRITE,       // section can be mapped as R/W
            0,                    // high-order size = 0
            wide_path_bytes as u32, // low-order size = DLL path length
            None,                 // unnamed
        )
        .map_err(|_| {
            let _ = CloseHandle(process_handle);
            MiscError::AllocFailed
        })?;

        // Map a writable view into our own process to copy the DLL path
        let local_view = MapViewOfFile(
            mapping_handle,
            FILE_MAP_WRITE,
            0,
            0,
            wide_path_bytes,
        );

        if local_view.Value.is_null() {
            let _ = CloseHandle(mapping_handle);
            let _ = CloseHandle(process_handle);
            return Err(MiscError::AllocFailed);
        }

        // Copy the DLL path into the local mapped view
        std::ptr::copy_nonoverlapping(
            wide_path.as_ptr() as *const u8,
            local_view.Value as *mut u8,
            wide_path_bytes,
        );

        // Unmap local view (writing is done)
        let _ = UnmapViewOfFile(local_view);

        // Map the same section into the remote process via NtMapViewOfSection.
        // This shares the file mapping — the remote view sees the DLL path we wrote.
        let mut remote_base: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut view_size: usize = 0; // 0 = map entire section

        let status = NtMapViewOfSection(
            mapping_handle.0 as *mut _,                   // section handle
            process_handle.0 as *mut _,                   // target process
            (&mut remote_base) as *mut _ as *mut *mut _,  // receives remote base address
            0,                                            // ZeroBits
            wide_path_bytes,                              // CommitSize
            std::ptr::null_mut(),                         // SectionOffset (start at 0)
            &mut view_size,                               // ViewSize (0 = entire section)
            2,                                            // ViewUnmap (not inherited by children)
            0,                                            // AllocationType
            0x04,                                         // PAGE_READWRITE
        );

        if status != 0 || remote_base.is_null() {
            let _ = CloseHandle(mapping_handle);
            let _ = CloseHandle(process_handle);
            return Err(MiscError::AllocFailed);
        }

        // Resolve LoadLibraryW address from kernel32.dll
        let kernel32_name = CString::new("kernel32.dll").unwrap();
        let kernel32 =
            GetModuleHandleA(PCSTR(kernel32_name.as_ptr() as *const u8)).map_err(|_| {
                let _ = CloseHandle(mapping_handle);
                let _ = CloseHandle(process_handle);
                MiscError::GetModuleHandleFailed
            })?;

        let load_library_name = CString::new("LoadLibraryW").unwrap();
        let load_library_addr =
            GetProcAddress(kernel32, PCSTR(load_library_name.as_ptr() as *const u8));

        let load_library_addr = match load_library_addr {
            Some(addr) => addr,
            None => {
                let _ = CloseHandle(mapping_handle);
                let _ = CloseHandle(process_handle);
                return Err(MiscError::GetProcAddressFailed);
            }
        };

        // Cast LoadLibraryW address to the thread start routine type
        let thread_start: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32 =
            std::mem::transmute(load_library_addr);

        // Create a remote thread that calls LoadLibraryW with the mapped DLL path
        let thread_handle = CreateRemoteThread(
            process_handle,
            None,
            0,
            Some(thread_start),
            Some(remote_base as *const _),
            0,
            None,
        )
        .map_err(|_| {
            let _ = CloseHandle(mapping_handle);
            let _ = CloseHandle(process_handle);
            MiscError::CreateRemoteThreadFailed
        })?;

        // Wait for the remote thread to finish (10 second timeout)
        let wait_result = WaitForSingleObject(thread_handle, 10_000);

        let _ = CloseHandle(thread_handle);
        // NOTE: Remote mapping stays in target process — small footprint (DLL path string only).
        // Closing mapping_handle is safe: the remote view holds its own section reference.
        let _ = CloseHandle(mapping_handle);
        let _ = CloseHandle(process_handle);

        if wait_result.0 != 0 {
            return Err(MiscError::Timeout);
        }

        Ok(())
    }
}
