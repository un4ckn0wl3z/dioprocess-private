use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_DECOMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE,
    VirtualAllocEx, VirtualFreeEx,
};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
};
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;

use crate::error::MiscError;

/// Commit a reserved memory region in a target process.
pub fn commit_memory(pid: u32, address: usize, size: usize) -> Result<(), MiscError> {
    unsafe {
        let process_handle = OpenProcess(PROCESS_VM_OPERATION, false, pid)
            .map_err(|_| MiscError::OpenProcessFailed(pid))?;

        let result = VirtualAllocEx(
            process_handle,
            Some(address as *const _),
            size,
            MEM_COMMIT,
            PAGE_READWRITE,
        );

        let _ = CloseHandle(process_handle);

        if result.is_null() {
            return Err(MiscError::CommitFailed(format!(
                "VirtualAllocEx failed at 0x{:X}",
                address
            )));
        }

        Ok(())
    }
}

/// Decommit a committed memory region in a target process.
pub fn decommit_memory(pid: u32, address: usize, size: usize) -> Result<(), MiscError> {
    unsafe {
        let process_handle = OpenProcess(PROCESS_VM_OPERATION, false, pid)
            .map_err(|_| MiscError::OpenProcessFailed(pid))?;

        let result = VirtualFreeEx(process_handle, address as *mut _, size, MEM_DECOMMIT);

        let _ = CloseHandle(process_handle);

        result.map_err(|e| {
            MiscError::DecommitFailed(format!("VirtualFreeEx failed at 0x{:X}: {}", address, e))
        })
    }
}

/// Allocate RWX memory in a target process near a target address (within ±2GB for JMP rel32).
/// Scans from target downward then upward in 64KB steps to find a free region.
/// Returns the allocated address.
pub fn allocate_near_address(pid: u32, target: u64, size: usize) -> Result<u64, MiscError> {
    unsafe {
        let process_handle = OpenProcess(
            PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
            false,
            pid,
        )
        .map_err(|_| MiscError::OpenProcessFailed(pid))?;

        let alloc_size = if size < 0x1000 { 0x1000 } else { (size + 0xFFF) & !0xFFF };
        let alloc_granularity: u64 = 0x10000; // 64KB Windows allocation granularity
        let max_range: u64 = 0x7FFF_0000; // ~2GB range for JMP rel32

        // Align target down to granularity boundary
        let base = target & !(alloc_granularity - 1);

        // Try addresses below target first, then above
        let mut result = std::ptr::null_mut();
        for step in 1..=(max_range / alloc_granularity) {
            // Try below
            if let Some(addr) = base.checked_sub(step * alloc_granularity) {
                if addr >= 0x10000 {
                    let ptr = VirtualAllocEx(
                        process_handle,
                        Some(addr as *const _),
                        alloc_size,
                        MEM_COMMIT | MEM_RESERVE,
                        PAGE_EXECUTE_READWRITE,
                    );
                    if !ptr.is_null() {
                        result = ptr;
                        break;
                    }
                }
            }
            // Try above
            let addr = base + step * alloc_granularity;
            if addr < 0x7FFF_FFFE_0000 {
                let ptr = VirtualAllocEx(
                    process_handle,
                    Some(addr as *const _),
                    alloc_size,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE,
                );
                if !ptr.is_null() {
                    result = ptr;
                    break;
                }
            }
        }

        let _ = CloseHandle(process_handle);

        if result.is_null() {
            return Err(MiscError::AllocFailed);
        }

        Ok(result as u64)
    }
}

/// Write bytes to a target process's memory.
pub fn write_process_memory_bytes(pid: u32, addr: u64, data: &[u8]) -> Result<(), MiscError> {
    unsafe {
        let process_handle = OpenProcess(
            PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
            false,
            pid,
        )
        .map_err(|_| MiscError::OpenProcessFailed(pid))?;

        let result = WriteProcessMemory(
            process_handle,
            addr as *const _,
            data.as_ptr() as *const _,
            data.len(),
            None,
        );

        let _ = CloseHandle(process_handle);

        result.map_err(|_| MiscError::WriteFailed)
    }
}

/// Free a remote allocation in a target process.
pub fn free_remote_memory(pid: u32, addr: u64) -> Result<(), MiscError> {
    unsafe {
        let process_handle = OpenProcess(PROCESS_VM_OPERATION, false, pid)
            .map_err(|_| MiscError::OpenProcessFailed(pid))?;

        let result = VirtualFreeEx(process_handle, addr as *mut _, 0, MEM_RELEASE);

        let _ = CloseHandle(process_handle);

        result.map_err(|e| {
            MiscError::FreeFailed(format!("VirtualFreeEx failed at 0x{:X}: {}", addr, e))
        })
    }
}

/// Free an entire allocation in a target process (uses allocation_base, size must be 0).
pub fn free_memory(pid: u32, allocation_base: usize) -> Result<(), MiscError> {
    unsafe {
        let process_handle = OpenProcess(PROCESS_VM_OPERATION, false, pid)
            .map_err(|_| MiscError::OpenProcessFailed(pid))?;

        let result = VirtualFreeEx(process_handle, allocation_base as *mut _, 0, MEM_RELEASE);

        let _ = CloseHandle(process_handle);

        result.map_err(|e| {
            MiscError::FreeFailed(format!(
                "VirtualFreeEx failed at 0x{:X}: {}",
                allocation_base, e
            ))
        })
    }
}
