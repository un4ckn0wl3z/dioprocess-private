use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_DECOMMIT, MEM_RELEASE, PAGE_READWRITE, VirtualAllocEx, VirtualFreeEx,
};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_VM_OPERATION};

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
