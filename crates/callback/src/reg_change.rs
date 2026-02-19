//! EPT register change hook management module
//!
//! Provides communication with the DioProcess kernel driver to install
//! register change hooks that modify guest registers at a specific RIP
//! via EPT + MTF (no code patching needed).

use crate::error::CallbackError;
use std::ffi::c_void;
use std::mem::size_of;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::IO::DeviceIoControl;
use windows::core::PCWSTR;

// IOCTL codes - must match DioProcessCommon.h
const FILE_DEVICE_UNKNOWN: u32 = 0x22;
const METHOD_BUFFERED: u32 = 0;
const FILE_ANY_ACCESS: u32 = 0;

const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}

const IOCTL_DIOPROCESS_REG_CHANGE_INSTALL: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, 0x8C0, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_DIOPROCESS_REG_CHANGE_REMOVE: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, 0x8C1, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_DIOPROCESS_REG_CHANGE_LIST: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, 0x8C2, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_DIOPROCESS_REG_CHANGE_REMOVE_ALL: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, 0x8C3, METHOD_BUFFERED, FILE_ANY_ACCESS);

const MAX_REG_CHANGES: usize = 32;

const DEVICE_PATH: &str = "\\\\.\\DioProcess\0";

// ============== Request/Response Structures ==============

#[repr(C)]
struct RegChangeInstallRequest {
    process_id: u32,
    target_address: u64,
    reg_index: u32,
    new_value: u64,
}

#[repr(C)]
struct RegChangeInstallResponse {
    entry_index: u32,
    success: u8, // BOOLEAN
}

#[repr(C)]
struct RegChangeRemoveRequest {
    entry_index: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RegChangeListEntry {
    process_id: u32,
    target_address: u64,
    reg_index: u32,
    new_value: u64,
    entry_index: u32,
    active: u8, // BOOLEAN
}

#[repr(C)]
struct RegChangeListResponse {
    count: u32,
    entries: [RegChangeListEntry; MAX_REG_CHANGES],
}

// ============== Public Types ==============

/// Information about an active register change hook
#[derive(Debug, Clone)]
pub struct RegChangeInfo {
    pub process_id: u32,
    pub target_address: u64,
    pub reg_index: u32,
    pub new_value: u64,
    pub entry_index: u32,
    pub active: bool,
}

/// Register names for display (0-15 = GPRs, 16-21 = individual RFLAGS flags)
pub const REG_NAMES: [&str; 22] = [
    "RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI",
    "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
    "CF", "PF", "AF", "ZF", "SF", "OF",
];

// ============== Driver Communication ==============

fn open_driver() -> Result<HANDLE, CallbackError> {
    let device_path: Vec<u16> = DEVICE_PATH.encode_utf16().collect();

    let handle = unsafe {
        CreateFileW(
            PCWSTR(device_path.as_ptr()),
            0x80000000 | 0x40000000, // GENERIC_READ | GENERIC_WRITE
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            HANDLE::default(),
        )
    };

    match handle {
        Ok(h) => {
            if h.is_invalid() {
                Err(CallbackError::DriverNotFound)
            } else {
                Ok(h)
            }
        }
        Err(_) => Err(CallbackError::DriverNotFound),
    }
}

/// Install a register change hook.
///
/// When execution reaches `target_va` in the target process, the hypervisor
/// modifies the specified register to `new_value` before the instruction runs.
///
/// Returns the entry index (used for removal).
pub fn install_reg_change(
    pid: u32,
    target_va: u64,
    reg_index: u32,
    new_value: u64,
) -> Result<u32, CallbackError> {
    if reg_index > 21 {
        return Err(CallbackError::InvalidParameter);
    }

    let handle = open_driver()?;

    let request = RegChangeInstallRequest {
        process_id: pid,
        target_address: target_va,
        reg_index,
        new_value,
    };

    let mut response = RegChangeInstallResponse {
        entry_index: 0,
        success: 0,
    };
    let mut bytes_returned: u32 = 0;

    let result = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_REG_CHANGE_INSTALL,
            Some(&request as *const _ as *const c_void),
            size_of::<RegChangeInstallRequest>() as u32,
            Some(&mut response as *mut _ as *mut c_void),
            size_of::<RegChangeInstallResponse>() as u32,
            Some(&mut bytes_returned),
            None,
        )
    };

    unsafe {
        let _ = CloseHandle(handle);
    }

    if result.is_ok() && response.success != 0 {
        Ok(response.entry_index)
    } else {
        Err(CallbackError::IoctlFailed(
            std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(0) as u32,
        ))
    }
}

/// Remove a register change hook by its entry index.
pub fn remove_reg_change(entry_index: u32) -> Result<(), CallbackError> {
    let handle = open_driver()?;

    let request = RegChangeRemoveRequest { entry_index };
    let mut bytes_returned: u32 = 0;

    let result = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_REG_CHANGE_REMOVE,
            Some(&request as *const _ as *const c_void),
            size_of::<RegChangeRemoveRequest>() as u32,
            None,
            0,
            Some(&mut bytes_returned),
            None,
        )
    };

    unsafe {
        let _ = CloseHandle(handle);
    }

    if result.is_ok() {
        Ok(())
    } else {
        Err(CallbackError::IoctlFailed(
            std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(0) as u32,
        ))
    }
}

/// List all active register change hooks.
pub fn list_reg_changes() -> Result<Vec<RegChangeInfo>, CallbackError> {
    let handle = open_driver()?;

    let mut response = RegChangeListResponse {
        count: 0,
        entries: [RegChangeListEntry {
            process_id: 0,
            target_address: 0,
            reg_index: 0,
            new_value: 0,
            entry_index: 0,
            active: 0,
        }; MAX_REG_CHANGES],
    };
    let mut bytes_returned: u32 = 0;

    let result = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_REG_CHANGE_LIST,
            None,
            0,
            Some(&mut response as *mut _ as *mut c_void),
            size_of::<RegChangeListResponse>() as u32,
            Some(&mut bytes_returned),
            None,
        )
    };

    unsafe {
        let _ = CloseHandle(handle);
    }

    if result.is_ok() {
        let count = response.count as usize;
        let mut changes = Vec::with_capacity(count);
        for i in 0..count.min(MAX_REG_CHANGES) {
            let entry = &response.entries[i];
            changes.push(RegChangeInfo {
                process_id: entry.process_id,
                target_address: entry.target_address,
                reg_index: entry.reg_index,
                new_value: entry.new_value,
                entry_index: entry.entry_index,
                active: entry.active != 0,
            });
        }
        Ok(changes)
    } else {
        Err(CallbackError::IoctlFailed(
            std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(0) as u32,
        ))
    }
}

/// Remove all register change hooks.
pub fn remove_all_reg_changes() -> Result<(), CallbackError> {
    let handle = open_driver()?;

    let mut bytes_returned: u32 = 0;

    let result = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_REG_CHANGE_REMOVE_ALL,
            None,
            0,
            None,
            0,
            Some(&mut bytes_returned),
            None,
        )
    };

    unsafe {
        let _ = CloseHandle(handle);
    }

    if result.is_ok() {
        Ok(())
    } else {
        Err(CallbackError::IoctlFailed(
            std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(0) as u32,
        ))
    }
}
