//! NSI port hiding - Rust bindings for PortHide IOCTLs

use crate::driver::open_device;
use crate::error::CallbackError;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::IO::DeviceIoControl;

// IOCTL codes: CTL_CODE(FILE_DEVICE_UNKNOWN=0x22, function, METHOD_BUFFERED=0, FILE_ANY_ACCESS=0)
// 0x8A0 << 2 = 0x2280, base = 0x00220000 => 0x00222280
const IOCTL_DIOPROCESS_PORT_HIDE: u32 = 0x00222280;
const IOCTL_DIOPROCESS_PORT_UNHIDE: u32 = 0x00222284;
const IOCTL_DIOPROCESS_PORT_HIDE_LIST: u32 = 0x00222288;

/// Maximum entries matching kernel side
const MAX_PORTHIDE_ENTRIES: usize = 64;

/// Info about a hidden port
#[derive(Debug, Clone)]
pub struct HiddenPortInfo {
    pub port: u16,
    pub index: u32,
}

/// Request struct matching kernel PortHideRequest
#[repr(C)]
struct PortHideRequest {
    port: u16,
}

/// Request struct matching kernel PortUnhideRequest
#[repr(C)]
struct PortUnhideRequest {
    index: u32,
}

/// Single entry matching kernel HiddenPortEntry
#[repr(C)]
#[derive(Clone, Copy)]
struct HiddenPortEntry {
    port: u16,
    _padding: u16, // alignment padding before index
    index: u32,
}

/// Response struct matching kernel PortHideListResponse
#[repr(C)]
struct PortHideListResponse {
    count: u32,
    entries: [HiddenPortEntry; MAX_PORTHIDE_ENTRIES],
}

/// Hide a TCP port via NSI hook
pub fn port_hide(port: u16) -> Result<(), CallbackError> {
    let handle = open_device()?;

    let request = PortHideRequest { port };

    let result = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_PORT_HIDE,
            Some(&request as *const _ as *const std::ffi::c_void),
            std::mem::size_of::<PortHideRequest>() as u32,
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

/// Unhide a TCP port by index
pub fn port_unhide(index: u32) -> Result<(), CallbackError> {
    let handle = open_device()?;

    let request = PortUnhideRequest { index };

    let result = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_PORT_UNHIDE,
            Some(&request as *const _ as *const std::ffi::c_void),
            std::mem::size_of::<PortUnhideRequest>() as u32,
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

/// List all currently hidden ports
pub fn port_hide_list() -> Result<Vec<HiddenPortInfo>, CallbackError> {
    let handle = open_device()?;

    let mut response = unsafe { std::mem::zeroed::<PortHideListResponse>() };
    let mut bytes_returned = 0u32;

    let result = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_PORT_HIDE_LIST,
            None,
            0,
            Some(&mut response as *mut _ as *mut std::ffi::c_void),
            std::mem::size_of::<PortHideListResponse>() as u32,
            Some(&mut bytes_returned),
            None,
        )
    };

    unsafe { let _ = CloseHandle(handle); }

    match result {
        Ok(_) => {
            let count = response.count as usize;
            let mut entries = Vec::with_capacity(count);
            for i in 0..count.min(MAX_PORTHIDE_ENTRIES) {
                entries.push(HiddenPortInfo {
                    port: response.entries[i].port,
                    index: response.entries[i].index,
                });
            }
            Ok(entries)
        }
        Err(e) => Err(CallbackError::IoctlFailed(e.code().0 as u32)),
    }
}
