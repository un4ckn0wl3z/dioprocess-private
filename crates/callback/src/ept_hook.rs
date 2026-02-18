//! Usermode EPT hook management module
//!
//! Provides communication with the DioProcess kernel driver to install
//! EPT split-page hooks on usermode process pages:
//! - Read/write access sees original bytes (passes integrity checks)
//! - Execute access routes to patched bytes (custom behavior)

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

const IOCTL_DIOPROCESS_EPT_HOOK_INSTALL: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, 0x8B0, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_DIOPROCESS_EPT_HOOK_REMOVE: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, 0x8B1, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_DIOPROCESS_EPT_HOOK_LIST: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, 0x8B2, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_DIOPROCESS_EPT_HOOK_INSTALL_DETOUR: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, 0x8B3, METHOD_BUFFERED, FILE_ANY_ACCESS);

const MAX_EPT_HOOK_LIST_ENTRIES: usize = 32;
const MAX_EPT_HOOK_DETOUR_SIZE: usize = 3800;

const DEVICE_PATH: &str = "\\\\.\\DioProcess\0";

// ============== Request/Response Structures ==============

#[repr(C)]
struct EptHookInstallRequest {
    process_id: u32,
    target_virtual_address: u64,
    patch_size: u32,
    patch_bytes: [u8; 256],
}

#[repr(C)]
struct EptHookInstallResponse {
    hook_index: u32,
    success: u8, // BOOLEAN
}

#[repr(C)]
struct EptHookDetourRequest {
    process_id: u32,
    target_virtual_address: u64,
    stolen_bytes: u32,
    detour_page_offset: u32,
    detour_code_size: u32,
    detour_code: [u8; MAX_EPT_HOOK_DETOUR_SIZE],
}

#[repr(C)]
struct EptHookRemoveRequest {
    hook_index: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct EptHookListEntry {
    process_id: u32,
    target_virtual_address: u64,
    patch_size: u32,
    hook_index: u32,
    active: u8, // BOOLEAN
}

#[repr(C)]
struct EptHookListResponse {
    count: u32,
    entries: [EptHookListEntry; MAX_EPT_HOOK_LIST_ENTRIES],
}

// ============== Public Types ==============

/// Information about an active EPT hook
#[derive(Debug, Clone)]
pub struct EptHookInfo {
    pub process_id: u32,
    pub target_address: u64,
    pub patch_size: u32,
    pub hook_index: u32,
    pub active: bool,
}

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

/// Install an EPT split-page hook on a usermode process page.
///
/// Read/write access to the hooked page sees the original bytes (integrity checks pass).
/// Execute access routes to the patched bytes (custom behavior runs).
///
/// Requirements:
/// - Hypervisor must be running
/// - patch_bytes must not cross a page boundary from target_va
/// - patch_bytes max 256 bytes
///
/// Returns the hook index (used for removal).
pub fn install_ept_hook(
    pid: u32,
    target_va: u64,
    patch_bytes: &[u8],
) -> Result<u32, CallbackError> {
    if patch_bytes.is_empty() || patch_bytes.len() > 256 {
        return Err(CallbackError::InvalidParameter);
    }

    let handle = open_driver()?;

    let mut request = EptHookInstallRequest {
        process_id: pid,
        target_virtual_address: target_va,
        patch_size: patch_bytes.len() as u32,
        patch_bytes: [0u8; 256],
    };
    request.patch_bytes[..patch_bytes.len()].copy_from_slice(patch_bytes);

    let mut response = EptHookInstallResponse {
        hook_index: 0,
        success: 0,
    };
    let mut bytes_returned: u32 = 0;

    let result = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_EPT_HOOK_INSTALL,
            Some(&request as *const _ as *const c_void),
            size_of::<EptHookInstallRequest>() as u32,
            Some(&mut response as *mut _ as *mut c_void),
            size_of::<EptHookInstallResponse>() as u32,
            Some(&mut bytes_returned),
            None,
        )
    };

    unsafe {
        let _ = CloseHandle(handle);
    }

    if result.is_ok() && response.success != 0 {
        Ok(response.hook_index)
    } else {
        Err(CallbackError::IoctlFailed(
            std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(0) as u32,
        ))
    }
}

/// Install an EPT hook with a detour: places a JMP at target_va that redirects to a
/// code cave elsewhere on the same 4KB page. Allows up to 3800 bytes of detour code.
///
/// - `stolen_bytes`: number of bytes at target_va to overwrite with JMP+NOPs (min 5)
/// - `detour_page_offset`: offset within the 4KB page where detour code is placed
/// - `detour_code`: the assembled detour code bytes (max 3800)
///
/// Returns the hook index (used for removal).
pub fn install_ept_hook_detour(
    pid: u32,
    target_va: u64,
    stolen_bytes: u32,
    detour_page_offset: u32,
    detour_code: &[u8],
) -> Result<u32, CallbackError> {
    if detour_code.is_empty() || detour_code.len() > MAX_EPT_HOOK_DETOUR_SIZE {
        return Err(CallbackError::InvalidParameter);
    }
    if stolen_bytes < 5 {
        return Err(CallbackError::InvalidParameter);
    }

    let handle = open_driver()?;

    let mut request = EptHookDetourRequest {
        process_id: pid,
        target_virtual_address: target_va,
        stolen_bytes,
        detour_page_offset,
        detour_code_size: detour_code.len() as u32,
        detour_code: [0u8; MAX_EPT_HOOK_DETOUR_SIZE],
    };
    request.detour_code[..detour_code.len()].copy_from_slice(detour_code);

    let mut response = EptHookInstallResponse {
        hook_index: 0,
        success: 0,
    };
    let mut bytes_returned: u32 = 0;

    let result = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_EPT_HOOK_INSTALL_DETOUR,
            Some(&request as *const _ as *const c_void),
            size_of::<EptHookDetourRequest>() as u32,
            Some(&mut response as *mut _ as *mut c_void),
            size_of::<EptHookInstallResponse>() as u32,
            Some(&mut bytes_returned),
            None,
        )
    };

    unsafe {
        let _ = CloseHandle(handle);
    }

    if result.is_ok() && response.success != 0 {
        Ok(response.hook_index)
    } else {
        Err(CallbackError::IoctlFailed(
            std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(0) as u32,
        ))
    }
}

/// Remove an EPT hook by its index (returned from install_ept_hook).
pub fn remove_ept_hook(hook_index: u32) -> Result<(), CallbackError> {
    let handle = open_driver()?;

    let request = EptHookRemoveRequest { hook_index };
    let mut bytes_returned: u32 = 0;

    let result = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_EPT_HOOK_REMOVE,
            Some(&request as *const _ as *const c_void),
            size_of::<EptHookRemoveRequest>() as u32,
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

/// List all active EPT hooks.
pub fn list_ept_hooks() -> Result<Vec<EptHookInfo>, CallbackError> {
    let handle = open_driver()?;

    let mut response = EptHookListResponse {
        count: 0,
        entries: [EptHookListEntry {
            process_id: 0,
            target_virtual_address: 0,
            patch_size: 0,
            hook_index: 0,
            active: 0,
        }; MAX_EPT_HOOK_LIST_ENTRIES],
    };
    let mut bytes_returned: u32 = 0;

    let result = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_EPT_HOOK_LIST,
            None,
            0,
            Some(&mut response as *mut _ as *mut c_void),
            size_of::<EptHookListResponse>() as u32,
            Some(&mut bytes_returned),
            None,
        )
    };

    unsafe {
        let _ = CloseHandle(handle);
    }

    if result.is_ok() {
        let count = response.count as usize;
        let mut hooks = Vec::with_capacity(count);
        for i in 0..count.min(MAX_EPT_HOOK_LIST_ENTRIES) {
            let entry = &response.entries[i];
            hooks.push(EptHookInfo {
                process_id: entry.process_id,
                target_address: entry.target_virtual_address,
                patch_size: entry.patch_size,
                hook_index: entry.hook_index,
                active: entry.active != 0,
            });
        }
        Ok(hooks)
    } else {
        Err(CallbackError::IoctlFailed(
            std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(0) as u32,
        ))
    }
}
