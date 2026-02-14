//! File hiding via minifilter - Rust bindings for FileHide IOCTLs

use crate::driver::open_device;
use crate::error::CallbackError;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::IO::DeviceIoControl;

// IOCTL codes: CTL_CODE(FILE_DEVICE_UNKNOWN=0x22, function, METHOD_BUFFERED=0, FILE_ANY_ACCESS=0)
// 0x870 << 2 = 0x21C0, base = 0x00220000 => 0x002221C0
const IOCTL_DIOPROCESS_FILEHIDE_HIDE: u32 = 0x002221C0;
const IOCTL_DIOPROCESS_FILEHIDE_UNHIDE: u32 = 0x002221C4;
const IOCTL_DIOPROCESS_FILEHIDE_LIST: u32 = 0x002221C8;

/// Maximum path length (WCHARs) matching kernel side
const FILEHIDE_MAX_PATH: usize = 260;

/// Maximum entries matching kernel side
const MAX_FILEHIDE_ENTRIES: usize = 128;

/// Info about a hidden file path
#[derive(Debug, Clone)]
pub struct HiddenFileInfo {
    pub path: String,
}

/// Request struct matching kernel FileHideRequest (260 WCHARs = 520 bytes)
#[repr(C)]
struct FileHideRequest {
    file_path: [u16; FILEHIDE_MAX_PATH],
}

/// Single entry in list response
#[repr(C)]
struct HiddenFileEntry {
    file_path: [u16; FILEHIDE_MAX_PATH],
}

/// Response struct matching kernel FileHideListResponse
#[repr(C)]
struct FileHideListResponse {
    count: u32,
    entries: [HiddenFileEntry; MAX_FILEHIDE_ENTRIES],
}

/// Convert a Rust &str path to a fixed-size u16 array for the kernel request
fn path_to_wide_array(path: &str) -> [u16; FILEHIDE_MAX_PATH] {
    let mut buf = [0u16; FILEHIDE_MAX_PATH];
    let wide: Vec<u16> = OsStr::new(path).encode_wide().collect();
    let copy_len = wide.len().min(FILEHIDE_MAX_PATH - 1);
    buf[..copy_len].copy_from_slice(&wide[..copy_len]);
    buf
}

/// Convert a null-terminated u16 slice to a Rust String
fn wide_to_string(wide: &[u16]) -> String {
    let len = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
    String::from_utf16_lossy(&wide[..len])
}

/// Hide a file or folder by full DOS path (e.g., "C:\\secret\\file.txt")
pub fn filehide_add(path: &str) -> Result<(), CallbackError> {
    let handle = open_device()?;

    let request = FileHideRequest {
        file_path: path_to_wide_array(path),
    };

    let result = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_FILEHIDE_HIDE,
            Some(&request as *const _ as *const std::ffi::c_void),
            std::mem::size_of::<FileHideRequest>() as u32,
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

/// Unhide a previously hidden file or folder
pub fn filehide_remove(path: &str) -> Result<(), CallbackError> {
    let handle = open_device()?;

    let request = FileHideRequest {
        file_path: path_to_wide_array(path),
    };

    let result = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_FILEHIDE_UNHIDE,
            Some(&request as *const _ as *const std::ffi::c_void),
            std::mem::size_of::<FileHideRequest>() as u32,
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

/// List all currently hidden file paths
pub fn filehide_list() -> Result<Vec<HiddenFileInfo>, CallbackError> {
    let handle = open_device()?;

    let mut response = unsafe { std::mem::zeroed::<FileHideListResponse>() };
    let mut bytes_returned = 0u32;

    let result = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_FILEHIDE_LIST,
            None,
            0,
            Some(&mut response as *mut _ as *mut std::ffi::c_void),
            std::mem::size_of::<FileHideListResponse>() as u32,
            Some(&mut bytes_returned),
            None,
        )
    };

    unsafe { let _ = CloseHandle(handle); }

    match result {
        Ok(_) => {
            let count = response.count as usize;
            let mut entries = Vec::with_capacity(count);
            for i in 0..count.min(MAX_FILEHIDE_ENTRIES) {
                let path = wide_to_string(&response.entries[i].file_path);
                if !path.is_empty() {
                    entries.push(HiddenFileInfo { path });
                }
            }
            Ok(entries)
        }
        Err(e) => Err(CallbackError::IoctlFailed(e.code().0 as u32)),
    }
}
