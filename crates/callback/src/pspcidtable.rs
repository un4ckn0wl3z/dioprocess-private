//! PspCidTable kernel handle table enumeration
//!
//! Enumerates all processes and threads by parsing the PspCidTable kernel handle table.
//! Uses signature scanning to dynamically locate PspCidTable (no hardcoded offsets).
//! Read-only operation - PatchGuard/KPP safe.

use crate::CallbackError;
use std::ffi::OsStr;
use std::iter::once;
use std::mem;
use std::os::windows::ffi::OsStrExt;
use windows::core::PCWSTR;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::IO::DeviceIoControl;

const DEVICE_PATH: &str = "\\\\.\\DioProcess";
const IOCTL_DIOPROCESS_ENUM_PSPCIDTABLE: u32 = 0x0022203C;
const MAX_CID_ENTRIES: usize = 2048;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CidObjectType {
    Process = 1,
    Thread = 2,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CidEntry {
    pub id: u32,              // PID or TID
    pub object_address: u64,  // EPROCESS or ETHREAD address
    pub object_type: CidObjectType,
    pub parent_pid: u32,      // Parent PID (for processes) or owning process PID (for threads)
    pub process_name: [u8; 16],  // Process name from ImageFileName (ANSI, null-terminated)
}

impl CidEntry {
    /// Get the process name as a UTF-8 string
    pub fn process_name_str(&self) -> String {
        // Find null terminator
        let len = self.process_name.iter()
            .position(|&c| c == 0)
            .unwrap_or(self.process_name.len());

        // Convert to string, replacing invalid UTF-8 with �
        String::from_utf8_lossy(&self.process_name[..len]).into_owned()
    }
}

#[repr(C)]
struct EnumCidTableResponse {
    count: u32,
    entries: [CidEntry; 1], // Variable length
}

/// Enumerate all processes and threads via PspCidTable
///
/// This reads the kernel's PspCidTable handle table and returns all process/thread entries.
/// Uses signature scanning to locate PspCidTable dynamically (no hardcoded offsets).
///
/// # Returns
/// Vector of CidEntry structs containing PID/TID, object address, and type
///
/// # Errors
/// Returns CallbackError if driver not loaded or enumeration fails
pub fn enumerate_pspcidtable() -> Result<Vec<CidEntry>, CallbackError> {
    unsafe {
        // Open device
        let device_path_wide: Vec<u16> = OsStr::new(DEVICE_PATH)
            .encode_wide()
            .chain(once(0))
            .collect();

        let handle = CreateFileW(
            PCWSTR(device_path_wide.as_ptr()),
            0xC0000000, // GENERIC_READ | GENERIC_WRITE
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        .map_err(|_| {
            CallbackError::DriverNotFound
        })?;

        // Prepare response buffer
        let buffer_size = mem::size_of::<EnumCidTableResponse>() +
                         (mem::size_of::<CidEntry>() * (MAX_CID_ENTRIES - 1));
        let mut buffer: Vec<u8> = vec![0; buffer_size];

        let mut bytes_returned: u32 = 0;
        let result = DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_ENUM_PSPCIDTABLE,
            None,
            0,
            Some(buffer.as_mut_ptr() as *mut _),
            buffer_size as u32,
            Some(&mut bytes_returned),
            None,
        );

        CloseHandle(handle).ok();

        if result.is_err() {
            return Err(CallbackError::IoctlFailed(0));
        }

        // Parse response
        let response = buffer.as_ptr() as *const EnumCidTableResponse;
        let count = (*response).count as usize;

        if count == 0 {
            return Ok(Vec::new());
        }

        // Copy entries from variable-length array
        let entries_ptr = (*response).entries.as_ptr();
        let mut entries = Vec::with_capacity(count);
        for i in 0..count {
            entries.push(*entries_ptr.add(i));
        }

        Ok(entries)
    }
}
