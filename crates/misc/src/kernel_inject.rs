//! Kernel-mode shellcode injection
//!
//! Based on RtlCreateUserThread technique - allocates memory and creates thread from kernel mode

use crate::MiscError;
use std::ffi::OsStr;
use std::iter::once;
use std::mem;
use std::os::windows::ffi::OsStrExt;
use windows::core::PCWSTR;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_NONE, OPEN_EXISTING,
};
use windows::Win32::System::IO::DeviceIoControl;

const DEVICE_PATH: &str = "\\\\.\\DioProcess";
const IOCTL_DIOPROCESS_KERNEL_INJECT_SHELLCODE: u32 = 0x00222030;
const IOCTL_DIOPROCESS_KERNEL_INJECT_DLL: u32 = 0x00222034;
const MAX_DLL_PATH_LENGTH: usize = 520;

#[repr(C)]
struct KernelInjectShellcodeRequest {
    target_process_id: u32,
    shellcode_size: u32,
    shellcode: [u8; 1], // Variable length
}

#[repr(C)]
struct KernelInjectShellcodeResponse {
    allocated_address: u64,
    success: u8, // BOOLEAN
}

#[repr(C)]
struct KernelInjectDllRequest {
    target_process_id: u32,
    dll_path: [u16; MAX_DLL_PATH_LENGTH],
}

#[repr(C)]
struct KernelInjectDllResponse {
    allocated_address: u64,
    load_library_address: u64,
    success: u8, // BOOLEAN
}

/// Check if the DioProcess kernel driver is loaded
pub fn is_kernel_driver_loaded() -> bool {
    callback::is_driver_loaded()
}

/// Inject shellcode into a process using kernel-mode technique
///
/// This uses RtlCreateUserThread from kernel mode to create a thread
/// that executes the shellcode. The memory allocation and thread creation
/// happen entirely in kernel space, bypassing usermode hooks.
///
/// # Arguments
/// * `pid` - Target process ID
/// * `shellcode` - Shellcode bytes to inject
///
/// # Returns
/// Ok(address) where shellcode was written, or Err(MiscError)
pub fn kernel_inject_shellcode(pid: u32, shellcode: &[u8]) -> Result<u64, MiscError> {
    if shellcode.is_empty() {
        return Err(MiscError::IoctlError("Shellcode is empty".to_string()));
    }

    unsafe {
        // Open device
        let device_path_wide: Vec<u16> = OsStr::new(DEVICE_PATH)
            .encode_wide()
            .chain(once(0))
            .collect();

        let handle = CreateFileW(
            PCWSTR(device_path_wide.as_ptr()),
            0xC0000000, // GENERIC_READ | GENERIC_WRITE
            FILE_SHARE_NONE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        .map_err(|e| {
            MiscError::IoctlError(format!("Failed to open driver (is it loaded?): {}", e))
        })?;

        // Allocate request buffer with variable-length shellcode
        let request_size = mem::size_of::<KernelInjectShellcodeRequest>() - 1 + shellcode.len();
        let mut buffer: Vec<u8> = vec![0; request_size];

        // Set header fields
        let request = buffer.as_mut_ptr() as *mut KernelInjectShellcodeRequest;
        (*request).target_process_id = pid;
        (*request).shellcode_size = shellcode.len() as u32;

        // Copy shellcode
        let shellcode_offset = mem::size_of::<KernelInjectShellcodeRequest>() - 1;
        buffer[shellcode_offset..].copy_from_slice(shellcode);

        // Prepare response buffer
        let mut response = KernelInjectShellcodeResponse {
            allocated_address: 0,
            success: 0,
        };

        let mut bytes_returned: u32 = 0;
        let result = DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_KERNEL_INJECT_SHELLCODE,
            Some(buffer.as_ptr() as *const _),
            request_size as u32,
            Some(&mut response as *mut _ as *mut _),
            mem::size_of::<KernelInjectShellcodeResponse>() as u32,
            Some(&mut bytes_returned),
            None,
        );

        CloseHandle(handle).ok();

        if result.is_err() {
            return Err(MiscError::IoctlError(format!(
                "DeviceIoControl failed: {}",
                result.err().unwrap()
            )));
        }

        if response.success == 0 {
            return Err(MiscError::IoctlError(
                "Kernel injection failed (driver returned error)".to_string(),
            ));
        }

        Ok(response.allocated_address)
    }
}

/// Inject a DLL into a process using kernel-mode technique
///
/// This uses RtlCreateUserThread from kernel mode to create a thread
/// that calls LoadLibraryW with the DLL path. The memory allocation,
/// path writing, and thread creation happen entirely in kernel space.
///
/// # Arguments
/// * `pid` - Target process ID
/// * `dll_path` - Full path to the DLL file
///
/// # Returns
/// Ok((dll_path_address, loadlibrary_address)) or Err(MiscError)
pub fn kernel_inject_dll(pid: u32, dll_path: &str) -> Result<(u64, u64), MiscError> {
    if dll_path.is_empty() {
        return Err(MiscError::IoctlError("DLL path is empty".to_string()));
    }

    unsafe {
        // Open device
        let device_path_wide: Vec<u16> = OsStr::new(DEVICE_PATH)
            .encode_wide()
            .chain(once(0))
            .collect();

        let handle = CreateFileW(
            PCWSTR(device_path_wide.as_ptr()),
            0xC0000000, // GENERIC_READ | GENERIC_WRITE
            FILE_SHARE_NONE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        .map_err(|e| {
            MiscError::IoctlError(format!("Failed to open driver (is it loaded?): {}", e))
        })?;

        // Prepare request
        let mut request = KernelInjectDllRequest {
            target_process_id: pid,
            dll_path: [0; MAX_DLL_PATH_LENGTH],
        };

        // Convert DLL path to wide string
        let dll_path_wide: Vec<u16> = OsStr::new(dll_path)
            .encode_wide()
            .chain(once(0))
            .collect();

        if dll_path_wide.len() > MAX_DLL_PATH_LENGTH {
            CloseHandle(handle).ok();
            return Err(MiscError::IoctlError("DLL path too long".to_string()));
        }

        request.dll_path[..dll_path_wide.len()].copy_from_slice(&dll_path_wide);

        // Prepare response buffer
        let mut response = KernelInjectDllResponse {
            allocated_address: 0,
            load_library_address: 0,
            success: 0,
        };

        let mut bytes_returned: u32 = 0;
        let result = DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_KERNEL_INJECT_DLL,
            Some(&request as *const _ as *const _),
            mem::size_of::<KernelInjectDllRequest>() as u32,
            Some(&mut response as *mut _ as *mut _),
            mem::size_of::<KernelInjectDllResponse>() as u32,
            Some(&mut bytes_returned),
            None,
        );

        CloseHandle(handle).ok();

        if result.is_err() {
            return Err(MiscError::IoctlError(format!(
                "DeviceIoControl failed: {}",
                result.err().unwrap()
            )));
        }

        if response.success == 0 {
            return Err(MiscError::IoctlError(
                "Kernel DLL injection failed (driver returned error)".to_string(),
            ));
        }

        Ok((response.allocated_address, response.load_library_address))
    }
}
