//! Early Injection bindings
//!
//! Provides communication with the kernel driver for early DLL injection
//! (before any user code executes in the target process).

use crate::error::CallbackError;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::IO::DeviceIoControl;

const DEVICE_PATH: &str = r"\\.\DioProcess";

// IOCTL codes (CTL_CODE(0x22, code, 0, 0) = (0x22 << 16) | (code << 2))
const IOCTL_DIOPROCESS_EARLY_INJECT_ARM: u32 = 0x00222140; // 0x850
const IOCTL_DIOPROCESS_EARLY_INJECT_DISARM: u32 = 0x00222144; // 0x851
const IOCTL_DIOPROCESS_EARLY_INJECT_STATUS: u32 = 0x00222148; // 0x852

// Constants matching DioProcessCommon.h
const MAX_TARGET_PROCESS_NAME: usize = 64;
const MAX_DLL_PATH_LENGTH: usize = 520;

/// Injection method for early injection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum EarlyInjectionMethod {
    /// Hook LdrLoadDll at process creation via PsSetCreateProcessNotifyRoutineEx
    Trampoline = 0,
    /// Queue APC when kernel32.dll loads via PsSetLoadImageNotifyRoutine
    ApcCallback = 1,
}

impl EarlyInjectionMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Trampoline => "Trampoline",
            Self::ApcCallback => "APC Callback",
        }
    }
}

impl From<u32> for EarlyInjectionMethod {
    fn from(value: u32) -> Self {
        match value {
            0 => Self::Trampoline,
            1 => Self::ApcCallback,
            _ => Self::Trampoline, // Default fallback
        }
    }
}

/// Status of the early injection subsystem
#[derive(Debug, Clone)]
pub struct EarlyInjectionStatus {
    /// Whether early injection is armed and waiting for target
    pub armed: bool,
    /// Target process name pattern (e.g., "notepad.exe")
    pub target_process_name: String,
    /// Full path to DLL to inject
    pub dll_path: String,
    /// Injection method being used
    pub method: EarlyInjectionMethod,
    /// Number of successful injections
    pub injection_count: u32,
    /// PID of last injected process
    pub last_injected_pid: u32,
    /// NTSTATUS of last injection attempt
    pub last_status: i32,
    /// Whether one-shot mode is enabled
    pub one_shot: bool,
}

/// Request structure for arming early injection (matches kernel struct layout)
/// Kernel struct has WCHAR arrays first, then ULONG Method, then BOOLEAN OneShot
#[repr(C)]
struct EarlyInjectionArmRequest {
    target_process_name: [u16; MAX_TARGET_PROCESS_NAME], // WCHAR[64] = 128 bytes
    dll_path: [u16; MAX_DLL_PATH_LENGTH],                // WCHAR[520] = 1040 bytes
    method: u32,                                         // EarlyInjectionMethod (ULONG)
    one_shot: u32,                                       // BOOLEAN - use u32 for alignment padding
}

/// Response structure for early injection status (matches kernel struct layout)
/// Kernel struct: BOOLEAN Armed, WCHAR arrays, ULONG fields, BOOLEAN OneShot
#[repr(C)]
struct EarlyInjectionStatusResponse {
    armed: u8,                                           // BOOLEAN (1 byte)
    _pad1: u8,                                           // Padding for WCHAR alignment
    target_process_name: [u16; MAX_TARGET_PROCESS_NAME], // WCHAR[64] = 128 bytes
    dll_path: [u16; MAX_DLL_PATH_LENGTH],                // WCHAR[520] = 1040 bytes
    _pad2: [u8; 2],                                      // Padding for ULONG alignment
    method: u32,                                         // EarlyInjectionMethod (ULONG)
    injection_count: u32,                                // ULONG
    last_injected_pid: u32,                              // ULONG
    last_status: i32,                                    // NTSTATUS (LONG)
    one_shot: u8,                                        // BOOLEAN (1 byte)
    _pad3: [u8; 3],                                      // Final padding for struct alignment
}

/// Open a handle to the driver device
fn open_device() -> Result<HANDLE, CallbackError> {
    unsafe {
        let device_path: Vec<u16> = OsStr::new(DEVICE_PATH)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let handle = CreateFileW(
            windows::core::PCWSTR(device_path.as_ptr()),
            0x80000000 | 0x40000000, // GENERIC_READ | GENERIC_WRITE
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        );

        match handle {
            Ok(h) if h != INVALID_HANDLE_VALUE => Ok(h),
            Ok(_) => {
                let err = GetLastError();
                Err(CallbackError::DeviceOpenFailed(err.0))
            }
            Err(_) => {
                let err = GetLastError();
                if err.0 == 2 || err.0 == 3 {
                    Err(CallbackError::DriverNotFound)
                } else {
                    Err(CallbackError::DeviceOpenFailed(err.0))
                }
            }
        }
    }
}

/// Arm early injection to wait for a target process
///
/// When a process matching `target` is created (for Trampoline) or loads kernel32.dll
/// (for ApcCallback), the specified DLL will be injected before any user code executes.
///
/// # Arguments
/// * `target` - Process name to match (e.g., "notepad.exe")
/// * `dll_path` - Full path to the DLL to inject
/// * `method` - Injection technique to use
/// * `one_shot` - If true, disarm after first successful injection
pub fn arm_early_injection(
    target: &str,
    dll_path: &str,
    method: EarlyInjectionMethod,
    one_shot: bool,
) -> Result<(), CallbackError> {
    let handle = open_device()?;

    unsafe {
        // Build request structure
        let mut request = EarlyInjectionArmRequest {
            target_process_name: [0u16; MAX_TARGET_PROCESS_NAME],
            dll_path: [0u16; MAX_DLL_PATH_LENGTH],
            method: method as u32,
            one_shot: if one_shot { 1 } else { 0 },
        };

        // Copy target process name (ensure null termination)
        let target_wide: Vec<u16> = OsStr::new(target)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let copy_len = target_wide.len().min(MAX_TARGET_PROCESS_NAME - 1);
        request.target_process_name[..copy_len].copy_from_slice(&target_wide[..copy_len]);

        // Copy DLL path (ensure null termination)
        let dll_wide: Vec<u16> = OsStr::new(dll_path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let copy_len = dll_wide.len().min(MAX_DLL_PATH_LENGTH - 1);
        request.dll_path[..copy_len].copy_from_slice(&dll_wide[..copy_len]);

        let mut bytes_returned: u32 = 0;

        let result = DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_EARLY_INJECT_ARM,
            Some(&request as *const _ as *const _),
            std::mem::size_of::<EarlyInjectionArmRequest>() as u32,
            None,
            0,
            Some(&mut bytes_returned),
            None,
        );

        let _ = CloseHandle(handle);

        if result.is_err() {
            let err = GetLastError();
            return Err(CallbackError::IoctlFailed(err.0));
        }
    }

    Ok(())
}

/// Disarm early injection
///
/// Stops waiting for target processes and clears the armed state.
pub fn disarm_early_injection() -> Result<(), CallbackError> {
    let handle = open_device()?;

    unsafe {
        let mut bytes_returned: u32 = 0;

        let result = DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_EARLY_INJECT_DISARM,
            None,
            0,
            None,
            0,
            Some(&mut bytes_returned),
            None,
        );

        let _ = CloseHandle(handle);

        if result.is_err() {
            let err = GetLastError();
            return Err(CallbackError::IoctlFailed(err.0));
        }
    }

    Ok(())
}

/// Get the current early injection status
///
/// Returns information about whether early injection is armed,
/// the target process, injection count, and last injection result.
pub fn get_early_injection_status() -> Result<EarlyInjectionStatus, CallbackError> {
    let handle = open_device()?;

    unsafe {
        let mut response = EarlyInjectionStatusResponse {
            armed: 0,
            _pad1: 0,
            target_process_name: [0u16; MAX_TARGET_PROCESS_NAME],
            dll_path: [0u16; MAX_DLL_PATH_LENGTH],
            _pad2: [0; 2],
            method: 0,
            injection_count: 0,
            last_injected_pid: 0,
            last_status: 0,
            one_shot: 0,
            _pad3: [0; 3],
        };

        let mut bytes_returned: u32 = 0;

        let result = DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_EARLY_INJECT_STATUS,
            None,
            0,
            Some(&mut response as *mut _ as *mut _),
            std::mem::size_of::<EarlyInjectionStatusResponse>() as u32,
            Some(&mut bytes_returned),
            None,
        );

        let _ = CloseHandle(handle);

        if result.is_err() {
            let err = GetLastError();
            return Err(CallbackError::IoctlFailed(err.0));
        }

        // Convert wide strings to Rust strings
        let target_process_name = wide_to_string(&response.target_process_name);
        let dll_path = wide_to_string(&response.dll_path);

        Ok(EarlyInjectionStatus {
            armed: response.armed != 0,
            target_process_name,
            dll_path,
            method: EarlyInjectionMethod::from(response.method),
            injection_count: response.injection_count,
            last_injected_pid: response.last_injected_pid,
            last_status: response.last_status,
            one_shot: response.one_shot != 0,
        })
    }
}

/// Convert a null-terminated wide string buffer to a Rust String
fn wide_to_string(wide: &[u16]) -> String {
    let len = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
    String::from_utf16_lossy(&wide[..len])
}
