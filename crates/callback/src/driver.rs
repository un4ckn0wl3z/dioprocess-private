//! Driver communication functions

use crate::error::CallbackError;
use crate::types::{CallbackEvent, CollectionState, EventType, RegistryOperation};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE,
    OPEN_EXISTING,
};
use windows::Win32::System::IO::{DeviceIoControl, OVERLAPPED};

const DEVICE_PATH: &str = r"\\.\DioProcess";
const READ_BUFFER_SIZE: usize = 1024 * 1024; // 1MB buffer

// IOCTL codes (calculated using CTL_CODE macro: FILE_DEVICE_UNKNOWN=0x22, METHOD_BUFFERED=0, FILE_ANY_ACCESS=0)
// CTL_CODE(0x22, 0x800, 0, 0) = (0x22 << 16) | (0 << 14) | (0x800 << 2) | 0 = 0x00222000
const IOCTL_DIOPROCESS_START_COLLECTION: u32 = 0x00222000;
const IOCTL_DIOPROCESS_STOP_COLLECTION: u32 = 0x00222004;
const IOCTL_DIOPROCESS_GET_COLLECTION_STATE: u32 = 0x00222008;
const IOCTL_DIOPROCESS_REGISTER_CALLBACKS: u32 = 0x0022200C;
const IOCTL_DIOPROCESS_UNREGISTER_CALLBACKS: u32 = 0x00222010;
const IOCTL_DIOPROCESS_PROTECT_PROCESS: u32 = 0x00222014;
const IOCTL_DIOPROCESS_UNPROTECT_PROCESS: u32 = 0x00222018;
const IOCTL_DIOPROCESS_ENABLE_PRIVILEGES: u32 = 0x0022201C;
const IOCTL_DIOPROCESS_CLEAR_DEBUG_FLAGS: u32 = 0x00222020;
const IOCTL_DIOPROCESS_ENUM_PROCESS_CALLBACKS: u32 = 0x00222024;
const IOCTL_DIOPROCESS_ENUM_THREAD_CALLBACKS: u32 = 0x00222028;
const IOCTL_DIOPROCESS_ENUM_IMAGE_CALLBACKS: u32 = 0x0022202C;

/// Check if the ProcessMonitorEx driver is loaded
pub fn is_driver_loaded() -> bool {
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
            Ok(h) => {
                let _ = CloseHandle(h);
                true
            }
            Err(_) => false,
        }
    }
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
                    // ERROR_FILE_NOT_FOUND or ERROR_PATH_NOT_FOUND
                    Err(CallbackError::DriverNotFound)
                } else {
                    Err(CallbackError::DeviceOpenFailed(err.0))
                }
            }
        }
    }
}

/// Register kernel callbacks
pub fn register_callbacks() -> Result<(), CallbackError> {
    let handle = open_device()?;

    unsafe {
        let mut bytes_returned: u32 = 0;

        let result = DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_REGISTER_CALLBACKS,
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

/// Unregister kernel callbacks
pub fn unregister_callbacks() -> Result<(), CallbackError> {
    let handle = open_device()?;

    unsafe {
        let mut bytes_returned: u32 = 0;

        let result = DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_UNREGISTER_CALLBACKS,
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

/// Start event collection in the kernel driver
/// This will register callbacks if not already registered, then enable collection
pub fn start_collection() -> Result<(), CallbackError> {
    // First, register callbacks
    register_callbacks()?;

    let handle = open_device()?;

    unsafe {
        let mut bytes_returned: u32 = 0;

        let result = DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_START_COLLECTION,
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

/// Stop event collection in the kernel driver
/// This will disable collection and unregister all callbacks
pub fn stop_collection() -> Result<(), CallbackError> {
    let handle = open_device()?;

    unsafe {
        let mut bytes_returned: u32 = 0;

        let result = DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_STOP_COLLECTION,
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

    // Then, unregister callbacks
    unregister_callbacks()?;

    Ok(())
}

/// Get the current collection state from the kernel driver
pub fn get_collection_state() -> Result<CollectionState, CallbackError> {
    let handle = open_device()?;

    unsafe {
        // CollectionStateResponse: BOOLEAN (1 byte padded to 4) + ULONG (4 bytes) = 8 bytes
        let mut buffer = [0u8; 8];
        let mut bytes_returned: u32 = 0;

        let result = DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_GET_COLLECTION_STATE,
            None,
            0,
            Some(buffer.as_mut_ptr() as *mut _),
            buffer.len() as u32,
            Some(&mut bytes_returned),
            None,
        );

        let _ = CloseHandle(handle);

        if result.is_err() {
            let err = GetLastError();
            return Err(CallbackError::IoctlFailed(err.0));
        }

        if bytes_returned < 8 {
            return Err(CallbackError::InvalidData);
        }

        // Parse response - BOOLEAN is 1 byte but padded to 4 bytes in struct
        let is_collecting = buffer[0] != 0;
        let item_count = u32::from_ne_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]);

        Ok(CollectionState {
            is_collecting,
            item_count,
        })
    }
}

/// Read events from the driver
/// Returns a vector of parsed callback events
pub fn read_events() -> Result<Vec<CallbackEvent>, CallbackError> {
    let handle = open_device()?;
    let mut events = Vec::new();

    unsafe {
        let mut buffer = vec![0u8; READ_BUFFER_SIZE];
        let mut bytes_read: u32 = 0;
        let overlapped: *const OVERLAPPED = std::ptr::null();

        let result = ReadFile(
            handle,
            Some(&mut buffer),
            Some(&mut bytes_read),
            Some(overlapped as *mut _),
        );

        let _ = CloseHandle(handle);

        if result.is_err() {
            let err = GetLastError();
            // STATUS_BUFFER_TOO_SMALL maps to various error codes
            if err.0 == 122 {
                // ERROR_INSUFFICIENT_BUFFER
                return Err(CallbackError::BufferTooSmall);
            }
            // No data is not an error
            if bytes_read == 0 {
                return Ok(events);
            }
            return Err(CallbackError::ReadFailed(err.0));
        }

        if bytes_read == 0 {
            return Ok(events);
        }

        // Build a PID to process name map for resolving names
        let pid_name_map = build_pid_name_map();

        // Parse the buffer containing multiple events
        let mut offset = 0usize;
        while offset + 16 <= bytes_read as usize {
            // EventHeader is at minimum 16 bytes: Type (4) + Size (4) + Timestamp (8)
            let event_type_raw = u32::from_ne_bytes([
                buffer[offset],
                buffer[offset + 1],
                buffer[offset + 2],
                buffer[offset + 3],
            ]);

            let size = u32::from_ne_bytes([
                buffer[offset + 4],
                buffer[offset + 5],
                buffer[offset + 6],
                buffer[offset + 7],
            ]) as usize;

            let timestamp = u64::from_ne_bytes([
                buffer[offset + 8],
                buffer[offset + 9],
                buffer[offset + 10],
                buffer[offset + 11],
                buffer[offset + 12],
                buffer[offset + 13],
                buffer[offset + 14],
                buffer[offset + 15],
            ]);

            if size < 16 || offset + size > bytes_read as usize {
                break;
            }

            let event_type = match EventType::from_u32(event_type_raw) {
                Some(et) => et,
                None => {
                    offset += size;
                    continue;
                }
            };

            // Parse event-specific data (starts at offset + 16, after header)
            let data_offset = offset + 16;
            let event = match event_type {
                EventType::ProcessCreate => {
                    parse_process_create_event(&buffer, data_offset, timestamp, &pid_name_map)
                }
                EventType::ProcessExit => {
                    parse_process_exit_event(&buffer, data_offset, timestamp, &pid_name_map)
                }
                EventType::ThreadCreate => {
                    parse_thread_create_event(&buffer, data_offset, timestamp, &pid_name_map)
                }
                EventType::ThreadExit => {
                    parse_thread_exit_event(&buffer, data_offset, timestamp, &pid_name_map)
                }
                EventType::ImageLoad => {
                    parse_image_load_event(&buffer, data_offset, timestamp, &pid_name_map)
                }
                EventType::ProcessHandleCreate | EventType::ProcessHandleDuplicate => {
                    parse_handle_operation_event(
                        &buffer,
                        data_offset,
                        timestamp,
                        event_type,
                        &pid_name_map,
                    )
                }
                EventType::ThreadHandleCreate | EventType::ThreadHandleDuplicate => {
                    parse_handle_operation_event(
                        &buffer,
                        data_offset,
                        timestamp,
                        event_type,
                        &pid_name_map,
                    )
                }
                EventType::RegistryCreate
                | EventType::RegistryOpen
                | EventType::RegistrySetValue
                | EventType::RegistryDeleteKey
                | EventType::RegistryDeleteValue
                | EventType::RegistryRenameKey
                | EventType::RegistryQueryValue => {
                    parse_registry_operation_event(
                        &buffer,
                        data_offset,
                        timestamp,
                        event_type,
                        &pid_name_map,
                    )
                }
            };

            if let Some(e) = event {
                events.push(e);
            }

            offset += size;
        }
    }

    Ok(events)
}

/// Build a map of PID to process name using ToolHelp32
fn build_pid_name_map() -> HashMap<u32, String> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    let mut map = HashMap::new();

    unsafe {
        let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(handle) => handle,
            Err(_) => return map,
        };

        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let name = String::from_utf16_lossy(
                    &entry.szExeFile[..entry
                        .szExeFile
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(entry.szExeFile.len())],
                );

                map.insert(entry.th32ProcessID, name);

                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }

        let _ = CloseHandle(snapshot);
    }

    map
}

fn parse_process_create_event(
    buffer: &[u8],
    offset: usize,
    timestamp: u64,
    pid_map: &HashMap<u32, String>,
) -> Option<CallbackEvent> {
    // ProcessCreateInfo: ProcessId (4) + ParentProcessId (4) + CreatingProcessId (4) + CommandLineLength (4) + CommandLine[1] (variable)
    if buffer.len() < offset + 16 {
        return None;
    }

    let process_id = u32::from_ne_bytes([
        buffer[offset],
        buffer[offset + 1],
        buffer[offset + 2],
        buffer[offset + 3],
    ]);

    let parent_process_id = u32::from_ne_bytes([
        buffer[offset + 4],
        buffer[offset + 5],
        buffer[offset + 6],
        buffer[offset + 7],
    ]);

    let creating_process_id = u32::from_ne_bytes([
        buffer[offset + 8],
        buffer[offset + 9],
        buffer[offset + 10],
        buffer[offset + 11],
    ]);

    let command_line_length = u32::from_ne_bytes([
        buffer[offset + 12],
        buffer[offset + 13],
        buffer[offset + 14],
        buffer[offset + 15],
    ]) as usize;

    let command_line = if command_line_length > 0 {
        let cmd_offset = offset + 16;
        let byte_len = command_line_length * 2; // WCHAR is 2 bytes
        if buffer.len() >= cmd_offset + byte_len {
            let wchars: Vec<u16> = (0..command_line_length)
                .map(|i| {
                    let idx = cmd_offset + i * 2;
                    u16::from_ne_bytes([buffer[idx], buffer[idx + 1]])
                })
                .collect();
            Some(String::from_utf16_lossy(&wchars))
        } else {
            None
        }
    } else {
        None
    };

    // Try to get process name from command line, or fall back to PID map
    let process_name = if let Some(ref cmd) = command_line {
        extract_process_name_from_cmdline(cmd)
    } else {
        pid_map
            .get(&process_id)
            .cloned()
            .unwrap_or_else(|| format!("<PID {}>", process_id))
    };

    Some(CallbackEvent {
        event_type: EventType::ProcessCreate,
        timestamp,
        process_id,
        process_name,
        parent_process_id: Some(parent_process_id),
        creating_process_id: Some(creating_process_id),
        command_line,
        thread_id: None,
        exit_code: None,
        image_base: None,
        image_size: None,
        image_name: None,
        is_system_image: None,
        is_kernel_image: None,
        source_process_id: None,
        source_thread_id: None,
        target_process_id: None,
        target_thread_id: None,
        desired_access: None,
        granted_access: None,
        source_image_name: None,
        key_name: None,
        value_name: None,
        registry_operation: None,
    })
}

fn parse_process_exit_event(
    buffer: &[u8],
    offset: usize,
    timestamp: u64,
    pid_map: &HashMap<u32, String>,
) -> Option<CallbackEvent> {
    // ProcessExitInfo: ProcessId (4) + ExitCode (4)
    if buffer.len() < offset + 8 {
        return None;
    }

    let process_id = u32::from_ne_bytes([
        buffer[offset],
        buffer[offset + 1],
        buffer[offset + 2],
        buffer[offset + 3],
    ]);

    let exit_code = u32::from_ne_bytes([
        buffer[offset + 4],
        buffer[offset + 5],
        buffer[offset + 6],
        buffer[offset + 7],
    ]);

    let process_name = pid_map
        .get(&process_id)
        .cloned()
        .unwrap_or_else(|| format!("<PID {}>", process_id));

    Some(CallbackEvent {
        event_type: EventType::ProcessExit,
        timestamp,
        process_id,
        process_name,
        parent_process_id: None,
        creating_process_id: None,
        command_line: None,
        thread_id: None,
        exit_code: Some(exit_code),
        image_base: None,
        image_size: None,
        image_name: None,
        is_system_image: None,
        is_kernel_image: None,
        source_process_id: None,
        source_thread_id: None,
        target_process_id: None,
        target_thread_id: None,
        desired_access: None,
        granted_access: None,
        source_image_name: None,
        key_name: None,
        value_name: None,
        registry_operation: None,
    })
}

fn parse_thread_create_event(
    buffer: &[u8],
    offset: usize,
    timestamp: u64,
    pid_map: &HashMap<u32, String>,
) -> Option<CallbackEvent> {
    // ThreadCreateInfo: ProcessId (4) + ThreadId (4)
    if buffer.len() < offset + 8 {
        return None;
    }

    let process_id = u32::from_ne_bytes([
        buffer[offset],
        buffer[offset + 1],
        buffer[offset + 2],
        buffer[offset + 3],
    ]);

    let thread_id = u32::from_ne_bytes([
        buffer[offset + 4],
        buffer[offset + 5],
        buffer[offset + 6],
        buffer[offset + 7],
    ]);

    let process_name = pid_map
        .get(&process_id)
        .cloned()
        .unwrap_or_else(|| format!("<PID {}>", process_id));

    Some(CallbackEvent {
        event_type: EventType::ThreadCreate,
        timestamp,
        process_id,
        process_name,
        parent_process_id: None,
        creating_process_id: None,
        command_line: None,
        thread_id: Some(thread_id),
        exit_code: None,
        image_base: None,
        image_size: None,
        image_name: None,
        is_system_image: None,
        is_kernel_image: None,
        source_process_id: None,
        source_thread_id: None,
        target_process_id: None,
        target_thread_id: None,
        desired_access: None,
        granted_access: None,
        source_image_name: None,
        key_name: None,
        value_name: None,
        registry_operation: None,
    })
}

fn parse_thread_exit_event(
    buffer: &[u8],
    offset: usize,
    timestamp: u64,
    pid_map: &HashMap<u32, String>,
) -> Option<CallbackEvent> {
    // ThreadExitInfo: ProcessId (4) + ThreadId (4) + ExitCode (4)
    if buffer.len() < offset + 12 {
        return None;
    }

    let process_id = u32::from_ne_bytes([
        buffer[offset],
        buffer[offset + 1],
        buffer[offset + 2],
        buffer[offset + 3],
    ]);

    let thread_id = u32::from_ne_bytes([
        buffer[offset + 4],
        buffer[offset + 5],
        buffer[offset + 6],
        buffer[offset + 7],
    ]);

    let exit_code = u32::from_ne_bytes([
        buffer[offset + 8],
        buffer[offset + 9],
        buffer[offset + 10],
        buffer[offset + 11],
    ]);

    let process_name = pid_map
        .get(&process_id)
        .cloned()
        .unwrap_or_else(|| format!("<PID {}>", process_id));

    Some(CallbackEvent {
        event_type: EventType::ThreadExit,
        timestamp,
        process_id,
        process_name,
        parent_process_id: None,
        creating_process_id: None,
        command_line: None,
        thread_id: Some(thread_id),
        exit_code: Some(exit_code),
        image_base: None,
        image_size: None,
        image_name: None,
        is_system_image: None,
        is_kernel_image: None,
        source_process_id: None,
        source_thread_id: None,
        target_process_id: None,
        target_thread_id: None,
        desired_access: None,
        granted_access: None,
        source_image_name: None,
        key_name: None,
        value_name: None,
        registry_operation: None,
    })
}

fn parse_image_load_event(
    buffer: &[u8],
    offset: usize,
    timestamp: u64,
    pid_map: &HashMap<u32, String>,
) -> Option<CallbackEvent> {
    // ImageLoadInfo: ProcessId (4) + ImageBase (8) + ImageSize (8) + IsSystemImage (1) + IsKernelImage (1) + ImageNameLength (4) + ImageName[1] (variable)
    if buffer.len() < offset + 26 {
        return None;
    }

    let process_id = u32::from_ne_bytes([
        buffer[offset],
        buffer[offset + 1],
        buffer[offset + 2],
        buffer[offset + 3],
    ]);

    let image_base = u64::from_ne_bytes([
        buffer[offset + 4],
        buffer[offset + 5],
        buffer[offset + 6],
        buffer[offset + 7],
        buffer[offset + 8],
        buffer[offset + 9],
        buffer[offset + 10],
        buffer[offset + 11],
    ]);

    let image_size = u64::from_ne_bytes([
        buffer[offset + 12],
        buffer[offset + 13],
        buffer[offset + 14],
        buffer[offset + 15],
        buffer[offset + 16],
        buffer[offset + 17],
        buffer[offset + 18],
        buffer[offset + 19],
    ]);

    let is_system_image = buffer[offset + 20] != 0;
    let is_kernel_image = buffer[offset + 21] != 0;

    let image_name_length = u32::from_ne_bytes([
        buffer[offset + 22],
        buffer[offset + 23],
        buffer[offset + 24],
        buffer[offset + 25],
    ]) as usize;

    let image_name = if image_name_length > 0 {
        let name_offset = offset + 26;
        let byte_len = image_name_length * 2; // WCHAR is 2 bytes
        if buffer.len() >= name_offset + byte_len {
            let wchars: Vec<u16> = (0..image_name_length)
                .map(|i| {
                    let idx = name_offset + i * 2;
                    u16::from_ne_bytes([buffer[idx], buffer[idx + 1]])
                })
                .collect();
            Some(String::from_utf16_lossy(&wchars))
        } else {
            None
        }
    } else {
        None
    };

    let process_name = pid_map
        .get(&process_id)
        .cloned()
        .unwrap_or_else(|| format!("<PID {}>", process_id));

    Some(CallbackEvent {
        event_type: EventType::ImageLoad,
        timestamp,
        process_id,
        process_name,
        parent_process_id: None,
        creating_process_id: None,
        command_line: None,
        thread_id: None,
        exit_code: None,
        image_base: Some(image_base),
        image_size: Some(image_size),
        image_name,
        is_system_image: Some(is_system_image),
        is_kernel_image: Some(is_kernel_image),
        source_process_id: None,
        source_thread_id: None,
        target_process_id: None,
        target_thread_id: None,
        desired_access: None,
        granted_access: None,
        source_image_name: None,
        key_name: None,
        value_name: None,
        registry_operation: None,
    })
}

fn parse_handle_operation_event(
    buffer: &[u8],
    offset: usize,
    timestamp: u64,
    event_type: EventType,
    pid_map: &HashMap<u32, String>,
) -> Option<CallbackEvent> {
    // HandleOperationInfo: SourceProcessId (4) + SourceThreadId (4) + TargetProcessId (4) + TargetThreadId (4) +
    //                      DesiredAccess (4) + GrantedAccess (4) + IsKernelHandle (1) + SourceImageNameLength (4) + SourceImageName[1] (variable)
    if buffer.len() < offset + 29 {
        return None;
    }

    let source_process_id = u32::from_ne_bytes([
        buffer[offset],
        buffer[offset + 1],
        buffer[offset + 2],
        buffer[offset + 3],
    ]);

    let source_thread_id = u32::from_ne_bytes([
        buffer[offset + 4],
        buffer[offset + 5],
        buffer[offset + 6],
        buffer[offset + 7],
    ]);

    let target_process_id = u32::from_ne_bytes([
        buffer[offset + 8],
        buffer[offset + 9],
        buffer[offset + 10],
        buffer[offset + 11],
    ]);

    let target_thread_id = u32::from_ne_bytes([
        buffer[offset + 12],
        buffer[offset + 13],
        buffer[offset + 14],
        buffer[offset + 15],
    ]);

    let desired_access = u32::from_ne_bytes([
        buffer[offset + 16],
        buffer[offset + 17],
        buffer[offset + 18],
        buffer[offset + 19],
    ]);

    let granted_access = u32::from_ne_bytes([
        buffer[offset + 20],
        buffer[offset + 21],
        buffer[offset + 22],
        buffer[offset + 23],
    ]);

    let _is_kernel_handle = buffer[offset + 24] != 0;

    let source_image_name_length = u32::from_ne_bytes([
        buffer[offset + 25],
        buffer[offset + 26],
        buffer[offset + 27],
        buffer[offset + 28],
    ]) as usize;

    let source_image_name = if source_image_name_length > 0 {
        let name_offset = offset + 29;
        let byte_len = source_image_name_length * 2; // WCHAR is 2 bytes
        if buffer.len() >= name_offset + byte_len {
            let wchars: Vec<u16> = (0..source_image_name_length)
                .map(|i| {
                    let idx = name_offset + i * 2;
                    u16::from_ne_bytes([buffer[idx], buffer[idx + 1]])
                })
                .collect();
            Some(String::from_utf16_lossy(&wchars))
        } else {
            None
        }
    } else {
        None
    };

    let process_name = pid_map
        .get(&source_process_id)
        .cloned()
        .unwrap_or_else(|| format!("<PID {}>", source_process_id));

    Some(CallbackEvent {
        event_type,
        timestamp,
        process_id: source_process_id,
        process_name,
        parent_process_id: None,
        creating_process_id: None,
        command_line: None,
        thread_id: None,
        exit_code: None,
        image_base: None,
        image_size: None,
        image_name: None,
        is_system_image: None,
        is_kernel_image: None,
        source_process_id: Some(source_process_id),
        source_thread_id: Some(source_thread_id),
        target_process_id: Some(target_process_id),
        target_thread_id: if target_thread_id != 0 {
            Some(target_thread_id)
        } else {
            None
        },
        desired_access: Some(desired_access),
        granted_access: Some(granted_access),
        source_image_name,
        key_name: None,
        value_name: None,
        registry_operation: None,
    })
}

fn parse_registry_operation_event(
    buffer: &[u8],
    offset: usize,
    timestamp: u64,
    event_type: EventType,
    pid_map: &HashMap<u32, String>,
) -> Option<CallbackEvent> {
    // RegistryOperationInfo: ProcessId (4) + ThreadId (4) + Operation (4) + Status (4) +
    //                        KeyNameLength (4) + ValueNameLength (4) + Names[1] (variable)
    if buffer.len() < offset + 24 {
        return None;
    }

    let process_id = u32::from_ne_bytes([
        buffer[offset],
        buffer[offset + 1],
        buffer[offset + 2],
        buffer[offset + 3],
    ]);

    let thread_id = u32::from_ne_bytes([
        buffer[offset + 4],
        buffer[offset + 5],
        buffer[offset + 6],
        buffer[offset + 7],
    ]);

    let operation_raw = u32::from_ne_bytes([
        buffer[offset + 8],
        buffer[offset + 9],
        buffer[offset + 10],
        buffer[offset + 11],
    ]);

    let _status = u32::from_ne_bytes([
        buffer[offset + 12],
        buffer[offset + 13],
        buffer[offset + 14],
        buffer[offset + 15],
    ]);

    let key_name_length = u32::from_ne_bytes([
        buffer[offset + 16],
        buffer[offset + 17],
        buffer[offset + 18],
        buffer[offset + 19],
    ]) as usize;

    let value_name_length = u32::from_ne_bytes([
        buffer[offset + 20],
        buffer[offset + 21],
        buffer[offset + 22],
        buffer[offset + 23],
    ]) as usize;

    let names_offset = offset + 24;

    let key_name = if key_name_length > 0 {
        let byte_len = key_name_length * 2;
        if buffer.len() >= names_offset + byte_len {
            let wchars: Vec<u16> = (0..key_name_length)
                .map(|i| {
                    let idx = names_offset + i * 2;
                    u16::from_ne_bytes([buffer[idx], buffer[idx + 1]])
                })
                .collect();
            Some(String::from_utf16_lossy(&wchars))
        } else {
            None
        }
    } else {
        None
    };

    let value_name = if value_name_length > 0 {
        let value_offset = names_offset + key_name_length * 2;
        let byte_len = value_name_length * 2;
        if buffer.len() >= value_offset + byte_len {
            let wchars: Vec<u16> = (0..value_name_length)
                .map(|i| {
                    let idx = value_offset + i * 2;
                    u16::from_ne_bytes([buffer[idx], buffer[idx + 1]])
                })
                .collect();
            Some(String::from_utf16_lossy(&wchars))
        } else {
            None
        }
    } else {
        None
    };

    let registry_operation = match operation_raw {
        0 => Some(RegistryOperation::CreateKey),
        1 => Some(RegistryOperation::OpenKey),
        2 => Some(RegistryOperation::SetValue),
        3 => Some(RegistryOperation::DeleteKey),
        4 => Some(RegistryOperation::DeleteValue),
        5 => Some(RegistryOperation::RenameKey),
        6 => Some(RegistryOperation::QueryValue),
        _ => None,
    };

    let process_name = pid_map
        .get(&process_id)
        .cloned()
        .unwrap_or_else(|| format!("<PID {}>", process_id));

    Some(CallbackEvent {
        event_type,
        timestamp,
        process_id,
        process_name,
        parent_process_id: None,
        creating_process_id: None,
        command_line: None,
        thread_id: Some(thread_id),
        exit_code: None,
        image_base: None,
        image_size: None,
        image_name: None,
        is_system_image: None,
        is_kernel_image: None,
        source_process_id: None,
        source_thread_id: None,
        target_process_id: None,
        target_thread_id: None,
        desired_access: None,
        granted_access: None,
        source_image_name: None,
        key_name,
        value_name,
        registry_operation,
    })
}

/// Extract process name from command line
fn extract_process_name_from_cmdline(cmdline: &str) -> String {
    let trimmed = cmdline.trim();

    // Handle quoted paths
    let path = if trimmed.starts_with('"') {
        if let Some(end) = trimmed[1..].find('"') {
            &trimmed[1..end + 1]
        } else {
            trimmed
        }
    } else {
        // Take until first space
        trimmed.split_whitespace().next().unwrap_or(trimmed)
    };

    // Extract filename from path
    if let Some(pos) = path.rfind('\\') {
        path[pos + 1..].to_string()
    } else if let Some(pos) = path.rfind('/') {
        path[pos + 1..].to_string()
    } else {
        path.to_string()
    }
}

// ============== Security Research Functions ==============

/// Protect a process with PPL (Protected Process Light)
/// Requires the DioProcess kernel driver to be loaded
pub fn protect_process(pid: u32) -> Result<(), CallbackError> {
    let handle = open_device()?;

    unsafe {
        let request = pid;
        let mut bytes_returned: u32 = 0;

        let result = DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_PROTECT_PROCESS,
            Some(&request as *const _ as *const _),
            std::mem::size_of::<u32>() as u32,
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

/// Remove protection from a protected process
/// Requires the DioProcess kernel driver to be loaded
pub fn unprotect_process(pid: u32) -> Result<(), CallbackError> {
    let handle = open_device()?;

    unsafe {
        let request = pid;
        let mut bytes_returned: u32 = 0;

        let result = DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_UNPROTECT_PROCESS,
            Some(&request as *const _ as *const _),
            std::mem::size_of::<u32>() as u32,
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

/// Enable all privileges for a process token
/// Requires the DioProcess kernel driver to be loaded
pub fn enable_all_privileges(pid: u32) -> Result<(), CallbackError> {
    let handle = open_device()?;

    unsafe {
        let request = pid;
        let mut bytes_returned: u32 = 0;

        let result = DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_ENABLE_PRIVILEGES,
            Some(&request as *const _ as *const _),
            std::mem::size_of::<u32>() as u32,
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

/// Clear anti-debug flags for a process (kernel-level)
/// Clears DebugPort, PEB.BeingDebugged, and PEB.NtGlobalFlag
/// Requires the DioProcess kernel driver to be loaded
pub fn clear_debug_flags(pid: u32) -> Result<(), CallbackError> {
    let handle = open_device()?;

    unsafe {
        let request = pid;
        let mut bytes_returned: u32 = 0;

        let result = DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_CLEAR_DEBUG_FLAGS,
            Some(&request as *const _ as *const _),
            std::mem::size_of::<u32>() as u32,
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


/// Information about a kernel callback
#[derive(Debug, Clone)]
pub struct CallbackInfo {
    pub module_name: String,
    pub callback_address: u64,
    pub index: u32,
}

/// Enumerate registered process creation callbacks
/// Returns a vector of active callbacks with their owning module names
pub fn enumerate_process_callbacks() -> Result<Vec<CallbackInfo>, CallbackError> {
    let handle = open_device()?;

    const MAX_CALLBACKS: usize = 64;
    const MAX_MODULE_NAME: usize = 256;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct RawCallbackInfo {
        module_name: [u8; MAX_MODULE_NAME],
        callback_address: u64,
        index: u32,
    }

    let mut buffer = vec![
        RawCallbackInfo {
            module_name: [0u8; MAX_MODULE_NAME],
            callback_address: 0,
            index: 0,
        };
        MAX_CALLBACKS
    ];

    unsafe {
        let mut bytes_returned: u32 = 0;

        let result = DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_ENUM_PROCESS_CALLBACKS,
            None,
            0,
            Some(buffer.as_mut_ptr() as *mut _),
            (std::mem::size_of::<RawCallbackInfo>() * MAX_CALLBACKS) as u32,
            Some(&mut bytes_returned),
            None,
        );

        let _ = CloseHandle(handle);

        if result.is_err() {
            let err = GetLastError();
            return Err(CallbackError::IoctlFailed(err.0));
        }
    }

    // Convert raw data to CallbackInfo, filtering out null entries
    let mut callbacks = Vec::new();
    for raw in buffer {
        if raw.callback_address != 0 {
            // Find null terminator in module_name
            let name_len = raw
                .module_name
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(MAX_MODULE_NAME);

            let module_name = String::from_utf8_lossy(&raw.module_name[..name_len]).to_string();

            callbacks.push(CallbackInfo {
                module_name,
                callback_address: raw.callback_address,
                index: raw.index,
            });
        }
    }

    Ok(callbacks)
}


/// Enumerate registered thread creation callbacks
pub fn enumerate_thread_callbacks() -> Result<Vec<CallbackInfo>, CallbackError> {
    enumerate_callbacks_internal(IOCTL_DIOPROCESS_ENUM_THREAD_CALLBACKS)
}

/// Enumerate registered image load callbacks
pub fn enumerate_image_callbacks() -> Result<Vec<CallbackInfo>, CallbackError> {
    enumerate_callbacks_internal(IOCTL_DIOPROCESS_ENUM_IMAGE_CALLBACKS)
}

/// Internal helper for callback enumeration
fn enumerate_callbacks_internal(ioctl_code: u32) -> Result<Vec<CallbackInfo>, CallbackError> {
    let handle = open_device()?;

    const MAX_CALLBACKS: usize = 64;
    const MAX_MODULE_NAME: usize = 256;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct RawCallbackInfo {
        module_name: [u8; MAX_MODULE_NAME],
        callback_address: u64,
        index: u32,
    }

    let mut buffer = vec![
        RawCallbackInfo {
            module_name: [0u8; MAX_MODULE_NAME],
            callback_address: 0,
            index: 0,
        };
        MAX_CALLBACKS
    ];

    unsafe {
        let mut bytes_returned: u32 = 0;

        let result = DeviceIoControl(
            handle,
            ioctl_code,
            None,
            0,
            Some(buffer.as_mut_ptr() as *mut _),
            (std::mem::size_of::<RawCallbackInfo>() * MAX_CALLBACKS) as u32,
            Some(&mut bytes_returned),
            None,
        );

        let _ = CloseHandle(handle);

        if result.is_err() {
            let err = GetLastError();
            return Err(CallbackError::IoctlFailed(err.0));
        }
    }

    let mut callbacks = Vec::new();
    for raw in buffer {
        if raw.callback_address != 0 {
            let name_len = raw
                .module_name
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(MAX_MODULE_NAME);

            let module_name = String::from_utf8_lossy(&raw.module_name[..name_len]).to_string();

            callbacks.push(CallbackInfo {
                module_name,
                callback_address: raw.callback_address,
                index: raw.index,
            });
        }
    }

    Ok(callbacks)
}

// ============== Object Callback Enumeration ==============

const IOCTL_DIOPROCESS_ENUM_OBJECT_CALLBACKS: u32 = 0x00222040; // CTL_CODE(0x22, 0x810, 0, 0)

/// Object type being monitored by the callback
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectCallbackType {
    Process = 1,
    Thread = 2,
}

impl ObjectCallbackType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(ObjectCallbackType::Process),
            2 => Some(ObjectCallbackType::Thread),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ObjectCallbackType::Process => "Process",
            ObjectCallbackType::Thread => "Thread",
        }
    }
}

/// Operations monitored by the callback
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectCallbackOperations {
    pub handle_create: bool,
    pub handle_duplicate: bool,
}

impl ObjectCallbackOperations {
    pub fn from_u32(value: u32) -> Self {
        Self {
            handle_create: (value & 1) != 0,
            handle_duplicate: (value & 2) != 0,
        }
    }

    pub fn as_string(&self) -> String {
        let mut ops = Vec::new();
        if self.handle_create {
            ops.push("Create");
        }
        if self.handle_duplicate {
            ops.push("Duplicate");
        }
        if ops.is_empty() {
            "None".to_string()
        } else {
            ops.join(", ")
        }
    }
}

/// Information about an object callback (ObRegisterCallbacks)
#[derive(Debug, Clone)]
pub struct ObjectCallbackInfo {
    pub module_name: String,
    pub altitude: String,
    pub pre_operation_callback: u64,
    pub post_operation_callback: u64,
    pub object_type: ObjectCallbackType,
    pub operations: ObjectCallbackOperations,
    pub index: u32,
}

/// Enumerate registered object callbacks (ObRegisterCallbacks)
/// Returns callbacks for both Process and Thread object types
pub fn enumerate_object_callbacks() -> Result<Vec<ObjectCallbackInfo>, CallbackError> {
    let handle = open_device()?;

    const MAX_ENTRIES: usize = 64;
    const MAX_MODULE_NAME: usize = 256;
    const MAX_ALTITUDE: usize = 64;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct RawObjectCallbackInfo {
        module_name: [u8; MAX_MODULE_NAME],
        altitude: [u8; MAX_ALTITUDE],
        pre_operation_callback: u64,
        post_operation_callback: u64,
        object_type: u8,
        _padding: [u8; 3],
        operations: u32,
        index: u32,
    }

    #[repr(C)]
    struct RawResponse {
        count: u32,
        entries: [RawObjectCallbackInfo; MAX_ENTRIES],
    }

    let buffer_size = std::mem::size_of::<RawResponse>();
    let mut buffer: Vec<u8> = vec![0; buffer_size];

    unsafe {
        let mut bytes_returned: u32 = 0;

        let result = DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_ENUM_OBJECT_CALLBACKS,
            None,
            0,
            Some(buffer.as_mut_ptr() as *mut _),
            buffer_size as u32,
            Some(&mut bytes_returned),
            None,
        );

        let _ = CloseHandle(handle);

        if result.is_err() {
            let err = GetLastError();
            return Err(CallbackError::IoctlFailed(err.0));
        }

        let response = &*(buffer.as_ptr() as *const RawResponse);
        let count = response.count as usize;

        let mut callbacks = Vec::with_capacity(count);
        for i in 0..count.min(MAX_ENTRIES) {
            let raw = &response.entries[i];

            // Skip entries with no callbacks
            if raw.pre_operation_callback == 0 && raw.post_operation_callback == 0 {
                continue;
            }

            let module_name_len = raw
                .module_name
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(MAX_MODULE_NAME);
            let module_name =
                String::from_utf8_lossy(&raw.module_name[..module_name_len]).to_string();

            let altitude_len = raw
                .altitude
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(MAX_ALTITUDE);
            let altitude = String::from_utf8_lossy(&raw.altitude[..altitude_len]).to_string();

            let object_type =
                ObjectCallbackType::from_u8(raw.object_type).unwrap_or(ObjectCallbackType::Process);

            callbacks.push(ObjectCallbackInfo {
                module_name,
                altitude,
                pre_operation_callback: raw.pre_operation_callback,
                post_operation_callback: raw.post_operation_callback,
                object_type,
                operations: ObjectCallbackOperations::from_u32(raw.operations),
                index: raw.index,
            });
        }

        Ok(callbacks)
    }
}

// ============== Minifilter Enumeration ==============

const IOCTL_DIOPROCESS_ENUM_MINIFILTERS: u32 = 0x00222044; // CTL_CODE(0x22, 0x811, 0, 0)

/// Callbacks registered by a minifilter for file operations
#[derive(Debug, Clone, Default)]
pub struct MinifilterCallbacks {
    pub pre_create: u64,
    pub post_create: u64,
    pub pre_read: u64,
    pub post_read: u64,
    pub pre_write: u64,
    pub post_write: u64,
    pub pre_set_info: u64,
    pub post_set_info: u64,
    pub pre_cleanup: u64,
    pub post_cleanup: u64,
}

/// Information about a registered minifilter driver
#[derive(Debug, Clone)]
pub struct MinifilterInfo {
    pub filter_name: String,
    pub altitude: String,
    pub filter_address: u64,
    pub frame_id: u64,
    pub num_instances: u32,
    pub flags: u32,
    pub callbacks: MinifilterCallbacks,
    pub owner_module: String,
    pub index: u32,
}

/// Enumerate registered filesystem minifilter drivers
/// Returns information about all minifilters registered with the Filter Manager
pub fn enumerate_minifilters() -> Result<Vec<MinifilterInfo>, CallbackError> {
    let handle = open_device()?;

    const MAX_ENTRIES: usize = 64;
    const MAX_FILTER_NAME: usize = 64;
    const MAX_ALTITUDE: usize = 64;
    const MAX_MODULE_NAME: usize = 256;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct RawMinifilterCallbacks {
        pre_create: u64,
        post_create: u64,
        pre_read: u64,
        post_read: u64,
        pre_write: u64,
        post_write: u64,
        pre_set_info: u64,
        post_set_info: u64,
        pre_cleanup: u64,
        post_cleanup: u64,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct RawMinifilterInfo {
        filter_name: [u8; MAX_FILTER_NAME],
        altitude: [u8; MAX_ALTITUDE],
        filter_address: u64,
        frame_id: u64,
        num_instances: u32,
        flags: u32,
        callbacks: RawMinifilterCallbacks,
        owner_module: [u8; MAX_MODULE_NAME],
        index: u32,
    }

    #[repr(C)]
    struct RawResponse {
        count: u32,
        entries: [RawMinifilterInfo; MAX_ENTRIES],
    }

    let buffer_size = std::mem::size_of::<RawResponse>();
    let mut buffer: Vec<u8> = vec![0; buffer_size];

    unsafe {
        let mut bytes_returned: u32 = 0;

        let result = DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_ENUM_MINIFILTERS,
            None,
            0,
            Some(buffer.as_mut_ptr() as *mut _),
            buffer_size as u32,
            Some(&mut bytes_returned),
            None,
        );

        let _ = CloseHandle(handle);

        if result.is_err() {
            let err = GetLastError();
            return Err(CallbackError::IoctlFailed(err.0));
        }

        let response = &*(buffer.as_ptr() as *const RawResponse);
        let count = response.count as usize;

        let mut filters = Vec::with_capacity(count);
        for i in 0..count.min(MAX_ENTRIES) {
            let raw = &response.entries[i];

            // Skip empty entries
            if raw.filter_address == 0 {
                continue;
            }

            let filter_name_len = raw
                .filter_name
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(MAX_FILTER_NAME);
            let filter_name =
                String::from_utf8_lossy(&raw.filter_name[..filter_name_len]).to_string();

            let altitude_len = raw
                .altitude
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(MAX_ALTITUDE);
            let altitude = String::from_utf8_lossy(&raw.altitude[..altitude_len]).to_string();

            let owner_len = raw
                .owner_module
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(MAX_MODULE_NAME);
            let owner_module =
                String::from_utf8_lossy(&raw.owner_module[..owner_len]).to_string();

            filters.push(MinifilterInfo {
                filter_name,
                altitude,
                filter_address: raw.filter_address,
                frame_id: raw.frame_id,
                num_instances: raw.num_instances,
                flags: raw.flags,
                callbacks: MinifilterCallbacks {
                    pre_create: raw.callbacks.pre_create,
                    post_create: raw.callbacks.post_create,
                    pre_read: raw.callbacks.pre_read,
                    post_read: raw.callbacks.post_read,
                    pre_write: raw.callbacks.pre_write,
                    post_write: raw.callbacks.post_write,
                    pre_set_info: raw.callbacks.pre_set_info,
                    post_set_info: raw.callbacks.post_set_info,
                    pre_cleanup: raw.callbacks.pre_cleanup,
                    post_cleanup: raw.callbacks.post_cleanup,
                },
                owner_module,
                index: raw.index,
            });
        }

        Ok(filters)
    }
}

// ============== Kernel Driver Enumeration ==============

const IOCTL_DIOPROCESS_ENUM_DRIVERS: u32 = 0x0022204C; // CTL_CODE(0x22, 0x813, 0, 0)

/// Information about a loaded kernel driver
#[derive(Debug, Clone)]
pub struct KernelDriverInfo {
    pub base_address: u64,
    pub size: u64,
    pub entry_point: u64,
    pub driver_object: u64,
    pub flags: u32,
    pub load_count: u16,
    pub driver_name: String,
    pub driver_path: String,
    pub index: u32,
}

/// Enumerate loaded kernel drivers from PsLoadedModuleList
/// Returns information about all kernel-mode drivers currently loaded
pub fn enumerate_kernel_drivers() -> Result<Vec<KernelDriverInfo>, CallbackError> {
    let handle = open_device()?;

    const MAX_ENTRIES: usize = 512;
    const MAX_DRIVER_NAME: usize = 64;
    const MAX_DRIVER_PATH: usize = 260;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct RawKernelDriverInfo {
        base_address: u64,
        size: u64,
        entry_point: u64,
        driver_object: u64,
        flags: u32,
        load_count: u32, // Actually u16 + padding
        driver_name: [u8; MAX_DRIVER_NAME],
        driver_path: [u16; MAX_DRIVER_PATH], // Wide string
        index: u32,
    }

    #[repr(C)]
    struct RawResponse {
        count: u32,
        entries: [RawKernelDriverInfo; MAX_ENTRIES],
    }

    let buffer_size = std::mem::size_of::<RawResponse>();
    let mut buffer: Vec<u8> = vec![0; buffer_size];

    unsafe {
        let mut bytes_returned: u32 = 0;

        let result = DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_ENUM_DRIVERS,
            None,
            0,
            Some(buffer.as_mut_ptr() as *mut _),
            buffer_size as u32,
            Some(&mut bytes_returned),
            None,
        );

        let _ = CloseHandle(handle);

        if result.is_err() {
            let err = GetLastError();
            return Err(CallbackError::IoctlFailed(err.0));
        }

        let response = &*(buffer.as_ptr() as *const RawResponse);
        let count = response.count as usize;

        let mut drivers = Vec::with_capacity(count);
        for i in 0..count.min(MAX_ENTRIES) {
            let raw = &response.entries[i];

            // Skip empty entries
            if raw.base_address == 0 {
                continue;
            }

            // Parse ANSI driver name
            let name_len = raw
                .driver_name
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(MAX_DRIVER_NAME);
            let driver_name =
                String::from_utf8_lossy(&raw.driver_name[..name_len]).to_string();

            // Parse wide driver path
            let path_len = raw
                .driver_path
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(MAX_DRIVER_PATH);
            let driver_path = String::from_utf16_lossy(&raw.driver_path[..path_len]);

            drivers.push(KernelDriverInfo {
                base_address: raw.base_address,
                size: raw.size,
                entry_point: raw.entry_point,
                driver_object: raw.driver_object,
                flags: raw.flags,
                load_count: (raw.load_count & 0xFFFF) as u16,
                driver_name,
                driver_path,
                index: raw.index,
            });
        }

        Ok(drivers)
    }
}
