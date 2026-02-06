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

/// Start event collection in the kernel driver
pub fn start_collection() -> Result<(), CallbackError> {
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
