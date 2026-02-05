//! Driver communication functions

use crate::error::CallbackError;
use crate::types::{CallbackEvent, EventType};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE,
    OPEN_EXISTING,
};
use windows::Win32::System::IO::OVERLAPPED;

const DEVICE_PATH: &str = r"\\.\ProcessMonitorEx";
const READ_BUFFER_SIZE: usize = 1024 * 1024; // 1MB buffer

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
        parent_process_id: Some(parent_process_id),
        creating_process_id: Some(creating_process_id),
        thread_id: None,
        exit_code: None,
        command_line,
        process_name,
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
        parent_process_id: None,
        creating_process_id: None,
        thread_id: None,
        exit_code: Some(exit_code),
        command_line: None,
        process_name,
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
        parent_process_id: None,
        creating_process_id: None,
        thread_id: Some(thread_id),
        exit_code: None,
        command_line: None,
        process_name,
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
        parent_process_id: None,
        creating_process_id: None,
        thread_id: Some(thread_id),
        exit_code: Some(exit_code),
        command_line: None,
        process_name,
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
