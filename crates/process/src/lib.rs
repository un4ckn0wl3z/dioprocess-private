//! Windows process management module
//! Contains Windows API calls for process enumeration and management

use std::mem::zeroed;
use std::process::Command;
use std::sync::Mutex;
use std::collections::HashMap;
use sysinfo::{System, ProcessesToUpdate, ProcessRefreshKind, RefreshKind};
use windows::Win32::Foundation::{CloseHandle, HANDLE, MAX_PATH};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    Thread32First, Thread32Next, THREADENTRY32, TH32CS_SNAPTHREAD,
};
use windows::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, TerminateProcess,
    PROCESS_NAME_WIN32, PROCESS_QUERY_INFORMATION, PROCESS_TERMINATE, PROCESS_VM_READ,
    PROCESS_SUSPEND_RESUME,
    OpenThread, SuspendThread, ResumeThread, TerminateThread, GetThreadPriority,
    THREAD_SUSPEND_RESUME, THREAD_TERMINATE, THREAD_QUERY_INFORMATION,
};
use windows::core::PWSTR;
use ntapi::ntpsapi::{NtSuspendProcess, NtResumeProcess};

/// Global system info for CPU tracking (needs to persist between calls)
static SYSTEM_INFO: Mutex<Option<System>> = Mutex::new(None);

/// Process information structure
#[derive(Clone, Debug, PartialEq)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub memory_mb: f64,
    pub thread_count: u32,
    pub exe_path: String,
    pub cpu_usage: f32,
}

/// System statistics
#[derive(Clone, Debug, Default)]
pub struct SystemStats {
    pub total_memory_gb: f64,
    pub used_memory_gb: f64,
    pub memory_percent: f64,
    pub cpu_usage: f32,
    pub process_count: usize,
    pub uptime_seconds: u64,
}

/// Get list of running processes using Windows API with CPU usage from sysinfo
pub fn get_processes() -> Vec<ProcessInfo> {
    let mut processes = Vec::new();
    
    // Get CPU usage from sysinfo
    let cpu_map = get_cpu_usage_map();

    unsafe {
        // Create a snapshot of all processes
        let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(handle) => handle,
            Err(_) => return processes,
        };

        let mut entry: PROCESSENTRY32W = zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        // Get the first process
        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let name = String::from_utf16_lossy(
                    &entry.szExeFile[..entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len())]
                );

                let (memory_mb, exe_path) = get_process_details(entry.th32ProcessID);
                let cpu_usage = cpu_map.get(&entry.th32ProcessID).copied().unwrap_or(0.0);

                processes.push(ProcessInfo {
                    pid: entry.th32ProcessID,
                    name,
                    memory_mb,
                    thread_count: entry.cntThreads,
                    exe_path,
                    cpu_usage,
                });

                // Get the next process
                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }

        let _ = CloseHandle(snapshot);
    }

    processes
}

/// Get CPU usage map using sysinfo
fn get_cpu_usage_map() -> HashMap<u32, f32> {
    let mut map = HashMap::new();
    
    let mut sys_guard = SYSTEM_INFO.lock().unwrap();
    let sys = sys_guard.get_or_insert_with(|| {
        System::new_with_specifics(RefreshKind::new().with_processes(ProcessRefreshKind::new().with_cpu()))
    });
    
    // Refresh processes to get CPU usage
    sys.refresh_processes_specifics(ProcessesToUpdate::All, ProcessRefreshKind::new().with_cpu());
    
    for (pid, process) in sys.processes() {
        map.insert(pid.as_u32(), process.cpu_usage());
    }
    
    map
}

/// Get system statistics
pub fn get_system_stats() -> SystemStats {
    let mut sys_guard = SYSTEM_INFO.lock().unwrap();
    let sys = sys_guard.get_or_insert_with(|| {
        System::new_with_specifics(
            RefreshKind::new()
                .with_memory(sysinfo::MemoryRefreshKind::new().with_ram())
                .with_cpu(sysinfo::CpuRefreshKind::new().with_cpu_usage())
                .with_processes(ProcessRefreshKind::new().with_cpu())
        )
    });
    
    // Refresh all relevant info
    sys.refresh_memory();
    sys.refresh_cpu_all();
    
    let total_memory = sys.total_memory() as f64 / (1024.0 * 1024.0 * 1024.0);
    let used_memory = sys.used_memory() as f64 / (1024.0 * 1024.0 * 1024.0);
    
    SystemStats {
        total_memory_gb: total_memory,
        used_memory_gb: used_memory,
        memory_percent: if total_memory > 0.0 { (used_memory / total_memory) * 100.0 } else { 0.0 },
        cpu_usage: sys.global_cpu_usage(),
        process_count: sys.processes().len(),
        uptime_seconds: System::uptime(),
    }
}

/// Get memory usage and executable path for a specific process
fn get_process_details(pid: u32) -> (f64, String) {
    unsafe {
        let handle: HANDLE = match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) {
            Ok(h) => h,
            Err(_) => return (0.0, String::new()),
        };

        // Get memory info
        let mut mem_counters: PROCESS_MEMORY_COUNTERS = zeroed();
        mem_counters.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;

        let memory = if GetProcessMemoryInfo(
            handle,
            &mut mem_counters,
            std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        )
        .is_ok()
        {
            mem_counters.WorkingSetSize as f64 / (1024.0 * 1024.0)
        } else {
            0.0
        };

        // Get executable path
        let mut path_buf = [0u16; MAX_PATH as usize];
        let mut size = path_buf.len() as u32;
        let exe_path = if QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            PWSTR(path_buf.as_mut_ptr()),
            &mut size,
        )
        .is_ok()
        {
            String::from_utf16_lossy(&path_buf[..size as usize])
        } else {
            String::new()
        };

        let _ = CloseHandle(handle);
        (memory, exe_path)
    }
}

/// Kill a process by PID
/// Returns true if successful, false otherwise
pub fn kill_process(pid: u32) -> bool {
    unsafe {
        let handle = match OpenProcess(PROCESS_TERMINATE, false, pid) {
            Ok(h) => h,
            Err(_) => return false,
        };

        let result = TerminateProcess(handle, 1).is_ok();
        let _ = CloseHandle(handle);
        result
    }
}

/// Suspend a process by PID (pause all threads)
/// Returns true if successful, false otherwise
pub fn suspend_process(pid: u32) -> bool {
    unsafe {
        let handle = match OpenProcess(PROCESS_SUSPEND_RESUME, false, pid) {
            Ok(h) => h,
            Err(_) => return false,
        };

        let status = NtSuspendProcess(handle.0 as *mut _);
        let _ = CloseHandle(handle);
        status == 0 // NTSTATUS 0 = STATUS_SUCCESS
    }
}

/// Resume a suspended process by PID
/// Returns true if successful, false otherwise
pub fn resume_process(pid: u32) -> bool {
    unsafe {
        let handle = match OpenProcess(PROCESS_SUSPEND_RESUME, false, pid) {
            Ok(h) => h,
            Err(_) => return false,
        };

        let status = NtResumeProcess(handle.0 as *mut _);
        let _ = CloseHandle(handle);
        status == 0 // NTSTATUS 0 = STATUS_SUCCESS
    }
}

/// Open file location in Windows Explorer
pub fn open_file_location(path: &str) {
    if path.is_empty() {
        return;
    }
    // Use explorer.exe with /select to highlight the file
    let _ = Command::new("explorer.exe")
        .args(["/select,", path])
        .spawn();
}

/// Format uptime in human readable format
pub fn format_uptime(seconds: u64) -> String {
    let days = seconds / 86400;
    let hours = (seconds % 86400) / 3600;
    let minutes = (seconds % 3600) / 60;
    
    if days > 0 {
        format!("{}d {}h {}m", days, hours, minutes)
    } else if hours > 0 {
        format!("{}h {}m", hours, minutes)
    } else {
        format!("{}m", minutes)
    }
}

/// Thread information structure
#[derive(Clone, Debug, PartialEq)]
pub struct ThreadInfo {
    pub thread_id: u32,
    pub owner_pid: u32,
    pub base_priority: i32,
    pub priority: i32,
}

/// Get list of threads for a specific process
pub fn get_process_threads(pid: u32) -> Vec<ThreadInfo> {
    let mut threads = Vec::new();

    unsafe {
        let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) {
            Ok(handle) => handle,
            Err(_) => return threads,
        };

        let mut entry: THREADENTRY32 = zeroed();
        entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;

        if Thread32First(snapshot, &mut entry).is_ok() {
            loop {
                if entry.th32OwnerProcessID == pid {
                    let priority = get_thread_priority(entry.th32ThreadID);
                    
                    threads.push(ThreadInfo {
                        thread_id: entry.th32ThreadID,
                        owner_pid: entry.th32OwnerProcessID,
                        base_priority: entry.tpBasePri,
                        priority,
                    });
                }

                if Thread32Next(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }

        let _ = CloseHandle(snapshot);
    }

    threads
}

/// Get thread priority
fn get_thread_priority(thread_id: u32) -> i32 {
    unsafe {
        let handle = match OpenThread(THREAD_QUERY_INFORMATION, false, thread_id) {
            Ok(h) => h,
            Err(_) => return 0,
        };

        let priority = GetThreadPriority(handle);
        let _ = CloseHandle(handle);
        priority
    }
}

/// Suspend a thread by ID
/// Returns true if successful, false otherwise
pub fn suspend_thread(thread_id: u32) -> bool {
    unsafe {
        let handle = match OpenThread(THREAD_SUSPEND_RESUME, false, thread_id) {
            Ok(h) => h,
            Err(_) => return false,
        };

        let result = SuspendThread(handle);
        let _ = CloseHandle(handle);
        result != u32::MAX // Returns previous suspend count, or -1 on error
    }
}

/// Resume a suspended thread by ID
/// Returns true if successful, false otherwise
pub fn resume_thread(thread_id: u32) -> bool {
    unsafe {
        let handle = match OpenThread(THREAD_SUSPEND_RESUME, false, thread_id) {
            Ok(h) => h,
            Err(_) => return false,
        };

        let result = ResumeThread(handle);
        let _ = CloseHandle(handle);
        result != u32::MAX // Returns previous suspend count, or -1 on error
    }
}

/// Terminate a thread by ID (DANGEROUS - may cause process instability)
/// Returns true if successful, false otherwise
pub fn kill_thread(thread_id: u32) -> bool {
    unsafe {
        let handle = match OpenThread(THREAD_TERMINATE, false, thread_id) {
            Ok(h) => h,
            Err(_) => return false,
        };

        let result = TerminateThread(handle, 1).is_ok();
        let _ = CloseHandle(handle);
        result
    }
}

/// Get thread priority name
pub fn get_priority_name(priority: i32) -> &'static str {
    match priority {
        -15 => "Idle",
        -2 => "Lowest",
        -1 => "Below Normal",
        0 => "Normal",
        1 => "Above Normal",
        2 => "Highest",
        15 => "Time Critical",
        _ => "Unknown",
    }
}
