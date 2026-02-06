//! Windows process management module
//! Contains Windows API calls for process enumeration and management

use ntapi::ntexapi::{NtQuerySystemInformation, SystemHandleInformation};
use ntapi::ntpsapi::{NtResumeProcess, NtSuspendProcess};
use std::collections::HashMap;
use std::mem::zeroed;
use std::process::Command;
use std::sync::Mutex;
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System};
use windows::core::PWSTR;
use windows::Win32::Foundation::DuplicateHandle;
use windows::Win32::Foundation::{CloseHandle, BOOL, HANDLE, MAX_PATH};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, Process32FirstW, Process32NextW,
    Thread32First, Thread32Next, MODULEENTRY32W, PROCESSENTRY32W, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_FREE, MEM_IMAGE, MEM_MAPPED,
    MEM_PRIVATE, MEM_RESERVE, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_NOACCESS, PAGE_NOCACHE, PAGE_READONLY,
    PAGE_READWRITE, PAGE_WRITECOMBINE, PAGE_WRITECOPY,
};
use windows::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
use windows::Win32::System::Threading::GetCurrentProcess;
use windows::Win32::System::Threading::{
    GetThreadPriority, IsWow64Process, OpenProcess, OpenThread, QueryFullProcessImageNameW,
    ResumeThread, SuspendThread, TerminateProcess, TerminateThread, PROCESS_DUP_HANDLE,
    PROCESS_NAME_WIN32, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SUSPEND_RESUME, PROCESS_TERMINATE, PROCESS_VM_READ, THREAD_QUERY_INFORMATION,
    THREAD_SUSPEND_RESUME, THREAD_TERMINATE,
};

/// Global system info for CPU tracking (needs to persist between calls)
static SYSTEM_INFO: Mutex<Option<System>> = Mutex::new(None);

/// Process architecture
#[derive(Clone, Debug, PartialEq, Copy)]
pub enum ProcessArch {
    X64,
    X86,
    Unknown,
}

impl std::fmt::Display for ProcessArch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProcessArch::X64 => write!(f, "x64"),
            ProcessArch::X86 => write!(f, "x86"),
            ProcessArch::Unknown => write!(f, "-"),
        }
    }
}

/// Process information structure
#[derive(Clone, Debug, PartialEq)]
pub struct ProcessInfo {
    pub pid: u32,
    pub parent_pid: u32,
    pub name: String,
    pub memory_mb: f64,
    pub thread_count: u32,
    pub exe_path: String,
    pub cpu_usage: f32,
    pub arch: ProcessArch,
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
                    &entry.szExeFile[..entry
                        .szExeFile
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(entry.szExeFile.len())],
                );

                let (memory_mb, exe_path) = get_process_details(entry.th32ProcessID);
                let cpu_usage = cpu_map.get(&entry.th32ProcessID).copied().unwrap_or(0.0);
                let arch = get_process_arch(entry.th32ProcessID);

                processes.push(ProcessInfo {
                    pid: entry.th32ProcessID,
                    parent_pid: entry.th32ParentProcessID,
                    name,
                    memory_mb,
                    thread_count: entry.cntThreads,
                    exe_path,
                    cpu_usage,
                    arch,
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
        System::new_with_specifics(
            RefreshKind::new().with_processes(ProcessRefreshKind::new().with_cpu()),
        )
    });

    // Refresh processes to get CPU usage
    sys.refresh_processes_specifics(ProcessesToUpdate::All, ProcessRefreshKind::new().with_cpu());

    for (pid, process) in sys.processes() {
        map.insert(pid.as_u32(), process.cpu_usage());
    }

    map
}

/// Process stats for graph display
#[derive(Clone, Debug, Default)]
pub struct ProcessStats {
    pub cpu_usage: f32,
    pub memory_mb: f64,
}

/// Get CPU and memory usage for a specific process
pub fn get_process_stats(pid: u32) -> ProcessStats {
    let mut sys_guard = SYSTEM_INFO.lock().unwrap();
    let sys = sys_guard.get_or_insert_with(|| {
        System::new_with_specifics(
            RefreshKind::new()
                .with_processes(ProcessRefreshKind::new().with_cpu().with_memory()),
        )
    });

    // Refresh the specific process
    sys.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[sysinfo::Pid::from_u32(pid)]),
        ProcessRefreshKind::new().with_cpu().with_memory(),
    );

    if let Some(process) = sys.process(sysinfo::Pid::from_u32(pid)) {
        ProcessStats {
            cpu_usage: process.cpu_usage(),
            memory_mb: process.memory() as f64 / (1024.0 * 1024.0),
        }
    } else {
        ProcessStats::default()
    }
}

/// Get system statistics
pub fn get_system_stats() -> SystemStats {
    let mut sys_guard = SYSTEM_INFO.lock().unwrap();
    let sys = sys_guard.get_or_insert_with(|| {
        System::new_with_specifics(
            RefreshKind::new()
                .with_memory(sysinfo::MemoryRefreshKind::new().with_ram())
                .with_cpu(sysinfo::CpuRefreshKind::new().with_cpu_usage())
                .with_processes(ProcessRefreshKind::new().with_cpu()),
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
        memory_percent: if total_memory > 0.0 {
            (used_memory / total_memory) * 100.0
        } else {
            0.0
        },
        cpu_usage: sys.global_cpu_usage(),
        process_count: sys.processes().len(),
        uptime_seconds: System::uptime(),
    }
}

/// Get process architecture (x64 or x86)
fn get_process_arch(pid: u32) -> ProcessArch {
    unsafe {
        let handle = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            Ok(h) => h,
            Err(_) => return ProcessArch::Unknown,
        };

        let mut is_wow64: BOOL = BOOL(0);
        let result = IsWow64Process(handle, &mut is_wow64);
        let _ = CloseHandle(handle);

        if result.is_ok() {
            // On 64-bit Windows: WoW64 = true means 32-bit process
            // On 64-bit Windows: WoW64 = false means 64-bit process
            if is_wow64.as_bool() {
                ProcessArch::X86
            } else {
                ProcessArch::X64
            }
        } else {
            ProcessArch::Unknown
        }
    }
}

/// Get memory usage and executable path for a specific process
fn get_process_details(pid: u32) -> (f64, String) {
    unsafe {
        let handle: HANDLE =
            match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) {
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

/// Handle information structure
#[derive(Clone, Debug, PartialEq)]
pub struct HandleInfo {
    pub handle_value: u16,
    pub object_type_index: u8,
    pub object_type_name: String,
    pub granted_access: u32,
}

/// Get list of handles for a specific process
pub fn get_process_handles(pid: u32) -> Vec<HandleInfo> {
    let mut handles = Vec::new();

    unsafe {
        // Start with a reasonable buffer size
        let mut buffer_size: usize = 0x10000; // 64KB initial
        let mut buffer: Vec<u8>;
        let mut return_length: u32 = 0;

        // Loop until we have enough buffer
        loop {
            buffer = vec![0u8; buffer_size];

            let status = NtQuerySystemInformation(
                SystemHandleInformation,
                buffer.as_mut_ptr() as *mut _,
                buffer_size as u32,
                &mut return_length,
            );

            // STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
            if status == 0xC0000004u32 as i32 {
                buffer_size *= 2;
                if buffer_size > 0x4000000 {
                    // 64MB max
                    return handles;
                }
                continue;
            }

            if status != 0 {
                return handles;
            }

            break;
        }

        // Parse the buffer manually
        // SYSTEM_HANDLE_INFORMATION structure:
        // ULONG NumberOfHandles
        // SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1]

        if buffer.len() < 4 {
            return handles;
        }

        let number_of_handles =
            u32::from_ne_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;

        // Each SYSTEM_HANDLE_TABLE_ENTRY_INFO is 16 bytes on x86, 24 bytes on x64
        #[cfg(target_pointer_width = "64")]
        const ENTRY_SIZE: usize = 24;
        #[cfg(target_pointer_width = "32")]
        const ENTRY_SIZE: usize = 16;

        let entries_start = if cfg!(target_pointer_width = "64") {
            8
        } else {
            4
        }; // alignment

        for i in 0..number_of_handles {
            let offset = entries_start + i * ENTRY_SIZE;
            if offset + ENTRY_SIZE > buffer.len() {
                break;
            }

            // Parse entry based on architecture
            #[cfg(target_pointer_width = "64")]
            let (entry_pid, handle_value, object_type, granted_access) = {
                // x64: UniqueProcessId (USHORT at 0), reserved (USHORT at 2), ObjectTypeIndex (UCHAR at 4),
                // HandleAttributes (UCHAR at 5), HandleValue (USHORT at 6), Object (PVOID at 8), GrantedAccess (ULONG at 16)
                let unique_pid = u16::from_ne_bytes([buffer[offset], buffer[offset + 1]]) as u32;
                let obj_type = buffer[offset + 4];
                let handle_val = u16::from_ne_bytes([buffer[offset + 6], buffer[offset + 7]]);
                let access = u32::from_ne_bytes([
                    buffer[offset + 16],
                    buffer[offset + 17],
                    buffer[offset + 18],
                    buffer[offset + 19],
                ]);
                (unique_pid, handle_val, obj_type, access)
            };

            #[cfg(target_pointer_width = "32")]
            let (entry_pid, handle_value, object_type, granted_access) = {
                let unique_pid = u16::from_ne_bytes([buffer[offset], buffer[offset + 1]]) as u32;
                let obj_type = buffer[offset + 4];
                let handle_val = u16::from_ne_bytes([buffer[offset + 6], buffer[offset + 7]]);
                let access = u32::from_ne_bytes([
                    buffer[offset + 12],
                    buffer[offset + 13],
                    buffer[offset + 14],
                    buffer[offset + 15],
                ]);
                (unique_pid, handle_val, obj_type, access)
            };

            if entry_pid == pid {
                let type_name = get_object_type_name(object_type);

                handles.push(HandleInfo {
                    handle_value,
                    object_type_index: object_type,
                    object_type_name: type_name,
                    granted_access,
                });
            }
        }
    }

    handles
}

/// Get object type name from type index (common Windows object types)
fn get_object_type_name(type_index: u8) -> String {
    // Common object type indices on Windows 10/11
    // Note: These can vary by Windows version
    match type_index {
        0 => "Reserved",
        1 => "Reserved",
        2 => "Type",
        3 => "Directory",
        4 => "SymbolicLink",
        5 => "Token",
        6 => "Job",
        7 => "Process",
        8 => "Thread",
        9 => "UserApcReserve",
        10 => "IoCompletionReserve",
        11 => "ActivityReference",
        12 => "PsSiloContextPaged",
        13 => "PsSiloContextNonPaged",
        14 => "DebugObject",
        15 => "Event",
        16 => "Mutant",
        17 => "Callback",
        18 => "Semaphore",
        19 => "Timer",
        20 => "IRTimer",
        21 => "Profile",
        22 => "KeyedEvent",
        23 => "WindowStation",
        24 => "Desktop",
        25 => "Composition",
        26 => "RawInputManager",
        27 => "CoreMessaging",
        28 => "TpWorkerFactory",
        29 => "Adapter",
        30 => "Controller",
        31 => "Device",
        32 => "Driver",
        33 => "IoCompletion",
        34 => "WaitCompletionPacket",
        35 => "File",
        36 => "TmTm",
        37 => "TmTx",
        38 => "TmRm",
        39 => "TmEn",
        40 => "Section",
        41 => "Session",
        42 => "Partition",
        43 => "Key",
        44 => "RegistryTransaction",
        45 => "ALPC Port",
        46 => "EnergyTracker",
        47 => "PowerRequest",
        48 => "WmiGuid",
        49 => "EtwRegistration",
        50 => "EtwSessionDemuxEntry",
        51 => "EtwConsumer",
        52 => "DmaAdapter",
        53 => "DmaDomain",
        54 => "PcwObject",
        55 => "FilterConnectionPort",
        56 => "FilterCommunicationPort",
        57 => "NdisCmState",
        58 => "DxgkSharedResource",
        59 => "DxgkSharedSyncObject",
        60 => "DxgkSharedSwapChainObject",
        _ => "Unknown",
    }
    .to_string()
}

/// Close a handle in another process
/// Returns true if successful, false otherwise
/// WARNING: Closing handles can cause process instability!
pub fn close_process_handle(pid: u32, handle_value: u16) -> bool {
    use windows::Win32::Foundation::DUPLICATE_CLOSE_SOURCE;

    unsafe {
        // Open the target process with DUP_HANDLE permission
        let process_handle = match OpenProcess(PROCESS_DUP_HANDLE, false, pid) {
            Ok(h) => h,
            Err(_) => return false,
        };

        // Duplicate the handle with DUPLICATE_CLOSE_SOURCE to close it in the target process
        let mut dup_handle: HANDLE = HANDLE::default();
        let result = DuplicateHandle(
            process_handle,
            HANDLE(handle_value as isize as *mut _),
            GetCurrentProcess(),
            &mut dup_handle,
            0,
            BOOL(0),
            DUPLICATE_CLOSE_SOURCE,
        );

        // Close our copy if we got one
        if !dup_handle.is_invalid() {
            let _ = CloseHandle(dup_handle);
        }

        let _ = CloseHandle(process_handle);
        result.is_ok()
    }
}

/// Get handle type category for display coloring
pub fn get_handle_type_category(type_name: &str) -> &'static str {
    match type_name {
        "File" => "file",
        "Key" => "registry",
        "Process" | "Thread" | "Job" => "process",
        "Event" | "Mutant" | "Semaphore" | "Timer" => "sync",
        "Section" => "memory",
        "Token" => "security",
        "ALPC Port" => "ipc",
        "Directory" | "SymbolicLink" => "namespace",
        _ => "other",
    }
}

/// Module information structure
#[derive(Clone, Debug, PartialEq)]
pub struct ModuleInfo {
    pub name: String,
    pub base_address: usize,
    pub size: u32,
    pub path: String,
}

/// Import entry for a PE module
#[derive(Clone, Debug, PartialEq)]
pub struct ImportEntry {
    pub dll_name: String,
    pub functions: Vec<String>,
}

/// Get list of loaded modules for a specific process
pub fn get_process_modules(pid: u32) -> Vec<ModuleInfo> {
    let mut modules = Vec::new();

    unsafe {
        let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
        {
            Ok(handle) => handle,
            Err(_) => return modules,
        };

        let mut entry: MODULEENTRY32W = zeroed();
        entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;

        if Module32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let name = String::from_utf16_lossy(
                    &entry.szModule[..entry
                        .szModule
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(entry.szModule.len())],
                );
                let path = String::from_utf16_lossy(
                    &entry.szExePath[..entry
                        .szExePath
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(entry.szExePath.len())],
                );

                modules.push(ModuleInfo {
                    name,
                    base_address: entry.modBaseAddr as usize,
                    size: entry.modBaseSize,
                    path,
                });

                if Module32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }

        let _ = CloseHandle(snapshot);
    }

    modules
}

/// Get imported DLLs and functions from a PE file on disk
pub fn get_module_imports(module_path: &str) -> Vec<ImportEntry> {
    let mut imports = Vec::new();
    let data = match std::fs::read(module_path) {
        Ok(d) => d,
        Err(_) => return imports,
    };

    // Parse DOS header
    if data.len() < 64 {
        return imports;
    }
    let dos_magic = u16::from_le_bytes([data[0], data[1]]);
    if dos_magic != 0x5A4D {
        // Not a valid PE ("MZ")
        return imports;
    }
    let pe_offset = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;

    // Parse PE signature
    if data.len() < pe_offset + 4 {
        return imports;
    }
    let pe_sig = u32::from_le_bytes([
        data[pe_offset],
        data[pe_offset + 1],
        data[pe_offset + 2],
        data[pe_offset + 3],
    ]);
    if pe_sig != 0x00004550 {
        // Not "PE\0\0"
        return imports;
    }

    // COFF header starts at pe_offset + 4
    let coff_offset = pe_offset + 4;
    if data.len() < coff_offset + 20 {
        return imports;
    }
    let optional_header_size =
        u16::from_le_bytes([data[coff_offset + 16], data[coff_offset + 17]]) as usize;

    // Optional header starts after COFF header
    let opt_offset = coff_offset + 20;
    if data.len() < opt_offset + 2 {
        return imports;
    }
    let opt_magic = u16::from_le_bytes([data[opt_offset], data[opt_offset + 1]]);

    // Determine import directory RVA based on PE32 vs PE32+
    let import_dir_rva;
    let import_dir_size;
    match opt_magic {
        0x10b => {
            // PE32
            if data.len() < opt_offset + 104 + 8 {
                return imports;
            }
            import_dir_rva = u32::from_le_bytes([
                data[opt_offset + 104],
                data[opt_offset + 105],
                data[opt_offset + 106],
                data[opt_offset + 107],
            ]) as usize;
            import_dir_size = u32::from_le_bytes([
                data[opt_offset + 108],
                data[opt_offset + 109],
                data[opt_offset + 110],
                data[opt_offset + 111],
            ]) as usize;
        }
        0x20b => {
            // PE32+ (64-bit)
            if data.len() < opt_offset + 120 + 8 {
                return imports;
            }
            import_dir_rva = u32::from_le_bytes([
                data[opt_offset + 120],
                data[opt_offset + 121],
                data[opt_offset + 122],
                data[opt_offset + 123],
            ]) as usize;
            import_dir_size = u32::from_le_bytes([
                data[opt_offset + 124],
                data[opt_offset + 125],
                data[opt_offset + 126],
                data[opt_offset + 127],
            ]) as usize;
        }
        _ => return imports,
    }

    if import_dir_rva == 0 || import_dir_size == 0 {
        return imports;
    }

    // Parse section headers to build RVA-to-file-offset mapping
    let num_sections = u16::from_le_bytes([data[coff_offset + 2], data[coff_offset + 3]]) as usize;
    let sections_offset = opt_offset + optional_header_size;

    struct SectionInfo {
        virtual_address: usize,
        virtual_size: usize,
        raw_data_offset: usize,
    }

    let mut sections = Vec::new();
    for i in 0..num_sections {
        let s_off = sections_offset + i * 40;
        if data.len() < s_off + 40 {
            break;
        }
        let virtual_size = u32::from_le_bytes([
            data[s_off + 8],
            data[s_off + 9],
            data[s_off + 10],
            data[s_off + 11],
        ]) as usize;
        let virtual_address = u32::from_le_bytes([
            data[s_off + 12],
            data[s_off + 13],
            data[s_off + 14],
            data[s_off + 15],
        ]) as usize;
        let raw_data_offset = u32::from_le_bytes([
            data[s_off + 20],
            data[s_off + 21],
            data[s_off + 22],
            data[s_off + 23],
        ]) as usize;
        sections.push(SectionInfo {
            virtual_address,
            virtual_size,
            raw_data_offset,
        });
    }

    let rva_to_offset = |rva: usize| -> Option<usize> {
        for s in &sections {
            if rva >= s.virtual_address && rva < s.virtual_address + s.virtual_size {
                return Some(rva - s.virtual_address + s.raw_data_offset);
            }
        }
        None
    };

    // Parse import directory table
    let import_dir_file_offset = match rva_to_offset(import_dir_rva) {
        Some(off) => off,
        None => return imports,
    };

    // Each IMAGE_IMPORT_DESCRIPTOR is 20 bytes
    let mut desc_offset = import_dir_file_offset;
    loop {
        if data.len() < desc_offset + 20 {
            break;
        }

        let ilt_rva = u32::from_le_bytes([
            data[desc_offset],
            data[desc_offset + 1],
            data[desc_offset + 2],
            data[desc_offset + 3],
        ]) as usize;
        let name_rva = u32::from_le_bytes([
            data[desc_offset + 12],
            data[desc_offset + 13],
            data[desc_offset + 14],
            data[desc_offset + 15],
        ]) as usize;

        // Null descriptor terminates the list
        if name_rva == 0 && ilt_rva == 0 {
            break;
        }

        // Read DLL name
        let dll_name = if let Some(name_off) = rva_to_offset(name_rva) {
            read_cstring(&data, name_off)
        } else {
            String::from("(unknown)")
        };

        // Read imported functions from ILT (or IAT if ILT is 0)
        let thunk_rva = if ilt_rva != 0 {
            ilt_rva
        } else {
            // Fallback to IAT (FirstThunk)
            u32::from_le_bytes([
                data[desc_offset + 16],
                data[desc_offset + 17],
                data[desc_offset + 18],
                data[desc_offset + 19],
            ]) as usize
        };

        let mut functions = Vec::new();
        if let Some(mut thunk_off) = rva_to_offset(thunk_rva) {
            let is_pe32plus = opt_magic == 0x20b;
            let entry_size = if is_pe32plus { 8 } else { 4 };

            loop {
                if data.len() < thunk_off + entry_size {
                    break;
                }

                let thunk_value = if is_pe32plus {
                    u64::from_le_bytes([
                        data[thunk_off],
                        data[thunk_off + 1],
                        data[thunk_off + 2],
                        data[thunk_off + 3],
                        data[thunk_off + 4],
                        data[thunk_off + 5],
                        data[thunk_off + 6],
                        data[thunk_off + 7],
                    ])
                } else {
                    u32::from_le_bytes([
                        data[thunk_off],
                        data[thunk_off + 1],
                        data[thunk_off + 2],
                        data[thunk_off + 3],
                    ]) as u64
                };

                if thunk_value == 0 {
                    break;
                }

                // Check ordinal flag (bit 63 for PE32+, bit 31 for PE32)
                let ordinal_flag = if is_pe32plus { 1u64 << 63 } else { 1u64 << 31 };
                if thunk_value & ordinal_flag != 0 {
                    let ordinal = thunk_value & 0xFFFF;
                    functions.push(format!("Ordinal #{}", ordinal));
                } else {
                    // Hint/Name table entry: 2-byte hint + null-terminated name
                    let hint_name_rva = (thunk_value & 0x7FFFFFFF) as usize;
                    if let Some(hn_off) = rva_to_offset(hint_name_rva) {
                        if data.len() > hn_off + 2 {
                            functions.push(read_cstring(&data, hn_off + 2));
                        }
                    }
                }

                thunk_off += entry_size;
            }
        }

        imports.push(ImportEntry {
            dll_name,
            functions,
        });
        desc_offset += 20;
    }

    imports
}

/// Read a null-terminated C string from a byte buffer
fn read_cstring(data: &[u8], offset: usize) -> String {
    let mut end = offset;
    while end < data.len() && data[end] != 0 {
        end += 1;
    }
    String::from_utf8_lossy(&data[offset..end]).to_string()
}

/// Memory region information structure
#[derive(Clone, Debug, PartialEq)]
pub struct MemoryRegionInfo {
    pub base_address: usize,
    pub allocation_base: usize,
    pub region_size: usize,
    pub state: u32,
    pub mem_type: u32,
    pub protect: u32,
    pub allocation_protect: u32,
}

/// Get all virtual memory regions for a process
pub fn get_process_memory_regions(pid: u32) -> Vec<MemoryRegionInfo> {
    let mut regions = Vec::new();

    unsafe {
        let handle = match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) {
            Ok(h) => h,
            Err(_) => return regions,
        };

        let mut address: usize = 0;
        let mbi_size = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();

        loop {
            let mut mbi: MEMORY_BASIC_INFORMATION = zeroed();
            let result = VirtualQueryEx(
                handle,
                Some(address as *const _),
                &mut mbi,
                mbi_size,
            );

            if result == 0 {
                break;
            }

            regions.push(MemoryRegionInfo {
                base_address: mbi.BaseAddress as usize,
                allocation_base: mbi.AllocationBase as usize,
                region_size: mbi.RegionSize,
                state: mbi.State.0,
                mem_type: mbi.Type.0,
                protect: mbi.Protect.0,
                allocation_protect: mbi.AllocationProtect.0,
            });

            // Advance to next region
            let next = address.checked_add(mbi.RegionSize);
            match next {
                Some(n) if n > address => address = n,
                _ => break,
            }
        }

        let _ = CloseHandle(handle);
    }

    regions
}

/// Read memory from a process at a given address
pub fn read_process_memory(pid: u32, address: usize, size: usize) -> Vec<u8> {
    let capped_size = size.min(1024 * 1024); // Cap at 1MB
    let mut buffer = vec![0u8; capped_size];

    unsafe {
        let handle = match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) {
            Ok(h) => h,
            Err(_) => return Vec::new(),
        };

        let mut bytes_read: usize = 0;
        let result = ReadProcessMemory(
            handle,
            address as *const _,
            buffer.as_mut_ptr() as *mut _,
            capped_size,
            Some(&mut bytes_read),
        );

        let _ = CloseHandle(handle);

        if result.is_err() || bytes_read == 0 {
            return Vec::new();
        }

        buffer.truncate(bytes_read);
    }

    buffer
}

/// Get human-readable state name
pub fn get_memory_state_name(state: u32) -> &'static str {
    if state == MEM_COMMIT.0 {
        "Commit"
    } else if state == MEM_RESERVE.0 {
        "Reserve"
    } else if state == MEM_FREE.0 {
        "Free"
    } else {
        "Unknown"
    }
}

/// Get human-readable memory type name
pub fn get_memory_type_name(mem_type: u32) -> &'static str {
    if mem_type == MEM_PRIVATE.0 {
        "Private"
    } else if mem_type == MEM_MAPPED.0 {
        "Mapped"
    } else if mem_type == MEM_IMAGE.0 {
        "Image"
    } else if mem_type == 0 {
        "-"
    } else {
        "Unknown"
    }
}

/// String encoding type for string scan results
#[derive(Clone, Debug, PartialEq, Copy)]
pub enum StringEncoding {
    Ascii,
    Utf16,
}

impl std::fmt::Display for StringEncoding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StringEncoding::Ascii => write!(f, "ASCII"),
            StringEncoding::Utf16 => write!(f, "UTF-16"),
        }
    }
}

/// String scan result
#[derive(Clone, Debug)]
pub struct StringResult {
    pub address: usize,
    pub value: String,
    pub encoding: StringEncoding,
    pub length: usize,
    pub region_type: String,
}

/// Configuration for string scanning
pub struct StringScanConfig {
    pub min_length: usize,
    pub scan_ascii: bool,
    pub scan_utf16: bool,
    pub max_string_length: usize,
}

impl Default for StringScanConfig {
    fn default() -> Self {
        Self {
            min_length: 4,
            scan_ascii: true,
            scan_utf16: true,
            max_string_length: 512,
        }
    }
}

/// Scan process memory for ASCII and UTF-16 strings
pub fn scan_process_strings(pid: u32, config: &StringScanConfig) -> Vec<StringResult> {
    let mut results = Vec::new();

    // Get all memory regions
    let regions = get_process_memory_regions(pid);

    unsafe {
        let handle = match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) {
            Ok(h) => h,
            Err(_) => return results,
        };

        for region in &regions {
            // Only scan committed regions with readable protection
            if region.state != MEM_COMMIT.0 {
                continue;
            }

            // Skip PAGE_NOACCESS and PAGE_GUARD regions
            let base_protect = region.protect & 0xFF;
            if base_protect == PAGE_NOACCESS.0 || region.protect & PAGE_GUARD.0 != 0 {
                continue;
            }

            // Get region type name
            let region_type = get_memory_type_name(region.mem_type).to_string();

            // Read memory in chunks (max 1MB per read)
            let chunk_size = region.region_size.min(1024 * 1024);
            let mut offset = 0;

            while offset < region.region_size {
                let read_size = (region.region_size - offset).min(chunk_size);
                let mut buffer = vec![0u8; read_size];
                let mut bytes_read: usize = 0;

                let read_result = ReadProcessMemory(
                    handle,
                    (region.base_address + offset) as *const _,
                    buffer.as_mut_ptr() as *mut _,
                    read_size,
                    Some(&mut bytes_read),
                );

                if read_result.is_err() || bytes_read == 0 {
                    break;
                }

                buffer.truncate(bytes_read);

                // Scan for ASCII strings
                if config.scan_ascii {
                    let ascii_strings = extract_ascii_strings(
                        &buffer,
                        region.base_address + offset,
                        config.min_length,
                        config.max_string_length,
                        &region_type,
                    );
                    results.extend(ascii_strings);
                }

                // Scan for UTF-16 strings
                if config.scan_utf16 {
                    let utf16_strings = extract_utf16_strings(
                        &buffer,
                        region.base_address + offset,
                        config.min_length,
                        config.max_string_length,
                        &region_type,
                    );
                    results.extend(utf16_strings);
                }

                offset += bytes_read;
            }
        }

        let _ = CloseHandle(handle);
    }

    results
}

/// Extract ASCII strings from a memory buffer
fn extract_ascii_strings(
    buffer: &[u8],
    base_address: usize,
    min_length: usize,
    max_length: usize,
    region_type: &str,
) -> Vec<StringResult> {
    let mut results = Vec::new();
    let mut start: Option<usize> = None;

    for (i, &byte) in buffer.iter().enumerate() {
        let is_printable = is_printable_ascii(byte);

        match (start, is_printable) {
            (None, true) => {
                start = Some(i);
            }
            (Some(s), false) => {
                let len = i - s;
                if len >= min_length {
                    let end = s + len.min(max_length);
                    let value = String::from_utf8_lossy(&buffer[s..end]).to_string();
                    results.push(StringResult {
                        address: base_address + s,
                        value,
                        encoding: StringEncoding::Ascii,
                        length: len,
                        region_type: region_type.to_string(),
                    });
                }
                start = None;
            }
            _ => {}
        }
    }

    // Check for string at end of buffer
    if let Some(s) = start {
        let len = buffer.len() - s;
        if len >= min_length {
            let end = s + len.min(max_length);
            let value = String::from_utf8_lossy(&buffer[s..end]).to_string();
            results.push(StringResult {
                address: base_address + s,
                value,
                encoding: StringEncoding::Ascii,
                length: len,
                region_type: region_type.to_string(),
            });
        }
    }

    results
}

/// Extract UTF-16 (Little Endian) strings from a memory buffer
fn extract_utf16_strings(
    buffer: &[u8],
    base_address: usize,
    min_length: usize,
    max_length: usize,
    region_type: &str,
) -> Vec<StringResult> {
    let mut results = Vec::new();

    if buffer.len() < 2 {
        return results;
    }

    let mut start: Option<usize> = None;
    let mut i = 0;

    while i + 1 < buffer.len() {
        let low = buffer[i];
        let high = buffer[i + 1];

        // UTF-16LE printable character: high byte is 0x00, low byte is printable ASCII
        let is_printable = high == 0 && is_printable_ascii(low);

        match (start, is_printable) {
            (None, true) => {
                start = Some(i);
            }
            (Some(s), false) => {
                let char_count = (i - s) / 2;
                if char_count >= min_length {
                    let end_chars = char_count.min(max_length);
                    let end_bytes = s + end_chars * 2;

                    // Convert to string
                    let wide_chars: Vec<u16> = buffer[s..end_bytes]
                        .chunks_exact(2)
                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                        .collect();
                    let value = String::from_utf16_lossy(&wide_chars);

                    results.push(StringResult {
                        address: base_address + s,
                        value,
                        encoding: StringEncoding::Utf16,
                        length: char_count,
                        region_type: region_type.to_string(),
                    });
                }
                start = None;
            }
            _ => {}
        }

        i += 2;
    }

    // Check for string at end of buffer
    if let Some(s) = start {
        let char_count = (buffer.len() - s) / 2;
        if char_count >= min_length {
            let end_chars = char_count.min(max_length);
            let end_bytes = s + end_chars * 2;

            if end_bytes <= buffer.len() {
                let wide_chars: Vec<u16> = buffer[s..end_bytes]
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                let value = String::from_utf16_lossy(&wide_chars);

                results.push(StringResult {
                    address: base_address + s,
                    value,
                    encoding: StringEncoding::Utf16,
                    length: char_count,
                    region_type: region_type.to_string(),
                });
            }
        }
    }

    results
}

/// Check if a byte is a printable ASCII character
#[inline]
fn is_printable_ascii(byte: u8) -> bool {
    // Printable range: 0x20-0x7E (space to tilde)
    // Also include tab (0x09) and newline (0x0A, 0x0D)
    matches!(byte, 0x20..=0x7E | 0x09 | 0x0A | 0x0D)
}

/// Get human-readable protection name
pub fn get_memory_protect_name(protect: u32) -> String {
    if protect == 0 {
        return "-".to_string();
    }

    let base = protect & 0xFF;
    let base_name = if base == PAGE_NOACCESS.0 {
        "NoAccess"
    } else if base == PAGE_READONLY.0 {
        "Read"
    } else if base == PAGE_READWRITE.0 {
        "ReadWrite"
    } else if base == PAGE_WRITECOPY.0 {
        "WriteCopy"
    } else if base == PAGE_EXECUTE.0 {
        "Execute"
    } else if base == PAGE_EXECUTE_READ.0 {
        "ExecuteRead"
    } else if base == PAGE_EXECUTE_READWRITE.0 {
        "ExecuteReadWrite"
    } else if base == PAGE_EXECUTE_WRITECOPY.0 {
        "ExecuteWriteCopy"
    } else {
        "Unknown"
    };

    let mut modifiers = Vec::new();
    if protect & PAGE_GUARD.0 != 0 {
        modifiers.push("Guard");
    }
    if protect & PAGE_NOCACHE.0 != 0 {
        modifiers.push("NoCache");
    }
    if protect & PAGE_WRITECOMBINE.0 != 0 {
        modifiers.push("WriteCombine");
    }

    if modifiers.is_empty() {
        base_name.to_string()
    } else {
        format!("{} + {}", base_name, modifiers.join(" + "))
    }
}
