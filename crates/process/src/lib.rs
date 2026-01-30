//! Windows process management module
//! Contains Windows API calls for process enumeration and management

use std::mem::zeroed;
use std::process::Command;
use std::sync::Mutex;
use std::collections::HashMap;
use sysinfo::{System, ProcessesToUpdate, ProcessRefreshKind, RefreshKind};
use windows::Win32::Foundation::{CloseHandle, HANDLE, MAX_PATH, BOOL};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable,
    MIB_TCP_STATE, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
    MIB_TCPROW_OWNER_PID, MIB_UDPROW_OWNER_PID,
};
use windows::Win32::Networking::WinSock::AF_INET;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    Thread32First, Thread32Next, THREADENTRY32, TH32CS_SNAPTHREAD,
};
use windows::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, TerminateProcess,
    PROCESS_NAME_WIN32, PROCESS_QUERY_INFORMATION, PROCESS_TERMINATE, PROCESS_VM_READ,
    PROCESS_SUSPEND_RESUME, PROCESS_DUP_HANDLE,
    OpenThread, SuspendThread, ResumeThread, TerminateThread, GetThreadPriority,
    THREAD_SUSPEND_RESUME, THREAD_TERMINATE, THREAD_QUERY_INFORMATION,
};
use windows::core::PWSTR;
use ntapi::ntpsapi::{NtSuspendProcess, NtResumeProcess};
use ntapi::ntexapi::{NtQuerySystemInformation, SystemHandleInformation};
use windows::Win32::System::Threading::GetCurrentProcess;
use windows::Win32::Foundation::DuplicateHandle;

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
                if buffer_size > 0x4000000 { // 64MB max
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
        
        let number_of_handles = u32::from_ne_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;
        
        // Each SYSTEM_HANDLE_TABLE_ENTRY_INFO is 16 bytes on x86, 24 bytes on x64
        #[cfg(target_pointer_width = "64")]
        const ENTRY_SIZE: usize = 24;
        #[cfg(target_pointer_width = "32")]
        const ENTRY_SIZE: usize = 16;
        
        let entries_start = if cfg!(target_pointer_width = "64") { 8 } else { 4 }; // alignment
        
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
                let access = u32::from_ne_bytes([buffer[offset + 16], buffer[offset + 17], buffer[offset + 18], buffer[offset + 19]]);
                (unique_pid, handle_val, obj_type, access)
            };
            
            #[cfg(target_pointer_width = "32")]
            let (entry_pid, handle_value, object_type, granted_access) = {
                let unique_pid = u16::from_ne_bytes([buffer[offset], buffer[offset + 1]]) as u32;
                let obj_type = buffer[offset + 4];
                let handle_val = u16::from_ne_bytes([buffer[offset + 6], buffer[offset + 7]]);
                let access = u32::from_ne_bytes([buffer[offset + 12], buffer[offset + 13], buffer[offset + 14], buffer[offset + 15]]);
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
    }.to_string()
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

/// Network connection protocol
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "TCP"),
            Protocol::Udp => write!(f, "UDP"),
        }
    }
}

/// TCP connection state
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    DeleteTcb,
    Unknown,
}

impl std::fmt::Display for TcpState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TcpState::Closed => write!(f, "CLOSED"),
            TcpState::Listen => write!(f, "LISTEN"),
            TcpState::SynSent => write!(f, "SYN_SENT"),
            TcpState::SynReceived => write!(f, "SYN_RECV"),
            TcpState::Established => write!(f, "ESTABLISHED"),
            TcpState::FinWait1 => write!(f, "FIN_WAIT1"),
            TcpState::FinWait2 => write!(f, "FIN_WAIT2"),
            TcpState::CloseWait => write!(f, "CLOSE_WAIT"),
            TcpState::Closing => write!(f, "CLOSING"),
            TcpState::LastAck => write!(f, "LAST_ACK"),
            TcpState::TimeWait => write!(f, "TIME_WAIT"),
            TcpState::DeleteTcb => write!(f, "DELETE_TCB"),
            TcpState::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

impl From<MIB_TCP_STATE> for TcpState {
    fn from(state: MIB_TCP_STATE) -> Self {
        match state {
            MIB_TCP_STATE(1) => TcpState::Closed,
            MIB_TCP_STATE(2) => TcpState::Listen,
            MIB_TCP_STATE(3) => TcpState::SynSent,
            MIB_TCP_STATE(4) => TcpState::SynReceived,
            MIB_TCP_STATE(5) => TcpState::Established,
            MIB_TCP_STATE(6) => TcpState::FinWait1,
            MIB_TCP_STATE(7) => TcpState::FinWait2,
            MIB_TCP_STATE(8) => TcpState::CloseWait,
            MIB_TCP_STATE(9) => TcpState::Closing,
            MIB_TCP_STATE(10) => TcpState::LastAck,
            MIB_TCP_STATE(11) => TcpState::TimeWait,
            MIB_TCP_STATE(12) => TcpState::DeleteTcb,
            _ => TcpState::Unknown,
        }
    }
}

/// Network connection information
#[derive(Clone, Debug, PartialEq)]
pub struct NetworkConnection {
    pub protocol: Protocol,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: Option<TcpState>,
    pub pid: u32,
    pub process_name: String,
    pub exe_path: String,
}

/// Convert u32 IP address to string
fn ip_to_string(ip: u32) -> String {
    let bytes = ip.to_ne_bytes();
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}

/// Convert network byte order port to host byte order
fn port_from_network(port: u32) -> u16 {
    ((port & 0xFF) << 8 | (port >> 8) & 0xFF) as u16
}

/// Get all network connections (TCP and UDP)
pub fn get_network_connections() -> Vec<NetworkConnection> {
    let mut connections = Vec::new();

    // Get process info map for name/path lookup
    let process_map: HashMap<u32, (String, String)> = get_processes()
        .into_iter()
        .map(|p| (p.pid, (p.name, p.exe_path)))
        .collect();

    // Get TCP connections
    connections.extend(get_tcp_connections(&process_map));

    // Get UDP connections
    connections.extend(get_udp_connections(&process_map));

    connections
}

/// Get TCP connections
fn get_tcp_connections(process_map: &HashMap<u32, (String, String)>) -> Vec<NetworkConnection> {
    let mut connections = Vec::new();

    unsafe {
        let mut size: u32 = 0;

        // First call to get required buffer size
        let _ = GetExtendedTcpTable(
            None,
            &mut size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );

        if size == 0 {
            return connections;
        }

        let mut buffer: Vec<u8> = vec![0; size as usize];

        let result = GetExtendedTcpTable(
            Some(buffer.as_mut_ptr() as *mut _),
            &mut size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );

        if result != 0 {
            return connections;
        }

        // Parse the table
        // Structure: DWORD dwNumEntries, MIB_TCPROW_OWNER_PID table[]
        let num_entries = u32::from_ne_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;
        let entry_size = std::mem::size_of::<MIB_TCPROW_OWNER_PID>();

        for i in 0..num_entries {
            let offset = 4 + i * entry_size;
            if offset + entry_size > buffer.len() {
                break;
            }

            let entry_ptr = buffer.as_ptr().add(offset) as *const MIB_TCPROW_OWNER_PID;
            let entry = &*entry_ptr;

            let pid = entry.dwOwningPid;
            let (process_name, exe_path) = process_map
                .get(&pid)
                .cloned()
                .unwrap_or_else(|| (format!("PID {}", pid), String::new()));

            connections.push(NetworkConnection {
                protocol: Protocol::Tcp,
                local_addr: ip_to_string(entry.dwLocalAddr),
                local_port: port_from_network(entry.dwLocalPort),
                remote_addr: ip_to_string(entry.dwRemoteAddr),
                remote_port: port_from_network(entry.dwRemotePort),
                state: Some(TcpState::from(MIB_TCP_STATE(entry.dwState as i32))),
                pid,
                process_name,
                exe_path,
            });
        }
    }

    connections
}

/// Get UDP connections
fn get_udp_connections(process_map: &HashMap<u32, (String, String)>) -> Vec<NetworkConnection> {
    let mut connections = Vec::new();

    unsafe {
        let mut size: u32 = 0;

        // First call to get required buffer size
        let _ = GetExtendedUdpTable(
            None,
            &mut size,
            false,
            AF_INET.0 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        );

        if size == 0 {
            return connections;
        }

        let mut buffer: Vec<u8> = vec![0; size as usize];

        let result = GetExtendedUdpTable(
            Some(buffer.as_mut_ptr() as *mut _),
            &mut size,
            false,
            AF_INET.0 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        );

        if result != 0 {
            return connections;
        }

        // Parse the table
        // Structure: DWORD dwNumEntries, MIB_UDPROW_OWNER_PID table[]
        let num_entries = u32::from_ne_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;
        let entry_size = std::mem::size_of::<MIB_UDPROW_OWNER_PID>();

        for i in 0..num_entries {
            let offset = 4 + i * entry_size;
            if offset + entry_size > buffer.len() {
                break;
            }

            let entry_ptr = buffer.as_ptr().add(offset) as *const MIB_UDPROW_OWNER_PID;
            let entry = &*entry_ptr;

            let pid = entry.dwOwningPid;
            let (process_name, exe_path) = process_map
                .get(&pid)
                .cloned()
                .unwrap_or_else(|| (format!("PID {}", pid), String::new()));

            connections.push(NetworkConnection {
                protocol: Protocol::Udp,
                local_addr: ip_to_string(entry.dwLocalAddr),
                local_port: port_from_network(entry.dwLocalPort),
                remote_addr: String::new(),
                remote_port: 0,
                state: None,
                pid,
                process_name,
                exe_path,
            });
        }
    }

    connections
}
