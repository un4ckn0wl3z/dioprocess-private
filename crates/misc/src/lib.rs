//! Miscellaneous process utilities

use std::ffi::CString;
use std::fmt;
use std::path::Path;

use windows::core::PCSTR;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::Debug::{
    GetThreadContext, SetThreadContext, WriteProcessMemory, CONTEXT, CONTEXT_FULL_AMD64,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::Win32::System::Memory::{
    VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_DECOMMIT, MEM_RELEASE, MEM_RESERVE,
    PAGE_EXECUTE_READWRITE, PAGE_READWRITE,
};
use windows::Win32::System::Threading::{
    CreateRemoteThread, OpenProcess, OpenThread, QueueUserAPC, ResumeThread, SuspendThread,
    WaitForSingleObject, PROCESS_ALL_ACCESS, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION,
    PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE, THREAD_GET_CONTEXT,
    THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME,
};

/// Errors that can occur during misc operations.
#[derive(Debug)]
pub enum MiscError {
    FileNotFound(String),
    OpenProcessFailed(u32),
    AllocFailed,
    WriteFailed,
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
}

impl fmt::Display for MiscError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MiscError::FileNotFound(path) => write!(f, "DLL file not found: {}", path),
            MiscError::OpenProcessFailed(pid) => write!(f, "Failed to open process {}", pid),
            MiscError::AllocFailed => write!(f, "Failed to allocate memory in target process"),
            MiscError::WriteFailed => write!(f, "Failed to write to target process memory"),
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
