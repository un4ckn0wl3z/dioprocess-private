use std::ffi::CString;
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
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAllocEx, VirtualFreeEx,
};
use windows::Win32::System::Threading::{
    OpenProcess, OpenThread, ResumeThread, SuspendThread, PROCESS_ALL_ACCESS,
    THREAD_GET_CONTEXT, THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME,
};

use crate::error::MiscError;

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
