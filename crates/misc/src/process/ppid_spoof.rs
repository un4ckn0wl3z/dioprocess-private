use std::path::Path;

use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, InitializeProcThreadAttributeList, OpenProcess,
    UpdateProcThreadAttribute, CREATE_SUSPENDED, EXTENDED_STARTUPINFO_PRESENT,
    LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_ALL_ACCESS, PROCESS_INFORMATION, STARTUPINFOEXW,
};

use crate::error::MiscError;

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
/// * `block_dlls` - If true, also blocks non-Microsoft signed DLLs from being loaded
pub fn create_ppid_spoofed_process(
    parent_pid: u32,
    exe_path: &str,
    args: &str,
    suspended: bool,
    block_dlls: bool,
) -> Result<(u32, u32), MiscError> {
    const PROC_THREAD_ATTRIBUTE_PARENT_PROCESS: usize = 0x00020000;
    const PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY: usize = 0x00020007;
    const PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON: u64 =
        0x0000_1000_0000_0000;

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

    let attr_count: u32 = if block_dlls { 2 } else { 1 };

    unsafe {
        // Open handle to the parent process
        let h_parent = OpenProcess(PROCESS_ALL_ACCESS, false, parent_pid)
            .map_err(|_| MiscError::OpenProcessFailed(parent_pid))?;

        // First call to get required attribute list size
        let mut attr_size: usize = 0;
        let _ = InitializeProcThreadAttributeList(
            LPPROC_THREAD_ATTRIBUTE_LIST(std::ptr::null_mut()),
            attr_count,
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
        if InitializeProcThreadAttributeList(attr_list, attr_count, 0, &mut attr_size).is_err() {
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
                "UpdateProcThreadAttribute for parent process failed".to_string(),
            ));
        }

        // Optionally set the block DLL policy attribute
        let mut policy: u64 =
            PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
        if block_dlls {
            if UpdateProcThreadAttribute(
                attr_list,
                0,
                PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
                Some(&mut policy as *mut _ as *const std::ffi::c_void),
                std::mem::size_of::<u64>(),
                None,
                None,
            )
            .is_err()
            {
                DeleteProcThreadAttributeList(attr_list);
                let _ = CloseHandle(h_parent);
                return Err(MiscError::PPidSpoofFailed(
                    "UpdateProcThreadAttribute for BlockDllPolicy failed".to_string(),
                ));
            }
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
