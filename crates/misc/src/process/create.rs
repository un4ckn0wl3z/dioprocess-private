use std::path::Path;

use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, InitializeProcThreadAttributeList,
    UpdateProcThreadAttribute, CREATE_SUSPENDED, EXTENDED_STARTUPINFO_PRESENT,
    LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION, STARTUPINFOEXW, STARTUPINFOW,
};

use crate::error::MiscError;

/// Create a new process using CreateProcessW.
///
/// Returns (pid, thread_id) on success.
///
/// # Arguments
/// * `exe_path` - Path to the executable
/// * `args` - Command line arguments (can be empty)
/// * `suspended` - If true, creates the process in a suspended state
/// * `block_dlls` - If true, blocks non-Microsoft signed DLLs from being loaded
pub fn create_process(exe_path: &str, args: &str, suspended: bool, block_dlls: bool) -> Result<(u32, u32), MiscError> {
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

    // Convert to wide string (UTF-16)
    let mut cmd_wide: Vec<u16> = cmd_line.encode_utf16().chain(std::iter::once(0)).collect();

    unsafe {
        let mut process_info: PROCESS_INFORMATION = std::mem::zeroed();

        if block_dlls {
            // Use STARTUPINFOEXW with mitigation policy attribute
            let mut attr_size: usize = 0;
            let _ = InitializeProcThreadAttributeList(
                LPPROC_THREAD_ATTRIBUTE_LIST(std::ptr::null_mut()),
                1,
                0,
                &mut attr_size,
            );

            if attr_size == 0 {
                return Err(MiscError::CreateProcessFailed(
                    "InitializeProcThreadAttributeList returned zero size".to_string(),
                ));
            }

            let mut attr_buf = vec![0u8; attr_size];
            let attr_list = LPPROC_THREAD_ATTRIBUTE_LIST(attr_buf.as_mut_ptr() as *mut _);

            if InitializeProcThreadAttributeList(attr_list, 1, 0, &mut attr_size).is_err() {
                return Err(MiscError::CreateProcessFailed(
                    "InitializeProcThreadAttributeList failed".to_string(),
                ));
            }

            let mut policy: u64 =
                PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;

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
                return Err(MiscError::CreateProcessFailed(
                    "UpdateProcThreadAttribute for BlockDllPolicy failed".to_string(),
                ));
            }

            let mut startup_info_ex: STARTUPINFOEXW = std::mem::zeroed();
            startup_info_ex.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
            startup_info_ex.lpAttributeList = attr_list;

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

            DeleteProcThreadAttributeList(attr_list);

            if result.is_err() {
                return Err(MiscError::CreateProcessFailed(format!(
                    "CreateProcessW with BlockDllPolicy failed for {}",
                    exe_path
                )));
            }
        } else {
            // Simple path without extended attributes
            let mut startup_info: STARTUPINFOW = std::mem::zeroed();
            startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as u32;

            let creation_flags = if suspended { CREATE_SUSPENDED } else { Default::default() };

            let result = CreateProcessW(
                None,
                windows::core::PWSTR(cmd_wide.as_mut_ptr()),
                None,
                None,
                false,
                creation_flags,
                None,
                None,
                &startup_info,
                &mut process_info,
            );

            if result.is_err() {
                return Err(MiscError::CreateProcessFailed(format!(
                    "CreateProcessW failed for {}",
                    exe_path
                )));
            }
        }

        let pid = process_info.dwProcessId;
        let tid = process_info.dwThreadId;

        // Close handles (we don't need them)
        let _ = CloseHandle(process_info.hThread);
        let _ = CloseHandle(process_info.hProcess);

        Ok((pid, tid))
    }
}
