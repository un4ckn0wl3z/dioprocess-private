//! UEFI NVRAM variable management
//!
//! Read/write DioProcess UEFI bootkit configuration variables via
//! GetFirmwareEnvironmentVariableW / SetFirmwareEnvironmentVariableW.
//! Requires SeSystemEnvironmentPrivilege (admin process).

use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, LUID};
use windows::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows::Win32::System::WindowsProgramming::{
    GetFirmwareEnvironmentVariableW, SetFirmwareEnvironmentVariableW,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::error::UefiError;

/// NVRAM namespace GUID for DioProcess variables
/// Must match the GUID in DioProcessEfi.c
const DIOPROCESS_UEFI_NAMESPACE: PCWSTR =
    w!("{D100C0C5-1337-4242-BEEF-CAFEBABE0001}");

/// NVRAM variable names
const VAR_DSE_BYPASS: PCWSTR = w!("DioProcessDseBypass");
const VAR_KPP_BYPASS: PCWSTR = w!("DioProcessKppBypass");

/// UEFI bootkit configuration (stored in NVRAM)
#[derive(Clone, Debug, Default)]
pub struct UefiConfig {
    /// Whether DSE (Driver Signature Enforcement) bypass is enabled
    pub dse_bypass: bool,
    /// Whether PatchGuard/KPP bypass is enabled
    pub kpp_bypass: bool,
}

/// Enable SeSystemEnvironmentPrivilege on the current process token.
/// Required for NVRAM variable access.
fn enable_system_environment_privilege() -> Result<(), UefiError> {
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
        .map_err(|_| {
            UefiError::PrivilegeError(format!(
                "OpenProcessToken failed: {}",
                GetLastError().0
            ))
        })?;

        let mut luid = LUID::default();
        LookupPrivilegeValueW(PCWSTR::null(), w!("SeSystemEnvironmentPrivilege"), &mut luid)
            .map_err(|_| {
                let _ = CloseHandle(token);
                UefiError::PrivilegeError(format!(
                    "LookupPrivilegeValue failed: {}",
                    GetLastError().0
                ))
            })?;

        let mut tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        AdjustTokenPrivileges(token, false, Some(&mut tp), 0, None, None).map_err(|_| {
            let _ = CloseHandle(token);
            UefiError::PrivilegeError(format!(
                "AdjustTokenPrivileges failed: {}",
                GetLastError().0
            ))
        })?;

        let _ = CloseHandle(token);
        Ok(())
    }
}

/// Read a single NVRAM boolean variable (1 byte: 0 or 1)
fn read_nvram_bool(name: PCWSTR) -> Result<bool, UefiError> {
    enable_system_environment_privilege()?;

    unsafe {
        let mut buffer: [u8; 1] = [0];
        let bytes_read = GetFirmwareEnvironmentVariableW(
            name,
            DIOPROCESS_UEFI_NAMESPACE,
            Some(buffer.as_mut_ptr() as *mut _),
            buffer.len() as u32,
        );

        if bytes_read == 0 {
            let err = GetLastError().0;
            // ERROR_ENVVAR_NOT_FOUND (203) means variable doesn't exist yet — default to false
            if err == 203 {
                return Ok(false);
            }
            return Err(UefiError::NvramReadFailed(err));
        }

        Ok(buffer[0] != 0)
    }
}

/// Write a single NVRAM boolean variable (1 byte: 0 or 1)
fn write_nvram_bool(name: PCWSTR, value: bool) -> Result<(), UefiError> {
    enable_system_environment_privilege()?;

    unsafe {
        let buffer: [u8; 1] = [if value { 1 } else { 0 }];
        let success = SetFirmwareEnvironmentVariableW(
            name,
            DIOPROCESS_UEFI_NAMESPACE,
            Some(buffer.as_ptr() as *const _),
            buffer.len() as u32,
        );

        if success.is_err() {
            return Err(UefiError::NvramWriteFailed(GetLastError().0));
        }

        Ok(())
    }
}

/// Read current UEFI bootkit configuration from NVRAM.
/// Returns default (all disabled) if variables don't exist yet.
pub fn read_uefi_config() -> Result<UefiConfig, UefiError> {
    Ok(UefiConfig {
        dse_bypass: read_nvram_bool(VAR_DSE_BYPASS)?,
        kpp_bypass: read_nvram_bool(VAR_KPP_BYPASS)?,
    })
}

/// Write UEFI bootkit configuration to NVRAM.
/// Changes take effect on next reboot.
pub fn write_uefi_config(config: &UefiConfig) -> Result<(), UefiError> {
    write_nvram_bool(VAR_DSE_BYPASS, config.dse_bypass)?;
    write_nvram_bool(VAR_KPP_BYPASS, config.kpp_bypass)?;
    Ok(())
}

/// Check if the system firmware is UEFI (not legacy BIOS).
/// Attempts to read a well-known EFI variable; if it fails with
/// ERROR_INVALID_FUNCTION (1), the firmware is legacy BIOS.
pub fn is_uefi_system() -> bool {
    unsafe {
        // Try to read an empty variable — the error code tells us firmware type
        let mut buf: [u8; 1] = [0];
        let result = GetFirmwareEnvironmentVariableW(
            w!(""),
            w!("{00000000-0000-0000-0000-000000000000}"),
            Some(buf.as_mut_ptr() as *mut _),
            buf.len() as u32,
        );

        if result == 0 {
            let err = GetLastError().0;
            // ERROR_INVALID_FUNCTION (1) = Legacy BIOS
            // Any other error (e.g. ERROR_ENVVAR_NOT_FOUND) = UEFI
            err != 1
        } else {
            true
        }
    }
}

/// Check if Secure Boot is currently enabled.
/// Reads the standard "SecureBoot" UEFI variable from the global namespace.
pub fn is_secure_boot_enabled() -> bool {
    unsafe {
        let mut buffer: [u8; 1] = [0];
        let bytes_read = GetFirmwareEnvironmentVariableW(
            w!("SecureBoot"),
            w!("{8be4df61-93ca-11d2-aa0d-00e098032b8c}"),
            Some(buffer.as_mut_ptr() as *mut _),
            buffer.len() as u32,
        );

        if bytes_read == 0 {
            return false;
        }

        buffer[0] != 0
    }
}

/// Read the debug log written by the UEFI bootkit's ExitBootServices hook.
/// The EFI driver saves a UTF-16 string to NVRAM after patching.
/// Returns the log string, or None if no log exists.
pub fn read_debug_log() -> Option<String> {
    if enable_system_environment_privilege().is_err() {
        return None;
    }

    unsafe {
        let mut buffer: [u8; 2048] = [0; 2048];
        let bytes_read = GetFirmwareEnvironmentVariableW(
            w!("DioProcessDebugLog"),
            DIOPROCESS_UEFI_NAMESPACE,
            Some(buffer.as_mut_ptr() as *mut _),
            buffer.len() as u32,
        );

        if bytes_read == 0 {
            return None;
        }

        // Convert UTF-16LE bytes to String
        let u16_slice = std::slice::from_raw_parts(
            buffer.as_ptr() as *const u16,
            bytes_read as usize / 2,
        );
        // Trim null terminators
        let trimmed = match u16_slice.iter().position(|&c| c == 0) {
            Some(pos) => &u16_slice[..pos],
            None => u16_slice,
        };
        Some(String::from_utf16_lossy(trimmed))
    }
}

/// Clear the debug log NVRAM variable.
pub fn clear_debug_log() -> Result<(), UefiError> {
    enable_system_environment_privilege()?;

    unsafe {
        // Setting size to 0 deletes the variable
        let _ = SetFirmwareEnvironmentVariableW(
            w!("DioProcessDebugLog"),
            DIOPROCESS_UEFI_NAMESPACE,
            None,
            0,
        );
        Ok(())
    }
}

/// Check if Windows test signing mode is enabled via bcdedit.
pub fn is_test_signing_enabled() -> bool {
    let output = std::process::Command::new("bcdedit")
        .args(["/enum", "{current}"])
        .output();

    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout).to_lowercase();
            stdout.contains("testsigning") && stdout.contains("yes")
        }
        Err(_) => false,
    }
}
