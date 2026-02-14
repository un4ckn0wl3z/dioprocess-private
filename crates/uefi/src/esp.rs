//! EFI System Partition management
//!
//! Mount/unmount the ESP, install/remove the DioProcess EFI driver,
//! and manage boot entries via bcdedit.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::UefiError;

/// Information about an installed EFI driver
#[derive(Clone, Debug)]
pub struct EfiInstallInfo {
    /// Full path to the EFI binary on the ESP
    pub efi_path: String,
    /// BCD boot entry identifier (GUID)
    pub boot_entry_id: Option<String>,
}

/// Find an available drive letter for ESP mounting (Z: down to S:)
fn find_available_drive() -> Result<String, UefiError> {
    for letter in ('S'..='Z').rev() {
        let drive = format!("{}:", letter);
        let path = format!("{}\\", drive);
        if !Path::new(&path).exists() {
            return Ok(drive);
        }
    }
    Err(UefiError::EspMountFailed(
        "No available drive letters".to_string(),
    ))
}

/// Mount the EFI System Partition to a temporary drive letter.
/// Returns the drive path (e.g., "Z:").
pub fn mount_esp() -> Result<PathBuf, UefiError> {
    let drive = find_available_drive()?;
    let drive_with_slash = format!("{}\\", drive);

    let output = Command::new("mountvol")
        .args([&drive_with_slash, "/s"])
        .output()
        .map_err(|e| UefiError::EspMountFailed(format!("Failed to run mountvol: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(UefiError::EspMountFailed(format!(
            "mountvol failed: {}",
            stderr.trim()
        )));
    }

    Ok(PathBuf::from(drive_with_slash))
}

/// Unmount the EFI System Partition from the given drive letter.
pub fn unmount_esp(drive: &Path) -> Result<(), UefiError> {
    let drive_str = drive.to_string_lossy().to_string();

    let output = Command::new("mountvol")
        .args([&drive_str, "/d"])
        .output()
        .map_err(|e| UefiError::EspUnmountFailed(format!("Failed to run mountvol: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(UefiError::EspUnmountFailed(format!(
            "mountvol /d failed: {}",
            stderr.trim()
        )));
    }

    Ok(())
}

/// Install the DioProcess EFI driver to the ESP.
///
/// 1. Mount ESP
/// 2. Create ESP:\EFI\DioProcess\ directory
/// 3. Copy the EFI binary
/// 4. Create a firmware boot entry via bcdedit
/// 5. Unmount ESP
pub fn install_efi_driver(efi_binary_path: &Path) -> Result<(), UefiError> {
    if !efi_binary_path.exists() {
        return Err(UefiError::FileOperationFailed(format!(
            "EFI binary not found: {}",
            efi_binary_path.display()
        )));
    }

    // Mount ESP
    let esp_drive = mount_esp()?;

    let result = (|| -> Result<(), UefiError> {
        // Create target directory
        let target_dir = esp_drive.join("EFI").join("DioProcess");
        std::fs::create_dir_all(&target_dir).map_err(|e| {
            UefiError::FileOperationFailed(format!("Failed to create directory: {}", e))
        })?;

        // Copy EFI binary
        let target_file = target_dir.join("DioProcessEfi.efi");
        std::fs::copy(efi_binary_path, &target_file).map_err(|e| {
            UefiError::FileOperationFailed(format!("Failed to copy EFI binary: {}", e))
        })?;

        // Create boot entry via bcdedit
        // Step 1: Copy {bootmgr} to create a new firmware entry
        let copy_output = Command::new("bcdedit")
            .args(["/copy", "{bootmgr}", "/d", "DioProcess UEFI"])
            .output()
            .map_err(|e| UefiError::BcdEditFailed(format!("Failed to run bcdedit: {}", e)))?;

        if !copy_output.status.success() {
            let stderr = String::from_utf8_lossy(&copy_output.stderr);
            return Err(UefiError::BcdEditFailed(format!(
                "bcdedit /copy failed: {}",
                stderr.trim()
            )));
        }

        // Extract the new GUID from bcdedit output
        let stdout = String::from_utf8_lossy(&copy_output.stdout);
        let guid = extract_guid(&stdout).ok_or_else(|| {
            UefiError::BcdEditFailed("Failed to extract GUID from bcdedit output".to_string())
        })?;

        // Step 2: Set the path to our EFI driver
        let set_path_output = Command::new("bcdedit")
            .args([
                "/set",
                &guid,
                "path",
                "\\EFI\\DioProcess\\DioProcessEfi.efi",
            ])
            .output()
            .map_err(|e| UefiError::BcdEditFailed(format!("Failed to run bcdedit /set: {}", e)))?;

        if !set_path_output.status.success() {
            // Clean up: delete the boot entry we just created
            let _ = Command::new("bcdedit").args(["/delete", &guid]).output();
            let stderr = String::from_utf8_lossy(&set_path_output.stderr);
            return Err(UefiError::BcdEditFailed(format!(
                "bcdedit /set path failed: {}",
                stderr.trim()
            )));
        }

        // Step 3: Add to firmware boot order (first position)
        let order_output = Command::new("bcdedit")
            .args([
                "/set",
                "{fwbootmgr}",
                "displayorder",
                &guid,
                "/addfirst",
            ])
            .output()
            .map_err(|e| {
                UefiError::BcdEditFailed(format!("Failed to run bcdedit displayorder: {}", e))
            })?;

        if !order_output.status.success() {
            let stderr = String::from_utf8_lossy(&order_output.stderr);
            return Err(UefiError::BcdEditFailed(format!(
                "bcdedit displayorder failed: {}",
                stderr.trim()
            )));
        }

        Ok(())
    })();

    // Always unmount ESP, even if installation failed
    let _ = unmount_esp(&esp_drive);

    result
}

/// Remove the DioProcess EFI driver from the ESP.
///
/// 1. Remove bcdedit boot entry
/// 2. Mount ESP
/// 3. Delete ESP:\EFI\DioProcess\ directory
/// 4. Unmount ESP
pub fn remove_efi_driver() -> Result<(), UefiError> {
    // First, find and remove the boot entry
    if let Some(guid) = find_dioprocess_boot_entry()? {
        let output = Command::new("bcdedit")
            .args(["/delete", &guid])
            .output()
            .map_err(|e| {
                UefiError::BcdEditFailed(format!("Failed to run bcdedit /delete: {}", e))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(UefiError::BcdEditFailed(format!(
                "bcdedit /delete failed: {}",
                stderr.trim()
            )));
        }
    }

    // Mount ESP and delete files
    let esp_drive = mount_esp()?;

    let result = (|| -> Result<(), UefiError> {
        let target_dir = esp_drive.join("EFI").join("DioProcess");
        if target_dir.exists() {
            std::fs::remove_dir_all(&target_dir).map_err(|e| {
                UefiError::FileOperationFailed(format!(
                    "Failed to remove EFI directory: {}",
                    e
                ))
            })?;
        }
        Ok(())
    })();

    let _ = unmount_esp(&esp_drive);

    result
}

/// Check if the DioProcess EFI driver is currently installed on the ESP.
pub fn is_efi_installed() -> Result<bool, UefiError> {
    // Check for boot entry first (doesn't require ESP mount)
    if let Some(_) = find_dioprocess_boot_entry()? {
        return Ok(true);
    }

    // Also check if the file exists on ESP
    let esp_drive = mount_esp()?;
    let target_file = esp_drive.join("EFI").join("DioProcess").join("DioProcessEfi.efi");
    let exists = target_file.exists();
    let _ = unmount_esp(&esp_drive);

    Ok(exists)
}

/// Get installation information (path, boot entry ID).
pub fn get_install_info() -> Result<Option<EfiInstallInfo>, UefiError> {
    let boot_entry_id = find_dioprocess_boot_entry()?;

    let esp_drive = mount_esp()?;
    let target_file = esp_drive.join("EFI").join("DioProcess").join("DioProcessEfi.efi");
    let exists = target_file.exists();
    let path_str = target_file.to_string_lossy().to_string();
    let _ = unmount_esp(&esp_drive);

    if exists || boot_entry_id.is_some() {
        Ok(Some(EfiInstallInfo {
            efi_path: if exists {
                path_str
            } else {
                String::new()
            },
            boot_entry_id,
        }))
    } else {
        Ok(None)
    }
}

/// Find the DioProcess boot entry GUID in bcdedit firmware entries.
fn find_dioprocess_boot_entry() -> Result<Option<String>, UefiError> {
    let output = Command::new("bcdedit")
        .args(["/enum", "firmware"])
        .output()
        .map_err(|e| UefiError::BcdEditFailed(format!("Failed to run bcdedit /enum: {}", e)))?;

    if !output.status.success() {
        return Ok(None);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse bcdedit output looking for "DioProcess UEFI" entry
    let mut current_guid: Option<String> = None;
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("identifier") {
            // Extract GUID: "identifier              {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}"
            if let Some(guid) = extract_guid(trimmed) {
                current_guid = Some(guid);
            }
        }
        if trimmed.starts_with("description") && trimmed.contains("DioProcess UEFI") {
            if let Some(guid) = current_guid.take() {
                return Ok(Some(guid));
            }
        }
        // Reset on new entry separator
        if trimmed.is_empty() {
            current_guid = None;
        }
    }

    Ok(None)
}

/// Extract a GUID from a string like "... {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx} ..."
fn extract_guid(s: &str) -> Option<String> {
    let start = s.find('{')?;
    let end = s.find('}')?;
    if end > start {
        Some(s[start..=end].to_string())
    } else {
        None
    }
}
