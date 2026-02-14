//! Error types for the UEFI manager crate

use std::fmt;

/// Errors that can occur during UEFI operations
#[derive(Debug)]
pub enum UefiError {
    /// Failed to enable required privilege
    PrivilegeError(String),
    /// Failed to read NVRAM variable
    NvramReadFailed(u32),
    /// Failed to write NVRAM variable
    NvramWriteFailed(u32),
    /// Failed to mount the EFI System Partition
    EspMountFailed(String),
    /// Failed to unmount the EFI System Partition
    EspUnmountFailed(String),
    /// File operation failed (copy, delete, etc.)
    FileOperationFailed(String),
    /// bcdedit command failed
    BcdEditFailed(String),
    /// EFI driver is not installed on ESP
    EfiNotInstalled,
    /// System is not UEFI (legacy BIOS)
    NotUefiSystem,
    /// Invalid state or parameter
    InvalidState,
}

impl fmt::Display for UefiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UefiError::PrivilegeError(msg) => {
                write!(f, "Privilege error: {}", msg)
            }
            UefiError::NvramReadFailed(code) => {
                write!(f, "NVRAM read failed: error code {}", code)
            }
            UefiError::NvramWriteFailed(code) => {
                write!(f, "NVRAM write failed: error code {}", code)
            }
            UefiError::EspMountFailed(msg) => {
                write!(f, "ESP mount failed: {}", msg)
            }
            UefiError::EspUnmountFailed(msg) => {
                write!(f, "ESP unmount failed: {}", msg)
            }
            UefiError::FileOperationFailed(msg) => {
                write!(f, "File operation failed: {}", msg)
            }
            UefiError::BcdEditFailed(msg) => {
                write!(f, "bcdedit failed: {}", msg)
            }
            UefiError::EfiNotInstalled => {
                write!(f, "EFI driver not installed on ESP")
            }
            UefiError::NotUefiSystem => {
                write!(f, "System is not UEFI (legacy BIOS detected)")
            }
            UefiError::InvalidState => {
                write!(f, "Invalid state")
            }
        }
    }
}

impl std::error::Error for UefiError {}
