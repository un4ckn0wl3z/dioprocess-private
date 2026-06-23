//! SMM error types

use thiserror::Error;

#[derive(Error, Debug)]
pub enum SmmError {
    #[error("Failed to open SMM driver: {0}")]
    DriverOpenFailed(String),

    #[error("SMM driver not loaded")]
    DriverNotLoaded,

    #[error("DeviceIoControl failed: {0}")]
    IoctlFailed(String),

    #[error("SMI handler not available")]
    SmiHandlerUnavailable,

    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    #[error("Failed to cache session info")]
    CacheSessionFailed,

    #[error("Physical read failed")]
    PhysReadFailed,

    #[error("Physical write failed")]
    PhysWriteFailed,

    #[error("Virtual read failed")]
    VirtualReadFailed,

    #[error("Virtual write failed")]
    VirtualWriteFailed,

    #[error("Virtual to physical translation failed")]
    VtopFailed,

    #[error("Privilege escalation failed")]
    PrivEscFailed,

    #[error("Read length exceeds maximum (0x1000 bytes)")]
    ReadLengthExceeded,

    #[error("Write length exceeds maximum (0x1000 bytes)")]
    WriteLengthExceeded,

    #[error("Memory allocation failed")]
    AllocationFailed,

    #[error("Windows error: {0}")]
    WindowsError(#[from] windows::core::Error),
}
