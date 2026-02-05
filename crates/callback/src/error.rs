//! Error types for callback crate

use std::fmt;

/// Errors that can occur when communicating with the kernel driver
#[derive(Debug)]
pub enum CallbackError {
    /// Driver device not found (driver not loaded)
    DriverNotFound,
    /// Failed to open device handle
    DeviceOpenFailed(u32),
    /// Failed to read from device
    ReadFailed(u32),
    /// Buffer too small
    BufferTooSmall,
    /// Invalid data received from driver
    InvalidData,
}

impl fmt::Display for CallbackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CallbackError::DriverNotFound => {
                write!(f, "DioProcess driver not found (not loaded)")
            }
            CallbackError::DeviceOpenFailed(code) => {
                write!(f, "Failed to open device handle: error code {}", code)
            }
            CallbackError::ReadFailed(code) => {
                write!(f, "Failed to read from driver: error code {}", code)
            }
            CallbackError::BufferTooSmall => write!(f, "Buffer too small"),
            CallbackError::InvalidData => write!(f, "Invalid data received from driver"),
        }
    }
}

impl std::error::Error for CallbackError {}
