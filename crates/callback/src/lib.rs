//! Kernel callback driver communication module
//!
//! This crate provides communication with the DioProcess kernel driver
//! to receive real-time kernel events including:
//! - Process creation/exit
//! - Thread creation/exit
//! - Image (DLL/EXE) loading
//! - Handle operations (process/thread handles)
//! - Registry operations

mod driver;
mod error;
mod types;

pub use driver::{is_driver_loaded, read_events};
pub use error::CallbackError;
pub use types::{CallbackEvent, EventCategory, EventType, RegistryOperation};
