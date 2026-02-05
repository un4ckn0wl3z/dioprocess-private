//! Kernel callback driver communication module
//!
//! This crate provides communication with the DioProcess kernel driver
//! to receive real-time process and thread creation/exit events.

mod driver;
mod error;
mod types;

pub use driver::{is_driver_loaded, read_events};
pub use error::CallbackError;
pub use types::{CallbackEvent, EventType};
