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
pub mod storage;
mod types;

pub use driver::{
    get_collection_state, is_driver_loaded, read_events, start_collection, stop_collection,
};
pub use error::CallbackError;
pub use storage::{EventFilter, EventStorage};
pub use types::{CallbackEvent, CollectionState, EventCategory, EventType, RegistryOperation};
