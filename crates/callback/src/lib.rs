//! Kernel callback driver communication module
//!
//! This crate provides communication with the DioProcess kernel driver
//! to receive real-time kernel events including:
//! - Process creation/exit
//! - Thread creation/exit
//! - Image (DLL/EXE) loading
//! - Handle operations (process/thread handles)
//! - Registry operations
//! - Hypervisor control and process protection

mod driver;
mod early_injection;
mod error;
mod hypervisor;
mod pspcidtable;
pub mod storage;
mod types;

pub use driver::{
    clear_debug_flags, enable_all_privileges, enumerate_image_callbacks, enumerate_kernel_drivers,
    enumerate_minifilters, enumerate_object_callbacks, enumerate_process_callbacks,
    enumerate_registry_callbacks, enumerate_thread_callbacks, get_collection_state, is_driver_loaded,
    protect_process, read_events, register_callbacks, remove_image_callback, remove_object_callback,
    remove_process_callback, remove_registry_callback, remove_thread_callback, start_collection,
    stop_collection, unprotect_process, unregister_callbacks, CallbackInfo, KernelDriverInfo,
    MinifilterCallbacks, MinifilterInfo, ObjectCallbackInfo, ObjectCallbackOperations,
    ObjectCallbackType, RegistryCallbackInfo,
};
pub use error::CallbackError;
pub use hypervisor::{
    hv_clear_hidden_drivers, hv_hide_driver, hv_inject_dll, hv_inject_shellcode, hv_install_hooks,
    hv_is_driver_hidden, hv_is_process_protected, hv_is_running, hv_list_hidden_drivers,
    hv_list_protected, hv_ping, hv_protect_process, hv_remove_hidden_driver, hv_remove_hooks,
    hv_start, hv_stop, hv_unhide_driver, hv_unprotect_process, HvInjectDllResult, HvInjectResult,
    HvStatus,
};
pub use early_injection::{
    arm_early_injection, disarm_early_injection, get_early_injection_status,
    EarlyInjectionMethod, EarlyInjectionStatus,
};
pub use pspcidtable::{enumerate_pspcidtable, CidEntry, CidObjectType};
pub use storage::{EventFilter, EventStorage};
pub use types::{CallbackEvent, CollectionState, EventCategory, EventType, RegistryOperation};
