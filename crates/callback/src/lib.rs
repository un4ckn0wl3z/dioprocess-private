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
//! - x86/x64 assembly for EPT hooks

pub mod assembler;
mod driver;
mod early_injection;
mod ept_hook;
mod error;
mod reg_change;
mod filehide;
mod hypervisor;
mod porthide;
mod physical_memory;
mod process_hide;
pub mod scanner;
pub mod hv_scanner;
mod pspcidtable;
pub mod storage;
mod types;
pub mod packet_capture;

pub use driver::{
    clear_debug_flags, enable_all_privileges, enumerate_image_callbacks, enumerate_kernel_drivers,
    enumerate_minifilters, enumerate_object_callbacks, enumerate_process_callbacks,
    enumerate_registry_callbacks, enumerate_thread_callbacks, get_collection_state, is_driver_loaded,
    kernel_copy_memory, kill_process_peb_corrupt, kill_process_terminate, kill_process_unmap,
    protect_process, read_events, register_callbacks, remove_image_callback,
    remove_object_callback, remove_process_callback, remove_registry_callback, remove_thread_callback,
    restore_image_callback, restore_object_callback, restore_process_callback,
    restore_registry_callback, restore_thread_callback, start_collection, stop_collection,
    hide_memory, unlink_minifilter, unprotect_process, unregister_callbacks, CallbackInfo, KernelDriverInfo,
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
pub use ept_hook::{install_ept_hook, install_ept_hook_detour, list_ept_hooks, remove_ept_hook, EptHookInfo};
pub use reg_change::{install_reg_change, list_reg_changes, remove_all_reg_changes, remove_reg_change, RegChangeInfo, REG_NAMES};
pub use early_injection::{
    arm_early_injection, disarm_early_injection, get_early_injection_status,
    EarlyInjectionMethod, EarlyInjectionStatus,
};
pub use filehide::{filehide_add, filehide_list, filehide_remove, HiddenFileInfo};
pub use porthide::{port_hide, port_hide_list, port_unhide, HiddenPortInfo};
pub use process_hide::{process_hide_add, process_hide_list, process_hide_remove, HiddenProcessInfo};
pub use physical_memory::{
    read_physical_memory, translate_virtual_address, write_physical_memory, PageTableEntry,
    PageTableWalkResult,
};
pub use pspcidtable::{enumerate_pspcidtable, CidEntry, CidObjectType};
pub use scanner::{
    enum_vm_regions, first_scan, next_scan, parse_aob_pattern, parse_scan_value,
    phys_read_virtual_memory, write_scan_value, format_bytes_as_value,
    AobPattern, ScanDataType, ScanRegion, ScanResult, ScanType,
};
pub use hv_scanner::{
    hv_read_virtual_memory, hv_write_virtual_memory, hv_write_scan_value,
    hv_first_scan, hv_next_scan, hv_alloc_write_near, HvAllocWriteNearResult,
};
pub use storage::{EventFilter, EventStorage};
pub use types::{CallbackEvent, CollectionState, EventCategory, EventType, RegistryOperation};
pub use assembler::{assemble, assemble_for_process, format_bytes_hex, validate_assembly, AssemblerError};
