//! UEFI Bootkit management module
//!
//! Provides usermode management of the DioProcess UEFI bootkit:
//! - NVRAM variable read/write for boot-time configuration (DSE/KPP bypass toggles)
//! - EFI System Partition management (install/remove EFI driver, boot entry management)
//! - System info queries (UEFI vs BIOS, Secure Boot status, test signing mode)

mod error;
mod esp;
mod nvram;

pub use error::UefiError;
pub use esp::{
    get_install_info, install_efi_driver, is_efi_installed, mount_esp, remove_efi_driver,
    unmount_esp, EfiInstallInfo,
};
pub use nvram::{
    clear_debug_log, is_secure_boot_enabled, is_test_signing_enabled, is_uefi_system,
    read_debug_log, read_uefi_config, write_uefi_config, UefiConfig,
};
