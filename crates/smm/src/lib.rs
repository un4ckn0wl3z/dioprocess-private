//! SMM (System Management Mode) communication crate
//!
//! This crate provides communication with SMM via a kernel driver bridge.
//! Based on the Deadwing project architecture:
//! - Usermode application (this crate) communicates with kernel driver
//! - Kernel driver triggers SMI to communicate with SMM handler
//! - SMM handler performs privileged operations (physical memory R/W, privilege escalation)
//!
//! Capabilities:
//! - Ping SMM handler to verify availability
//! - Physical memory read/write (up to 4KB per operation)
//! - Virtual memory read/write with process ID targeting
//! - Virtual to physical address translation
//! - Privilege escalation via token manipulation

mod driver;
mod error;
mod types;

pub use driver::{
    is_smm_driver_loaded, smm_cache_session, smm_escalate_privileges, smm_phys_read,
    smm_phys_write, smm_ping, smm_virtual_read, smm_virtual_write, smm_vtop, SmmSession,
};
pub use error::SmmError;
pub use types::{
    SmmReadRequest, SmmVtopRequest, SmmVtopResponse, SmmWriteRequest, SmmCacheSessionRequest,
    SmmReadWriteResponse, MAX_SMM_TRANSFER_SIZE,
    IOCTL_SMM_CACHE_SESSION, IOCTL_SMM_PING, IOCTL_SMM_PRIV_ESC, IOCTL_SMM_READ_PHYS,
    IOCTL_SMM_READ_VIRTUAL, IOCTL_SMM_VIRT_TO_PHYS, IOCTL_SMM_WRITE_PHYS, IOCTL_SMM_WRITE_VIRTUAL,
};
