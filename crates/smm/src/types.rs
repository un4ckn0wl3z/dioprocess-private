//! SMM communication types matching kernel driver structures

/// Maximum bytes per SMM transfer (4KB)
pub const MAX_SMM_TRANSFER_SIZE: u32 = 0x1000;

pub const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}

pub const FILE_DEVICE_UNKNOWN: u32 = 0x22;
pub const METHOD_BUFFERED: u32 = 0;
pub const FILE_ANY_ACCESS: u32 = 0;

// SMM IOCTLs (Ring -2) matching kernel driver DioProcessCommon.h
pub const IOCTL_SMM_PING: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0xD00, METHOD_BUFFERED, FILE_ANY_ACCESS);
pub const IOCTL_SMM_CACHE_SESSION: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0xD02, METHOD_BUFFERED, FILE_ANY_ACCESS);
pub const IOCTL_SMM_READ_PHYS: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0xD03, METHOD_BUFFERED, FILE_ANY_ACCESS);
pub const IOCTL_SMM_READ_VIRTUAL: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0xD04, METHOD_BUFFERED, FILE_ANY_ACCESS);
pub const IOCTL_SMM_WRITE_PHYS: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0xD05, METHOD_BUFFERED, FILE_ANY_ACCESS);
pub const IOCTL_SMM_WRITE_VIRTUAL: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0xD06, METHOD_BUFFERED, FILE_ANY_ACCESS);
pub const IOCTL_SMM_VIRT_TO_PHYS: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0xD08, METHOD_BUFFERED, FILE_ANY_ACCESS);
pub const IOCTL_SMM_PRIV_ESC: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0xD0A, METHOD_BUFFERED, FILE_ANY_ACCESS);

/// Request for SMM physical/virtual memory read
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SmmReadRequest {
    pub process_id: u32,      // 0 for physical, >0 for virtual
    pub address: u64,         // Physical or virtual address
    pub buffer_address: u64,  // Usermode buffer to write results
    pub size: u32,            // Bytes to read (max MAX_SMM_TRANSFER_SIZE)
}

/// Request for SMM physical/virtual memory write
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SmmWriteRequest {
    pub process_id: u32,      // 0 for physical, >0 for virtual
    pub address: u64,         // Physical or virtual address
    pub buffer_address: u64,  // Usermode buffer with data to write
    pub size: u32,            // Bytes to write (max MAX_SMM_TRANSFER_SIZE)
}

/// Request for virtual-to-physical address translation
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SmmVtopRequest {
    pub process_id: u32,       // Target process
    pub virtual_address: u64,  // Virtual address to translate
}

/// Response for virtual-to-physical translation
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SmmVtopResponse {
    pub physical_address: u64, // Translated physical address
    pub success: u8,           // BOOLEAN
}

/// Request for caching session info
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SmmCacheSessionRequest {
    pub controller_pid: u32,   // Usermode controller process PID
}

/// Response for read/write operations
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SmmReadWriteResponse {
    pub bytes_transferred: u32,
    pub success: u8,           // BOOLEAN
}
