//! Physical memory translation and access via kernel driver
//!
//! Provides virtual address translation through x86-64 4-level page tables
//! and direct physical memory read/write operations.

use crate::driver::open_device;
use crate::error::CallbackError;
use windows::Win32::Foundation::{CloseHandle, GetLastError};
use windows::Win32::System::IO::DeviceIoControl;

// IOCTL codes: CTL_CODE(FILE_DEVICE_UNKNOWN=0x22, function, METHOD_BUFFERED=0, FILE_ANY_ACCESS=0)
const IOCTL_DIOPROCESS_TRANSLATE_VA: u32 = 0x00222240;
const IOCTL_DIOPROCESS_READ_PHYSICAL: u32 = 0x00222244;
const IOCTL_DIOPROCESS_WRITE_PHYSICAL: u32 = 0x00222248;

/// Decoded page table entry with all x86-64 PTE bits
#[derive(Debug, Clone, Default)]
pub struct PageTableEntry {
    /// Physical address where this PTE lives
    pub virtual_address: u64,
    /// Physical address this entry points to (PFN << 12)
    pub physical_address: u64,
    /// Raw 8-byte PTE value
    pub raw_value: u64,
    /// Bit 0: Page is present in physical memory
    pub present: bool,
    /// Bit 1: Read/Write (0=read-only, 1=read-write)
    pub read_write: bool,
    /// Bit 2: User/Supervisor (0=supervisor only, 1=user accessible)
    pub user_supervisor: bool,
    /// Bit 3: Page-level write-through
    pub write_through: bool,
    /// Bit 4: Page-level cache disable
    pub cache_disable: bool,
    /// Bit 5: Accessed
    pub accessed: bool,
    /// Bit 6: Dirty
    pub dirty: bool,
    /// Bit 7: Large page (2MB at PD level, 1GB at PDPT level)
    pub large_page: bool,
    /// Bit 8: Global
    pub global: bool,
    /// Bit 63: No-Execute
    pub no_execute: bool,
}

/// Result of a 4-level page table walk
#[derive(Debug, Clone)]
pub struct PageTableWalkResult {
    /// CR3 register value (page directory base)
    pub cr3: u64,
    /// PML4 entry (level 1)
    pub pml4e: PageTableEntry,
    /// PDPT entry (level 2)
    pub pdpte: PageTableEntry,
    /// PD entry (level 3)
    pub pde: PageTableEntry,
    /// PT entry (level 4) — None if large page (2MB or 1GB)
    pub pte: Option<PageTableEntry>,
    /// Final translated physical address
    pub physical_address: u64,
    /// Page size: 4096 (4KB), 0x200000 (2MB), or 0x40000000 (1GB)
    pub page_size: u32,
    /// Walk depth: 4=normal 4KB, 3=2MB large, 2=1GB large
    pub walk_depth: u8,
}

// ============== Wire structs matching kernel driver layout ==============

#[repr(C)]
struct TranslateVaRequest {
    process_id: u32,
    virtual_address: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PageTableEntryResult {
    virtual_address: u64,
    physical_address: u64,
    raw_value: u64,
    present: u8,
    read_write: u8,
    user_supervisor: u8,
    write_through: u8,
    cache_disable: u8,
    accessed: u8,
    dirty: u8,
    large_page: u8,
    global: u8,
    no_execute: u8,
}

#[repr(C)]
struct TranslateVaResponse {
    cr3: u64,
    pml4e: PageTableEntryResult,
    pdpte: PageTableEntryResult,
    pde: PageTableEntryResult,
    pte: PageTableEntryResult,
    physical_address: u64,
    page_size: u32,
    walk_depth: u8,
    success: u8,
}

#[repr(C)]
struct PhysicalMemoryRequest {
    physical_address: u64,
    buffer_address: u64,
    size: u32,
}

#[repr(C)]
struct PhysicalMemoryResponse {
    bytes_transferred: u32,
    success: u8,
}

// ============== Conversion helpers ==============

fn convert_pte(raw: &PageTableEntryResult) -> PageTableEntry {
    PageTableEntry {
        virtual_address: raw.virtual_address,
        physical_address: raw.physical_address,
        raw_value: raw.raw_value,
        present: raw.present != 0,
        read_write: raw.read_write != 0,
        user_supervisor: raw.user_supervisor != 0,
        write_through: raw.write_through != 0,
        cache_disable: raw.cache_disable != 0,
        accessed: raw.accessed != 0,
        dirty: raw.dirty != 0,
        large_page: raw.large_page != 0,
        global: raw.global != 0,
        no_execute: raw.no_execute != 0,
    }
}

// ============== Public API ==============

/// Translate a virtual address to physical via 4-level page table walk.
///
/// Requires the DioProcess kernel driver to be loaded.
pub fn translate_virtual_address(
    pid: u32,
    va: u64,
) -> Result<PageTableWalkResult, CallbackError> {
    let handle = open_device()?;

    unsafe {
        let request = TranslateVaRequest {
            process_id: pid,
            virtual_address: va,
        };

        let mut response: TranslateVaResponse = std::mem::zeroed();
        let mut bytes_returned: u32 = 0;

        let result = DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_TRANSLATE_VA,
            Some(&request as *const _ as *const _),
            std::mem::size_of::<TranslateVaRequest>() as u32,
            Some(&mut response as *mut _ as *mut _),
            std::mem::size_of::<TranslateVaResponse>() as u32,
            Some(&mut bytes_returned),
            None,
        );

        let _ = CloseHandle(handle);

        if result.is_err() {
            let err = GetLastError();
            return Err(CallbackError::IoctlFailed(err.0));
        }

        if response.success == 0 && response.walk_depth == 0 {
            return Err(CallbackError::IoctlFailed(0));
        }

        let pte = if response.walk_depth >= 4 {
            Some(convert_pte(&response.pte))
        } else {
            None
        };

        Ok(PageTableWalkResult {
            cr3: response.cr3,
            pml4e: convert_pte(&response.pml4e),
            pdpte: convert_pte(&response.pdpte),
            pde: convert_pte(&response.pde),
            pte,
            physical_address: response.physical_address,
            page_size: response.page_size,
            walk_depth: response.walk_depth,
        })
    }
}

/// Read physical memory directly.
///
/// Maximum read size is 4096 bytes (one page).
pub fn read_physical_memory(phys_addr: u64, size: usize) -> Result<Vec<u8>, CallbackError> {
    if size == 0 || size > 4096 {
        return Err(CallbackError::InvalidParameter);
    }

    let handle = open_device()?;
    let mut buffer = vec![0u8; size];

    unsafe {
        let request = PhysicalMemoryRequest {
            physical_address: phys_addr,
            buffer_address: buffer.as_mut_ptr() as u64,
            size: size as u32,
        };

        let mut response = PhysicalMemoryResponse {
            bytes_transferred: 0,
            success: 0,
        };

        let mut bytes_returned: u32 = 0;

        let result = DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_READ_PHYSICAL,
            Some(&request as *const _ as *const _),
            std::mem::size_of::<PhysicalMemoryRequest>() as u32,
            Some(&mut response as *mut _ as *mut _),
            std::mem::size_of::<PhysicalMemoryResponse>() as u32,
            Some(&mut bytes_returned),
            None,
        );

        let _ = CloseHandle(handle);

        if result.is_err() {
            let err = GetLastError();
            return Err(CallbackError::IoctlFailed(err.0));
        }

        if response.success != 0 {
            buffer.truncate(response.bytes_transferred as usize);
            Ok(buffer)
        } else {
            Err(CallbackError::IoctlFailed(0))
        }
    }
}

/// Write data to physical memory directly.
///
/// Maximum write size is 4096 bytes (one page).
/// Returns the number of bytes written.
pub fn write_physical_memory(phys_addr: u64, data: &[u8]) -> Result<usize, CallbackError> {
    if data.is_empty() || data.len() > 4096 {
        return Err(CallbackError::InvalidParameter);
    }

    let handle = open_device()?;

    unsafe {
        let request = PhysicalMemoryRequest {
            physical_address: phys_addr,
            buffer_address: data.as_ptr() as u64,
            size: data.len() as u32,
        };

        let mut response = PhysicalMemoryResponse {
            bytes_transferred: 0,
            success: 0,
        };

        let mut bytes_returned: u32 = 0;

        let result = DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_WRITE_PHYSICAL,
            Some(&request as *const _ as *const _),
            std::mem::size_of::<PhysicalMemoryRequest>() as u32,
            Some(&mut response as *mut _ as *mut _),
            std::mem::size_of::<PhysicalMemoryResponse>() as u32,
            Some(&mut bytes_returned),
            None,
        );

        let _ = CloseHandle(handle);

        if result.is_err() {
            let err = GetLastError();
            return Err(CallbackError::IoctlFailed(err.0));
        }

        if response.success != 0 {
            Ok(response.bytes_transferred as usize)
        } else {
            Err(CallbackError::IoctlFailed(0))
        }
    }
}
