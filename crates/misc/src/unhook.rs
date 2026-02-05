//! DLL Unhooking Module
//!
//! This module provides functionality to unhook DLLs by reading a fresh copy from disk
//! and replacing the hooked .text section in memory.
//!
//! Supports:
//! - ntdll.dll
//! - kernel32.dll
//! - kernelbase.dll
//! - Any custom DLL path

use std::ffi::CString;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

use windows::core::PCSTR;
use windows::Win32::System::LibraryLoader::GetModuleHandleA;
use windows::Win32::System::Memory::{VirtualProtect, PAGE_EXECUTE_WRITECOPY, PAGE_PROTECTION_FLAGS};
use windows::Win32::System::SystemInformation::GetSystemDirectoryA;

use crate::error::MiscError;

/// Common DLLs that can be unhooked
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommonDll {
    Ntdll,
    Kernel32,
    KernelBase,
    User32,
    Advapi32,
    Ws2_32,
}

impl CommonDll {
    /// Get the DLL filename
    pub fn filename(&self) -> &'static str {
        match self {
            CommonDll::Ntdll => "ntdll.dll",
            CommonDll::Kernel32 => "kernel32.dll",
            CommonDll::KernelBase => "kernelbase.dll",
            CommonDll::User32 => "user32.dll",
            CommonDll::Advapi32 => "advapi32.dll",
            CommonDll::Ws2_32 => "ws2_32.dll",
        }
    }

    /// Get the full path to the DLL in System32
    pub fn system_path(&self) -> Result<PathBuf, MiscError> {
        get_system32_dll_path(self.filename())
    }
}

/// Get the System32 directory path
fn get_system32_path() -> Result<PathBuf, MiscError> {
    unsafe {
        let mut buffer = [0u8; 260];
        let len = GetSystemDirectoryA(Some(&mut buffer));
        if len == 0 {
            return Err(MiscError::FileNotFound("System32 directory".to_string()));
        }
        let path = String::from_utf8_lossy(&buffer[..len as usize]);
        Ok(PathBuf::from(path.to_string()))
    }
}

/// Get the full path to a DLL in System32
fn get_system32_dll_path(dll_name: &str) -> Result<PathBuf, MiscError> {
    let mut path = get_system32_path()?;
    path.push(dll_name);
    Ok(path)
}

/// Read a DLL file from disk into memory
fn read_dll_from_disk(path: &std::path::Path) -> Result<Vec<u8>, MiscError> {
    let mut file = File::open(path)
        .map_err(|_| MiscError::FileNotFound(path.display().to_string()))?;
    
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .map_err(|_| MiscError::FileReadFailed(path.display().to_string()))?;
    
    Ok(buffer)
}

/// Get the base address of a loaded module by name
fn get_module_base_address(dll_name: &str) -> Result<*mut u8, MiscError> {
    unsafe {
        let name = CString::new(dll_name).unwrap();
        let handle = GetModuleHandleA(PCSTR(name.as_ptr() as *const u8))
            .map_err(|_| MiscError::GetModuleHandleFailed)?;
        Ok(handle.0 as *mut u8)
    }
}

/// PE Header structures for parsing
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct ImageDosHeader {
    e_magic: u16,
    e_cblp: u16,
    e_cp: u16,
    e_crlc: u16,
    e_cparhdr: u16,
    e_minalloc: u16,
    e_maxalloc: u16,
    e_ss: u16,
    e_sp: u16,
    e_csum: u16,
    e_ip: u16,
    e_cs: u16,
    e_lfarlc: u16,
    e_ovno: u16,
    e_res: [u16; 4],
    e_oemid: u16,
    e_oeminfo: u16,
    e_res2: [u16; 10],
    e_lfanew: i32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct ImageFileHeader {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct ImageSectionHeader {
    name: [u8; 8],
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    pointer_to_relocations: u32,
    pointer_to_linenumbers: u32,
    number_of_relocations: u16,
    number_of_linenumbers: u16,
    characteristics: u32,
}

const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D; // "MZ"
const IMAGE_NT_SIGNATURE: u32 = 0x00004550; // "PE\0\0"

/// Find the .text section in a PE file
fn find_text_section(pe_base: *const u8) -> Result<(usize, usize, usize), MiscError> {
    unsafe {
        // Parse DOS header
        let dos_header = &*(pe_base as *const ImageDosHeader);
        if dos_header.e_magic != IMAGE_DOS_SIGNATURE {
            return Err(MiscError::InvalidPE("Invalid DOS signature".to_string()));
        }

        // Get to NT headers
        let nt_header_offset = dos_header.e_lfanew as usize;
        let nt_signature = *(pe_base.add(nt_header_offset) as *const u32);
        if nt_signature != IMAGE_NT_SIGNATURE {
            return Err(MiscError::InvalidPE("Invalid NT signature".to_string()));
        }

        // Parse file header
        let file_header = &*(pe_base.add(nt_header_offset + 4) as *const ImageFileHeader);
        let number_of_sections = file_header.number_of_sections;
        let optional_header_size = file_header.size_of_optional_header as usize;

        // Calculate section headers offset
        let section_headers_offset = nt_header_offset + 4 + std::mem::size_of::<ImageFileHeader>() + optional_header_size;

        // Iterate through sections to find .text
        for i in 0..number_of_sections as usize {
            let section_offset = section_headers_offset + (i * std::mem::size_of::<ImageSectionHeader>());
            let section = &*(pe_base.add(section_offset) as *const ImageSectionHeader);

            // Check if this is the .text section (comparing first 5 bytes: ".text")
            if section.name[0] == b'.' 
                && section.name[1] == b't' 
                && section.name[2] == b'e' 
                && section.name[3] == b'x' 
                && section.name[4] == b't' 
            {
                return Ok((
                    section.virtual_address as usize,
                    section.pointer_to_raw_data as usize,
                    section.virtual_size as usize,
                ));
            }
        }

        Err(MiscError::InvalidPE("Could not find .text section".to_string()))
    }
}

/// Unhook result with details
#[derive(Debug)]
pub struct UnhookResult {
    pub dll_name: String,
    pub text_section_rva: usize,
    pub text_section_size: usize,
    pub bytes_replaced: usize,
}

/// Unhook a common DLL by replacing its .text section with a fresh copy from disk
/// 
/// # Arguments
/// * `dll` - The common DLL to unhook
/// 
/// # Returns
/// * `Ok(UnhookResult)` - Information about the unhook operation
/// * `Err(MiscError)` - If the operation failed
/// 
/// # Safety
/// This function modifies memory of loaded modules. Use with caution.
pub fn unhook_dll(dll: CommonDll) -> Result<UnhookResult, MiscError> {
    let dll_path = dll.system_path()?;
    let dll_name = dll.filename();
    unhook_dll_by_path(&dll_path, dll_name)
}

/// Unhook a DLL by providing a custom path
/// 
/// # Arguments
/// * `disk_path` - Path to the clean DLL on disk
/// * `module_name` - Name of the module as loaded in memory (e.g., "custom.dll")
/// 
/// # Returns
/// * `Ok(UnhookResult)` - Information about the unhook operation
/// * `Err(MiscError)` - If the operation failed
/// 
/// # Safety
/// This function modifies memory of loaded modules. Use with caution.
pub fn unhook_dll_by_path(disk_path: &std::path::Path, module_name: &str) -> Result<UnhookResult, MiscError> {
    // Read clean DLL from disk
    let clean_dll = read_dll_from_disk(disk_path)?;
    
    // Get loaded module base address
    let module_base = get_module_base_address(module_name)?;
    
    // Find .text section info from the loaded module
    let (text_rva, _text_raw, text_size) = find_text_section(module_base)?;
    
    // Find .text section info from the clean DLL (might have different raw offset)
    let (_, clean_text_raw, _) = find_text_section(clean_dll.as_ptr())?;
    
    unsafe {
        // Calculate addresses
        let hooked_text_addr = module_base.add(text_rva);
        let clean_text_ptr = clean_dll.as_ptr().add(clean_text_raw);
        
        // Make the .text section writable
        let mut old_protection = PAGE_PROTECTION_FLAGS(0);
        VirtualProtect(
            hooked_text_addr as *const _,
            text_size,
            PAGE_EXECUTE_WRITECOPY,
            &mut old_protection,
        ).map_err(|_| MiscError::InvalidPE("VirtualProtect failed".to_string()))?;
        
        // Copy the clean .text section over the hooked one
        std::ptr::copy_nonoverlapping(clean_text_ptr, hooked_text_addr, text_size);
        
        // Restore original protection
        let mut temp = PAGE_PROTECTION_FLAGS(0);
        let _ = VirtualProtect(
            hooked_text_addr as *const _,
            text_size,
            old_protection,
            &mut temp,
        );
    }
    
    Ok(UnhookResult {
        dll_name: module_name.to_string(),
        text_section_rva: text_rva,
        text_section_size: text_size,
        bytes_replaced: text_size,
    })
}

/// Unhook multiple DLLs at once
/// 
/// # Arguments
/// * `dlls` - Slice of common DLLs to unhook
/// 
/// # Returns
/// * Vector of results for each DLL (success or failure)
pub fn unhook_multiple_dlls(dlls: &[CommonDll]) -> Vec<Result<UnhookResult, MiscError>> {
    dlls.iter().map(|dll| unhook_dll(*dll)).collect()
}

/// Check if a function appears to be hooked by examining its first bytes
/// 
/// A typical syscall stub starts with:
/// - `mov r10, rcx` (4C 8B D1)
/// - `mov eax, <syscall_number>` (B8 xx xx xx xx)
/// 
/// If the first bytes don't match this pattern, the function is likely hooked.
/// 
/// # Arguments
/// * `func_addr` - Address of the function to check
/// 
/// # Returns
/// * `true` if the function appears to be hooked
/// * `false` if the function appears clean
pub fn is_function_hooked(func_addr: *const u8) -> bool {
    unsafe {
        // Expected syscall stub pattern: 4C 8B D1 B8 (mov r10, rcx; mov eax, ...)
        let expected_pattern: u32 = 0xB8D18B4C;
        let actual_bytes = *(func_addr as *const u32);
        actual_bytes != expected_pattern
    }
}

/// Check if a specific export in a DLL is hooked
/// 
/// # Arguments
/// * `dll_name` - Name of the DLL (e.g., "ntdll.dll")
/// * `func_name` - Name of the function to check
/// 
/// # Returns
/// * `Ok(true)` if hooked, `Ok(false)` if clean
/// * `Err` if the function couldn't be found
pub fn is_export_hooked(dll_name: &str, func_name: &str) -> Result<bool, MiscError> {
    unsafe {
        let dll_cstr = CString::new(dll_name).unwrap();
        let func_cstr = CString::new(func_name).unwrap();
        
        let module = GetModuleHandleA(PCSTR(dll_cstr.as_ptr() as *const u8))
            .map_err(|_| MiscError::GetModuleHandleFailed)?;
        
        let func_addr = windows::Win32::System::LibraryLoader::GetProcAddress(
            module,
            PCSTR(func_cstr.as_ptr() as *const u8),
        );
        
        match func_addr {
            Some(addr) => Ok(is_function_hooked(addr as *const u8)),
            None => Err(MiscError::GetProcAddressFailed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_system32_path() {
        let path = get_system32_path();
        assert!(path.is_ok());
        let path = path.unwrap();
        assert!(path.exists());
    }

    #[test]
    fn test_common_dll_path() {
        let ntdll_path = CommonDll::Ntdll.system_path();
        assert!(ntdll_path.is_ok());
        let path = ntdll_path.unwrap();
        assert!(path.exists());
    }
}
