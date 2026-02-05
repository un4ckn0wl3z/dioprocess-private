use crate::MiscError;
use std::mem;
use std::path::Path;
use windows::Win32::Foundation::{CloseHandle, HANDLE, MAX_PATH};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32First, Module32Next, MODULEENTRY32, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32,
};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
use windows::Win32::System::SystemInformation::GetSystemDirectoryA;

/// Result of scanning memory for hook signatures
#[derive(Debug, Clone)]
pub struct HookScanResult {
    pub module_name: String,
    pub function_name: String,
    pub memory_address: usize,
    pub bytes_found: Vec<u8>,
    pub hook_type: HookType,
    pub description: String,
}

/// Type of hook detected
#[derive(Debug, Clone, PartialEq)]
pub enum HookType {
    None,
    InlineJmp,       // E9 near JMP hook
    InlineCall,      // E8 near CALL hook  
    ShortJmp,        // EB short JMP hook
    IndirectJmp,     // FF 25 indirect JMP hook
    MovJmp,          // 48 B8 [addr] FF E0 (mov rax + jmp rax) hook
}

/// Scan process memory for hook signature opcodes
pub fn scan_process_hooks(pid: u32) -> Result<Vec<HookScanResult>, MiscError> {
    unsafe {
        // Open process for reading memory
        let handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid)
            .map_err(|_| MiscError::OpenProcessFailed(pid))?;
        
        // Enumerate modules to map addresses to module names
        let modules = enumerate_modules(pid);
        
        // Scan IAT for hooks by comparing with disk
        let results = scan_iat_hooks(handle, pid, &modules)?;
        
        let _ = CloseHandle(handle);
        
        Ok(results)
    }
}

/// Helper to read memory from remote process
unsafe fn read_process_memory(handle: HANDLE, address: usize, buffer: &mut [u8]) -> Result<(), MiscError> {
    let mut bytes_read = 0;
    ReadProcessMemory(
        handle,
        address as *const _,
        buffer.as_mut_ptr() as *mut _,
        buffer.len(),
        Some(&mut bytes_read),
    )
    .map_err(|_| MiscError::ReadFailed)?;
    
    Ok(())
}

/// Enumerate all modules in a process and return (name, full_path, base_address, size) tuples
unsafe fn enumerate_modules(pid: u32) -> Vec<(String, String, usize, usize)> {
    let mut modules = Vec::new();
    
    let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) else {
        return modules;
    };
    
    let mut module_entry = MODULEENTRY32 {
        dwSize: mem::size_of::<MODULEENTRY32>() as u32,
        ..Default::default()
    };
    
    if Module32First(snapshot, &mut module_entry).is_ok() {
        loop {
            let module_name = String::from_utf8_lossy(
                &module_entry
                    .szModule
                    .iter()
                    .take_while(|&&c| c != 0)
                    .map(|&c| c as u8)
                    .collect::<Vec<_>>(),
            )
            .to_string();
            
            let full_path = String::from_utf8_lossy(
                &module_entry
                    .szExePath
                    .iter()
                    .take_while(|&&c| c != 0)
                    .map(|&c| c as u8)
                    .collect::<Vec<_>>(),
            )
            .to_string();
            
            let base_addr = module_entry.modBaseAddr as usize;
            let size = module_entry.modBaseSize as usize;
            
            modules.push((module_name, full_path, base_addr, size));
            
            if Module32Next(snapshot, &mut module_entry).is_err() {
                break;
            }
        }
    }
    
    let _ = CloseHandle(snapshot);
    modules
}

/// Find which module contains a given memory address
fn find_module_for_address(address: usize, modules: &[(String, String, usize, usize)]) -> Option<String> {
    for (name, _path, base, size) in modules {
        if address >= *base && address < (*base + *size) {
            return Some(name.clone());
        }
    }
    None
}

/// Scan IAT entries and check for inline hooks (E9 JMP at function start)
unsafe fn scan_iat_hooks(
    handle: HANDLE,
    _pid: u32,
    modules: &[(String, String, usize, usize)],
) -> Result<Vec<HookScanResult>, MiscError> {
    let mut results = Vec::new();
    
    // Get System32 directory for DLL lookups
    let mut sys_dir = vec![0u8; MAX_PATH as usize];
    let sys_dir_len = GetSystemDirectoryA(Some(&mut sys_dir)) as usize;
    let sys_dir_path = String::from_utf8_lossy(&sys_dir[..sys_dir_len]).to_string();
    
    for (module_name, _module_path, base_addr, _size) in modules {
        // Parse PE headers to find IAT
        let mut dos_header = [0u8; 64];
        if read_process_memory(handle, *base_addr, &mut dos_header).is_err() {
            continue;
        }
        
        let e_lfanew = u32::from_le_bytes([
            dos_header[60],
            dos_header[61],
            dos_header[62],
            dos_header[63],
        ]) as usize;
        
        // Read NT headers
        let mut nt_headers = [0u8; 512];
        if read_process_memory(handle, base_addr + e_lfanew, &mut nt_headers).is_err() {
            continue;
        }
        
        // Get Import Directory RVA from data directory (index 1 = Import Directory)
        // PE64: Signature(4) + FileHeader(20) + OptionalHeader starts at 24
        // DataDirectory in PE64 OptionalHeader is at offset 112
        let import_dir_offset = 24 + 112 + (1 * 8);
        if nt_headers.len() < import_dir_offset + 8 {
            continue;
        }
        
        let import_rva = u32::from_le_bytes([
            nt_headers[import_dir_offset],
            nt_headers[import_dir_offset + 1],
            nt_headers[import_dir_offset + 2],
            nt_headers[import_dir_offset + 3],
        ]) as usize;
        
        let import_size = u32::from_le_bytes([
            nt_headers[import_dir_offset + 4],
            nt_headers[import_dir_offset + 5],
            nt_headers[import_dir_offset + 6],
            nt_headers[import_dir_offset + 7],
        ]) as usize;
        
        if import_rva == 0 || import_size == 0 {
            continue;
        }
        
        // Parse Import Descriptors (each is 20 bytes)
        let import_desc_addr = base_addr + import_rva;
        let mut desc_offset = 0;
        
        loop {
            let desc_addr = import_desc_addr + desc_offset;
            let mut desc_bytes = [0u8; 20];
            
            if read_process_memory(handle, desc_addr, &mut desc_bytes).is_err() {
                break;
            }
            
            // Check if this is the null terminator descriptor
            let original_first_thunk = u32::from_le_bytes([
                desc_bytes[0], desc_bytes[1], desc_bytes[2], desc_bytes[3],
            ]) as usize;
            
            let first_thunk = u32::from_le_bytes([
                desc_bytes[16], desc_bytes[17], desc_bytes[18], desc_bytes[19],
            ]) as usize;
            
            if original_first_thunk == 0 && first_thunk == 0 {
                break; // End of import descriptors
            }
            
            // Read import name (DLL name this import descriptor refers to)
            let name_rva = u32::from_le_bytes([
                desc_bytes[12], desc_bytes[13], desc_bytes[14], desc_bytes[15],
            ]) as usize;
            
            // Read the import DLL name string
            let import_dll_name = if name_rva != 0 {
                let name_addr = base_addr + name_rva;
                let mut name_buf = [0u8; 256];
                if read_process_memory(handle, name_addr, &mut name_buf).is_ok() {
                    let end = name_buf.iter().position(|&c| c == 0).unwrap_or(name_buf.len());
                    String::from_utf8_lossy(&name_buf[..end]).to_string()
                } else {
                    "<unknown>".to_string()
                }
            } else {
                "<unknown>".to_string()
            };
            
            // FirstThunk points to the IAT for this DLL
            let iat_rva = first_thunk;
            if iat_rva == 0 {
                desc_offset += 20;
                continue;
            }
            
            // OriginalFirstThunk points to the INT (Import Name Table) for function names
            let int_rva = original_first_thunk;
            
            // Read IAT entries for this DLL (each entry is 8 bytes on x64)
            let iat_addr = base_addr + iat_rva;
            let int_addr = if int_rva != 0 { base_addr + int_rva } else { 0 };
            let mut entry_offset = 0;
            
            loop {
                let entry_addr = iat_addr + entry_offset;
                let mut entry_bytes = [0u8; 8];
            
            if read_process_memory(handle, entry_addr, &mut entry_bytes).is_err() {
                break;
            }
            
            let func_addr = u64::from_le_bytes(entry_bytes) as usize;
            if func_addr == 0 {
                break; // End of IAT for this DLL
            }
            
            // Read function name from INT (Import Name Table)
            let function_name = if int_addr != 0 {
                let int_entry_addr = int_addr + entry_offset;
                let mut int_entry_bytes = [0u8; 8];
                if read_process_memory(handle, int_entry_addr, &mut int_entry_bytes).is_ok() {
                    let int_value = u64::from_le_bytes(int_entry_bytes);
                    // Check if imported by ordinal (high bit set)
                    if int_value & 0x8000_0000_0000_0000 != 0 {
                        format!("Ordinal#{}", int_value & 0xFFFF)
                    } else {
                        // RVA to IMAGE_IMPORT_BY_NAME (2-byte hint + name string)
                        let name_rva = (int_value & 0x7FFF_FFFF) as usize;
                        if name_rva != 0 {
                            let hint_name_addr = base_addr + name_rva + 2; // Skip 2-byte hint
                            let mut name_buf = [0u8; 128];
                            if read_process_memory(handle, hint_name_addr, &mut name_buf).is_ok() {
                                let end = name_buf.iter().position(|&c| c == 0).unwrap_or(name_buf.len());
                                String::from_utf8_lossy(&name_buf[..end]).to_string()
                            } else {
                                "<unknown>".to_string()
                            }
                        } else {
                            "<unknown>".to_string()
                        }
                    }
                } else {
                    "<unknown>".to_string()
                }
            } else {
                "<unknown>".to_string()
            };
            
            // Read first 5 bytes of the function in memory (enough for E9 JMP)
            let mut mem_bytes = [0u8; 16];
            if read_process_memory(handle, func_addr, &mut mem_bytes).is_err() {
                entry_offset += 8;
                continue;
            }
            
            // Find which DLL this function belongs to
            let Some(target_module) = find_module_for_address(func_addr, modules) else {
                entry_offset += 8;
                continue;
            };
            
            // Skip if it's the main module (not an import)
            if target_module.eq_ignore_ascii_case(module_name) {
                entry_offset += 8;
                continue;
            }
            
            // Detect hook type from function prologue bytes
            let hook_type = detect_hook_type(&mem_bytes);
            
            if hook_type == HookType::None {
                entry_offset += 8;
                continue; // Not hooked
            }
            
            // Detected hook! Try to read disk for comparison
            let disk_path = if Path::new(&target_module).is_absolute() {
                target_module.clone()
            } else {
                format!("{}\\{}", sys_dir_path, target_module)
            };
            
            let Ok(disk_bytes) = std::fs::read(&disk_path) else {
                // Can't read disk DLL, but we detected hook opcode, so report it anyway
                results.push(HookScanResult {
                    module_name: module_name.clone(),
                    function_name: function_name.clone(),
                    memory_address: func_addr,
                    bytes_found: mem_bytes.to_vec(),
                    hook_type: hook_type.clone(),
                    description: format!(
                        "{}!{} hooked ({})",
                        import_dll_name, function_name, 
                        get_hook_type_name(&hook_type)
                    ),
                });
                entry_offset += 8;
                continue;
            };
            
            // Parse disk DLL to find the function offset
            if disk_bytes.len() < 64 {
                entry_offset += 8;
                continue;
            }
            
            let disk_e_lfanew = u32::from_le_bytes([
                disk_bytes[60],
                disk_bytes[61],
                disk_bytes[62],
                disk_bytes[63],
            ]) as usize;
            
            if disk_bytes.len() < disk_e_lfanew + 256 {
                entry_offset += 8;
                continue;
            }
            
            // Calculate RVA from memory address
            let target_base = modules.iter()
                .find(|(name, _, _, _)| name.eq_ignore_ascii_case(&target_module))
                .map(|(_, _, base, _)| *base)
                .unwrap_or(0);
            
            if target_base == 0 {
                entry_offset += 8;
                continue;
            }
            
            let func_rva = func_addr - target_base;
            
            // Read bytes from disk at the same RVA
            // Convert RVA to file offset by finding section
            let num_sections = u16::from_le_bytes([
                disk_bytes[disk_e_lfanew + 6],
                disk_bytes[disk_e_lfanew + 7],
            ]) as usize;
            
            let section_header_offset = disk_e_lfanew + 4 + 20 + 240; // After NT headers
            let mut file_offset = 0;
            let mut found_section = false;
            
            for j in 0..num_sections {
                let sec_offset = section_header_offset + (j * 40);
                if disk_bytes.len() < sec_offset + 40 {
                    break;
                }
                
                let virtual_addr = u32::from_le_bytes([
                    disk_bytes[sec_offset + 12],
                    disk_bytes[sec_offset + 13],
                    disk_bytes[sec_offset + 14],
                    disk_bytes[sec_offset + 15],
                ]) as usize;
                
                let virtual_size = u32::from_le_bytes([
                    disk_bytes[sec_offset + 8],
                    disk_bytes[sec_offset + 9],
                    disk_bytes[sec_offset + 10],
                    disk_bytes[sec_offset + 11],
                ]) as usize;
                
                let raw_offset = u32::from_le_bytes([
                    disk_bytes[sec_offset + 20],
                    disk_bytes[sec_offset + 21],
                    disk_bytes[sec_offset + 22],
                    disk_bytes[sec_offset + 23],
                ]) as usize;
                
                if func_rva >= virtual_addr && func_rva < virtual_addr + virtual_size {
                    file_offset = raw_offset + (func_rva - virtual_addr);
                    found_section = true;
                    break;
                }
            }
            
            if !found_section || file_offset + 16 > disk_bytes.len() {
                // Could not find in disk file, but we detected hook in memory
                results.push(HookScanResult {
                    module_name: module_name.clone(),
                    function_name: function_name.clone(),
                    memory_address: func_addr,
                    bytes_found: mem_bytes.to_vec(),
                    hook_type: hook_type.clone(),
                    description: format!(
                        "{}!{} hooked ({})",
                        import_dll_name, function_name,
                        get_hook_type_name(&hook_type)
                    ),
                });
                entry_offset += 8;
                continue;
            }
            
            let disk_func_bytes = &disk_bytes[file_offset..file_offset + 16];
            
            // Check if disk version also has the same hook signature (legitimate redirect)
            let disk_hook_type = detect_hook_type(disk_func_bytes.try_into().unwrap_or(&[0u8; 16]));
            if disk_hook_type != HookType::None {
                entry_offset += 8;
                continue; // Original also has hook signature, might be legitimate
            }
            
            // Memory has hook but disk doesn't - confirmed hook!
            let mut combined_bytes = Vec::with_capacity(32);
            combined_bytes.extend_from_slice(&mem_bytes);
            combined_bytes.extend_from_slice(disk_func_bytes);
            
            results.push(HookScanResult {
                module_name: module_name.clone(),
                function_name: function_name.clone(),
                memory_address: func_addr,
                bytes_found: combined_bytes,
                hook_type: hook_type.clone(),
                description: format!(
                    "{}!{} | Mem[{:02X} {:02X} {:02X} {:02X} {:02X}] vs Disk[{:02X} {:02X} {:02X} {:02X} {:02X}]",
                    import_dll_name, function_name,
                    mem_bytes[0], mem_bytes[1], mem_bytes[2], mem_bytes[3], mem_bytes[4],
                    disk_func_bytes[0], disk_func_bytes[1], disk_func_bytes[2], disk_func_bytes[3], disk_func_bytes[4]
                ),
            });
            
            entry_offset += 8;
        }  // End of IAT entries loop for this DLL
        
        desc_offset += 20;
    }  // End of import descriptors loop
    }  // End of modules loop
    
    Ok(results)
}

/// Detect the type of hook from function prologue bytes
fn detect_hook_type(bytes: &[u8; 16]) -> HookType {
    // E9 xx xx xx xx - near JMP (5 bytes)
    if bytes[0] == 0xE9 {
        return HookType::InlineJmp;
    }
    
    // E8 xx xx xx xx - near CALL (5 bytes)
    if bytes[0] == 0xE8 {
        return HookType::InlineCall;
    }
    
    // EB xx - short JMP (2 bytes)
    if bytes[0] == 0xEB {
        return HookType::ShortJmp;
    }
    
    // FF 25 xx xx xx xx - indirect JMP through memory (6 bytes)
    if bytes[0] == 0xFF && bytes[1] == 0x25 {
        return HookType::IndirectJmp;
    }
    
    // 48 B8 [8-byte addr] FF E0 - mov rax, addr; jmp rax (12 bytes total)
    // Common x64 hook pattern for jumping to addresses > 2GB away
    if bytes[0] == 0x48 && bytes[1] == 0xB8 && bytes[10] == 0xFF && bytes[11] == 0xE0 {
        return HookType::MovJmp;
    }
    
    // 48 B8 [8-byte addr] 50 C3 - mov rax, addr; push rax; ret (12 bytes)
    // Another common x64 pattern
    if bytes[0] == 0x48 && bytes[1] == 0xB8 && bytes[10] == 0x50 && bytes[11] == 0xC3 {
        return HookType::MovJmp;
    }
    
    HookType::None
}

/// Get human-readable name for hook type
fn get_hook_type_name(hook_type: &HookType) -> &'static str {
    match hook_type {
        HookType::None => "None",
        HookType::InlineJmp => "E9 JMP",
        HookType::InlineCall => "E8 CALL",
        HookType::ShortJmp => "EB Short JMP",
        HookType::IndirectJmp => "FF25 Indirect JMP",
        HookType::MovJmp => "MOV+JMP (x64)",
    }
}

/// Get the Windows system directory path (public API for UI crate)
pub fn get_system_directory_path() -> String {
    unsafe {
        let mut sys_dir = vec![0u8; MAX_PATH as usize];
        let sys_dir_len = GetSystemDirectoryA(Some(&mut sys_dir)) as usize;
        String::from_utf8_lossy(&sys_dir[..sys_dir_len]).to_string()
    }
}

/// Enumerate all modules in a process (public API for UI crate)
/// Returns (name, full_path, base_address, size) tuples
pub fn enumerate_process_modules(pid: u32) -> Result<Vec<(String, String, usize, usize)>, MiscError> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
            .map_err(|_| MiscError::OpenProcessFailed(pid))?;
        
        let mut modules = Vec::new();
        let mut module_entry = MODULEENTRY32 {
            dwSize: mem::size_of::<MODULEENTRY32>() as u32,
            ..Default::default()
        };
        
        if Module32First(snapshot, &mut module_entry).is_ok() {
            loop {
                let module_name = String::from_utf8_lossy(
                    &module_entry
                        .szModule
                        .iter()
                        .take_while(|&&c| c != 0)
                        .map(|&c| c as u8)
                        .collect::<Vec<_>>(),
                )
                .to_string();
                
                let full_path = String::from_utf8_lossy(
                    &module_entry
                        .szExePath
                        .iter()
                        .take_while(|&&c| c != 0)
                        .map(|&c| c as u8)
                        .collect::<Vec<_>>(),
                )
                .to_string();
                
                let base_addr = module_entry.modBaseAddr as usize;
                let size = module_entry.modBaseSize as usize;
                
                modules.push((module_name, full_path, base_addr, size));
                
                if Module32Next(snapshot, &mut module_entry).is_err() {
                    break;
                }
            }
        }
        
        let _ = CloseHandle(snapshot);
        Ok(modules)
    }
}
