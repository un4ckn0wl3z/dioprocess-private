use std::ffi::CString;
use std::path::Path;

use windows::core::PCSTR;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::Debug::{FlushInstructionCache, WriteProcessMemory};
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE,
    PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_PROTECTION_FLAGS,
    PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY, VirtualAllocEx, VirtualFreeEx,
    VirtualProtectEx,
};
use windows::Win32::System::Threading::{
    CreateRemoteThread, OpenProcess, WaitForSingleObject, PROCESS_ALL_ACCESS,
};

use crate::error::MiscError;

// Section characteristic flags
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
const IMAGE_SCN_MEM_READ: u32 = 0x40000000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;

/// Inject a DLL into a target process using manual mapping.
///
/// Reads the DLL file, maps it into the target process manually (sections, relocations,
/// imports), sets proper per-section memory protections, then executes DllMain via a remote thread.
///
/// # Safety
/// This function uses unsafe Windows API calls to manipulate another process's memory.
pub fn inject_dll_manual_map(pid: u32, dll_path: &str) -> Result<(), MiscError> {
    // Validate and read DLL file
    if !Path::new(dll_path).exists() {
        return Err(MiscError::FileNotFound(dll_path.to_string()));
    }

    let data =
        std::fs::read(dll_path).map_err(|_| MiscError::FileReadFailed(dll_path.to_string()))?;

    // Parse DOS header
    if data.len() < 64 {
        return Err(MiscError::InvalidPE("File too small for DOS header".into()));
    }
    let dos_magic = u16::from_le_bytes([data[0], data[1]]);
    if dos_magic != 0x5A4D {
        return Err(MiscError::InvalidPE("Invalid DOS magic (not MZ)".into()));
    }
    let pe_offset = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;

    // Parse PE signature
    if data.len() < pe_offset + 4 {
        return Err(MiscError::InvalidPE(
            "File too small for PE signature".into(),
        ));
    }
    let pe_sig = u32::from_le_bytes([
        data[pe_offset],
        data[pe_offset + 1],
        data[pe_offset + 2],
        data[pe_offset + 3],
    ]);
    if pe_sig != 0x00004550 {
        return Err(MiscError::InvalidPE("Invalid PE signature".into()));
    }

    // COFF header
    let coff_offset = pe_offset + 4;
    if data.len() < coff_offset + 20 {
        return Err(MiscError::InvalidPE(
            "File too small for COFF header".into(),
        ));
    }
    let num_sections = u16::from_le_bytes([data[coff_offset + 2], data[coff_offset + 3]]) as usize;
    let optional_header_size =
        u16::from_le_bytes([data[coff_offset + 16], data[coff_offset + 17]]) as usize;

    // Optional header
    let opt_offset = coff_offset + 20;
    if data.len() < opt_offset + 2 {
        return Err(MiscError::InvalidPE(
            "File too small for optional header".into(),
        ));
    }
    let opt_magic = u16::from_le_bytes([data[opt_offset], data[opt_offset + 1]]);
    if opt_magic != 0x20b {
        return Err(MiscError::InvalidPE(
            "Only PE32+ (64-bit) DLLs are supported".into(),
        ));
    }

    // PE32+ optional header fields
    if data.len() < opt_offset + 112 {
        return Err(MiscError::InvalidPE("Optional header too small".into()));
    }

    let entry_point_rva = u32::from_le_bytes([
        data[opt_offset + 16],
        data[opt_offset + 17],
        data[opt_offset + 18],
        data[opt_offset + 19],
    ]) as usize;

    let image_base = u64::from_le_bytes([
        data[opt_offset + 24],
        data[opt_offset + 25],
        data[opt_offset + 26],
        data[opt_offset + 27],
        data[opt_offset + 28],
        data[opt_offset + 29],
        data[opt_offset + 30],
        data[opt_offset + 31],
    ]);

    let size_of_image = u32::from_le_bytes([
        data[opt_offset + 56],
        data[opt_offset + 57],
        data[opt_offset + 58],
        data[opt_offset + 59],
    ]) as usize;

    let size_of_headers = u32::from_le_bytes([
        data[opt_offset + 60],
        data[opt_offset + 61],
        data[opt_offset + 62],
        data[opt_offset + 63],
    ]) as usize;

    // Data directories (PE32+: start at opt_offset + 112)
    // Import directory: index 1 (offset 112 + 1*8 = 120)
    let import_dir_rva;
    let import_dir_size;
    if data.len() >= opt_offset + 128 {
        import_dir_rva = u32::from_le_bytes([
            data[opt_offset + 120],
            data[opt_offset + 121],
            data[opt_offset + 122],
            data[opt_offset + 123],
        ]) as usize;
        import_dir_size = u32::from_le_bytes([
            data[opt_offset + 124],
            data[opt_offset + 125],
            data[opt_offset + 126],
            data[opt_offset + 127],
        ]) as usize;
    } else {
        import_dir_rva = 0;
        import_dir_size = 0;
    }

    // Base relocation directory: index 5 (offset 112 + 5*8 = 152)
    let reloc_dir_rva;
    let reloc_dir_size;
    if data.len() >= opt_offset + 160 {
        reloc_dir_rva = u32::from_le_bytes([
            data[opt_offset + 152],
            data[opt_offset + 153],
            data[opt_offset + 154],
            data[opt_offset + 155],
        ]) as usize;
        reloc_dir_size = u32::from_le_bytes([
            data[opt_offset + 156],
            data[opt_offset + 157],
            data[opt_offset + 158],
            data[opt_offset + 159],
        ]) as usize;
    } else {
        reloc_dir_rva = 0;
        reloc_dir_size = 0;
    }

    // Parse section headers (including characteristics for per-section permissions)
    let sections_offset = opt_offset + optional_header_size;

    struct SectionInfo {
        virtual_address: usize,
        virtual_size: usize,
        raw_data_offset: usize,
        raw_data_size: usize,
        characteristics: u32,
    }

    let mut sections = Vec::new();
    for i in 0..num_sections {
        let s_off = sections_offset + i * 40;
        if data.len() < s_off + 40 {
            break;
        }
        let virtual_size = u32::from_le_bytes([
            data[s_off + 8],
            data[s_off + 9],
            data[s_off + 10],
            data[s_off + 11],
        ]) as usize;
        let virtual_address = u32::from_le_bytes([
            data[s_off + 12],
            data[s_off + 13],
            data[s_off + 14],
            data[s_off + 15],
        ]) as usize;
        let raw_data_size = u32::from_le_bytes([
            data[s_off + 16],
            data[s_off + 17],
            data[s_off + 18],
            data[s_off + 19],
        ]) as usize;
        let raw_data_offset = u32::from_le_bytes([
            data[s_off + 20],
            data[s_off + 21],
            data[s_off + 22],
            data[s_off + 23],
        ]) as usize;
        let characteristics = u32::from_le_bytes([
            data[s_off + 36],
            data[s_off + 37],
            data[s_off + 38],
            data[s_off + 39],
        ]);
        sections.push(SectionInfo {
            virtual_address,
            virtual_size,
            raw_data_offset,
            raw_data_size,
            characteristics,
        });
    }

    // Build local image buffer
    let mut image = vec![0u8; size_of_image];

    // Copy PE headers
    let header_copy_len = size_of_headers.min(data.len()).min(size_of_image);
    image[..header_copy_len].copy_from_slice(&data[..header_copy_len]);

    // Map each section
    for section in &sections {
        if section.raw_data_size == 0 || section.raw_data_offset == 0 {
            continue;
        }
        let src_start = section.raw_data_offset;
        let src_end = (src_start + section.raw_data_size).min(data.len());
        let dst_start = section.virtual_address;
        let copy_len = (src_end - src_start).min(size_of_image.saturating_sub(dst_start));
        if copy_len > 0 && dst_start < size_of_image {
            image[dst_start..dst_start + copy_len]
                .copy_from_slice(&data[src_start..src_start + copy_len]);
        }
    }

    unsafe {
        // Open target process
        let process_handle = OpenProcess(PROCESS_ALL_ACCESS, false, pid)
            .map_err(|_| MiscError::OpenProcessFailed(pid))?;

        // Allocate remote memory for the full image (start with RW, we'll fix protections later)
        let remote_base = VirtualAllocEx(
            process_handle,
            Some(std::ptr::null()),
            size_of_image,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if remote_base.is_null() {
            let _ = CloseHandle(process_handle);
            return Err(MiscError::AllocFailed);
        }

        let actual_base = remote_base as u64;
        let delta = actual_base.wrapping_sub(image_base) as i64;

        // Process base relocations
        if reloc_dir_rva != 0 && reloc_dir_size != 0 && delta != 0 {
            let mut reloc_offset = reloc_dir_rva;
            let reloc_end = reloc_dir_rva + reloc_dir_size;

            while reloc_offset + 8 <= reloc_end && reloc_offset + 8 <= size_of_image {
                let block_rva = u32::from_le_bytes([
                    image[reloc_offset],
                    image[reloc_offset + 1],
                    image[reloc_offset + 2],
                    image[reloc_offset + 3],
                ]) as usize;
                let block_size = u32::from_le_bytes([
                    image[reloc_offset + 4],
                    image[reloc_offset + 5],
                    image[reloc_offset + 6],
                    image[reloc_offset + 7],
                ]) as usize;

                if block_size < 8 {
                    break;
                }

                let num_entries = (block_size - 8) / 2;
                for i in 0..num_entries {
                    let entry_offset = reloc_offset + 8 + i * 2;
                    if entry_offset + 2 > size_of_image {
                        break;
                    }
                    let entry = u16::from_le_bytes([image[entry_offset], image[entry_offset + 1]]);
                    let reloc_type = (entry >> 12) as u8;
                    let offset = (entry & 0x0FFF) as usize;
                    let target = block_rva + offset;

                    match reloc_type {
                        10 => {
                            // IMAGE_REL_BASED_DIR64
                            if target + 8 <= size_of_image {
                                let val = u64::from_le_bytes([
                                    image[target],
                                    image[target + 1],
                                    image[target + 2],
                                    image[target + 3],
                                    image[target + 4],
                                    image[target + 5],
                                    image[target + 6],
                                    image[target + 7],
                                ]);
                                let new_val = (val as i64).wrapping_add(delta) as u64;
                                image[target..target + 8].copy_from_slice(&new_val.to_le_bytes());
                            }
                        }
                        3 => {
                            // IMAGE_REL_BASED_HIGHLOW
                            if target + 4 <= size_of_image {
                                let val = u32::from_le_bytes([
                                    image[target],
                                    image[target + 1],
                                    image[target + 2],
                                    image[target + 3],
                                ]);
                                let new_val = (val as i32).wrapping_add(delta as i32) as u32;
                                image[target..target + 4].copy_from_slice(&new_val.to_le_bytes());
                            }
                        }
                        0 => {} // IMAGE_REL_BASED_ABSOLUTE - padding, skip
                        _ => {}
                    }
                }

                reloc_offset += block_size;
            }
        }

        // Resolve imports - use LoadLibraryA to ensure DLLs are loaded
        if import_dir_rva != 0 && import_dir_size != 0 {
            let mut desc_offset = import_dir_rva;
            loop {
                if desc_offset + 20 > size_of_image {
                    break;
                }

                let ilt_rva = u32::from_le_bytes([
                    image[desc_offset],
                    image[desc_offset + 1],
                    image[desc_offset + 2],
                    image[desc_offset + 3],
                ]) as usize;
                let name_rva = u32::from_le_bytes([
                    image[desc_offset + 12],
                    image[desc_offset + 13],
                    image[desc_offset + 14],
                    image[desc_offset + 15],
                ]) as usize;
                let iat_rva = u32::from_le_bytes([
                    image[desc_offset + 16],
                    image[desc_offset + 17],
                    image[desc_offset + 18],
                    image[desc_offset + 19],
                ]) as usize;

                // Null descriptor terminates the list
                if name_rva == 0 && ilt_rva == 0 {
                    break;
                }

                // Read DLL name from image buffer
                let dll_name = read_cstring_from_buf(&image, name_rva);
                let dll_cname = CString::new(dll_name.as_str()).unwrap_or_default();

                // First try GetModuleHandleA, if not loaded then LoadLibraryA
                let module = match GetModuleHandleA(PCSTR(dll_cname.as_ptr() as *const u8)) {
                    Ok(m) => m,
                    Err(_) => {
                        // DLL not loaded, try to load it
                        match LoadLibraryA(PCSTR(dll_cname.as_ptr() as *const u8)) {
                            Ok(m) => m,
                            Err(_) => {
                                // Still can't load - skip this import descriptor
                                desc_offset += 20;
                                continue;
                            }
                        }
                    }
                };

                // Walk the ILT (or IAT if ILT is 0)
                let thunk_rva = if ilt_rva != 0 { ilt_rva } else { iat_rva };
                let mut thunk_off = thunk_rva;
                let mut iat_off = iat_rva;

                loop {
                    if thunk_off + 8 > size_of_image || iat_off + 8 > size_of_image {
                        break;
                    }

                    let thunk_value = u64::from_le_bytes([
                        image[thunk_off],
                        image[thunk_off + 1],
                        image[thunk_off + 2],
                        image[thunk_off + 3],
                        image[thunk_off + 4],
                        image[thunk_off + 5],
                        image[thunk_off + 6],
                        image[thunk_off + 7],
                    ]);

                    if thunk_value == 0 {
                        break;
                    }

                    let func_addr: u64;

                    // Check ordinal flag (bit 63 for PE32+)
                    if thunk_value & (1u64 << 63) != 0 {
                        let ordinal = (thunk_value & 0xFFFF) as u16;
                        let addr = GetProcAddress(module, PCSTR(ordinal as usize as *const u8));
                        func_addr = match addr {
                            Some(a) => a as usize as u64,
                            None => 0,
                        };
                    } else {
                        // Hint/Name: 2-byte hint + name string
                        let hint_name_rva = (thunk_value & 0x7FFFFFFF) as usize;
                        if hint_name_rva + 2 < size_of_image {
                            let func_name = read_cstring_from_buf(&image, hint_name_rva + 2);
                            let func_cname = CString::new(func_name.as_str()).unwrap_or_default();
                            let addr =
                                GetProcAddress(module, PCSTR(func_cname.as_ptr() as *const u8));
                            func_addr = match addr {
                                Some(a) => a as usize as u64,
                                None => 0,
                            };
                        } else {
                            func_addr = 0;
                        }
                    }

                    // Write resolved address to the IAT in our local buffer
                    image[iat_off..iat_off + 8].copy_from_slice(&func_addr.to_le_bytes());

                    thunk_off += 8;
                    iat_off += 8;
                }

                desc_offset += 20;
            }
        }

        // Write the processed image to remote memory
        if WriteProcessMemory(
            process_handle,
            remote_base,
            image.as_ptr() as *const _,
            size_of_image,
            None,
        )
        .is_err()
        {
            let _ = VirtualFreeEx(process_handle, remote_base, 0, MEM_RELEASE);
            let _ = CloseHandle(process_handle);
            return Err(MiscError::WriteFailed);
        }

        // Set proper per-section memory protections
        for section in &sections {
            if section.virtual_size == 0 || section.virtual_address == 0 {
                continue;
            }

            let chars = section.characteristics;
            let protection = section_chars_to_protection(chars);

            // Use virtual_size for protection (covers full section including uninitialized data)
            let section_size = section.virtual_size.max(section.raw_data_size);
            if section_size == 0 {
                continue;
            }

            let section_addr = (actual_base as usize + section.virtual_address) as *const _;
            let mut old_protect = PAGE_PROTECTION_FLAGS(0);
            let _ = VirtualProtectEx(
                process_handle,
                section_addr,
                section_size,
                protection,
                &mut old_protect,
            );
        }

        // Flush instruction cache to ensure CPU sees the new code
        let _ = FlushInstructionCache(process_handle, Some(remote_base), size_of_image);

        // Build DllMain loader shellcode
        let entry_addr = actual_base + entry_point_rva as u64;
        let mut shellcode: Vec<u8> = Vec::new();

        // sub rsp, 0x28 (shadow space + alignment)
        shellcode.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);

        // mov rcx, <remote_base> (hModule = DLL base)
        shellcode.extend_from_slice(&[0x48, 0xB9]);
        shellcode.extend_from_slice(&actual_base.to_le_bytes());

        // mov rdx, 1 (DLL_PROCESS_ATTACH)
        shellcode.extend_from_slice(&[0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00]);

        // xor r8, r8 (lpvReserved = NULL)
        shellcode.extend_from_slice(&[0x4D, 0x31, 0xC0]);

        // mov rax, <entry_point>
        shellcode.extend_from_slice(&[0x48, 0xB8]);
        shellcode.extend_from_slice(&entry_addr.to_le_bytes());

        // call rax
        shellcode.extend_from_slice(&[0xFF, 0xD0]);

        // add rsp, 0x28
        shellcode.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]);

        // xor eax, eax (return 0 for thread exit code)
        shellcode.extend_from_slice(&[0x31, 0xC0]);

        // ret
        shellcode.push(0xC3);

        // Allocate + write shellcode to separate remote memory
        let shellcode_mem = VirtualAllocEx(
            process_handle,
            Some(std::ptr::null()),
            shellcode.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );

        if shellcode_mem.is_null() {
            // Don't free remote_base - image memory must stay for DLL
            let _ = CloseHandle(process_handle);
            return Err(MiscError::AllocFailed);
        }

        if WriteProcessMemory(
            process_handle,
            shellcode_mem,
            shellcode.as_ptr() as *const _,
            shellcode.len(),
            None,
        )
        .is_err()
        {
            let _ = VirtualFreeEx(process_handle, shellcode_mem, 0, MEM_RELEASE);
            let _ = CloseHandle(process_handle);
            return Err(MiscError::WriteFailed);
        }

        // Flush instruction cache for shellcode
        let _ = FlushInstructionCache(process_handle, Some(shellcode_mem), shellcode.len());

        // Create remote thread to execute shellcode (calls DllMain)
        let thread_start: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32 =
            std::mem::transmute(shellcode_mem);

        let thread_handle =
            CreateRemoteThread(process_handle, None, 0, Some(thread_start), None, 0, None)
                .map_err(|_| {
                    let _ = VirtualFreeEx(process_handle, shellcode_mem, 0, MEM_RELEASE);
                    let _ = CloseHandle(process_handle);
                    MiscError::CreateRemoteThreadFailed
                })?;

        // Wait for DllMain to finish (10s timeout)
        let wait_result = WaitForSingleObject(thread_handle, 10_000);

        let _ = CloseHandle(thread_handle);
        // Free shellcode memory (no longer needed after DllMain returns)
        let _ = VirtualFreeEx(process_handle, shellcode_mem, 0, MEM_RELEASE);
        // NOTE: remote_base (image memory) stays allocated - required for DLL to function
        let _ = CloseHandle(process_handle);

        if wait_result.0 != 0 {
            return Err(MiscError::Timeout);
        }

        Ok(())
    }
}

/// Convert PE section characteristics to Windows memory protection flags.
fn section_chars_to_protection(chars: u32) -> PAGE_PROTECTION_FLAGS {
    let is_exec = (chars & IMAGE_SCN_MEM_EXECUTE) != 0;
    let is_read = (chars & IMAGE_SCN_MEM_READ) != 0;
    let is_write = (chars & IMAGE_SCN_MEM_WRITE) != 0;

    match (is_exec, is_read, is_write) {
        (true, true, true) => PAGE_EXECUTE_READWRITE,
        (true, true, false) => PAGE_EXECUTE_READ,
        (true, false, true) => PAGE_EXECUTE_WRITECOPY,
        (true, false, false) => PAGE_EXECUTE,
        (false, true, true) => PAGE_READWRITE,
        (false, true, false) => PAGE_READONLY,
        (false, false, true) => PAGE_WRITECOPY,
        (false, false, false) => PAGE_READONLY, // Default to readonly if no flags
    }
}

/// Read a null-terminated C string from a byte buffer at a given offset.
fn read_cstring_from_buf(data: &[u8], offset: usize) -> String {
    let mut end = offset;
    while end < data.len() && data[end] != 0 {
        end += 1;
    }
    String::from_utf8_lossy(&data[offset..end]).to_string()
}
