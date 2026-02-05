//! Hook DLL - Hooks NtProtectVirtualMemory to demonstrate DLL unhooking
//!
//! This DLL uses MinHook to install a hook on NtProtectVirtualMemory.
//! After loading this DLL, the function will be "hooked" and can be
//! restored using the unhook feature.

use std::ffi::CString;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use minhook::MinHook;
use windows::core::PCSTR;
use windows::Win32::Foundation::{BOOL, HANDLE, HMODULE, NTSTATUS};
use windows::Win32::System::Console::AllocConsole;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::Win32::System::SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH};

/// NtProtectVirtualMemory function signature
type FnNtProtectVirtualMemory = unsafe extern "system" fn(
    ProcessHandle: HANDLE,
    BaseAddress: *mut *mut std::ffi::c_void,
    RegionSize: *mut usize,
    NewProtect: u32,
    OldProtect: *mut u32,
) -> NTSTATUS;

/// Original function pointer (trampoline)
static ORIGINAL_FN: AtomicUsize = AtomicUsize::new(0);

/// Hook call counter
static HOOK_CALL_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Hook installed flag
static HOOK_INSTALLED: AtomicBool = AtomicBool::new(false);

/// Target function address for cleanup
static TARGET_FN_ADDR: AtomicUsize = AtomicUsize::new(0);

/// Our hook function - intercepts calls to NtProtectVirtualMemory
unsafe extern "system" fn hooked_nt_protect_virtual_memory(
    process_handle: HANDLE,
    base_address: *mut *mut std::ffi::c_void,
    region_size: *mut usize,
    new_protect: u32,
    old_protect: *mut u32,
) -> NTSTATUS {
    // Increment call counter
    let count = HOOK_CALL_COUNT.fetch_add(1, Ordering::SeqCst) + 1;

    // Log the hook (only first few calls to avoid spam)
    if count <= 5 {
        println!(
            "[HOOK] NtProtectVirtualMemory called (#{}) - NewProtect: 0x{:X}",
            count, new_protect
        );
    }

    // Call the original function via trampoline
    let original: FnNtProtectVirtualMemory =
        std::mem::transmute(ORIGINAL_FN.load(Ordering::SeqCst));
    original(
        process_handle,
        base_address,
        region_size,
        new_protect,
        old_protect,
    )
}

/// Install the hook on NtProtectVirtualMemory
fn install_hook() -> bool {
    unsafe {
        // Get ntdll.dll handle
        let ntdll_name = CString::new("ntdll.dll").unwrap();
        let ntdll = match GetModuleHandleA(PCSTR(ntdll_name.as_ptr() as *const u8)) {
            Ok(h) => h,
            Err(_) => {
                println!("[!] Failed to get ntdll.dll handle");
                return false;
            }
        };

        // Get NtProtectVirtualMemory address
        let func_name = CString::new("NtProtectVirtualMemory").unwrap();
        let target_fn = GetProcAddress(ntdll, PCSTR(func_name.as_ptr() as *const u8));

        let target_ptr = match target_fn {
            Some(f) => f as *mut std::ffi::c_void,
            None => {
                println!("[!] Failed to get NtProtectVirtualMemory address");
                return false;
            }
        };

        println!("[*] Target function at: {:p}", target_ptr);
        TARGET_FN_ADDR.store(target_ptr as usize, Ordering::SeqCst);

        // Create the hook using MinHook's high-level API
        let hook_ptr = hooked_nt_protect_virtual_memory as *mut std::ffi::c_void;

        match MinHook::create_hook(target_ptr, hook_ptr) {
            Ok(trampoline) => {
                // Store original function pointer (trampoline)
                ORIGINAL_FN.store(trampoline as usize, Ordering::SeqCst);

                // Enable the hook
                match MinHook::enable_hook(target_ptr) {
                    Ok(()) => {
                        HOOK_INSTALLED.store(true, Ordering::SeqCst);
                        println!("[+] Hook installed on NtProtectVirtualMemory @ {:p}", target_ptr);
                        true
                    }
                    Err(e) => {
                        println!("[!] MH_EnableHook failed: {:?}", e);
                        false
                    }
                }
            }
            Err(e) => {
                println!("[!] MH_CreateHook failed: {:?}", e);
                false
            }
        }
    }
}

/// DLL entry point
#[no_mangle]
pub unsafe extern "system" fn DllMain(
    _hinst_dll: HMODULE,
    fdw_reason: u32,
    _lpv_reserved: *mut std::ffi::c_void,
) -> BOOL {
    match fdw_reason {
        DLL_PROCESS_ATTACH => {
            // Allocate console for output (optional - for debugging)
            let _ = AllocConsole();

            println!("=================================");
            println!("[*] Hook DLL loaded!");
            println!("[*] Installing hook on NtProtectVirtualMemory...");

            if install_hook() {
                println!("[+] Hook installed successfully!");
            } else {
                println!("[-] Hook installation failed!");
            }
            println!("=================================");

            BOOL::from(true)
        }
        DLL_PROCESS_DETACH => {
            println!("[*] Hook DLL unloading...");
            BOOL::from(true)
        }
        _ => BOOL::from(true),
    }
}

/// Export to check if hook is active (can be called from test exe)
#[no_mangle]
pub extern "system" fn IsHookActive() -> bool {
    HOOK_INSTALLED.load(Ordering::SeqCst)
}

/// Export to get hook call count
#[no_mangle]
pub extern "system" fn GetHookCallCount() -> usize {
    HOOK_CALL_COUNT.load(Ordering::SeqCst)
}
