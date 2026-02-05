//! Test EXE - Tests the DLL unhooking feature automatically
//!
//! This program:
//! 1. Checks initial hook status of NtProtectVirtualMemory
//! 2. Loads the hook DLL (installs hook)
//! 3. Verifies the function is now hooked
//! 4. Calls the unhook function from misc crate
//! 5. Verifies the function is now unhooked
//!
//! For manual testing with dioprocess UI, use: manual_test.exe

#[cfg(feature = "auto")]
use misc::{is_export_hooked, unhook_dll, CommonDll};

use std::ffi::CString;
use std::io::{self, Write};

#[cfg(feature = "auto")]
use misc::{is_export_hooked, unhook_dll, CommonDll};
use windows::core::PCSTR;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA};

fn print_separator() {
    println!("{}", "=".repeat(60));
}

fn get_function_address(dll: &str, func: &str) -> Option<*const u8> {
    unsafe {
        let dll_cstr = CString::new(dll).ok()?;
        let func_cstr = CString::new(func).ok()?;

        let module = GetModuleHandleA(PCSTR(dll_cstr.as_ptr() as *const u8)).ok()?;
        let addr = GetProcAddress(module, PCSTR(func_cstr.as_ptr() as *const u8))?;

        Some(addr as *const u8)
    }
}

fn check_hook_status(label: &str) {
    println!("\n[{}] {}", label, "Checking hook status...");

    let func_addr = get_function_address("ntdll.dll", "NtProtectVirtualMemory");

    match func_addr {
        Some(addr) => {
            // Read first 4 bytes
            let first_bytes = unsafe { *(addr as *const u32) };

            // Expected syscall stub: 4C 8B D1 B8 (mov r10, rcx; mov eax, ...)
            let expected: u32 = 0xB8D18B4C;
            let is_hooked = first_bytes != expected;

            println!(
                "    NtProtectVirtualMemory @ {:p}",
                addr
            );
            println!(
                "    First 4 bytes: 0x{:08X} (expected: 0x{:08X})",
                first_bytes, expected
            );
            println!(
                "    Status: {}",
                if is_hooked { "🔴 HOOKED" } else { "🟢 UNHOOKED" }
            );

            // Also use the misc crate's detection (only in auto mode)
            #[cfg(feature = "auto")]
            match is_export_hooked("ntdll.dll", "NtProtectVirtualMemory") {
                Ok(hooked) => {
                    println!(
                        "    misc::is_export_hooked: {}",
                        if hooked { "HOOKED" } else { "CLEAN" }
                    );
                }
                Err(e) => {
                    println!("    misc::is_export_hooked error: {}", e);
                }
            }
        }
        None => {
            println!("    ❌ Failed to get function address");
        }
    }
}

fn load_hook_dll() -> bool {
    println!("\n[2] Loading hook DLL...");

    // Try to find the hook DLL in various locations
    let possible_paths = [
        ".\\hook_dll.dll",
        ".\\target\\release\\hook_dll.dll",
        ".\\target\\debug\\hook_dll.dll",
        "..\\target\\release\\hook_dll.dll",
        "..\\target\\debug\\hook_dll.dll",
    ];

    for path in &possible_paths {
        let path_cstr = match CString::new(*path) {
            Ok(s) => s,
            Err(_) => continue,
        };

        unsafe {
            match LoadLibraryA(PCSTR(path_cstr.as_ptr() as *const u8)) {
                Ok(handle) => {
                    if !handle.is_invalid() {
                        println!("    ✅ Hook DLL loaded from: {}", path);
                        return true;
                    }
                }
                Err(_) => continue,
            }
        }
    }

    println!("    ❌ Failed to load hook DLL from any location");
    println!("    Tried paths: {:?}", possible_paths);
    println!("\n    Make sure to build the hook_dll first:");
    println!("    cargo build --release -p hook_dll");
    false
}

#[cfg(feature = "auto")]
fn perform_unhook() -> bool {
    println!("\n[4] Calling misc::unhook_dll(CommonDll::Ntdll)...");

    match unhook_dll(CommonDll::Ntdll) {
        Ok(result) => {
            println!("    ✅ Unhook successful!");
            println!("    DLL: {}", result.dll_name);
            println!("    .text section RVA: 0x{:X}", result.text_section_rva);
            println!("    .text section size: {} bytes", result.text_section_size);
            println!("    Bytes replaced: {}", result.bytes_replaced);
            true
        }
        Err(e) => {
            println!("    ❌ Unhook failed: {}", e);
            false
        }
    }
}

fn wait_for_enter(prompt: &str) {
    print!("\n{}", prompt);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
}

#[cfg(feature = "auto")]
fn main() {
    print_separator();
    println!("       DLL UNHOOK TEST - NtProtectVirtualMemory");
    println!("       (Automated test using misc crate)");
    print_separator();

    // Step 1: Check initial state
    check_hook_status("1");

    wait_for_enter("Press Enter to load hook DLL...");

    // Step 2: Load hook DLL
    if !load_hook_dll() {
        println!("\n❌ Test aborted: Could not load hook DLL");
        wait_for_enter("Press Enter to exit...");
        return;
    }

    // Step 3: Verify hook is installed
    check_hook_status("3");

    // Trigger a VirtualProtect call to verify the hook is working
    println!("\n[*] Triggering VirtualProtect to verify hook...");
    unsafe {
        let mut old_protect = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
        let mut dummy = [0u8; 4096];
        let _ = windows::Win32::System::Memory::VirtualProtect(
            dummy.as_mut_ptr() as *const _,
            4096,
            windows::Win32::System::Memory::PAGE_READWRITE,
            &mut old_protect,
        );
    }
    println!("    (Check console for hook output)");

    wait_for_enter("Press Enter to perform unhook...");

    // Step 4: Perform unhook
    if !perform_unhook() {
        println!("\n❌ Test failed: Unhook operation failed");
        wait_for_enter("Press Enter to exit...");
        return;
    }

    // Step 5: Verify unhook worked
    check_hook_status("5");

    // Final result
    print_separator();

    let final_check = is_export_hooked("ntdll.dll", "NtProtectVirtualMemory");
    match final_check {
        Ok(false) => {
            println!("✅ TEST PASSED - Function successfully unhooked!");
        }
        Ok(true) => {
            println!("❌ TEST FAILED - Function is still hooked!");
        }
        Err(e) => {
            println!("⚠️  TEST INCONCLUSIVE - Could not verify: {}", e);
        }
    }

    print_separator();
    wait_for_enter("Press Enter to exit...");
}

#[cfg(not(feature = "auto"))]
fn main() {
    println!("This binary requires the 'auto' feature.");
    println!("Build with: cargo build --release -p test_exe --features auto");
    println!("\nFor manual testing, use: manual_test.exe");
}
