//! Manual Test EXE - Loads hook DLL and waits for you to unhook via dioprocess UI
//!
//! This program:
//! 1. Loads the hook DLL (installs hook on NtProtectVirtualMemory)
//! 2. Shows the hooked status
//! 3. Waits for you to use dioprocess UI to unhook
//! 4. You press Enter to verify the unhook worked

use std::ffi::CString;
use std::io::{self, Write};

use windows::core::PCSTR;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA};

fn print_separator() {
    println!("{}", "=".repeat(60));
}

fn get_function_bytes(dll: &str, func: &str) -> Option<(u32, *const u8)> {
    unsafe {
        let dll_cstr = CString::new(dll).ok()?;
        let func_cstr = CString::new(func).ok()?;

        let module = GetModuleHandleA(PCSTR(dll_cstr.as_ptr() as *const u8)).ok()?;
        let addr = GetProcAddress(module, PCSTR(func_cstr.as_ptr() as *const u8))?;

        let first_bytes = *(addr as *const u32);
        Some((first_bytes, addr as *const u8))
    }
}

fn check_hook_status() -> bool {
    println!("\n  Checking NtProtectVirtualMemory...");

    if let Some((first_bytes, addr)) = get_function_bytes("ntdll.dll", "NtProtectVirtualMemory") {
        // Expected syscall stub: 4C 8B D1 B8 (mov r10, rcx; mov eax, ...)
        let expected: u32 = 0xB8D18B4C;
        let is_hooked = first_bytes != expected;

        println!("    Address: {:p}", addr);
        println!("    First 4 bytes: 0x{:08X}", first_bytes);
        println!("    Expected:      0x{:08X}", expected);
        println!(
            "    Status: {}",
            if is_hooked { "🔴 HOOKED" } else { "🟢 UNHOOKED" }
        );

        is_hooked
    } else {
        println!("    ❌ Failed to get function address");
        false
    }
}

fn load_hook_dll() -> bool {
    println!("\n[*] Loading hook DLL...");

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

    println!("    ❌ Failed to load hook DLL");
    println!("\n    Build the hook_dll first:");
    println!("    cargo build --release -p hook_dll");
    false
}

fn wait_for_enter(prompt: &str) {
    print!("{}", prompt);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
}

fn main() {
    print_separator();
    println!("    MANUAL DLL UNHOOK TEST");
    println!("    Test unhooking via dioprocess UI");
    print_separator();

    // Get this process's PID
    let pid = std::process::id();
    println!("\n📋 This process PID: {}", pid);
    println!("   Use this PID in dioprocess to find this process");

    // Step 1: Check initial state
    println!("\n[1] Initial state (before hook):");
    check_hook_status();

    wait_for_enter("\nPress Enter to load hook DLL...");

    // Step 2: Load hook DLL
    if !load_hook_dll() {
        wait_for_enter("\nPress Enter to exit...");
        return;
    }

    // Step 3: Show hooked state
    println!("\n[2] After loading hook DLL:");
    let is_hooked = check_hook_status();

    if !is_hooked {
        println!("\n⚠️  Hook doesn't appear to be installed!");
        println!("    The first bytes still match the expected pattern.");
    }

    print_separator();
    println!("\n🎯 NOW DO THIS:");
    println!("   1. Open dioprocess (as Administrator)");
    println!("   2. Find this process (PID: {})", pid);
    println!("   3. Right-click → Miscellaneous → DLL Unhook → ntdll.dll");
    println!("   4. Come back here and press Enter");
    print_separator();

    wait_for_enter("\nPress Enter AFTER you unhook via dioprocess UI...");

    // Step 4: Check if unhook worked
    println!("\n[3] After unhooking via dioprocess:");
    let still_hooked = check_hook_status();

    print_separator();
    if !still_hooked {
        println!("✅ SUCCESS! The function is now unhooked!");
        println!("   dioprocess successfully restored ntdll.dll");
    } else {
        println!("❌ STILL HOOKED - unhook didn't work or wasn't performed");
    }
    print_separator();

    wait_for_enter("\nPress Enter to exit...");
}
