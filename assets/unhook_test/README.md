# DLL Unhook Test Suite

This folder contains a test suite to verify the DLL unhooking feature works correctly.

## Components

### hook_dll
A DLL that hooks `NtProtectVirtualMemory` from ntdll.dll using MinHook.
When loaded, it installs a hook that logs all calls to `NtProtectVirtualMemory`.

### test_exe
A test executable that:
1. Shows hook status of `NtProtectVirtualMemory`
2. Loads the hook DLL (installs hook)
3. Shows hook status again (should show HOOKED)
4. Calls the unhook function from misc crate
5. Shows hook status again (should show UNHOOKED)

## Building

```bash
cd assets/unhook_test

# Build the hook DLL (must be built first)
cargo build --release -p hook_dll

# Build the test executable
cargo build --release -p test_exe
```

## Running

```bash
# Run as administrator (required for unhooking)
.\target\release\test_exe.exe
```

## Expected Output

```
=== DLL Unhook Test ===

[1] Initial state (before hook DLL loaded):
    NtProtectVirtualMemory @ 0x00007FFxxxxxxxxx -> UNHOOKED

[2] Loading hook DLL...
    Hook DLL loaded successfully!

[3] After hook DLL loaded:
    NtProtectVirtualMemory @ 0x00007FFxxxxxxxxx -> HOOKED

[4] Calling misc::unhook_dll(CommonDll::Ntdll)...
    Unhook result: ntdll.dll - 1234567 bytes replaced

[5] After unhooking:
    NtProtectVirtualMemory @ 0x00007FFxxxxxxxxx -> UNHOOKED

=== Test PASSED ===
```

## How the Hook Works

The hook DLL uses MinHook to:
1. Find `NtProtectVirtualMemory` in ntdll.dll
2. Install a trampoline hook that redirects calls to our function
3. Our hook function logs the call and forwards to the original

The unhook feature works by:
1. Reading a fresh copy of ntdll.dll from `C:\Windows\System32\`
2. Parsing the PE headers to find the `.text` section
3. Replacing the hooked `.text` section with the clean copy

## Hook Detection

A typical NT syscall stub looks like:
```asm
4C 8B D1    mov r10, rcx
B8 xx xx    mov eax, syscall_number
...
```

If the first 4 bytes don't match `0xB8D18B4C`, the function is likely hooked.
