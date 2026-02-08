# CLAUDE.md — DioProcess

## What is this project?

DioProcess is a Windows desktop system monitoring and process management tool built with **Rust** and **Dioxus 0.6**. It provides real-time process, network, and service monitoring with advanced capabilities like DLL injection, thread control, handle inspection, and kernel-level security research features (process protection manipulation, token privilege escalation). Requires administrator privileges (UAC manifest embedded at build time).

## Tech stack

- **Language:** Rust 2021 edition
- **UI framework:** Dioxus 0.6 (desktop renderer, router)
- **Async runtime:** tokio 1.x
- **System info:** sysinfo 0.31
- **Windows API:** windows 0.58, ntapi 0.4
- **Clipboard:** arboard 3.x
- **File dialogs:** rfd 0.15
- **Build:** Cargo workspace (resolver v2), embed-resource for manifest

## Workspace structure

```
crates/
├── process/       # Process enumeration, threads, handles, modules, CPU/memory, string scanning
├── network/       # TCP/UDP connection enumeration via Windows IP Helper API
├── service/       # Windows Service Control Manager ops (enum, start, stop, create, delete)
├── callback/      # Kernel driver communication + SQLite event storage + security research IOCTLs + hypervisor
│   └── src/
│       ├── lib.rs         # Module declarations + pub use re-exports
│       ├── error.rs       # CallbackError enum
│       ├── types.rs       # CallbackEvent, EventType, EventCategory, RegistryOperation
│       ├── driver.rs      # Driver communication (is_driver_loaded, read_events, protect/unprotect, enable_privileges, clear_debug_flags, callback enumeration)
│       ├── hypervisor.rs  # Bundled hypervisor (Ring -1) bindings (hv_is_running, hv_inject_shellcode, hv_inject_dll, HvInjectResult, HvInjectDllResult)
│       ├── pspcidtable.rs # PspCidTable enumeration (CidEntry, CidObjectType, enumerate_pspcidtable)
│       └── storage.rs     # SQLite persistence (EventStorage, EventFilter, batched writes)
├── misc/          # DLL injection (7 methods), DLL unhooking, hook detection, kernel injection, process creation, process hollowing, ghostly hollowing, process herpaderping, herpaderping hollowing, token theft, module unloading, memory ops
│   └── src/
│       ├── lib.rs                      # Module declarations + pub use re-exports (slim)
│       ├── error.rs                    # MiscError enum, Display, Error impls
│       ├── kernel_inject.rs            # Kernel shellcode/DLL injection via RtlCreateUserThread
│       ├── unhook.rs                   # DLL unhooking (restore .text from disk)
│       ├── hook_scanner.rs             # IAT hook detection (E9/E8/EB/FF25/MOV+JMP patterns)
│       ├── injection/
│       │   ├── mod.rs                  # Re-exports all injection functions
│       │   ├── loadlibrary.rs          # inject_dll()
│       │   ├── thread_hijack.rs        # inject_dll_thread_hijack()
│       │   ├── apc_queue.rs            # inject_dll_apc_queue()
│       │   ├── earlybird.rs            # inject_dll_earlybird()
│       │   ├── remote_mapping.rs       # inject_dll_remote_mapping()
│       │   ├── function_stomping.rs    # inject_dll_function_stomping()
│       │   └── manual_map.rs           # inject_dll_manual_map()
│       ├── memory.rs                   # commit_memory(), decommit_memory(), free_memory()
│       ├── module.rs                   # unload_module()
│       ├── shellcode_inject/
│       │   ├── mod.rs                  # Re-exports all shellcode injection functions
│       │   ├── classic.rs              # inject_shellcode_classic(), inject_shellcode_bytes()
│       │   ├── web_staging.rs          # inject_shellcode_url()
│       │   └── threadless.rs           # inject_shellcode_threadless()
│       ├── process/
│       │   ├── mod.rs                  # Re-exports all process functions
│       │   ├── create.rs               # create_process()
│       │   ├── ppid_spoof.rs           # create_ppid_spoofed_process()
│       │   ├── hollow.rs               # hollow_process()
│       │   ├── ghostly_hollow.rs       # ghostly_hollow_process()
│       │   ├── ghost.rs                # ghost_process()
│       │   ├── herpaderp.rs            # herpaderp_process()
│       │   └── herpaderp_hollow.rs     # herpaderp_hollow_process()
│       └── token.rs                    # steal_token()
├── ui/            # Dioxus components, routing, state, styles, config
│   └── src/
│       ├── components/
│       │   ├── app.rs            # Main app + router layout + theme selector
│       │   ├── process_tab.rs    # Process monitoring tab
│       │   ├── network_tab.rs    # Network connections tab
│       │   ├── service_tab.rs    # Service management tab
│       │   ├── process_row.rs    # Individual process row component
│       │   ├── thread_window.rs  # Thread inspection modal
│       │   ├── handle_window.rs  # Handle inspection modal
│       │   ├── module_window.rs  # Module/DLL view + injection UI
│       │   ├── memory_window.rs  # Memory regions view + hex dump + dump to file
│       │   ├── graph_window.rs   # Real-time CPU/memory performance graphs
│       │   ├── create_process_window.rs  # Process creation + hollowing modal
│       │   ├── token_thief_window.rs    # Token theft + impersonation modal
│       │   ├── function_stomping_window.rs  # Function stomping injection modal
│       │   ├── ghost_process_window.rs  # Process ghosting modal
│       │   ├── hook_scan_window.rs      # IAT hook detection modal
│       │   ├── shellcode_inject_window.rs # Shellcode injection (web staging) modal
│       │   ├── threadless_inject_window.rs # Threadless shellcode injection modal
│       │   ├── string_scan_window.rs    # Process memory string scan modal
│       │   ├── utilities_tab.rs         # Usermode Utilities tab (file bloating, etc.)
│       │   ├── kernel_utilities_tab.rs  # Kernel Enumeration tab (callback enum, PspCidTable)
│       │   ├── kernel_enumeration/
│       │   │   ├── mod.rs               # Kernel enumeration sub-tabs
│       │   │   └── hypervisor.rs        # Hypervisor tab (Ring -1) - standalone top-level tab
│       │   └── callback_tab.rs          # System Events tab (Experimental)
│       ├── config.rs             # Theme enum, AppConfig, SQLite config storage
│       ├── routes.rs             # Tab routing definitions
│       ├── state.rs              # Global signal state types
│       ├── helpers.rs            # Clipboard utilities
│       └── styles.rs             # CSS themes (Aura Glow, Cyber) with CSS variables
└── dioprocess/    # Binary entry point, window config, manifest embedding
    ├── src/main.rs
    ├── build.rs        # Embeds app.manifest via embed-resource
    ├── app.manifest    # UAC requireAdministrator
    └── resources.rc
```

## Architecture

```
UI Layer (ui crate — Dioxus components + signals)
    ├── process crate  → Windows API (ToolHelp32, Threading, ProcessStatus)
    ├── network crate  → Windows API (IpHelper, WinSock)
    ├── service crate  → Windows API (Services / SCM)
    ├── callback crate → Kernel driver (\\.\DioProcess) + SQLite (%LOCALAPPDATA%\DioProcess\events.db)
    └── misc crate     → Windows API (Memory, LibraryLoader, Debug, Security)
```

UI components call library functions directly. Libraries wrap unsafe Windows API calls and return typed Rust structs. Dioxus signals provide reactive state with 3-second auto-refresh.

## Key data types

| Struct | Crate | Fields (key) |
|--------|-------|------|
| `ProcessInfo` | process | pid, parent_pid, name, memory, threads, cpu, exe_path |
| `SystemStats` | process | cpu_percent, memory_gb, process_count, uptime |
| `ThreadInfo` | process | thread_id, owner_pid, base_priority, priority |
| `HandleInfo` | process | handle_value, type, name |
| `ModuleInfo` | process | base_address, size, path, entry_point |
| `MemoryRegionInfo` | process | base_address, allocation_base, region_size, state, mem_type, protect |
| `ProcessStats` | process | cpu_usage, memory_mb |
| `StringResult` | process | address, value, encoding, length, region_type |
| `StringScanConfig` | process | min_length, scan_ascii, scan_utf16, max_string_length |
| `StringEncoding` | process | Ascii, Utf16 |
| `CallbackEvent` | callback | event_type, timestamp, process_id, process_name, image_base/size, key_name, desired_access, etc. |
| `EventType` | callback | ProcessCreate/Exit, ThreadCreate/Exit, ImageLoad, Handle ops (4), Registry ops (7) |
| `EventCategory` | callback | Process, Thread, Image, Handle, Registry |
| `EventStorage` | callback | SQLite wrapper with batched writes, queries, retention cleanup |
| `EventFilter` | callback | event_type, category, process_id, search (for DB queries) |
| `NetworkConnection` | network | protocol, local/remote addr:port, state, pid |
| `ServiceInfo` | service | name, display_name, status, start_type, binary_path, description, pid |
| `Theme` | ui | AuraGlow (default), Cyber |
| `AppConfig` | ui | theme |
| `ConfigStorage` | ui | SQLite wrapper for app settings |
| `CallbackInfo` | callback | index, callback_address, module_name |
| `ObjectCallbackInfo` | callback | module_name, altitude, pre_operation_callback, post_operation_callback, object_type, operations, index |
| `ObjectCallbackType` | callback | Process, Thread |
| `ObjectCallbackOperations` | callback | handle_create, handle_duplicate |
| `CidEntry` | callback | id, object_address, object_type, parent_pid, process_name |
| `CidObjectType` | callback | Process, Thread |
| `HvInjectResult` | callback | bytes_written, thread_handle, shellcode_address, success |
| `HvInjectDllResult` | callback | module_base, path_address, success |

## Build & run

```bash
cargo build              # Debug build
cargo run                # Run debug (needs admin)
cargo build --release    # Release build
```

The binary opens a 1100x700 borderless window with custom title bar and disabled context menu.

## Theme system

The app supports multiple UI themes with persistent preference storage.

### Available themes

| Theme | Description | Accent Color |
|-------|-------------|--------------|
| **Aura Glow** (default) | Dark background with purple/violet accents and glowing white text | `#8b5cf6` (violet) |
| **Cyber** | Original cyan/teal theme | `#22d3ee` (cyan) |

### Implementation

Located in `crates/ui/src/`:
- **`config.rs`** — `Theme` enum, `AppConfig` struct, `ConfigStorage` for SQLite persistence
- **`styles.rs`** — CSS variables per theme (`AURA_GLOW_VARS`, `CYBER_VARS`) + shared `BASE_STYLES`

**Theme enum:**
```rust
pub enum Theme {
    AuraGlow,  // Default - dark with violet glow
    Cyber,     // Original cyan theme
}
```

**CSS variable approach:** Each theme defines `:root` CSS variables (colors, gradients, shadows). The `BASE_STYLES` const uses these variables, allowing runtime theme switching without duplicating CSS.

**Storage:** Theme preference saved to `%LOCALAPPDATA%\DioProcess\config.db` (separate from `events.db`)

**UI:** Theme selector dropdown in the title bar, immediately saves preference on change.

## Conventions

- **Naming:** snake_case functions, PascalCase types, SCREAMING_SNAKE_CASE constants
- **Error handling:** Custom error enums (`MiscError`, `ServiceError`) with `Result<T, E>`
- **Unsafe:** Used for all Windows API calls; always paired with proper resource cleanup (CloseHandle)
- **State management:** Dioxus global signals (`THREAD_WINDOW_STATE`, `HANDLE_WINDOW_STATE`, `MODULE_WINDOW_STATE`, `MEMORY_WINDOW_STATE`, `GRAPH_WINDOW_STATE`, `CREATE_PROCESS_WINDOW_STATE`, `TOKEN_THIEF_WINDOW_STATE`, `FUNCTION_STOMPING_WINDOW_STATE`, `GHOST_PROCESS_WINDOW_STATE`, `HOOK_SCAN_WINDOW_STATE`, `STRING_SCAN_WINDOW_STATE`, `SHELLCODE_INJECT_WINDOW_STATE`, `THREADLESS_INJECT_WINDOW_STATE`); local signals for view mode (`ProcessViewMode::Flat`/`Tree`) and expanded PIDs (`HashSet<u32>`)
- **Async:** `tokio::spawn` for background tasks
- **Strings:** UTF-16 wide strings for Windows API, converted to/from Rust `String`
- **UI keyboard shortcuts:** F5 (refresh), Delete (kill), Escape (close menu)
- **Context menu positioning:** CSS `clamp()` keeps the menu within viewport bounds; submenus are bottom-anchored to avoid overflow

## DLL injection methods (misc crate)

Each injection method is in its own file under `crates/misc/src/injection/`:

1. **LoadLibrary** (`loadlibrary.rs`) — Classic CreateRemoteThread + WriteProcessMemory
2. **Thread Hijack** (`thread_hijack.rs`) — Suspend thread, redirect RIP/PC to shellcode
3. **APC Queue** (`apc_queue.rs`) — QueueUserAPC + LoadLibraryW on all threads; fires when a thread enters alertable wait
4. **EarlyBird** (`earlybird.rs`) — CreateRemoteThread suspended + QueueUserAPC before thread runs; APC fires during LdrInitializeThunk guaranteeing execution
5. **Remote Mapping** (`remote_mapping.rs`) — CreateFileMappingW + MapViewOfFile locally + NtMapViewOfSection remotely; avoids VirtualAllocEx/WriteProcessMemory entirely
6. **Function Stomping** (`function_stomping.rs`) — Overwrite a sacrificial function (default: setupapi.dll!SetupScanFileQueueA) in the remote process with LoadLibraryW shellcode; avoids new executable memory allocation
7. **Manual Mapping** (`manual_map.rs`) — Parse PE, map sections, resolve imports with LoadLibraryA fallback, apply per-section memory protections (PAGE_EXECUTE_READ for .text, PAGE_READWRITE for .data, etc.), FlushInstructionCache, call DllMain via shellcode

## Shellcode injection methods (misc crate)

Each shellcode injection method is in its own file under `crates/misc/src/shellcode_inject/`:

1. **Classic** (`classic.rs`) — Read raw shellcode from .bin file, `OpenProcess` → `VirtualAllocEx(PAGE_READWRITE)` → `WriteProcessMemory` → `VirtualProtectEx(PAGE_EXECUTE_READWRITE)` → `CreateRemoteThread` at shellcode address
2. **Web Staging** (`web_staging.rs`) — Download raw shellcode from URL via WinInet (`InternetOpenW` → `InternetOpenUrlW` → `InternetReadFile` in 1024-byte chunks), then inject using the classic technique
3. **Threadless** (`threadless.rs`) — No `CreateRemoteThread`. Hooks an exported function (e.g. `USER32!MessageBoxW`) with a 5-byte CALL trampoline. Allocates a "memory hole" within ±1.75 GB of the target function, writes a 63-byte hook shellcode stub (saves registers, restores original bytes, calls payload, jumps back) + the main shellcode payload. Payload fires when the target process naturally calls the hooked function. Self-healing: the hook restores the original function bytes after first execution.

Shared injection core in `inject_shellcode_bytes()` (`classic.rs`) is used by Classic and Web Staging.

Access via right-click context menu > Miscellaneous > Shellcode Injection:
- **Classic** — file picker for `.bin` shellcode files
- **Web Staging** — opens modal window with URL input field (HTTP/HTTPS)
- **Threadless** — opens modal window with shellcode file picker + target DLL/function inputs (defaults: USER32 / MessageBoxW)

## Process creation methods (misc crate)

Each process creation method is in its own file under `crates/misc/src/process/`:

1. **Normal CreateProcess** (`create.rs`) — Launch executable via `CreateProcessW`, optionally suspended, optionally with Block DLL Policy
2. **PPID Spoofing** (`ppid_spoof.rs`) — Open handle to target parent process, set up `STARTUPINFOEXW` with `InitializeProcThreadAttributeList` + `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS)`, create process via `CreateProcessW` with `EXTENDED_STARTUPINFO_PRESENT` flag; the new process appears as a child of the specified parent PID; optionally combined with Block DLL Policy
3. **Process Hollowing** (`hollow.rs`) — Create host process suspended, get PEB address via thread context Rdx, unmap original image via `NtUnmapViewOfSection`, allocate memory at payload's preferred base, write PE headers and sections individually, apply base relocations if needed, patch PEB ImageBaseAddress, fix per-section memory permissions via `VirtualProtectEx` (R/RW/RX/RWX based on section characteristics), hijack thread entry point (RCX), resume thread
4. **Process Ghosting** (`ghost.rs`) — Create temp file, open via `NtOpenFile` with DELETE permission, mark for deletion with `NtSetInformationFile(FileDispositionInformation)`, write payload via `NtWriteFile`, create SEC_IMAGE section via `NtCreateSection`, close file (deleted while section survives), create process via `NtCreateProcessEx`, retrieve environment via `CreateEnvironmentBlock`, set up PEB process parameters with `RtlCreateProcessParametersEx` (NORMALIZED), allocate at exact params address in remote process via `NtAllocateVirtualMemory` (no pointer relocation), write params and environment via `NtWriteVirtualMemory` with two-scenario layout handling, create initial thread via `NtCreateThreadEx`
5. **Process Herpaderping** (`herpaderp.rs`) — Write payload PE to temp file, create SEC_IMAGE section via `NtCreateSection`, create process via `NtCreateProcessEx`, **overwrite temp file with legitimate PE content** (the "herpaderp" — AV/OS sees legit PE on disk), set up PEB/params/environment with `RtlCreateProcessParametersEx` (NORMALIZED), create initial thread via `NtCreateThreadEx` at payload entry point; supports optional command-line arguments for the payload
6. **Ghostly Hollowing** (`ghostly_hollow.rs`) — Combine process ghosting with hollowing: create temp file, mark for deletion via `NtSetInformationFile`, write payload via `NtWriteFile`, create `SEC_IMAGE` section via `NtCreateSection`, close file (deleted, section survives), `CreateProcessW` with legitimate host executable (SUSPENDED), `NtMapViewOfSection` to map ghost section into suspended process, hijack thread context (set RCX to entry point), patch PEB.ImageBase, `ResumeThread`
7. **Herpaderping Hollowing** (`herpaderp_hollow.rs`) — Write payload PE to temp file, create SEC_IMAGE section via `NtCreateSection`, create legitimate host process SUSPENDED via `CreateProcessW`, map the herpaderped section into the suspended process via `NtMapViewOfSection`, **overwrite temp file with legitimate PE content** (the "herpaderp"), hijack thread execution (set RCX to mapped entry point, patch PEB.ImageBase via `NtWriteVirtualMemory`), resume thread; combines herpaderping with hollowing — the on-disk file shows the legit PE while the in-memory section runs the payload inside a legitimate process

## Token theft (misc crate)

Located in `crates/misc/src/token.rs`:

`steal_token(pid, exe_path, args)` — Open target process with `PROCESS_QUERY_LIMITED_INFORMATION`, obtain its primary token via `OpenProcessToken`, duplicate as a primary token with `DuplicateTokenEx(SecurityAnonymous, TokenPrimary)`, enable `SeAssignPrimaryTokenPrivilege` via `AdjustTokenPrivileges`, impersonate with `ImpersonateLoggedOnUser`, spawn a new process under that token via `CreateProcessAsUserW`, then `RevertToSelf`. Access via right-click context menu > Miscellaneous > Steal Token.

## Security Research Features (callback crate + kernel driver)

**Requires DioProcess kernel driver to be loaded.** Three offensive capabilities via direct kernel structure manipulation:

### 1. Process Protection Manipulation

**Functions:**
- `callback::protect_process(pid: u32) -> Result<(), CallbackError>` — Apply PPL protection
- `callback::unprotect_process(pid: u32) -> Result<(), CallbackError>` — Remove PPL protection

**Implementation:**
Located in `kernelmode/DioProcess/DioProcessDriver/DioProcessDriver.cpp` (IOCTL handlers) and `crates/callback/src/driver.rs` (Rust bindings).

**Algorithm (Protect):**
1. Call `GetWindowsVersion()` to detect current Windows build (10240-26100)
2. `PsLookupProcessByProcessId()` to get `EPROCESS` pointer from PID
3. Calculate protection structure address: `EPROCESS + PROCESS_PROTECTION_OFFSET[version]`
4. Write protection values to `_EPROCESS.Protection` structure:
   - `SignatureLevel = 0x3E` (SE_SIGNING_LEVEL_WINDOWS_TCB)
   - `SectionSignatureLevel = 0x3C` (SE_SIGNING_LEVEL_WINDOWS)
   - `Protection.Type = 2` (PsProtectedTypeProtectedLight)
   - `Protection.Signer = 6` (PsProtectedSignerWinTcb)
5. `ObDereferenceObject(eProcess)`

**Algorithm (Unprotect):**
Same as above, but zero out all protection fields instead of setting them.

**Structure Offsets:**
```cpp
// PROCESS_PROTECTION_OFFSET array (indexed by WINDOWS_VERSION)
Win 10 1809 (17763):  0x6ca
Win 10 2004 (19041):  0x87a
Win 11 21H2 (22000):  0x87a
Win 11 22H2 (22621):  0x87a
Win 11 23H2 (22631):  0x87a
Win 11 24H2 (26100):  0x87a (⚠️ needs verification)
```

**Use Cases:**
- Protect benign processes from termination/injection
- Remove protection from protected processes (lsass.exe, AV, etc.) for research
- Test PPL bypass techniques

**UI Access:**
Right-click process → Miscellaneous → **🛡️ Protect Process** / **🔓 Unprotect Process**
(Buttons disabled/grayed when driver not loaded)

### 2. Kernel Injection (shellcode + DLL)

**Functions:**
- `misc::kernel_inject_shellcode(pid: u32, shellcode: &[u8]) -> Result<u64, MiscError>` — Inject shellcode from kernel mode
- `misc::kernel_inject_dll(pid: u32, dll_path: &str) -> Result<(u64, u64), MiscError>` — Inject DLL from kernel mode

**Implementation:**
Located in `kernelmode/DioProcess/DioProcessDriver/DioProcessDriver.cpp` (kernel functions) and `crates/misc/src/kernel_inject.rs` (Rust bindings).

**Algorithm (Shellcode):**
1. Dynamically resolve `RtlCreateUserThread` via `MmGetSystemRoutineAddress`
2. `PsLookupProcessByProcessId()` to get `EPROCESS` pointer
3. `KeStackAttachProcess()` to attach to target process context
4. `ZwAllocateVirtualMemory()` to allocate RWX memory in target
5. `RtlCopyMemory()` to write shellcode bytes
6. `RtlCreateUserThread(process, NULL, FALSE, 0, 0, 0, shellcode_addr, NULL, &hThread, NULL)`
7. `ZwClose(hThread)`, `KeUnstackDetachProcess()`, `ObDereferenceObject()`

**Algorithm (DLL):**
1. Resolve `RtlCreateUserThread` dynamically
2. Get `LoadLibraryW` address in target process:
   - Get PEB via `PROCESS_PEB_OFFSET[GetWindowsVersion()]`
   - Walk `PEB->Ldr->InLoadOrderModuleList` to find `kernel32.dll`
   - Parse PE export directory to find `LoadLibraryW`
3. Attach to target process
4. Allocate memory for wide-char DLL path
5. Write DLL path via `RtlCopyMemory`
6. `RtlCreateUserThread(process, NULL, FALSE, 0, 0, 0, LoadLibraryW_addr, dll_path_addr, &hThread, NULL)`
7. Cleanup

**IOCTLs:**
```cpp
IOCTL_DIOPROCESS_KERNEL_INJECT_SHELLCODE  // 0x00222030
IOCTL_DIOPROCESS_KERNEL_INJECT_DLL        // 0x00222034
```

**UI Access:**
Right-click process → Miscellaneous → **Kernel Injection** → Shellcode Injection / DLL Injection
(Submenu disabled/grayed when driver not loaded)

### 2b. Ring -1 Injection (Hypervisor Level)

**Functions:**
- `callback::hv_inject_shellcode(pid: u32, shellcode: &[u8]) -> Result<HvInjectResult, CallbackError>` — Inject shellcode via hypervisor
- `callback::hv_inject_dll(pid: u32, dll_path: &str) -> Result<HvInjectDllResult, CallbackError>` — Inject DLL via hypervisor

**Implementation:**
Located in `kernelmode/DioProcess/DioProcessDriver/IRP/DeviceControl.cpp` (IOCTL handlers) and `crates/callback/src/hypervisor.rs` (Rust bindings).

**Algorithm (Shellcode):**
1. Open target process, allocate RWX memory via `ZwAllocateVirtualMemory`
2. **Touch memory** via `RtlZeroMemory` while attached — creates physical backing pages
3. Detach from process context
4. VMCALL to hypervisor: EPT translate virtual → physical, write shellcode bytes
5. Create thread via `RtlCreateUserThread` at shellcode address

**Algorithm (DLL):**
1. Allocate memory for DLL path, touch to page in
2. VMCALL to write DLL path via physical memory
3. Resolve `LoadLibraryW` via `GetLoadLibraryWAddress()`
4. Create thread with `RtlCreateUserThread(LoadLibraryW, path_addr)`

**IOCTLs:**
```cpp
IOCTL_DIOPROCESS_HV_INJECT_SHELLCODE  // 0x840
IOCTL_DIOPROCESS_HV_INJECT_DLL        // 0x841
```

**Key difference from Ring 0 injection:**
- Writes to physical memory via EPT — bypasses ring 0 memory protections
- Requires DioProcess.sys with bundled hypervisor to be running
- Memory must be touched/paged in before hypervisor can write

**UI Access:**
Right-click process → Miscellaneous → **HV Inject Shellcode (Ring -1)** / **HV Inject DLL (Ring -1)**
(Items disabled when driver/hypervisor not loaded)

### 3. Token Privilege Escalation

**Function:**
- `callback::enable_all_privileges(pid: u32) -> Result<(), CallbackError>` — Enable all Windows privileges

**Implementation:**
Located in `kernelmode/DioProcess/DioProcessDriver/DioProcessDriver.cpp` (IOCTL handler) and `crates/callback/src/driver.rs` (Rust binding).

**Algorithm:**
1. Call `GetWindowsVersion()` to detect current Windows build
2. `PsLookupProcessByProcessId()` to get `EPROCESS` pointer from PID
3. `PsReferencePrimaryToken(eProcess)` to get `TOKEN` pointer
4. Calculate privilege structure address: `TOKEN + PROCESS_PRIVILEGE_OFFSET[version]` (usually 0x40)
5. Set all privilege bitmasks to 0xFF:
   ```cpp
   tokenPrivs->Present[0-4] = 0xff;
   tokenPrivs->Enabled[0-4] = 0xff;
   tokenPrivs->EnabledByDefault[0-4] = 0xff;
   ```
6. `PsDereferencePrimaryToken(pToken)` and `ObDereferenceObject(eProcess)`

**Privileges Enabled (40 total):**
- `SeDebugPrivilege` — Debug any process
- `SeLoadDriverPrivilege` — Load kernel drivers
- `SeTcbPrivilege` — Act as part of OS
- `SeBackupPrivilege`, `SeRestorePrivilege`, `SeImpersonatePrivilege`
- Plus 34 more Windows privileges

**Structure Offset:**
Token privilege offset is **0x40** across all Windows 10/11 versions (very stable).

**Use Cases:**
- Grant unrestricted access to a process without restarting it
- Bypass privilege checks for security research
- Test privilege escalation detection

**UI Access:**
Right-click process → Miscellaneous → **⚡ Enable All Privileges**
(Button disabled/grayed when driver not loaded)

### Driver Communication

**IOCTLs (defined in DioProcessCommon.h):**
```cpp
IOCTL_DIOPROCESS_PROTECT_PROCESS      // 0x00222014
IOCTL_DIOPROCESS_UNPROTECT_PROCESS    // 0x00222018
IOCTL_DIOPROCESS_ENABLE_PRIVILEGES    // 0x0022201C
```

**Request Structure:**
```cpp
struct TargetProcessRequest {
    ULONG ProcessId;  // Target PID
};
```

**Error Handling:**
- `STATUS_NOT_SUPPORTED` — Unsupported Windows version (< Win 10 or unrecognized build)
- `STATUS_BUFFER_TOO_SMALL` — Invalid request size
- `STATUS_INVALID_PARAMETER` — NULL request buffer
- `PsLookupProcessByProcessId` failures return NTSTATUS error codes

### Windows Version Support

**Supported Versions:**
- ✅ Windows 10: 1507 (10240) through 22H2 (19045)
- ✅ Windows 11: 21H2 (22000) through 24H2 (26100)

**Version Detection:**
`GetWindowsVersion()` in `DioProcessDriver.cpp` uses `RtlGetVersion()` to get build number and maps to `WINDOWS_VERSION` enum. If build is unrecognized but >= 19041, uses Windows 10 2004 offsets as fallback.

**Offset Verification:**
See `tools/verify_offsets.md` for instructions on:
- Testing offsets on your system via DbgView
- Using WinDbg to find correct offsets: `dt nt!_EPROCESS`, `dt nt!_TOKEN`
- Using Vergilius Project (online PDB browser)
- Updating offset arrays if needed

### PatchGuard / KPP Safety

**These operations DO NOT trigger PatchGuard** because:
- ✅ Data-only modifications to per-process/per-token structures
- ✅ No kernel code patching
- ✅ No SSDT/IDT/GDT modifications
- ✅ No function hooking

PatchGuard only cares about **code patches** and **critical kernel table modifications**. Direct writes to `_EPROCESS` and `_TOKEN` fields are pure data modifications and safe.

### Debug Logging

The driver logs all operations via `KdPrint()` for verification:
```
DioProcess: Windows Build: 10.0 (Build 26100)
DioProcess: Protecting process PID 1234 (EPROCESS=0x..., Offset=0x87A)
DioProcess: Current Protection: SigLvl=0x00, SectSigLvl=0x00, Type=0, Signer=0
DioProcess: New Protection: SigLvl=0x3E, SectSigLvl=0x3C, Type=2, Signer=6
DioProcess: Process PID 1234 protected successfully
```

Use **DbgView** (SysInternals) to capture debug output for verification.

### 4. Clear Debug Flags (Anti-Anti-Debugging)

**Function:**
- `callback::clear_debug_flags(pid: u32) -> Result<(), CallbackError>` — Clear debugging indicators

**Implementation:**
Located in `kernelmode/DioProcess/DioProcessDriver/DioProcessDriver.cpp` (IOCTL handler) and `crates/callback/src/driver.rs` (Rust binding).

**Algorithm:**
1. `PsLookupProcessByProcessId()` to get `EPROCESS` pointer from PID
2. Zero out `_EPROCESS.DebugPort` (removes kernel debugger detection)
3. Get PEB address via `PROCESS_PEB_OFFSET[GetWindowsVersion()]`
4. Zero out `PEB.BeingDebugged` (single byte flag)
5. Zero out `PEB.NtGlobalFlag` (removes heap debug flags like FLG_HEAP_ENABLE_TAIL_CHECK)
6. `ObDereferenceObject(eProcess)`

**IOCTL:**
```cpp
IOCTL_DIOPROCESS_CLEAR_DEBUG_FLAGS  // 0x00222020
```

**Use Cases:**
- Hide debugger presence from anti-debug checks
- Bypass `IsDebuggerPresent()`, `NtQueryInformationProcess(ProcessDebugPort)`, heap-based checks
- Security research and malware analysis

**UI Access:**
Right-click process → Miscellaneous → **🔍 Clear Debug Flags**
(Button disabled/grayed when driver not loaded)

### Security Notes

⚠️ **These are offensive security research capabilities:**
- Bypasses Windows process protection mechanisms
- Grants arbitrary privileges without restrictions
- Can be used to unprotect security products or system processes
- **For authorized security research and testing only**
- Requires administrator privileges + kernel driver loaded
- Test on VM/non-production systems first

## DLL Unhooking (misc crate)

Located in `crates/misc/src/unhook.rs`:

Restores hooked DLLs by replacing the in-memory `.text` section with a clean copy read from disk. **Supports both local and remote process unhooking.**

### Functions:
- `unhook_dll(CommonDll)` — Unhook a DLL in the current process
- `unhook_dll_by_path(path, module_name)` — Unhook any DLL by providing disk path and module name (local)
- `unhook_dll_remote(pid, CommonDll, module_base)` — **Unhook a DLL in a remote process by PID**
- `unhook_dll_remote_by_path(pid, path, module_name, module_base)` — Remote unhook with custom path
- `unhook_multiple_dlls(&[CommonDll])` — Batch unhook multiple DLLs (local)
- `is_function_hooked(addr)` — Check if a function's first bytes match expected syscall stub pattern (`4C 8B D1 B8`)
- `is_export_hooked(dll_name, func_name)` — Check if a specific export is hooked

### Remote Unhooking Algorithm:
1. Read clean DLL from `System32` via `GetSystemDirectoryA`
2. Open target process with `PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE`
3. Parse PE headers (DOS → NT → Section Headers) to find `.text` section
4. Make remote `.text` writable via `VirtualProtectEx(PAGE_EXECUTE_WRITECOPY)`
5. Write clean `.text` bytes to remote process via `WriteProcessMemory`
6. Restore original memory protection via `VirtualProtectEx`

### UI Access:
Right-click process → Miscellaneous → DLL Unhook → select DLL

The unhook is performed on the **selected process**, not on dioprocess itself.

### Test Suite:
Located in `assets/unhook_test/`:
- `hook_dll` — MinHook-based DLL that hooks `NtProtectVirtualMemory`
- `manual_test` — CLI program to verify unhooking via dioprocess UI

```bash
cd assets/unhook_test
cargo build --release
copy target\release\hook_dll.dll target\release\
.\target\release\manual_test.exe  # Run as admin, then unhook via dioprocess
```

## Process tree view

Toggleable tree view in the Process tab showing parent-child process relationships:
- **Toggle** — "Tree View" button in the toolbar switches between flat list and tree hierarchy
- **Parent tracking** — `ProcessInfo.parent_pid` captured from `PROCESSENTRY32W.th32ParentProcessID`
- **Tree building** — UI-side only (`build_tree_rows()` in `process_tab.rs`); builds `HashMap<u32, Vec<ProcessInfo>>` children map, identifies roots (parent_pid == 0 or parent not in process list), DFS pre-order traversal producing `Vec<TreeRow>` with depth/connector metadata
- **Tree connectors** — Unicode box-drawing chars (│ ├ └ ─) rendered as `<span>` elements in the Name cell via `ProcessRow` tree props
- **Expand/collapse** — Per-node toggle (▶/▼ arrows), plus "Expand All" / "Collapse All" toolbar buttons; state stored in `expanded_pids: Signal<HashSet<u32>>` and survives auto-refresh
- **Search in tree mode** — Shows matching processes plus all ancestors up to root to preserve hierarchy context; children of matching nodes auto-expand
- **Sorting in tree mode** — Siblings sorted within their group using the active sort column/order, not globally
- **Orphaned processes** — Processes whose parent PID is no longer in the process list become tree roots

## CSV export

Each tab (Processes, Network, Services) has an "Export CSV" button that exports the current filtered list to a CSV file via save dialog. Uses `rfd::AsyncFileDialog` for native file picker.

## Performance graph window

Real-time CPU and memory monitoring for individual processes:
- **SVG-based graphs** - Smooth line graphs with fill area
- **60-second history** - Rolling window updated every second
- **Auto-scaling** - Memory graph auto-scales based on usage
- **Pause/Resume** - Pause updates to analyze a specific moment
- Access via right-click context menu > Inspect > "Performance"

## Memory window features

- **Region enumeration** — Lists all virtual memory regions via `VirtualQueryEx`
- **Module correlation** — MEM_IMAGE regions display the associated module name (ntdll.dll, kernel32.dll, etc.) with full path tooltip
- **Hex dump viewer** — Paginated hex dump (4KB pages) with ASCII column for committed regions
- **Memory dump** — Export any committed region to .bin file via save dialog (from action button, context menu, or hex dump view)
- **Memory operations** — Commit reserved regions, decommit committed regions, free allocations (via misc crate)
- **Filtering** — Filter by address, state, type, protection, or module name

## Create process window

Access via "Create Process" button in the process tab toolbar:
- **Technique selector** — Choose between Normal (CreateProcess), PPID Spoofing, or Process Hollowing
- **Normal mode** — Select executable, optional arguments, optional "create suspended" checkbox
- **PPID Spoofing mode** — Select executable, enter parent PID to spoof, optional arguments, optional "create suspended" checkbox
- **Hollowing mode** — Select host executable and payload PE (64-bit only)
- **File picker** — Native file dialog filtered to .exe files
- **Status feedback** — Success shows PID/TID, errors show detailed message
- Uses `misc::create_process()`, `misc::create_ppid_spoofed_process()`, and `misc::hollow_process()` functions

## Token thief window

Access via right-click context menu > Miscellaneous > Steal Token:
- **Source display** — Shows the target process name and PID whose token will be stolen
- **Executable picker** — Select the executable to launch under the stolen token
- **Arguments input** — Optional command line arguments
- **Status feedback** — Success shows new PID/TID, errors show detailed message
- Uses `misc::steal_token()` function

## Process ghosting (misc crate)

Located in `crates/misc/src/process/ghost.rs`:

`ghost_process(exe_path)` — Creates a process whose backing file no longer exists on disk. Algorithm:

1. Read payload PE, validate 64-bit PE32+ format, extract entry point RVA from local buffer
2. Resolve NT functions dynamically (`NtOpenFile`, `NtSetInformationFile`, `NtWriteFile`, `NtCreateSection`, `NtCreateProcessEx`, `NtQueryInformationProcess`, `NtReadVirtualMemory`, `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `RtlCreateProcessParametersEx`, `RtlDestroyProcessParameters`, `NtCreateThreadEx`) and userenv.dll functions (`CreateEnvironmentBlock`, `DestroyEnvironmentBlock`)
3. Create temp file (`PG_{timestamp}.tmp`), open via `NtOpenFile` with DELETE permission
4. Mark for deletion via `NtSetInformationFile(FileDispositionInformation)`
5. Write payload via `NtWriteFile`, create image section via `NtCreateSection(SEC_IMAGE)`
6. Close file handle (triggering deletion while section survives)
7. Create process from orphaned section via `NtCreateProcessEx`
8. Retrieve environment block via `CreateEnvironmentBlock` from userenv.dll
9. Set up process parameters via `RtlCreateProcessParametersEx` with `RTL_USER_PROC_PARAMS_NORMALIZED` flag
10. Query PEB via `NtQueryInformationProcess` + `NtReadVirtualMemory`, get ImageBaseAddress
11. Calculate env + params memory range handling two scenarios (environment before or after parameters)
12. Allocate at exact params address in remote process via `NtAllocateVirtualMemory` (no pointer relocation needed since params are NORMALIZED)
13. Write params and environment separately via `NtWriteVirtualMemory`, update `PEB.ProcessParameters`
14. Create initial thread via `NtCreateThreadEx` at entry point
15. Clean up local resources with `RtlDestroyProcessParameters` and `DestroyEnvironmentBlock`

Access via "Ghost Process" button in the process tab toolbar.

## Ghost process window

Access via "Ghost Process" button in the process tab toolbar:
- **Payload picker** — Select the 64-bit executable to ghost
- **Status feedback** — Success shows new PID, errors show detailed NT status codes
- **Implementation details** — Uses `NtOpenFile`, `NtWriteFile`, `NtCreateSection`, `NtCreateProcessEx`, `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx` for full NT API process/thread creation
- Uses `misc::ghost_process()` function

## Hook scan window

Access via right-click context menu > Inspect > Hook Scan:
- **IAT parsing** — Walks the Import Directory (PE data directory index 1) to enumerate all imported DLLs and functions
- **Import Descriptor parsing** — Reads 20-byte Import Descriptors, follows FirstThunk to actual IAT entries, extracts import DLL name
- **Hook type detection** — Identifies multiple hook patterns via `detect_hook_type()` function:
  - `InlineJmp` — E9 near JMP (5-byte hook)
  - `InlineCall` — E8 near CALL hook
  - `ShortJmp` — EB short JMP (2-byte hook)
  - `IndirectJmp` — FF 25 indirect JMP through memory
  - `MovJmp` — 48 B8 [addr] FF E0 or 48 B8 [addr] 50 C3 (x64 long-range hook)
- **Disk comparison** — Reads original DLL from System32, parses PE to find function offset, compares memory vs disk bytes
- **Multi-DLL support** — Works for all imported DLLs: ntdll.dll, kernel32.dll, user32.dll, ws2_32.dll, advapi32.dll, etc.
- **Results table** — Shows module name, memory address, hook type with severity indicator (⚠/🔴), bytes comparison (memory vs disk), and description with import DLL name
- **Unhook from context menu** — Right-click detected hook → "Unhook Module" to restore original bytes from disk via `unhook_dll_remote_by_path()`
- **Filtering** — Filter by address or region name
- **Status feedback** — Shows hook count or clean status
- Uses `misc::scan_process_hooks()` function from `hook_scanner.rs`
- Helper functions: `misc::get_system_directory_path()`, `misc::enumerate_process_modules()`

## String scan window

Access via right-click context menu > Inspect > String Scan:
- **Memory scanning** — Scans all committed memory regions of the target process for printable strings
- **Dual encoding** — Detects both ASCII and UTF-16 strings; encoding filter dropdown (All/ASCII Only/UTF-16 Only)
- **Configurable min length** — Adjustable 1–100 characters (default: 4); max capture length 512 characters
- **Pagination** — 1000 results per page with navigation controls (<< < > >>); prevents UI lag on large result sets
- **Filtering** — Real-time text filter matches string content or hex address
- **Export** — Export all filtered results to .txt file via save dialog
- **Context menu** — Copy String, Copy Address, Copy Row
- **Region type** — Each result shows whether it came from Private, Mapped, or Image memory
- Uses `process::scan_process_strings()` function; scanning runs on `tokio::task::spawn_blocking` to avoid UI freeze

## Utilities tab

Access via "Utilities" tab in the main navigation (between Services and System Events). Hosts standalone utility tools for security research.

### File Bloating

Inflates file size by appending data to bypass security scanner file size limits. Two methods available:

1. **Append Null Bytes (0x00)** — Copies source file to output path, appends `size_mb * 1MB` of zero bytes in 1MB chunks
2. **Large Metadata / Random Data (0xFF)** — Same approach but appends `0xFF` bytes instead, simulating embedded binary resources

**UI controls:**
- **Source file picker** — Browse for any file via `rfd::AsyncFileDialog`
- **Output file picker** — Save As dialog for destination path
- **Method selector** — Dropdown to choose between Null Bytes and Random Data
- **Size input** — 1–2000 MB (default: 200)
- **Bloat File button** — Triggers the operation; disabled with "Bloating..." text while running
- **Status feedback** — Success/error message with auto-dismiss after 5 seconds on success

**Implementation:** Pure file I/O in `utilities_tab.rs` — no new crate, no unsafe code. Runs on `tokio::task::spawn_blocking` to avoid UI freeze.

### Ghostly Hollowing

Combine process ghosting with process hollowing for fileless execution inside a legitimate process. Access via the **Utilities** tab:

- **Host executable** — Legitimate Windows binary (e.g. `RuntimeBroker.exe`) created SUSPENDED
- **PE payload** — 64-bit PE whose ghost section is mapped into the host process
- **Algorithm** — Create ghost section (temp file → delete disposition → write PE → SEC_IMAGE section → file deleted), then map section into suspended host via `NtMapViewOfSection`, hijack thread (set RCX = entry point, patch PEB.ImageBase), resume
- Runs on background thread to keep UI responsive

## Ghostly hollowing (Utilities tab)

Access via the **Utilities** tab → Ghostly Hollowing section:
- **Host executable picker** — Select legitimate 64-bit Windows executable (host process)
- **PE payload picker** — Select 64-bit PE payload to execute via ghost section
- **Status feedback** — Success shows new PID, errors show detailed NT status codes
- Uses `misc::ghostly_hollow_process()` function

## Process Herpaderping (misc crate)

Located in `crates/misc/src/process/herpaderp.rs`:

`herpaderp_process(pe_path, pe_args, legit_img)` — Executes a PE payload while making the on-disk file appear legitimate. Algorithm:

1. Read payload PE into memory, validate PE32+ (64-bit), extract entry point RVA
2. Read legitimate PE (used to overwrite temp file later)
3. Create temp file in %TEMP%, open with GENERIC_READ|GENERIC_WRITE and full sharing
4. Write payload bytes to temp file via WriteFile + FlushFileBuffers + SetEndOfFile
5. Create SEC_IMAGE section from temp file via NtCreateSection
6. Create process from section via NtCreateProcessEx
7. **Overwrite** temp file with legitimate PE content (the "herpaderp") — AV/OS sees legit PE on disk
8. Close file handles
9. Set up PEB, process parameters, environment block via RtlCreateProcessParametersEx (NORMALIZED)
10. Create initial thread via NtCreateThreadEx at payload's entry point

Access via Utilities tab in the main navigation. UI provides PE Payload picker, optional command arguments input, and Legitimate Image picker. Note: the legitimate image file should be larger than the payload PE.

## Herpaderping Hollowing (misc crate)

Located in `crates/misc/src/process/herpaderp_hollow.rs`:

`herpaderp_hollow_process(pe_path, legit_img)` — Combines process herpaderping with process hollowing. The legit image serves dual purpose: it's the host process AND its content overwrites the temp file. Algorithm:

1. Read payload PE into memory, validate PE32+ (64-bit), extract entry point RVA
2. Create temp file in %TEMP%, open with GENERIC_READ|GENERIC_WRITE and full sharing
3. Write payload bytes to temp file via WriteFile + FlushFileBuffers + SetEndOfFile
4. Create SEC_IMAGE section from temp file via NtCreateSection
5. Create legitimate host process SUSPENDED via CreateProcessW (using legit_img path)
6. Map the herpaderped section into the suspended process via NtMapViewOfSection
7. **Overwrite** temp file with legitimate PE content — AV/OS sees legit PE on disk
8. Close file handles
9. Hijack thread: GetThreadContext, set RCX to mapped_base + entry_point_rva, SetThreadContext, patch PEB.ImageBase via NtWriteVirtualMemory
10. Resume thread — payload executes inside the legitimate process

Access via Utilities tab in the main navigation. UI provides PE Payload picker and Legitimate Image picker (serves as both host process and disk overwrite content). Note: the legitimate image should be larger than the payload PE.

## Kernel Utilities tab

Access via "Kernel Utilities" tab in the main navigation. Hosts kernel-mode security research features requiring the DioProcess driver.

### Callback Enumeration sub-tab

Enumerate registered kernel callbacks (process, thread, image load, and object notifications):

**Functions (callback crate):**
- `callback::enumerate_process_callbacks() -> Result<Vec<CallbackInfo>, CallbackError>` — List `PsSetCreateProcessNotifyRoutineEx` callbacks
- `callback::enumerate_thread_callbacks() -> Result<Vec<CallbackInfo>, CallbackError>` — List `PsSetCreateThreadNotifyRoutine` callbacks
- `callback::enumerate_image_callbacks() -> Result<Vec<CallbackInfo>, CallbackError>` — List `PsSetLoadImageNotifyRoutine` callbacks
- `callback::enumerate_object_callbacks() -> Result<Vec<ObjectCallbackInfo>, CallbackError>` — List `ObRegisterCallbacks` handle operation callbacks

**CallbackInfo struct:**
```rust
pub struct CallbackInfo {
    pub index: u32,            // Callback slot index (0-63)
    pub callback_address: u64, // Kernel address of callback function
    pub module_name: String,   // Driver module name (e.g., "ntoskrnl.exe", "WdFilter.sys")
}
```

**ObjectCallbackInfo struct:**
```rust
pub struct ObjectCallbackInfo {
    pub module_name: String,           // Driver that registered the callback
    pub altitude: String,              // Callback altitude (priority)
    pub pre_operation_callback: u64,   // Pre-operation callback address
    pub post_operation_callback: u64,  // Post-operation callback address
    pub object_type: ObjectCallbackType, // Process or Thread
    pub operations: ObjectCallbackOperations, // Create, Duplicate, or both
    pub index: u32,
}
```

**IOCTLs:**
```cpp
IOCTL_DIOPROCESS_ENUM_PROCESS_CALLBACKS  // 0x00222024
IOCTL_DIOPROCESS_ENUM_THREAD_CALLBACKS   // 0x00222028
IOCTL_DIOPROCESS_ENUM_IMAGE_CALLBACKS    // 0x0022202C
IOCTL_DIOPROCESS_ENUM_OBJECT_CALLBACKS   // 0x00222040
```

**UI Features:**
- **Callback type selector** — Process, Thread, Image Load, or Object buttons
- **Regular callback table** — Index, Callback Address (hex), Driver Module columns
- **Object callback table** — Type (Process/Thread), Pre-Operation, Post-Operation, Module, Altitude, Operations columns
- **Sorting** — Click column headers to sort ascending/descending
- **Search filter** — Filter by module name, address, altitude, or type
- **CSV export** — Export enumerated callbacks to CSV file
- **Context menu** — Copy Index, Copy Address, Copy Module
- **Keyboard shortcuts** — F5 (refresh), Escape (close menu)
- **Driver status** — Green/red indicator showing driver availability

**Use Cases:**
- Identify EDR/AV callbacks for security research
- Understand which drivers are monitoring process/thread/image events
- Detect rootkits that register malicious callbacks
- Find handle operation hooks (ObRegisterCallbacks) used by security products
- Analyze callback altitudes to understand driver priority order

### PspCidTable sub-tab

Enumerate all processes and threads via the kernel's PspCidTable (CID handle table):

**Function (callback crate):**
- `callback::enumerate_pspcidtable() -> Result<Vec<CidEntry>, CallbackError>` — List all CID entries

**CidEntry struct:**
```rust
pub struct CidEntry {
    pub id: u32,                    // PID (for processes) or TID (for threads)
    pub object_address: u64,        // EPROCESS or ETHREAD kernel address
    pub object_type: CidObjectType, // Process or Thread
    pub parent_pid: u32,            // Parent PID or owning process PID
    pub process_name: [u8; 16],     // ImageFileName from EPROCESS
}
```

**IOCTL:**
```cpp
IOCTL_DIOPROCESS_ENUM_PSPCIDTABLE  // 0x0022203C
```

**Implementation:**
- Uses **signature scanning** to dynamically locate `PspCidTable` (no hardcoded offsets)
- Walks the CID handle table to enumerate all entries
- Returns EPROCESS/ETHREAD addresses directly from kernel structures
- Read-only operation — **PatchGuard/KPP safe**

**UI Features:**
- **Type filter** — All, Processes, or Threads buttons
- **CID table** — Type, ID, Process Name, Object Address (hex), Parent/Owner PID columns
- **Sorting** — Click column headers to sort
- **Search filter** — Filter by name, ID, address, or parent PID
- **CSV export** — Export to pspcidtable.csv
- **Context menu** — Copy ID, Copy Process Name, Copy Object Address, Copy Parent/Owner PID
- **Color coding** — Green "Process" label, blue "Thread" label

**Use Cases:**
- Enumerate hidden processes (DKOM detection)
- View raw EPROCESS/ETHREAD kernel addresses
- Compare with ToolHelp32 to detect process hiding techniques
- Security research and rootkit analysis

## Hypervisor Tab (Ring -1)

Access via the **Hypervisor** tab in main navigation (marked with red "Ring -1" badge). Operates at hypervisor level (Ring -1) via Intel VT-x for advanced security research.

**Requirements:**
- DioProcess.sys kernel driver loaded (hypervisor is bundled — single driver)

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                 DioProcess UI (Dioxus)                      │
│   Hypervisor Tab [Ring -1]                                  │
└──────────────────────────┬──────────────────────────────────┘
                           │ DeviceIoControl
┌──────────────────────────▼──────────────────────────────────┐
│              callback crate (Rust bindings)                  │
│   hv_is_running(), hv_inject_shellcode(), hv_inject_dll()   │
└──────────────────────────┬──────────────────────────────────┘
                           │ IOCTL
┌──────────────────────────▼──────────────────────────────────┐
│                  DioProcess.sys                              │
│   ┌─────────────────────────────────────────────────────┐   │
│   │  Ring 0: Kernel Driver (IOCTL handlers, memory ops) │   │
│   └──────────────────────────┬──────────────────────────┘   │
│                              │ VMCALL                        │
│   ┌──────────────────────────▼──────────────────────────┐   │
│   │  Ring -1: Bundled Hypervisor (Intel VT-x, EPT)      │   │
│   └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### Ring -1 Injection

**Functions (callback crate):**
- `callback::hv_inject_shellcode(pid: u32, shellcode: &[u8]) -> Result<HvInjectResult, CallbackError>` — Inject shellcode via hypervisor
- `callback::hv_inject_dll(pid: u32, dll_path: &str) -> Result<HvInjectDllResult, CallbackError>` — Inject DLL via hypervisor

**HvInjectResult struct:**
```rust
pub struct HvInjectResult {
    pub bytes_written: u64,      // Bytes written via VMCALL
    pub thread_handle: u64,      // Handle to created thread
    pub shellcode_address: u64,  // Address where shellcode was written
    pub success: bool,
}
```

**HvInjectDllResult struct:**
```rust
pub struct HvInjectDllResult {
    pub module_base: u64,   // Base address of loaded DLL
    pub path_address: u64,  // Address where DLL path was written
    pub success: bool,
}
```

**Algorithm (Shellcode Injection):**
1. Open target process, allocate RWX memory via `ZwAllocateVirtualMemory`
2. **Touch memory** via `RtlZeroMemory` while attached to process — creates physical backing pages
3. Detach from process context
4. VMCALL to hypervisor: translate virtual → physical via EPT, write shellcode to physical memory
5. Create thread via `RtlCreateUserThread` at shellcode address
6. Return thread handle and shellcode address

**Algorithm (DLL Injection):**
1. Allocate memory for DLL path in target process
2. Touch memory to create physical backing
3. VMCALL to write DLL path via physical memory
4. Resolve `LoadLibraryW` in target process via `GetLoadLibraryWAddress()`
5. Create thread via `RtlCreateUserThread(LoadLibraryW, dll_path_addr)`
6. Return module base and path address

**IOCTLs:**
```cpp
IOCTL_DIOPROCESS_HV_INJECT_SHELLCODE  // 0x840
IOCTL_DIOPROCESS_HV_INJECT_DLL        // 0x841
```

**Key Implementation Details:**
- Memory must be "paged in" before hypervisor can write — allocated virtual memory has no physical backing until accessed
- Driver touches memory with `RtlZeroMemory` while attached to process context to force page-in
- Hypervisor translates virtual → physical addresses via EPT before writing
- Bypasses ring 0 memory protections since writes happen at physical level

**PatchGuard Safety:**
- Data-only modifications to usermode memory — does not trigger KPP
- Hypervisor operates outside PatchGuard's monitoring scope
- No kernel code patching or table modifications

**UI Access:**
- Hypervisor tab → Injection section
- Right-click process → Miscellaneous → **HV Inject Shellcode (Ring -1)**
- Right-click process → Miscellaneous → **HV Inject DLL (Ring -1)**

### Other Hypervisor Features

- **Status Display** — Shows hypervisor running state and driver status
- **Process Hiding** — Hide processes from ring 0 enumeration via EPT hooks
- **Driver Hiding** — Hide kernel drivers from ring 0 enumeration
- **Memory Operations** — Read/write physical and virtual memory via hypervisor EPT access

### Bundled Hypervisor

The Intel VT-x hypervisor is bundled into DioProcess.sys (single driver):
- Located in `kernelmode/DioProcess/DioProcessDriver/Hypervisor/`
- Virtualizes the OS at driver load time
- Provides VMCALL interface for physical memory access
- EPT (Extended Page Tables) for address translation
- Hypercall key: `69420` (hardcoded)

**Single driver loading:**
```batch
sc create DioProcess type= kernel binPath= "C:\path\to\DioProcess.sys"
sc start DioProcess
```

## System Events - Experimental (callback crate)

Real-time monitoring of kernel callbacks via the DioProcess kernel driver. Captures process, thread, image load, handle operations, and registry events.

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    DioProcess UI (Rust/Dioxus)              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │              CallbackTab Component                     │ │
│  │  - Event table with filtering/sorting                  │ │
│  │  - Real-time updates via polling (1s)                  │ │
│  │  - CSV export, driver status indicator                 │ │
│  └────────────────────────────────────────────────────────┘ │
│                           │                                  │
│  ┌────────────────────────▼───────────────────────────────┐ │
│  │              callback crate                             │ │
│  │  - is_driver_loaded() - check if driver available      │ │
│  │  - read_events() - ReadFile to get events              │ │
│  │  - CallbackEvent, EventType, EventCategory structs     │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                            │
                   DeviceIoControl / ReadFile
                   \\.\DioProcess
                            │
┌───────────────────────────▼─────────────────────────────────┐
│              Kernel Driver (C++ WDM)                        │
│  - PsSetCreateProcessNotifyRoutineEx (process callbacks)    │
│  - PsSetCreateThreadNotifyRoutine (thread callbacks)        │
│  - PsSetLoadImageNotifyRoutine (image load callbacks)       │
│  - ObRegisterCallbacks (handle operation callbacks)         │
│  - CmRegisterCallbackEx (registry callbacks)                │
│  - Events queued and delivered via IRP_MJ_READ              │
└─────────────────────────────────────────────────────────────┘
```

### Event types (matching DioProcessCommon.h)

| Category | Event Type | Description |
|----------|------------|-------------|
| Process | ProcessCreate | New process created (includes command line, PPID) |
| Process | ProcessExit | Process terminated (includes exit code) |
| Thread | ThreadCreate | New thread created in a process |
| Thread | ThreadExit | Thread terminated (includes exit code) |
| Image | ImageLoad | DLL/EXE loaded (includes base address, size, path) |
| Handle | ProcessHandleCreate | Handle opened to a process |
| Handle | ProcessHandleDuplicate | Process handle duplicated |
| Handle | ThreadHandleCreate | Handle opened to a thread |
| Handle | ThreadHandleDuplicate | Thread handle duplicated |
| Registry | RegistryCreate | Registry key created |
| Registry | RegistryOpen | Registry key opened |
| Registry | RegistrySetValue | Registry value written |
| Registry | RegistryDeleteKey | Registry key deleted |
| Registry | RegistryDeleteValue | Registry value deleted |
| Registry | RegistryRenameKey | Registry key renamed |
| Registry | RegistryQueryValue | Registry value queried |

### Driver data structures

```c
enum class EventType {
    ProcessCreate, ProcessExit, ThreadCreate, ThreadExit,
    ImageLoad,
    ProcessHandleCreate, ProcessHandleDuplicate, ThreadHandleCreate, ThreadHandleDuplicate,
    RegistryCreate, RegistryOpen, RegistrySetValue, RegistryDeleteKey,
    RegistryDeleteValue, RegistryRenameKey, RegistryQueryValue
};

struct ImageLoadInfo {
    ULONG ProcessId;
    ULONG64 ImageBase;
    ULONG64 ImageSize;
    BOOLEAN IsSystemImage;
    BOOLEAN IsKernelImage;
    ULONG ImageNameLength;
    WCHAR ImageName[1];
};

struct HandleOperationInfo {
    ULONG SourceProcessId;
    ULONG SourceThreadId;
    ULONG TargetProcessId;
    ULONG TargetThreadId;
    ULONG DesiredAccess;
    ULONG GrantedAccess;
    BOOLEAN IsKernelHandle;
    ULONG SourceImageNameLength;
    WCHAR SourceImageName[1];
};

struct RegistryOperationInfo {
    ULONG ProcessId;
    ULONG ThreadId;
    RegistryOperation Operation;
    NTSTATUS Status;
    ULONG KeyNameLength;
    ULONG ValueNameLength;
    WCHAR Names[1];  // KeyName followed by ValueName
};
```

### System Events tab features

Access via "System Events" tab in the main navigation (marked as Experimental):
- **Event table** — Time, Type, PID, Process Name, Details columns
- **SQLite storage** — Events persisted to `%LOCALAPPDATA%\DioProcess\events.db`
- **Batched writes** — 500 events or 100ms flush interval for performance
- **Pagination** — 500 events per page with navigation controls (<< < > >>)
- **24-hour retention** — Auto-cleanup of old events (runs hourly)
- **Category filter** — Filter by Process, Thread, Image, Handle, or Registry events
- **Type filter** — Filter by individual event types (17 event types total)
- **Search filter** — By PID, process name, command line, image name, registry key/value
- **Auto-refresh** — 1-second polling when driver loaded
- **Driver status** — Green/red indicator showing driver availability
- **DB stats** — Header shows total event count and database file size
- **Clear all** — Delete all events from database
- **CSV export** — Export current page to CSV file
- **Color coding** — Green (process create), red (process exit), blue (thread create), yellow (thread exit), purple (image load), pink (handle ops), cyan/orange (registry read/write)
- **Context menu** — Copy PID, Copy Process Name, Copy Command Line, Filter by PID/Name

### Driver Installation Requirements

⚠️ **Before installing the kernel driver, you MUST:**

1. **Disable Hyper-V:** `bcdedit /set hypervisorlaunchtype off` (reboot required)
2. **Disable Secure Boot** in BIOS/UEFI settings
3. **Disable Windows driver protections:**
   - Disable Driver Signature Enforcement (test mode or boot options)
   - Disable Vulnerable Driver Blocklist (Windows Security → Device Security → Core Isolation)
   - Disable Memory Integrity / HVCI if enabled

⚠️ **Use ONLY on test systems. You are responsible for any damage.**

**Install Log:** Driver installation output is logged to `%LOCALAPPDATA%\DioProcess\install.log` for troubleshooting.

### Loading the driver

```batch
:: Build with Visual Studio + WDK
:: Enable test signing mode (for unsigned drivers)
bcdedit /set testsigning on

:: Create and start the driver service
sc create DioProcess type= kernel binPath= "C:\path\to\DioProcess.sys"
sc start DioProcess

:: Stop and delete the service
sc stop DioProcess
sc delete DioProcess
```

### Driver location

The kernel driver source is in `kernelmode/DioProcess/`:
- `DioProcess.sln` — Visual Studio solution
- `DioProcessDriver/DioProcessDriver.cpp` — Main driver code (device name: `\\.\DioProcess`)
- `DioProcessDriver/DioProcessCommon.h` — Shared data structures
- `DioProcessCli/` — Test CLI client

## No tests

There is no test infrastructure. Development relies on manual testing through the UI.

## Local storage

The app uses SQLite for persistent storage (two separate databases):

### Event storage (`events.db`)
- **Location:** `%LOCALAPPDATA%\DioProcess\events.db`
- **Purpose:** Kernel callback event persistence
- **Engine:** rusqlite 0.31 with bundled SQLite
- **Mode:** WAL (Write-Ahead Logging) for concurrent access
- **Retention:** Events older than 24 hours auto-deleted

### Config storage (`config.db`)
- **Location:** `%LOCALAPPDATA%\DioProcess\config.db`
- **Purpose:** Application settings (theme preference, etc.)
- **Engine:** rusqlite 0.31 with bundled SQLite
- **Mode:** WAL mode
- **Schema:** Simple key-value table (`config(key TEXT PRIMARY KEY, value INTEGER)`)

### Install log (`install.log`)
- **Location:** `%LOCALAPPDATA%\DioProcess\install.log`
- **Purpose:** Driver installation output for troubleshooting
- **Format:** Timestamped entries with exit code, stdout, and stderr
- **Mode:** Append-only (preserves history of all install attempts)

No external services, network connections, or cloud storage — fully self-contained.
