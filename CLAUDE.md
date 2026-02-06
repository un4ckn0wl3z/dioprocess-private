# CLAUDE.md — DioProcess

## What is this project?

DioProcess is a Windows desktop system monitoring and process management tool built with **Rust** and **Dioxus 0.6**. It provides real-time process, network, and service monitoring with advanced capabilities like DLL injection, thread control, and handle inspection. Requires administrator privileges (UAC manifest embedded at build time).

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
├── callback/      # Kernel driver communication + SQLite event storage
│   └── src/
│       ├── lib.rs     # Module declarations + pub use re-exports
│       ├── error.rs   # CallbackError enum
│       ├── types.rs   # CallbackEvent, EventType, EventCategory, RegistryOperation
│       ├── driver.rs  # Driver communication (is_driver_loaded, read_events)
│       └── storage.rs # SQLite persistence (EventStorage, EventFilter, batched writes)
├── misc/          # DLL injection (7 methods), DLL unhooking, hook detection, process creation, process hollowing, token theft, module unloading, memory ops
│   └── src/
│       ├── lib.rs                      # Module declarations + pub use re-exports (slim)
│       ├── error.rs                    # MiscError enum, Display, Error impls
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
│       │   └── classic.rs              # inject_shellcode_classic()
│       ├── process/
│       │   ├── mod.rs                  # Re-exports all process functions
│       │   ├── create.rs               # create_process()
│       │   ├── ppid_spoof.rs           # create_ppid_spoofed_process()
│       │   ├── hollow.rs               # hollow_process()
│       │   └── ghost.rs                # ghost_process()
│       └── token.rs                    # steal_token()
├── ui/            # Dioxus components, routing, state, styles
│   └── src/
│       ├── components/
│       │   ├── app.rs            # Main app + router layout
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
│       │   ├── string_scan_window.rs    # Process memory string scan modal
│       │   ├── utilities_tab.rs         # Utilities tab (file bloating, etc.)
│       │   └── callback_tab.rs          # System Events tab (Experimental)
│       ├── routes.rs             # Tab routing definitions
│       ├── state.rs              # Global signal state types
│       ├── helpers.rs            # Clipboard utilities
│       └── styles.rs             # Embedded CSS (dark theme)
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

## Build & run

```bash
cargo build              # Debug build
cargo run                # Run debug (needs admin)
cargo build --release    # Release build
```

The binary opens a 1100x700 borderless window with custom title bar, dark theme, and disabled context menu.

## Conventions

- **Naming:** snake_case functions, PascalCase types, SCREAMING_SNAKE_CASE constants
- **Error handling:** Custom error enums (`MiscError`, `ServiceError`) with `Result<T, E>`
- **Unsafe:** Used for all Windows API calls; always paired with proper resource cleanup (CloseHandle)
- **State management:** Dioxus global signals (`THREAD_WINDOW_STATE`, `HANDLE_WINDOW_STATE`, `MODULE_WINDOW_STATE`, `MEMORY_WINDOW_STATE`, `GRAPH_WINDOW_STATE`, `CREATE_PROCESS_WINDOW_STATE`, `TOKEN_THIEF_WINDOW_STATE`, `FUNCTION_STOMPING_WINDOW_STATE`, `GHOST_PROCESS_WINDOW_STATE`, `HOOK_SCAN_WINDOW_STATE`, `STRING_SCAN_WINDOW_STATE`); local signals for view mode (`ProcessViewMode::Flat`/`Tree`) and expanded PIDs (`HashSet<u32>`)
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

Access via right-click context menu > Miscellaneous > Shellcode Injection > Classic. User selects a `.bin` file containing raw shellcode bytes.

## Process creation methods (misc crate)

Each process creation method is in its own file under `crates/misc/src/process/`:

1. **Normal CreateProcess** (`create.rs`) — Launch executable via `CreateProcessW`, optionally suspended, optionally with Block DLL Policy
2. **PPID Spoofing** (`ppid_spoof.rs`) — Open handle to target parent process, set up `STARTUPINFOEXW` with `InitializeProcThreadAttributeList` + `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS)`, create process via `CreateProcessW` with `EXTENDED_STARTUPINFO_PRESENT` flag; the new process appears as a child of the specified parent PID; optionally combined with Block DLL Policy
3. **Process Hollowing** (`hollow.rs`) — Create host process suspended, get PEB address via thread context Rdx, unmap original image via `NtUnmapViewOfSection`, allocate memory at payload's preferred base, write PE headers and sections individually, apply base relocations if needed, patch PEB ImageBaseAddress, fix per-section memory permissions via `VirtualProtectEx` (R/RW/RX/RWX based on section characteristics), hijack thread entry point (RCX), resume thread
4. **Process Ghosting** (`ghost.rs`) — Create temp file, open via `NtOpenFile` with DELETE permission, mark for deletion with `NtSetInformationFile(FileDispositionInformation)`, write payload via `NtWriteFile`, create SEC_IMAGE section via `NtCreateSection`, close file (deleted while section survives), create process via `NtCreateProcessEx`, retrieve environment via `CreateEnvironmentBlock`, set up PEB process parameters with `RtlCreateProcessParametersEx` (NORMALIZED), allocate at exact params address in remote process via `NtAllocateVirtualMemory` (no pointer relocation), write params and environment via `NtWriteVirtualMemory` with two-scenario layout handling, create initial thread via `NtCreateThreadEx`

## Token theft (misc crate)

Located in `crates/misc/src/token.rs`:

`steal_token(pid, exe_path, args)` — Open target process with `PROCESS_QUERY_LIMITED_INFORMATION`, obtain its primary token via `OpenProcessToken`, duplicate as a primary token with `DuplicateTokenEx(SecurityAnonymous, TokenPrimary)`, enable `SeAssignPrimaryTokenPrivilege` via `AdjustTokenPrivileges`, impersonate with `ImpersonateLoggedOnUser`, spawn a new process under that token via `CreateProcessAsUserW`, then `RevertToSelf`. Access via right-click context menu > Miscellaneous > Steal Token.

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

The app uses SQLite for kernel callback event persistence:
- **Location:** `%LOCALAPPDATA%\DioProcess\events.db`
- **Engine:** rusqlite 0.31 with bundled SQLite
- **Mode:** WAL (Write-Ahead Logging) for concurrent access
- **Retention:** Events older than 24 hours auto-deleted

No external services, network connections, or cloud storage — fully self-contained.
