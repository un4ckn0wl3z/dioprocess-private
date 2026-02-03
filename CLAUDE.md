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
├── process/       # Process enumeration, threads, handles, modules, CPU/memory
├── network/       # TCP/UDP connection enumeration via Windows IP Helper API
├── service/       # Windows Service Control Manager ops (enum, start, stop, create, delete)
├── misc/          # DLL injection (7 methods), process creation, process hollowing, token theft, module unloading, memory ops
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
│       │   └── ghost_process_window.rs  # Process ghosting modal
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
- **State management:** Dioxus global signals (`THREAD_WINDOW_STATE`, `HANDLE_WINDOW_STATE`, `MODULE_WINDOW_STATE`, `MEMORY_WINDOW_STATE`, `GRAPH_WINDOW_STATE`, `CREATE_PROCESS_WINDOW_STATE`, `TOKEN_THIEF_WINDOW_STATE`, `FUNCTION_STOMPING_WINDOW_STATE`, `GHOST_PROCESS_WINDOW_STATE`); local signals for view mode (`ProcessViewMode::Flat`/`Tree`) and expanded PIDs (`HashSet<u32>`)
- **Async:** `tokio::spawn` for background tasks
- **Strings:** UTF-16 wide strings for Windows API, converted to/from Rust `String`
- **UI keyboard shortcuts:** F5 (refresh), Delete (kill), Escape (close menu)
- **Context menu positioning:** CSS `clamp()` keeps the menu within viewport bounds; submenus are bottom-anchored to avoid overflow

## DLL injection methods (misc crate)

1. **LoadLibrary** — Classic CreateRemoteThread + WriteProcessMemory
2. **Thread Hijack** — Suspend thread, redirect RIP/PC to shellcode
3. **APC Queue** — QueueUserAPC + LoadLibraryW on all threads; fires when a thread enters alertable wait
4. **EarlyBird** — CreateRemoteThread suspended + QueueUserAPC before thread runs; APC fires during LdrInitializeThunk guaranteeing execution
5. **Remote Mapping** — CreateFileMappingW + MapViewOfFile locally + NtMapViewOfSection remotely; avoids VirtualAllocEx/WriteProcessMemory entirely
6. **Function Stomping** — Overwrite a sacrificial function (default: setupapi.dll!SetupScanFileQueueA) in the remote process with LoadLibraryW shellcode; avoids new executable memory allocation
7. **Manual Mapping** — Parse PE, map sections, resolve imports, call DllMain

## Process creation methods (misc crate)

1. **Normal CreateProcess** — Launch executable via `CreateProcessW`, optionally suspended
2. **PPID Spoofing** — Open handle to target parent process, set up `STARTUPINFOEXW` with `InitializeProcThreadAttributeList` + `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS)`, create process via `CreateProcessW` with `EXTENDED_STARTUPINFO_PRESENT` flag; the new process appears as a child of the specified parent PID
3. **Process Hollowing** — Create host process suspended, get PEB address via thread context Rdx, unmap original image via `NtUnmapViewOfSection`, allocate memory at payload's preferred base, write PE headers and sections individually, apply base relocations if needed, patch PEB ImageBaseAddress, fix per-section memory permissions via `VirtualProtectEx` (R/RW/RX/RWX based on section characteristics), hijack thread entry point (RCX), resume thread
4. **Process Ghosting** — Create temp file, open via `NtOpenFile` with DELETE permission, mark for deletion with `NtSetInformationFile(FileDispositionInformation)`, write payload via `NtWriteFile`, create SEC_IMAGE section via `NtCreateSection`, close file (deleted while section survives), create process via `NtCreateProcessEx`, retrieve environment via `CreateEnvironmentBlock`, set up PEB process parameters with `RtlCreateProcessParametersEx` (NORMALIZED), allocate at exact params address in remote process via `NtAllocateVirtualMemory` (no pointer relocation), write params and environment via `NtWriteVirtualMemory` with two-scenario layout handling, create initial thread via `NtCreateThreadEx`

## Token theft (misc crate)

`steal_token(pid, exe_path, args)` — Open target process with `PROCESS_QUERY_LIMITED_INFORMATION`, obtain its primary token via `OpenProcessToken`, duplicate as a primary token with `DuplicateTokenEx(SecurityAnonymous, TokenPrimary)`, enable `SeAssignPrimaryTokenPrivilege` via `AdjustTokenPrivileges`, impersonate with `ImpersonateLoggedOnUser`, spawn a new process under that token via `CreateProcessAsUserW`, then `RevertToSelf`. Access via right-click context menu > Miscellaneous > Steal Token.

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

## No tests

There is no test infrastructure. Development relies on manual testing through the UI.

## No external services or databases

The app is fully self-contained, communicating only with the Windows OS via system APIs.
