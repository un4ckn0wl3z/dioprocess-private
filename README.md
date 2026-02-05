# DioProcess — Advanced Windows Process & System Monitor

Modern, Windows desktop application for real-time system monitoring and low-level process manipulation.
Built with **Rust 2021** + **Dioxus 0.6** (desktop renderer)
**Requires administrator privileges** (UAC `requireAdministrator` embedded at build time via manifest)

![Preview 1](./assets/preview1.png)
![Preview 2](./assets/preview2.png)
![Preview 3](./assets/preview3.png)

[![Rust](https://img.shields.io/badge/Rust-2021-orange?logo=rust)](https://www.rust-lang.org)
[![Windows](https://img.shields.io/badge/Platform-Windows-blue?logo=windows)](https://microsoft.com/windows)
[![Dioxus](https://img.shields.io/badge/UI-Dioxus%200.6-purple)](https://dioxuslabs.com)

## Core Features

- Live enumeration of processes, threads, handles, modules & virtual memory regions
- TCP/UDP connection listing with owning process (via IP Helper API)
- Windows Service enumeration, start/stop/create/delete (Service Control Manager)
- **Kernel Callback Monitor** — real-time kernel event capture via custom WDM driver:
  - Process/thread create & exit events
  - Image (DLL/EXE) load events
  - Handle operations (process/thread handle create & duplicate)
  - Registry operations (create, open, set, delete, rename, query)
  - **SQLite persistence** with 24-hour retention and paginated UI
- **7 DLL injection techniques** — from classic LoadLibrary to function stomping & full manual mapping
- **DLL Unhooking** — restore hooked DLLs (ntdll, kernel32, kernelbase, user32, advapi32, ws2_32) by replacing .text section from disk
- **Hook Detection & Unhooking** — scan IAT entries for inline hooks (E9 JMP, E8 CALL, EB short JMP, FF25 indirect JMP, MOV+JMP x64 patterns), compare with disk, and optionally unhook detected hooks
- Advanced process creation & masquerading:
  - Normal `CreateProcessW` (suspended option)
  - PPID spoofing (`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`)
  - Classic process hollowing (unmap → map → relocations → PEB patch → thread hijack)
  - **Process ghosting** (fileless execution via orphaned image section + `NtCreateProcessEx`)
- Primary token theft & impersonation (`CreateProcessAsUserW` under stolen token)

## Project Structure (Cargo Workspace)

```
crates/
├── process/       # ToolHelp32, NtQueryInformationThread, VirtualQueryEx, modules, memory regions
├── network/       # GetExtendedTcpTable / GetUdpTable → PID mapping
├── service/       # SCM: EnumServicesStatusEx, Start/Stop/Create/Delete service
├── callback/      # Kernel driver communication + SQLite event storage
│   └── src/
│       ├── lib.rs     # Module re-exports
│       ├── driver.rs  # ReadFile from \\.\DioProcess device
│       ├── storage.rs # SQLite persistence (WAL mode, batched writes)
│       ├── types.rs   # CallbackEvent, EventType, EventCategory
│       └── error.rs   # CallbackError enum
├── misc/          # DLL injection (7 methods), process hollowing, ghosting, token theft, hook scanning, NT syscalls
│   └── src/
│       ├── lib.rs              # Module declarations + pub use re-exports
│       ├── error.rs            # MiscError enum
│       ├── injection/          # 7 injection techniques (each in own file)
│       ├── memory.rs           # commit/decommit/free memory
│       ├── module.rs           # unload_module
│       ├── process/            # create, ppid_spoof, hollow, ghost
│       ├── token.rs            # steal_token
│       ├── unhook.rs           # DLL unhooking (local + remote process)
│       └── hook_scanner.rs     # IAT hook detection (E9/E8/EB/FF25/MOV+JMP patterns)
├── ui/            # Dioxus components, router, global signals, dark theme
└── dioprocess/    # Binary crate — entry point, custom window, manifest embedding
kernelmode/
└── ProcessMonitorEx/  # WDM kernel driver (C++) for callback monitoring
    ├── ProcessMonitorEx.cpp        # Driver code (device: \\.\DioProcess)
    ├── ProcessMonitorExCommon.h    # Shared event structures
    └── ProcessMonitorExCli/        # Test CLI client
```

## Implemented Techniques — Summary

### DLL Injection Methods (misc crate)

1. **LoadLibrary** — `CreateRemoteThread` + `WriteProcessMemory` + `LoadLibraryW`
2. **Thread Hijack** — Suspend thread → alter RIP → shellcode
3. **APC Queue** — `QueueUserAPC` + `LoadLibraryW` on alertable threads
4. **EarlyBird** — Suspended `CreateRemoteThread` → `QueueUserAPC` before first run
5. **Remote Mapping** — `CreateFileMapping` + `NtMapViewOfSection` (no `VirtualAllocEx`)
6. **Function Stomping** — Overwrite sacrificial function (e.g. `setupapi!SetupScanFileQueueA`) with shellcode
7. **Manual Mapping** — PE parsing, section mapping, import resolution, per-section memory protections, `FlushInstructionCache`, call `DllMain`

### Process Creation & Stealth

- Normal + suspended
- PPID spoofing via extended startup attributes
- Process hollowing — full unmap, section-by-section write, relocations, PEB.ImageBaseAddress patch, section protection fix, thread context hijack (RCX)
- **Process ghosting** — temp file → delete disposition → `SEC_IMAGE` section → orphaned section → `NtCreateProcessEx` → normalized process parameters → `NtCreateThreadEx`

### DLL Unhooking

Restore hooked DLLs in **any process** by reading a clean copy from `System32` and replacing the in-memory `.text` section:
- Remote process unhooking via `VirtualProtectEx` + `WriteProcessMemory`
- Parse PE headers to locate `.text` section (RVA + raw offset)
- Read clean DLL from disk, make .text writable, copy clean bytes, restore protection
- Supports: `ntdll.dll`, `kernel32.dll`, `kernelbase.dll`, `user32.dll`, `advapi32.dll`, `ws2_32.dll`
- **Test suite** included in `assets/unhook_test/` with MinHook-based hook DLL

### Hook Detection & Removal

Scan process IAT (Import Address Table) for inline hooks by comparing imported function bytes with original DLL from disk:
- Parse PE Import Directory to enumerate all imported DLLs and functions
- Read first 16 bytes of each imported function from process memory
- Detect multiple hook types:
  - **E9 JMP** — Near jump (5-byte inline hook)
  - **E8 CALL** — Near call hook
  - **EB Short JMP** — Short jump (2-byte hook)
  - **FF25 Indirect JMP** — Indirect jump via memory
  - **MOV+JMP x64** — `48 B8 [addr] FF E0` or `48 B8 [addr] 50 C3` patterns
- Read original DLL from System32 and compare function bytes
- Works for **all** imported DLLs: ntdll, kernel32, user32, ws2_32, advapi32, etc.
- **Unhook from UI** — Right-click detected hooks to restore original bytes
- Displays hook location, memory vs disk bytes, target module, and import DLL name
- Accessed via context menu: **Inspect → Hook Scan**

### Token Theft

`OpenProcessToken → DuplicateTokenEx(TokenPrimary) → SeAssignPrimaryTokenPrivilege → ImpersonateLoggedOnUser → CreateProcessAsUserW → RevertToSelf`

### Kernel Callback Monitor

Real-time kernel event capture via WDM driver with 17 event types:

| Category | Events |
|----------|--------|
| Process | ProcessCreate, ProcessExit |
| Thread | ThreadCreate, ThreadExit |
| Image | ImageLoad (DLL/EXE loading) |
| Handle | ProcessHandleCreate, ProcessHandleDuplicate, ThreadHandleCreate, ThreadHandleDuplicate |
| Registry | RegistryCreate, RegistryOpen, RegistrySetValue, RegistryDeleteKey, RegistryDeleteValue, RegistryRenameKey, RegistryQueryValue |

**Storage:** SQLite database at `%LOCALAPPDATA%\DioProcess\events.db`
- WAL mode for concurrent reads/writes
- Batched inserts (500 events or 100ms flush)
- 24-hour auto-retention cleanup
- Paginated UI (500 events per page)

**Driver:** Build with Visual Studio + WDK, load via `sc create DioProcess type= kernel binPath= "path\to\DioProcess.sys" && sc start DioProcess`

## UI & Interaction Highlights

- Borderless dark-themed window with custom title bar
- Tabs: **Processes** · **Network** · **Services** · **Callback Monitor**
- **Tree view** in Processes tab (DFS traversal, box-drawing connectors ├ │ └ ─, ancestor-inclusive search)
- Modal inspectors: Threads · Handles · Modules · Memory · Performance graphs
- Real-time per-process CPU/memory graphs (60-second rolling history, SVG + fill)
- Paginated hex + ASCII memory dump viewer (4 KB pages)
- Memory operations: commit/reserve/decommit/free regions
- CSV export per tab
- Context menu with viewport clamping & upward-anchored submenus

## Keyboard Shortcuts

| Key       | Action                          |
|-----------|---------------------------------|
| `F5`      | Refresh current list            |
| `Delete`  | Kill selected process           |
| `Escape`  | Close modal / context menu      |

## Build & Run

```bash
# Debug build + run (must run as administrator)
cargo run

# Optimized release binary
cargo build --release
.\target\release\dioprocess.exe
```

## Key Dependencies

- dioxus 0.6 — UI framework + router + signals
- tokio — async background refresh
- sysinfo 0.31 — global CPU/memory/uptime stats
- windows 0.58 — Win32 API bindings
- ntapi 0.4 — Native NTSTATUS & undocumented APIs
- rusqlite 0.31 — SQLite storage for kernel events
- arboard — clipboard
- rfd — native file dialogs

## Project Notes

- No automated unit/integration tests (manual UI testing only)
- Fully offline — only talks to Windows kernel/user-mode APIs
- Heavy usage of unsafe Rust blocks around Windows API calls
- Development focus: red-team tooling, malware research, OS internals learning

## MIT licensed.

Contributions welcome — especially around:

- stability & better error messages
- 32-bit Windows support
- additional evasion / injection techniques
- UI polish & accessibility

Built with Rust & Dioxus — low-level Windows fun since 2025
