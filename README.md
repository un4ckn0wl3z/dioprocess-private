# DioProcess — Advanced Windows Process & System Monitor

Modern, Windows desktop application for real-time system monitoring and low-level process manipulation.
Built with **Rust 2021** + **Dioxus 0.6** (desktop renderer)
**Requires administrator privileges** (UAC `requireAdministrator` embedded at build time via manifest)

![Preview 1](./assets/preview1.png)
![Preview 2](./assets/preview2.png)
![Preview 3](./assets/preview3.png)
![Preview 2](./assets/preview4.png)
![Preview 3](./assets/preview5.png)


[![Rust](https://img.shields.io/badge/Rust-2021-orange?logo=rust)](https://www.rust-lang.org)
[![Windows](https://img.shields.io/badge/Platform-Windows-blue?logo=windows)](https://microsoft.com/windows)
[![Dioxus](https://img.shields.io/badge/UI-Dioxus%200.6-purple)](https://dioxuslabs.com)

## Core Features

- Live enumeration of processes, threads, handles, modules & virtual memory regions
- TCP/UDP connection listing with owning process (via IP Helper API)
- Windows Service enumeration, start/stop/create/delete (Service Control Manager)
- **System Events (Experimental)** — real-time kernel event capture via custom WDM driver:
  - Process/thread create & exit events
  - Image (DLL/EXE) load events
  - Handle operations (process/thread handle create & duplicate)
  - Registry operations (create, open, set, delete, rename, query)
  - **SQLite persistence** with 24-hour retention and paginated UI
- **Security Research Features (Kernel Driver)** — Direct kernel structure manipulation for process protection and privilege escalation:
  - **Process Protection** — Apply/remove PPL (Protected Process Light) protection via `_EPROCESS` modification
  - **Token Privilege Escalation** — Enable all 40 Windows privileges via `_TOKEN` modification
  - Supports Windows 10 (1507-22H2) and Windows 11 (21H2-24H2)
- **7 DLL injection techniques** — from classic LoadLibrary to function stomping & full manual mapping
- **Shellcode injection** — classic (from .bin file), web staging (download from URL via WinInet), and threadless (hook exported function, no new threads)
- **DLL Unhooking** — restore hooked DLLs (ntdll, kernel32, kernelbase, user32, advapi32, ws2_32) by replacing .text section from disk
- **Hook Detection & Unhooking** — scan IAT entries for inline hooks (E9 JMP, E8 CALL, EB short JMP, FF25 indirect JMP, MOV+JMP x64 patterns), compare with disk, and optionally unhook detected hooks
- **Process String Scanning** — extract ASCII and UTF-16 strings from process memory with configurable min length, encoding filter, paginated results (1000/page), and text export
- Advanced process creation & masquerading:
  - Normal `CreateProcessW` (suspended option)
  - PPID spoofing (`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`)
  - Classic process hollowing (unmap → map → relocations → PEB patch → thread hijack)
  - **Process ghosting** (fileless execution via orphaned image section + `NtCreateProcessEx`)
  - **Ghostly hollowing** (ghost section mapped into suspended legitimate process via `NtMapViewOfSection` + thread hijack)
  - **Process herpaderping** (write payload PE to temp file, create image section, overwrite file with legitimate PE before inspection)
  - **Herpaderping hollowing** (herpaderping + hollowing: payload section mapped into suspended legit process, temp file overwritten with legit PE, thread hijacked)
- Primary token theft & impersonation (`CreateProcessAsUserW` under stolen token)
- **Utilities tab** — File bloating (append null bytes or random data to inflate file size, 1–2000 MB)

## Project Structure (Cargo Workspace)

```
crates/
├── process/       # ToolHelp32, NtQueryInformationThread, VirtualQueryEx, modules, memory regions, string scanning
├── network/       # GetExtendedTcpTable / GetUdpTable → PID mapping
├── service/       # SCM: EnumServicesStatusEx, Start/Stop/Create/Delete service
├── callback/      # Kernel driver communication + SQLite event storage + security research IOCTLs
│   └── src/
│       ├── lib.rs     # Module re-exports (protect/unprotect/enable_privileges)
│       ├── driver.rs  # ReadFile + IOCTLs (protection/privilege manipulation)
│       ├── storage.rs # SQLite persistence (WAL mode, batched writes)
│       ├── types.rs   # CallbackEvent, EventType, EventCategory
│       └── error.rs   # CallbackError enum
├── misc/          # DLL injection (7 methods), process hollowing, ghosting, token theft, hook scanning, NT syscalls
│   └── src/
│       ├── lib.rs              # Module declarations + pub use re-exports
│       ├── error.rs            # MiscError enum
│       ├── injection/          # 7 DLL injection techniques (each in own file)
│       ├── shellcode_inject/   # Shellcode injection techniques (classic, etc.)
│       ├── memory.rs           # commit/decommit/free memory
│       ├── module.rs           # unload_module
│       ├── process/            # create, ppid_spoof, hollow, ghost, ghostly_hollow, herpaderp, herpaderp_hollow
│       ├── token.rs            # steal_token
│       ├── unhook.rs           # DLL unhooking (local + remote process)
│       └── hook_scanner.rs     # IAT hook detection (E9/E8/EB/FF25/MOV+JMP patterns)
├── ui/            # Dioxus components, router, global signals, dark theme
└── dioprocess/    # Binary crate — entry point, custom window, manifest embedding
kernelmode/
└── DioProcess/        # WDM kernel driver (C++) for system event monitoring + security research
    ├── DioProcessDriver/
    │   ├── DioProcessDriver.cpp    # Driver code (device: \\.\DioProcess)
    │   ├── DioProcessDriver.h      # Protection structures, Windows version detection
    │   └── DioProcessCommon.h      # Shared event structures + security IOCTLs
    └── DioProcessCli/              # Test CLI client
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

### Shellcode Injection Methods (misc crate)

1. **Classic** — Read raw shellcode from `.bin` file → `VirtualAllocEx(RW)` → `WriteProcessMemory` → `VirtualProtectEx(RWX)` → `CreateRemoteThread`
2. **Web Staging** — Download shellcode from URL via WinInet (`InternetOpenW` → `InternetOpenUrlW` → `InternetReadFile` in 1024-byte chunks) → inject using classic technique
3. **Threadless** — Hook an exported function (e.g. `USER32!MessageBoxW`) with a CALL trampoline → payload fires when the function is naturally called by the target process (no `CreateRemoteThread`). Self-healing hook restores original bytes after execution.

Access via context menu: **Miscellaneous → Shellcode Injection → Classic**, **Web Staging**, or **Threadless**

### Process Creation & Stealth

- Normal + suspended
- PPID spoofing via extended startup attributes
- Process hollowing — full unmap, section-by-section write, relocations, PEB.ImageBaseAddress patch, section protection fix, thread context hijack (RCX)
- **Process ghosting** — temp file → delete disposition → `SEC_IMAGE` section → orphaned section → `NtCreateProcessEx` → normalized process parameters → `NtCreateThreadEx`
- **Ghostly hollowing** — Create ghost section (temp file → mark deleted → write PE → SEC_IMAGE section → file deleted), create legitimate host process SUSPENDED via `CreateProcessW`, map ghost section into remote process via `NtMapViewOfSection`, hijack thread (set RCX to entry point, patch PEB.ImageBase via `WriteProcessMemory`), resume thread
- **Process herpaderping** — Write payload PE to a temp file, create an image section from it, create a process from the section, then overwrite the temp file with a legitimate PE. When AV/OS inspects the on-disk file, it sees the legitimate PE, but the in-memory image is the payload. Located in `crates/misc/src/process/herpaderp.rs`; function: `herpaderp_process(pe_path, pe_args, legit_img)`. Key NT APIs: `NtCreateSection`, `NtCreateProcessEx`, `NtCreateThreadEx`, `RtlCreateProcessParametersEx`. Note: the legitimate image should be larger than the payload PE.
- **Herpaderping hollowing** — Combines herpaderping with hollowing: write payload PE to temp file, create image section, launch legitimate process suspended, map section into it, overwrite temp file with legitimate PE, hijack thread execution and resume. The on-disk file shows the legitimate PE while the in-memory mapped section runs the payload inside a legitimate process. Located in `crates/misc/src/process/herpaderp_hollow.rs`; function: `herpaderp_hollow_process(pe_path, legit_img)`. Key APIs: `NtCreateSection`, `CreateProcessW` (SUSPENDED), `NtMapViewOfSection`, `NtWriteVirtualMemory`, `GetThreadContext`, `SetThreadContext`, `ResumeThread`. Note: the legitimate image should be larger than the payload PE.

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

### Security Research Features (Kernel Driver Required)

**Process Protection Manipulation** — Apply or remove Protected Process Light (PPL) protection via direct `_EPROCESS` structure modification:
- **🛡️ Protect Process** — Set PPL WinTcb-Light protection (SignatureLevel=0x3E, SectionSignatureLevel=0x3C, Type=2, Signer=6)
- **🔓 Unprotect Process** — Zero out all protection fields (SignatureLevel, SectionSignatureLevel, Type, Signer)
- Can protect unprotected processes or unprotect protected processes (lsass.exe, AV, etc.)
- Bypasses normal process protection mechanisms for security research

**Token Privilege Escalation** — Enable all Windows privileges for a process token:
- **⚡ Enable All Privileges** — Set all privilege bitmasks to 0xFF in `_TOKEN.Privileges`
- Grants all 40 Windows privileges including:
  - `SeDebugPrivilege` — Debug any process
  - `SeLoadDriverPrivilege` — Load kernel drivers
  - `SeTcbPrivilege` — Act as part of the operating system
  - `SeBackupPrivilege`, `SeRestorePrivilege`, `SeImpersonatePrivilege`, etc.
- Direct `_TOKEN` structure manipulation bypasses `AdjustTokenPrivileges` restrictions

**Implementation Details:**
- Requires DioProcess kernel driver to be loaded and running
- UI features automatically disabled when driver not loaded (grayed out in context menu)
- Supports Windows 10 (1507-22H2) and Windows 11 (21H2-24H2)
- Uses version-specific structure offsets (auto-detected via `RtlGetVersion`)
- Data-only modifications — **does not trigger PatchGuard/KPP**
- Located in: `kernelmode/DioProcess/DioProcessDriver/` (driver) and `crates/callback/src/driver.rs` (Rust bindings)
- Access via: Right-click process → **Miscellaneous** → Protect/Unprotect/Enable Privileges

**Offset Verification:** See `tools/verify_offsets.md` for testing and updating structure offsets for your Windows version

### Utilities

**File Bloating** — Inflate file size to test security scanner file size limits. Access via the **Utilities** tab:

- **Append Null Bytes** — Copy source file, append N MB of `0x00` bytes
- **Large Metadata (Random Data)** — Copy source file, append N MB of `0xFF` bytes
- Configurable size: 1–2000 MB (default 200)
- Runs on background thread to keep UI responsive

**Ghostly Hollowing** — Combine process ghosting + hollowing for fileless execution inside a legitimate process:

- **Host executable** — Select legitimate Windows binary (e.g. `RuntimeBroker.exe`)
- **PE payload** — Select 64-bit PE to execute via ghost section
- Ghost section mapped into suspended host via `NtMapViewOfSection`, thread hijacked, PEB patched, resumed

**Process Herpaderping** — Write payload PE to a temp file, create an image section from it, create a process from the section, then overwrite the temp file with a legitimate PE. When AV/OS inspects the on-disk file, it sees the legitimate PE, but the in-memory image is the payload. Access via the **Utilities** tab:

- **PE Payload** — Select the 64-bit executable to run via herpaderping
- **Command Arguments** — Optional command line arguments for the payload
- **Legitimate Image** — Select a legitimate PE to overwrite the temp file with (should be larger than the payload PE)
- Located in `crates/misc/src/process/herpaderp.rs`; function: `herpaderp_process(pe_path, pe_args, legit_img)`
- Key NT APIs: `NtCreateSection`, `NtCreateProcessEx`, `NtCreateThreadEx`, `RtlCreateProcessParametersEx`

**Herpaderping Hollowing** — Combines herpaderping with hollowing: write payload PE to a temp file, create an image section from it, launch a legitimate process suspended, map the section into it, overwrite the temp file with the legitimate PE, hijack thread execution and resume. The on-disk file shows the legitimate PE while the in-memory mapped section runs the payload inside a legitimate process. Access via the **Utilities** tab:

- **PE Payload** — Select the 64-bit executable to run via herpaderping hollowing
- **Legitimate Image** — Select a legitimate PE that serves as both the host process and the disk overwrite (should be larger than the payload PE)
- Located in `crates/misc/src/process/herpaderp_hollow.rs`; function: `herpaderp_hollow_process(pe_path, legit_img)`
- Key APIs: `NtCreateSection`, `CreateProcessW` (SUSPENDED), `NtMapViewOfSection`, `NtWriteVirtualMemory`, `GetThreadContext`, `SetThreadContext`, `ResumeThread`

### System Events (Experimental)

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
- Tabs: **Processes** · **Network** · **Services** · **Utilities** · **System Events**
- **Tree view** in Processes tab (DFS traversal, box-drawing connectors ├ │ └ ─, ancestor-inclusive search)
- Modal inspectors: Threads · Handles · Modules · Memory · Performance graphs · String Scan
- Real-time per-process CPU/memory graphs (60-second rolling history, SVG + fill)
- Paginated hex + ASCII memory dump viewer (4 KB pages)
- Process memory string scanning (ASCII + UTF-16, paginated 1000/page, export to .txt)
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
