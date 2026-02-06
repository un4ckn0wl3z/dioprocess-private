# DioProcess — Copilot Instructions

## Project Overview
Windows desktop process monitor built with **Rust 2021** and **Dioxus 0.6** (desktop renderer). Requires administrator privileges (UAC manifest embedded via `build.rs`). Features: live process/network/service monitoring, **System Events (Experimental)** - kernel event monitoring (17 event types with SQLite persistence), 7 DLL injection methods, shellcode injection (classic + web staging + threadless), DLL unhooking, advanced hook detection (E9/E8/EB/FF25/MOV+JMP patterns) with integrated unhooking, process memory string scanning (ASCII + UTF-16), process hollowing/ghosting/ghostly hollowing/herpaderping/herpaderping hollowing, token theft, **Utilities tab** with file bloating (append null bytes or random data to inflate file size), process herpaderping, and herpaderping hollowing.

## Build & Run
```powershell
cargo build --release   # Release build (recommended)
cargo run               # Debug build (requires admin terminal)
```
No test suite exists — all testing is manual via the UI.

## Workspace Architecture
```
crates/
├── process/     # Process enumeration (ToolHelp32, threads, handles, modules, memory, string scanning)
├── network/     # TCP/UDP via IP Helper API
├── service/     # SCM operations (enumerate, start/stop, create/delete)
├── callback/    # Kernel driver comm + SQLite storage (driver.rs, storage.rs, types.rs)
├── misc/        # Low-level ops: injection/, process/ (hollow, ghost, ghostly_hollow, herpaderp, herpaderp_hollow), token.rs, unhook.rs, hook_scanner.rs
├── ui/          # Dioxus components, routing, state signals, styles
└── dioprocess/  # Binary entry point + UAC manifest embedding
kernelmode/
└── DioProcess/        # WDM kernel driver (C++) for system event monitoring
```
**Data flow:** UI components call library functions directly. Libraries wrap unsafe Windows API and return typed Rust structs. Dioxus signals provide reactive state. System events stored in SQLite at `%LOCALAPPDATA%\DioProcess\events.db`.

## Key Conventions

### Error Handling
- Each crate defines its own error enum (`MiscError`, `ServiceError`) implementing `Display` + `Debug`
- Functions return `Result<T, CrateError>` — propagate errors to UI where they're displayed in status boxes

### Unsafe Windows API Pattern
```rust
unsafe {
    let handle = OpenProcess(access, false, pid);
    if handle.is_invalid() { return Err(MiscError::OpenProcessFailed(pid)); }
    // ... use handle ...
    let _ = CloseHandle(handle);  // Always cleanup
}
```

### Dioxus State Management
- Global signals in `ui/src/state.rs`: `THREAD_WINDOW_STATE`, `MEMORY_WINDOW_STATE`, `STRING_SCAN_WINDOW_STATE`, `HOOK_SCAN_WINDOW_STATE`, etc.
- Pattern: `GlobalSignal<Option<(u32, String)>>` for modal windows (PID + process name)
- Local signals for view mode, expanded PIDs, search filters

### Adding New Injection/Process Techniques
1. Create new file in `crates/misc/src/injection/` or `crates/misc/src/process/`
2. Export via parent `mod.rs`: `pub use new_technique::*;`
3. Re-export in `crates/misc/src/lib.rs` via `pub use injection::*;`
4. Create UI window component in `crates/ui/src/components/`
5. Add global signal state in `ui/src/state.rs`
6. Wire into context menu or toolbar in `process_tab.rs`

### UI Component Structure
```rust
#[component]
pub fn SomeWindow() -> Element {
    let state = use_signal(|| LocalState::default());
    let global = SOME_WINDOW_STATE.read();  // Global signal
    
    rsx! {
        div { class: "modal", /* ... */ }
    }
}
```
- Components in `ui/src/components/` with `mod.rs` re-exports
- Dark theme CSS in `styles.rs` (embedded, no external files)
- Context menus use viewport clamping via CSS `clamp()`

## Important File Locations
| Purpose | Path |
|---------|------|
| DLL injection techniques | `crates/misc/src/injection/*.rs` |
| Shellcode injection (classic + web staging + threadless) | `crates/misc/src/shellcode_inject/*.rs` |
| Shellcode inject UI (web staging modal) | `crates/ui/src/components/shellcode_inject_window.rs` |
| Threadless inject UI (modal) | `crates/ui/src/components/threadless_inject_window.rs` |
| Process creation (hollow, ghost, herpaderp_hollow) | `crates/misc/src/process/*.rs` |
| Ghostly hollowing | `crates/misc/src/process/ghostly_hollow.rs` |
| Process herpaderping | `crates/misc/src/process/herpaderp.rs` |
| Herpaderping hollowing | `crates/misc/src/process/herpaderp_hollow.rs` |
| DLL unhooking | `crates/misc/src/unhook.rs` |
| Hook detection | `crates/misc/src/hook_scanner.rs` |
| String scan UI | `crates/ui/src/components/string_scan_window.rs` |
| String scan backend | `crates/process/src/lib.rs` (scan_process_strings) |
| Kernel driver communication | `crates/callback/src/driver.rs` |
| System event SQLite storage | `crates/callback/src/storage.rs` |
| System event types | `crates/callback/src/types.rs` |
| Kernel driver source | `kernelmode/DioProcess/DioProcessDriver/` |
| UI component patterns | `crates/ui/src/components/process_tab.rs` |
| Utilities tab UI | `crates/ui/src/components/utilities_tab.rs` |
| System Events tab UI | `crates/ui/src/components/callback_tab.rs` |
| Global state signals | `crates/ui/src/state.rs` |
| UAC manifest | `crates/dioprocess/app.manifest` |
| Unhook test harness | `assets/unhook_test/` |

## Gotchas
- **64-bit only:** Process ghosting/hollowing/ghostly hollowing/herpaderping/herpaderping hollowing require x64 PE payloads
- **Admin required:** Most features fail without elevation — binary embeds UAC manifest
- **UTF-16 strings:** Windows APIs use wide strings; convert with `encode_utf16().chain(Some(0))`
- **No async in misc crate:** All Windows API calls are synchronous; UI uses `tokio::spawn` for background
- **Tree view:** Built UI-side in `build_tree_rows()`, not in the process crate
- **Kernel driver:** Requires test signing mode (`bcdedit /set testsigning on`) and manual loading via `sc create/start`
- **SQLite storage:** System events persisted at `%LOCALAPPDATA%\DioProcess\events.db` with 24-hour retention
