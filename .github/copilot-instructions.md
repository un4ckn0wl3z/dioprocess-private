# DioProcess — Copilot Instructions

## Project Overview
Windows desktop process monitor built with **Rust 2021** and **Dioxus 0.6** (desktop renderer). Requires administrator privileges (UAC manifest embedded via `build.rs`). Features: live process/network/service monitoring, 7 DLL injection methods, DLL unhooking, process hollowing/ghosting, token theft.

## Build & Run
```powershell
cargo build --release   # Release build (recommended)
cargo run               # Debug build (requires admin terminal)
```
No test suite exists — all testing is manual via the UI.

## Workspace Architecture
```
crates/
├── process/     # Process enumeration (ToolHelp32, threads, handles, modules, memory)
├── network/     # TCP/UDP via IP Helper API
├── service/     # SCM operations (enumerate, start/stop, create/delete)
├── misc/        # Low-level ops: injection/, process/, token.rs, unhook.rs, hook_scanner.rs
├── ui/          # Dioxus components, routing, state signals, styles
└── dioprocess/  # Binary entry point + UAC manifest embedding
```
**Data flow:** UI components call library functions directly. Libraries wrap unsafe Windows API and return typed Rust structs. Dioxus signals provide reactive state with 3-second auto-refresh.

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
- Global signals in `ui/src/state.rs`: `THREAD_WINDOW_STATE`, `MEMORY_WINDOW_STATE`, etc.
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
| Injection techniques | `crates/misc/src/injection/*.rs` |
| Process creation (hollow, ghost) | `crates/misc/src/process/*.rs` |
| DLL unhooking | `crates/misc/src/unhook.rs` |
| Hook detection | `crates/misc/src/hook_scanner.rs` |
| UI component patterns | `crates/ui/src/components/process_tab.rs` |
| Global state signals | `crates/ui/src/state.rs` |
| UAC manifest | `crates/dioprocess/app.manifest` |
| Unhook test harness | `assets/unhook_test/` |

## Gotchas
- **64-bit only:** Process ghosting/hollowing require x64 PE payloads
- **Admin required:** Most features fail without elevation — binary embeds UAC manifest
- **UTF-16 strings:** Windows APIs use wide strings; convert with `encode_utf16().chain(Some(0))`
- **No async in misc crate:** All Windows API calls are synchronous; UI uses `tokio::spawn` for background
- **Tree view:** Built UI-side in `build_tree_rows()`, not in the process crate
