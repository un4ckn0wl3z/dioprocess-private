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
├── misc/          # DLL injection (3 methods), module unloading, memory ops
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
│       │   └── graph_window.rs   # Real-time CPU/memory performance graphs
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
    └── misc crate     → Windows API (Memory, LibraryLoader, Debug)
```

UI components call library functions directly. Libraries wrap unsafe Windows API calls and return typed Rust structs. Dioxus signals provide reactive state with 3-second auto-refresh.

## Key data types

| Struct | Crate | Fields (key) |
|--------|-------|------|
| `ProcessInfo` | process | pid, name, memory, threads, cpu, exe_path |
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
- **State management:** Dioxus global signals (`THREAD_WINDOW_STATE`, `HANDLE_WINDOW_STATE`, `MODULE_WINDOW_STATE`, `MEMORY_WINDOW_STATE`, `GRAPH_WINDOW_STATE`)
- **Async:** `tokio::spawn` for background tasks
- **Strings:** UTF-16 wide strings for Windows API, converted to/from Rust `String`
- **UI keyboard shortcuts:** F5 (refresh), Delete (kill), Escape (close menu)

## DLL injection methods (misc crate)

1. **LoadLibrary** — Classic CreateRemoteThread + WriteProcessMemory
2. **Thread Hijack** — Suspend thread, redirect RIP/PC to shellcode
3. **Manual Mapping** — Parse PE, map sections, resolve imports, call DllMain

## CSV export

Each tab (Processes, Network, Services) has an "Export CSV" button that exports the current filtered list to a CSV file via save dialog. Uses `rfd::AsyncFileDialog` for native file picker.

## Performance graph window

Real-time CPU and memory monitoring for individual processes:
- **SVG-based graphs** - Smooth line graphs with fill area
- **60-second history** - Rolling window updated every second
- **Auto-scaling** - Memory graph auto-scales based on usage
- **Pause/Resume** - Pause updates to analyze a specific moment
- Access via right-click context menu > "View Performance"

## Memory window features

- **Region enumeration** — Lists all virtual memory regions via `VirtualQueryEx`
- **Module correlation** — MEM_IMAGE regions display the associated module name (ntdll.dll, kernel32.dll, etc.) with full path tooltip
- **Hex dump viewer** — Paginated hex dump (4KB pages) with ASCII column for committed regions
- **Memory dump** — Export any committed region to .bin file via save dialog (from action button, context menu, or hex dump view)
- **Memory operations** — Commit reserved regions, decommit committed regions, free allocations (via misc crate)
- **Filtering** — Filter by address, state, type, protection, or module name

## No tests

There is no test infrastructure. Development relies on manual testing through the UI.

## No external services or databases

The app is fully self-contained, communicating only with the Windows OS via system APIs.
