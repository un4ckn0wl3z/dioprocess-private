# 🖥️ DioProcess - Windows Process Monitor

A modern, lightweight Windows process monitor built with **Rust**, **Dioxus**, and **Windows API**.

![image](preview.png)

![Rust](https://img.shields.io/badge/Rust-2021-orange?logo=rust)
![Windows](https://img.shields.io/badge/Platform-Windows-blue?logo=windows)
![Dioxus](https://img.shields.io/badge/UI-Dioxus%200.6-purple)

## ✨ Features

### Process Management
- 📋 **Process List** - View all running processes with PID, name, CPU, threads, memory, and path
- 🔍 **Search & Filter** - Quick search by process name, PID, or executable path
- ⚡ **Real-time Updates** - Auto-refresh every 3 seconds (toggleable)
- ☠️ **Kill Process** - Terminate processes with a click or keyboard shortcut
- 📊 **Sortable Columns** - Sort by PID, Name, CPU, Threads, or Memory (ascending/descending)

### System Monitoring
- 🖥️ **CPU Usage** - Global CPU usage with visual progress bar
- 💾 **RAM Usage** - Memory consumption (used/total GB) with progress bar
- ⏱️ **System Uptime** - Time since last boot
- 📈 **Process Count** - Total number of running processes

### User Interface
- 🎨 **Modern Dark Theme** - Sleek gradient design with Tailwind CSS
- 🪟 **Borderless Window** - Custom title bar with drag, minimize, maximize, close
- 📱 **Responsive Layout** - Adapts to window resizing

### Context Menu (Right-Click)
- ☠️ Kill Process
- ⏸️ Suspend Process
- ▶️ Resume Process
- 📂 Open File Location
- 📋 Copy PID
- 📝 Copy Path
- 🧵 View Threads
- � View Handles
- 🔄 Refresh List

### Thread View (Right-click → View Threads)
- 🧵 View all threads of a process in a modal window
- ⏸️ Suspend individual threads
- ▶️ Resume individual threads
- ☠️ Kill threads (use with caution!)
- 📋 Copy Thread ID
- Auto-refresh thread list

### Handle View (Right-click → View Handles)
- 🔗 View all handles (files, registry, events, etc.) of a process
- 🔍 Filter handles by type
- ✕ Close handles (use with caution!)
- 📋 Copy Handle value
- Color-coded handle types (File, Registry, Process, Sync, Memory, etc.)

### Keyboard Shortcuts
| Key | Action |
|-----|--------|
| `F5` | Refresh process list |
| `Delete` | Kill selected process |
| `Escape` | Close context menu |

## 🚀 Getting Started

### Prerequisites
- [Rust](https://rustup.rs/) (2021 edition)
- Windows 10/11

### Build & Run

```bash
# Clone the repository
git clone https://github.com/un4ckn0wl3z/dioprocess.git
cd dioprocess

# Build release version
cargo build --release

# Run the application
.\target\release\dioprocess.exe
```

### Development

```bash
# Run in development mode
cargo run

# Build with optimizations
cargo build --release
```

## 📦 Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `dioxus` | 0.6 | Desktop UI framework |
| `tokio` | 1.x | Async runtime for auto-refresh |
| `sysinfo` | 0.31 | CPU/Memory system statistics |
| `windows` | 0.58 | Windows API bindings |

### Windows API Features Used
- `Win32_System_Diagnostics_ToolHelp` - Process enumeration
- `Win32_System_Threading` - Process management
- `Win32_System_ProcessStatus` - Memory information
- `Win32_Foundation` - Core Windows types
- `Win32_Security` - Process access rights

## 📁 Project Structure

This project uses a **Cargo workspace** with two crates:

```
dioprocess/
├── Cargo.toml              # Workspace configuration
├── README.md               # This file
├── LICENSE
└── crates/
    ├── process/            # Library crate - Windows process APIs
    │   ├── Cargo.toml
    │   └── src/
    │       └── lib.rs      # Process enumeration, kill, system stats
    └── dioprocess/         # Binary crate - Desktop application
        ├── Cargo.toml
        └── src/
            ├── main.rs     # Entry point, window configuration
            └── ui.rs       # Dioxus UI components
```

### Crates

| Crate | Type | Description |
|-------|------|-------------|
| `process` | Library | Windows API bindings for process management (sysinfo, windows-rs) |
| `dioprocess` | Binary | Desktop UI application (Dioxus, Tokio) |

## 📄 License

This project is open source and available under the [MIT License](LICENSE).

## 🤝 Contributing

Contributions are welcome! Feel free to:
- Report bugs
- Suggest features
- Submit pull requests



Built with ❤️ using Rust and Dioxus
