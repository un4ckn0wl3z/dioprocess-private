# Copilot Instructions for DioProcess

## Project Overview
Windows process monitoring & manipulation tool. Rust + Dioxus 0.6 UI, kernel driver for advanced features.

## Code Style
- Snake_case for functions/vars, PascalCase for types
- Unsafe blocks for Windows API calls only
- Error handling: custom error enums (`MiscError`, `CallbackError`)
- No tests - manual UI testing only

## Key Patterns
- **UI State:** Dioxus signals for reactive updates
- **Background tasks:** `tokio::spawn` for async work
- **Driver communication:** DeviceIoControl via callback/misc crates
- **Memory safety:** Always CloseHandle, ObDereferenceObject in kernel code

## Windows API Usage
- Use `windows` crate bindings, `ntapi` for undocumented APIs
- UTF-16 wide strings for all Windows text
- Handle elevated permissions (requireAdministrator manifest)

## Driver Code (C++ WDM)
- PatchGuard safe: modify per-process structures only
- Version-aware offsets: `PROCESS_*_OFFSET[]` arrays
- Exception handling: `__try/__except` for kernel memory access
- Always dereference objects: `ObDereferenceObject`

## Feature Areas
- **process crate:** ToolHelp32, threads, handles, modules, memory
- **misc crate:** Injection (7 DLL methods, 3 shellcode methods, 2 kernel methods), process creation (7 techniques), hooking, token theft
- **callback crate:** Driver IOCTLs for protection/privileges/events, SQLite storage
- **ui crate:** Dioxus components, signals, modals, context menus

## Important
- No backwards-compatibility hacks
- Over-engineering is not helpful
- Security research focus: red team, malware analysis, OS internals
