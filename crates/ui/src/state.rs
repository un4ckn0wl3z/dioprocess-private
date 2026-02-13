//! State types and enums for the UI

use dioxus::prelude::*;

/// Thread window state - stores PID and process name to open in new window
pub static THREAD_WINDOW_STATE: GlobalSignal<Option<(u32, String)>> = Signal::global(|| None);

/// Handle window state - stores PID and process name to open in new window
pub static HANDLE_WINDOW_STATE: GlobalSignal<Option<(u32, String)>> = Signal::global(|| None);

/// Module window state - stores PID and process name to open in new window
pub static MODULE_WINDOW_STATE: GlobalSignal<Option<(u32, String)>> = Signal::global(|| None);

/// Memory window state - stores PID and process name to open in new window
pub static MEMORY_WINDOW_STATE: GlobalSignal<Option<(u32, String)>> = Signal::global(|| None);

/// Graph window state - stores PID and process name to open in new window
pub static GRAPH_WINDOW_STATE: GlobalSignal<Option<(u32, String)>> = Signal::global(|| None);

/// Create process window state - controls visibility of create process modal
pub static CREATE_PROCESS_WINDOW_STATE: GlobalSignal<bool> = Signal::global(|| false);

/// Token thief window state - stores PID and process name to open token thief modal
pub static TOKEN_THIEF_WINDOW_STATE: GlobalSignal<Option<(u32, String)>> = Signal::global(|| None);

/// Function stomping window state - stores PID and process name to open function stomping modal
pub static FUNCTION_STOMPING_WINDOW_STATE: GlobalSignal<Option<(u32, String)>> =
    Signal::global(|| None);

/// Hook Scan window state - stores PID and process name to open hook scan modal
pub static HOOK_SCAN_WINDOW_STATE: GlobalSignal<Option<(u32, String)>> =
    Signal::global(|| None);

/// String Scan window state - stores PID and process name to open string scan modal
pub static STRING_SCAN_WINDOW_STATE: GlobalSignal<Option<(u32, String)>> =
    Signal::global(|| None);

/// Shellcode inject window state (web staging) - stores PID and process name
pub static SHELLCODE_INJECT_WINDOW_STATE: GlobalSignal<Option<(u32, String)>> =
    Signal::global(|| None);

/// Threadless inject window state - stores PID and process name
pub static THREADLESS_INJECT_WINDOW_STATE: GlobalSignal<Option<(u32, String)>> =
    Signal::global(|| None);

/// Ghost process window state - controls visibility of ghost process modal
pub static GHOST_PROCESS_WINDOW_STATE: GlobalSignal<bool> = Signal::global(|| false);

/// Early injection window state - controls visibility of early injection modal
pub static EARLY_INJECTION_WINDOW_STATE: GlobalSignal<bool> = Signal::global(|| false);

// ============================================================================
// Tab Search Query Signals - persist search text across tab switches
// ============================================================================

/// Process tab search query
pub static PROCESS_SEARCH_QUERY: GlobalSignal<String> = Signal::global(|| String::new());

/// Network tab search query
pub static NETWORK_SEARCH_QUERY: GlobalSignal<String> = Signal::global(|| String::new());

/// Service tab search query
pub static SERVICE_SEARCH_QUERY: GlobalSignal<String> = Signal::global(|| String::new());

/// System Events (callback) tab search query
pub static CALLBACK_SEARCH_QUERY: GlobalSignal<String> = Signal::global(|| String::new());

/// PspCidTable tab search query
pub static PSPCIDTABLE_SEARCH_QUERY: GlobalSignal<String> = Signal::global(|| String::new());

/// Callback enumeration tab search query
pub static CALLBACK_ENUM_SEARCH_QUERY: GlobalSignal<String> = Signal::global(|| String::new());

/// Minifilters tab search query
pub static MINIFILTERS_SEARCH_QUERY: GlobalSignal<String> = Signal::global(|| String::new());

/// Drivers tab search query
pub static DRIVERS_SEARCH_QUERY: GlobalSignal<String> = Signal::global(|| String::new());

/// Process view mode - flat list or tree hierarchy
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum ProcessViewMode {
    Flat,
    Tree,
}

/// Sort column options
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum SortColumn {
    Pid,
    Name,
    Arch,
    Memory,
    Threads,
    Cpu,
}

/// Sort order options
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum SortOrder {
    Ascending,
    Descending,
}

/// Context menu state for main process list
#[derive(Clone, Debug, Default)]
pub struct ContextMenuState {
    pub visible: bool,
    pub x: i32,
    pub y: i32,
    pub pid: Option<u32>,
    pub exe_path: String,
}

/// Thread context menu state
#[derive(Clone, Debug, Default)]
pub struct ThreadContextMenuState {
    pub visible: bool,
    pub x: i32,
    pub y: i32,
    pub thread_id: Option<u32>,
}

/// Handle context menu state
#[derive(Clone, Debug, Default)]
pub struct HandleContextMenuState {
    pub visible: bool,
    pub x: i32,
    pub y: i32,
    pub handle_value: Option<u16>,
}

/// Module context menu state
#[derive(Clone, Debug, Default)]
pub struct ModuleContextMenuState {
    pub visible: bool,
    pub x: i32,
    pub y: i32,
    pub module_base: Option<usize>,
    pub module_path: String,
}

/// Memory context menu state
#[derive(Clone, Debug, Default)]
pub struct MemoryContextMenuState {
    pub visible: bool,
    pub x: i32,
    pub y: i32,
    pub base_address: usize,
    pub allocation_base: usize,
    pub region_size: usize,
    pub state: u32,
}
