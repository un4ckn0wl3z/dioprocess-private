//! State types and enums for the UI

use dioxus::prelude::*;
use std::sync::atomic::{AtomicBool, Ordering};

/// Debug mode flag — set via `-debug` CLI flag, enables local file install for EFI
static DEBUG_MODE: AtomicBool = AtomicBool::new(false);

/// All driver methods flag — set via `-alldrv` CLI flag, enables KDU/KDMapper install methods
static ALLDRV_MODE: AtomicBool = AtomicBool::new(false);

pub fn set_debug_mode(enabled: bool) {
    DEBUG_MODE.store(enabled, Ordering::Relaxed);
}

pub fn is_debug_mode() -> bool {
    DEBUG_MODE.load(Ordering::Relaxed)
}

pub fn set_alldrv_mode(enabled: bool) {
    ALLDRV_MODE.store(enabled, Ordering::Relaxed);
}

pub fn is_alldrv_mode() -> bool {
    ALLDRV_MODE.load(Ordering::Relaxed)
}

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

// ============================================================================
// Physical Memory Tab State - persist across tab switches
// ============================================================================

pub static PHYS_MEM_PID: GlobalSignal<String> = Signal::global(|| String::new());
pub static PHYS_MEM_VA: GlobalSignal<String> = Signal::global(|| String::new());
pub static PHYS_MEM_WALK_RESULT: GlobalSignal<Option<callback::PageTableWalkResult>> =
    Signal::global(|| None);
pub static PHYS_MEM_PAGE_DATA: GlobalSignal<Vec<u8>> = Signal::global(Vec::new);
pub static PHYS_MEM_PAGE_BASE: GlobalSignal<u64> = Signal::global(|| 0);
pub static PHYS_MEM_READ_MODE: GlobalSignal<String> = Signal::global(|| "full".to_string());
pub static PHYS_MEM_EXACT_PA: GlobalSignal<u64> = Signal::global(|| 0);
pub static PHYS_MEM_WRITE_OFFSET: GlobalSignal<String> = Signal::global(|| String::new());
pub static PHYS_MEM_WRITE_VALUE: GlobalSignal<String> = Signal::global(|| String::new());
pub static PHYS_MEM_WRITE_TYPE: GlobalSignal<String> = Signal::global(|| "hex".to_string());
pub static PHYS_MEM_STATUS: GlobalSignal<String> = Signal::global(|| String::new());
pub static PHYS_MEM_IS_ERROR: GlobalSignal<bool> = Signal::global(|| false);
pub static PHYS_MEM_HEX_PAGE: GlobalSignal<usize> = Signal::global(|| 0);

// ============================================================================
// Memory Scanner Tab State - persist across tab switches
// ============================================================================

pub static SCANNER_PID: GlobalSignal<String> = Signal::global(|| String::new());
pub static SCANNER_VALUE: GlobalSignal<String> = Signal::global(|| String::new());
pub static SCANNER_VALUE2: GlobalSignal<String> = Signal::global(|| String::new());
pub static SCANNER_DATA_TYPE_IDX: GlobalSignal<usize> = Signal::global(|| 4);
pub static SCANNER_SCAN_TYPE_IDX: GlobalSignal<usize> = Signal::global(|| 0);
pub static SCANNER_RESULTS: GlobalSignal<Vec<callback::ScanResult>> = Signal::global(Vec::new);
pub static SCANNER_HAS_SCANNED: GlobalSignal<bool> = Signal::global(|| false);
pub static SCANNER_IS_SCANNING: GlobalSignal<bool> = Signal::global(|| false);
pub static SCANNER_STATUS: GlobalSignal<String> = Signal::global(|| String::new());
pub static SCANNER_IS_ERROR: GlobalSignal<bool> = Signal::global(|| false);
pub static SCANNER_PAGE: GlobalSignal<usize> = Signal::global(|| 0);
pub static SCANNER_SELECTED: GlobalSignal<Option<usize>> = Signal::global(|| None);
pub static SCANNER_WRITE_VALUE: GlobalSignal<String> = Signal::global(|| String::new());
pub static SCANNER_EDITING_IDX: GlobalSignal<Option<usize>> = Signal::global(|| None);
pub static SCANNER_EDIT_VALUE: GlobalSignal<String> = Signal::global(|| String::new());

// EPT Hook state
pub static EPT_HOOK_BYTES_INPUT: GlobalSignal<String> = Signal::global(|| String::new());
pub static EPT_HOOK_TARGET_ADDR: GlobalSignal<Option<u64>> = Signal::global(|| None);
pub static EPT_HOOK_SHOW_MODAL: GlobalSignal<bool> = Signal::global(|| false);
pub static EPT_HOOKS_LIST: GlobalSignal<Vec<callback::EptHookInfo>> = Signal::global(Vec::new);
pub static EPT_HOOK_STATUS: GlobalSignal<String> = Signal::global(|| String::new());
pub static EPT_HOOK_IS_ERROR: GlobalSignal<bool> = Signal::global(|| false);

// EPT Hook Assembly mode state
/// Input mode for EPT hook: Hex bytes or Assembly code
#[derive(Clone, Copy, PartialEq, Debug, Default)]
pub enum EptHookInputMode {
    #[default]
    Hex,
    Assembly,
    Detour,
}

pub static EPT_HOOK_INPUT_MODE: GlobalSignal<EptHookInputMode> = Signal::global(|| EptHookInputMode::Hex);
pub static EPT_HOOK_ASM_INPUT: GlobalSignal<String> = Signal::global(|| String::new());
pub static EPT_HOOK_ASM_PREVIEW: GlobalSignal<String> = Signal::global(|| String::new());
pub static EPT_HOOK_ASM_ERROR: GlobalSignal<String> = Signal::global(|| String::new());

// EPT Hook Detour mode state
pub static EPT_HOOK_DETOUR_ASM_INPUT: GlobalSignal<String> = Signal::global(|| String::new());
pub static EPT_HOOK_DETOUR_ASM_PREVIEW: GlobalSignal<String> = Signal::global(|| String::new());
pub static EPT_HOOK_DETOUR_ASM_ERROR: GlobalSignal<String> = Signal::global(|| String::new());
pub static EPT_HOOK_DETOUR_STOLEN_BYTES: GlobalSignal<String> = Signal::global(|| "6".to_string());
/// Tracks detour memory allocations for cleanup: hook_index -> (pid, allocated_address)
pub static EPT_HOOK_DETOUR_ALLOCS: GlobalSignal<std::collections::HashMap<u32, (u32, u64)>> =
    Signal::global(std::collections::HashMap::new);

// DPH Script state
/// A loaded .dph (DioProcess Hook) script entry
#[derive(Clone, Debug)]
pub struct DphScript {
    pub name: String,
    pub file_path: String,
    pub target_expr: String,      // "module+offset" or "0xABCD"
    pub resolved_addr: Option<u64>,
    pub mode: EptHookInputMode,
    pub stolen_bytes: u32,
    pub code: String,
    pub hook_index: Option<u32>,  // Set after applied
    pub status: String,           // "Applied", "Error: ...", "Pending"
}

pub static DPH_SCRIPTS: GlobalSignal<Vec<DphScript>> = Signal::global(Vec::new);
pub static DPH_SHOW_SCRIPTS_TAB: GlobalSignal<bool> = Signal::global(|| false);

// DPR Script state
/// A loaded .dpr (DioProcess Register) script entry
#[derive(Clone, Debug)]
pub struct DprScript {
    pub name: String,
    pub file_path: String,
    pub target_expr: String,        // "module+offset" or "0xABCD"
    pub resolved_addr: Option<u64>,
    pub register: String,           // "ZF", "RAX", etc.
    pub reg_index: u32,             // 0-21
    pub value_expr: String,         // "set", "clear", "0x1234"
    pub new_value: u64,             // Resolved numeric value
    pub entry_index: Option<u32>,   // Set after hook installed
    pub status: String,             // "Pending" / "Applied" / "Error: ..."
}

pub static DPR_SCRIPTS: GlobalSignal<Vec<DprScript>> = Signal::global(Vec::new);

// Register Change hook state
pub static REG_CHANGE_SHOW_MODAL: GlobalSignal<bool> = Signal::global(|| false);
pub static REG_CHANGE_TARGET_ADDR: GlobalSignal<Option<u64>> = Signal::global(|| None);
pub static REG_CHANGE_LIST: GlobalSignal<Vec<callback::RegChangeInfo>> = Signal::global(Vec::new);
pub static REG_CHANGE_STATUS: GlobalSignal<String> = Signal::global(|| String::new());
pub static REG_CHANGE_IS_ERROR: GlobalSignal<bool> = Signal::global(|| false);

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
