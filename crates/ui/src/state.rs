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

/// Sort column options
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum SortColumn {
    Pid,
    Name,
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
