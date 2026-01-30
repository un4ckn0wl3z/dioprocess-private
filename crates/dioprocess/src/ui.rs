//! UI module for Process Monitor
//! Contains Dioxus components with custom CSS (offline)

use dioxus::prelude::*;
use process::{ProcessInfo, get_processes, get_system_stats, kill_process, open_file_location, format_uptime, suspend_process, resume_process};
use arboard::Clipboard;

/// Helper function to copy text to clipboard
fn copy_to_clipboard(text: &str) -> bool {
    if let Ok(mut clipboard) = Clipboard::new() {
        clipboard.set_text(text).is_ok()
    } else {
        false
    }
}

// Thread window state - stores PID and process name to open in new window
static THREAD_WINDOW_STATE: GlobalSignal<Option<(u32, String)>> = Signal::global(|| None);
// Handle window state - stores PID and process name to open in new window
static HANDLE_WINDOW_STATE: GlobalSignal<Option<(u32, String)>> = Signal::global(|| None);

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

/// Context menu state
#[derive(Clone, Debug, Default)]
pub struct ContextMenuState {
    pub visible: bool,
    pub x: i32,
    pub y: i32,
    pub pid: Option<u32>,
    pub exe_path: String,
}

/// Process row component
#[component]
pub fn ProcessRow(
    process: ProcessInfo,
    is_selected: bool,
    max_memory: f64,
    on_select: EventHandler<u32>,
    on_context_menu: EventHandler<(i32, i32, u32, String)>,
) -> Element {
    let memory_percent = if max_memory > 0.0 { 
        process.memory_mb / max_memory * 100.0 
    } else { 
        0.0 
    };
    let pid = process.pid;
    let exe_path = process.exe_path.clone();
    let exe_path_for_context = process.exe_path.clone();
    let exe_filename = process.exe_path.split('\\').last().unwrap_or(&process.exe_path).to_string();
    
    // CPU usage color based on value
    let cpu_class = if process.cpu_usage > 50.0 {
        "cpu-high"
    } else if process.cpu_usage > 25.0 {
        "cpu-medium"
    } else {
        "cpu-low"
    };
    
    let row_class = if is_selected {
        "process-row selected"
    } else {
        "process-row"
    };

    rsx! {
        tr { 
            key: "{process.pid}",
            class: "{row_class}",
            onclick: move |_| on_select.call(pid),
            oncontextmenu: move |e| {
                e.prevent_default();
                let coords = e.client_coordinates();
                on_context_menu.call((coords.x as i32, coords.y as i32, pid, exe_path_for_context.clone()));
            },
            td { class: "cell cell-pid", "{process.pid}" }
            td { class: "cell cell-name", "{process.name}" }
            td { class: "cell cell-cpu {cpu_class}", "{process.cpu_usage:.1}%" }
            td { class: "cell cell-threads", "{process.thread_count}" }
            td { class: "cell cell-memory",
                div { class: "memory-bar-container",
                    div { class: "memory-bar-bg",
                        div { 
                            class: "memory-bar-fill",
                            style: "width: {memory_percent}%",
                        }
                    }
                    span { class: "memory-text", "{process.memory_mb:.1} MB" }
                }
            }
            td { class: "cell cell-path", title: "{exe_path}", "{exe_filename}" }
        }
    }
}

/// Main application component
#[component]
pub fn App() -> Element {
    let mut processes = use_signal(|| get_processes());
    let mut system_stats = use_signal(|| get_system_stats());
    let mut search_query = use_signal(|| String::new());
    let mut sort_column = use_signal(|| SortColumn::Memory);
    let mut sort_order = use_signal(|| SortOrder::Descending);
    let mut auto_refresh = use_signal(|| true);
    let mut selected_pid = use_signal(|| None::<u32>);
    let mut status_message = use_signal(|| String::new());
    let mut context_menu = use_signal(|| ContextMenuState::default());

    // Auto-refresh every 3 seconds
    use_future(move || async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            if *auto_refresh.read() {
                processes.set(get_processes());
                system_stats.set(get_system_stats());
            }
        }
    });

    // Keyboard shortcuts handler
    let handle_keydown = move |e: KeyboardEvent| {
        // Close context menu on Escape
        if e.key() == Key::Escape {
            context_menu.set(ContextMenuState::default());
            return;
        }
        
        // F5 = Refresh
        if e.key() == Key::F5 {
            processes.set(get_processes());
            system_stats.set(get_system_stats());
            return;
        }
        
        // Delete = Kill selected process
        if e.key() == Key::Delete {
            let pid_to_kill = *selected_pid.read();
            if let Some(pid) = pid_to_kill {
                if kill_process(pid) {
                    status_message.set(format!("✓ Process {} terminated", pid));
                    processes.set(get_processes());
                    selected_pid.set(None);
                } else {
                    status_message.set(format!("✗ Failed to terminate process {}", pid));
                }
                spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                    status_message.set(String::new());
                });
            }
        }
    };

    // Find max memory for percentage calculation
    let max_memory = processes.read().iter().map(|p| p.memory_mb).fold(0.0_f64, |a, b| a.max(b));

    // Filter and sort processes
    let mut filtered_processes: Vec<ProcessInfo> = processes
        .read()
        .iter()
        .filter(|p| {
            let query = search_query.read().to_lowercase();
            if query.is_empty() {
                true
            } else {
                p.name.to_lowercase().contains(&query) 
                    || p.pid.to_string().contains(&query)
                    || p.exe_path.to_lowercase().contains(&query)
            }
        })
        .cloned()
        .collect();

    // Sort based on selected column
    filtered_processes.sort_by(|a, b| {
        let cmp = match *sort_column.read() {
            SortColumn::Pid => a.pid.cmp(&b.pid),
            SortColumn::Name => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
            SortColumn::Memory => a.memory_mb.partial_cmp(&b.memory_mb).unwrap_or(std::cmp::Ordering::Equal),
            SortColumn::Threads => a.thread_count.cmp(&b.thread_count),
            SortColumn::Cpu => a.cpu_usage.partial_cmp(&b.cpu_usage).unwrap_or(std::cmp::Ordering::Equal),
        };
        match *sort_order.read() {
            SortOrder::Ascending => cmp,
            SortOrder::Descending => cmp.reverse(),
        }
    });

    let process_count = filtered_processes.len();
    let total_memory: f64 = filtered_processes.iter().map(|p| p.memory_mb).sum();
    
    // Get system stats
    let stats = system_stats.read().clone();

    // Get current sort state for display
    let current_sort_col = *sort_column.read();
    let current_sort_ord = *sort_order.read();
    
    // Context menu state
    let ctx_menu = context_menu.read().clone();

    // Get sort indicator
    let sort_indicator = |column: SortColumn| -> &'static str {
        if current_sort_col == column {
            match current_sort_ord {
                SortOrder::Ascending => " ▲",
                SortOrder::Descending => " ▼",
            }
        } else {
            ""
        }
    };

    rsx! {
        style { {CUSTOM_STYLES} }

        // Main container with keyboard handler
        div {
            tabindex: "0",
            onkeydown: handle_keydown,
            onclick: move |_| context_menu.set(ContextMenuState::default()),
            class: "main-container",

            // Custom title bar for borderless window
            div { class: "title-bar",
                div { 
                    class: "title-bar-drag",
                    onmousedown: move |_| {
                        let window = dioxus::desktop::window();
                        let _ = window.drag_window();
                    },
                    span { class: "title-text", "🖥️ Process Monitor" }
                }
                div { class: "title-bar-buttons",
                    button {
                        class: "title-btn",
                        onclick: move |_| {
                            let window = dioxus::desktop::window();
                            window.set_minimized(true);
                        },
                        "─"
                    }
                    button {
                        class: "title-btn",
                        onclick: move |_| {
                            let window = dioxus::desktop::window();
                            window.set_maximized(!window.is_maximized());
                        },
                        "□"
                    }
                    button {
                        class: "title-btn title-btn-close",
                        onclick: move |_| {
                            let window = dioxus::desktop::window();
                            window.close();
                        },
                        "✕"
                    }
                }
            }

            // System Stats Bar
            div { class: "stats-bar",
                // CPU Usage
                div { class: "stat-item",
                    span { class: "stat-label", "CPU" }
                    div { class: "stat-bar",
                        div { 
                            class: "stat-bar-fill stat-bar-cpu",
                            style: "width: {stats.cpu_usage}%",
                        }
                    }
                    span { class: "stat-value stat-value-cyan", "{stats.cpu_usage:.1}%" }
                }
                
                // Memory Usage
                div { class: "stat-item",
                    span { class: "stat-label", "RAM" }
                    div { class: "stat-bar",
                        div { 
                            class: "stat-bar-fill stat-bar-ram",
                            style: "width: {stats.memory_percent}%",
                        }
                    }
                    span { class: "stat-value stat-value-purple", "{stats.used_memory_gb:.1}/{stats.total_memory_gb:.1} GB" }
                }
                
                // Uptime
                div { class: "stat-item",
                    span { class: "stat-label", "Uptime" }
                    span { class: "stat-value stat-value-green", "{format_uptime(stats.uptime_seconds)}" }
                }
                
                // Process count
                div { class: "stat-item stat-item-right",
                    span { class: "stat-label", "Total Processes" }
                    span { class: "stat-value stat-value-yellow", "{stats.process_count}" }
                }
            }

            div { class: "content-area",
                // Header
                div { class: "header-box",
                    h1 { class: "header-title", "🖥️ Windows Process Monitor" }
                    div { class: "header-stats",
                        span { "Showing: {process_count} processes" }
                        span { "Memory: {total_memory:.1} MB" }
                        span { class: "header-shortcuts", "F5: Refresh | Del: Kill | Esc: Close menu" }
                    }
                    if !status_message.read().is_empty() {
                        div { class: "status-message", "{status_message}" }
                    }
                }

                // Controls
                div { class: "controls",
                    input {
                        class: "search-input",
                        r#type: "text",
                        placeholder: "Search by name, PID, or path... (Ctrl+F)",
                        value: "{search_query}",
                        oninput: move |e| search_query.set(e.value().clone()),
                    }
                    
                    label { class: "checkbox-label",
                        input {
                            r#type: "checkbox",
                            class: "checkbox",
                            checked: *auto_refresh.read(),
                            onchange: move |e| auto_refresh.set(e.checked()),
                        }
                        span { "Auto-refresh" }
                    }

                    button {
                        class: "btn btn-primary",
                        onclick: move |_| {
                            processes.set(get_processes());
                            system_stats.set(get_system_stats());
                        },
                        "🔄 Refresh"
                    }

                    button {
                        class: "btn btn-danger",
                        disabled: selected_pid.read().is_none(),
                        onclick: move |_| {
                            let pid_to_kill = *selected_pid.read();
                            if let Some(pid) = pid_to_kill {
                                if kill_process(pid) {
                                    status_message.set(format!("✓ Process {} terminated", pid));
                                    processes.set(get_processes());
                                    selected_pid.set(None);
                                } else {
                                    status_message.set(format!("✗ Failed to terminate process {} (access denied?)", pid));
                                }
                                spawn(async move {
                                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                                    status_message.set(String::new());
                                });
                            }
                        },
                        "☠️ Kill Process"
                    }
                }

                // Process table
                div { class: "table-container",
                    table { class: "process-table",
                        thead { class: "table-header",
                            tr {
                                th { 
                                    class: "th sortable",
                                    onclick: move |_| {
                                        if *sort_column.read() == SortColumn::Pid {
                                            let new_order = if *sort_order.read() == SortOrder::Ascending { SortOrder::Descending } else { SortOrder::Ascending };
                                            sort_order.set(new_order);
                                        } else {
                                            sort_column.set(SortColumn::Pid);
                                            sort_order.set(SortOrder::Descending);
                                        }
                                    },
                                    "PID{sort_indicator(SortColumn::Pid)}" 
                                }
                                th { 
                                    class: "th sortable",
                                    onclick: move |_| {
                                        if *sort_column.read() == SortColumn::Name {
                                            let new_order = if *sort_order.read() == SortOrder::Ascending { SortOrder::Descending } else { SortOrder::Ascending };
                                            sort_order.set(new_order);
                                        } else {
                                            sort_column.set(SortColumn::Name);
                                            sort_order.set(SortOrder::Descending);
                                        }
                                    },
                                    "Name{sort_indicator(SortColumn::Name)}" 
                                }
                                th { 
                                    class: "th sortable",
                                    onclick: move |_| {
                                        if *sort_column.read() == SortColumn::Cpu {
                                            let new_order = if *sort_order.read() == SortOrder::Ascending { SortOrder::Descending } else { SortOrder::Ascending };
                                            sort_order.set(new_order);
                                        } else {
                                            sort_column.set(SortColumn::Cpu);
                                            sort_order.set(SortOrder::Descending);
                                        }
                                    },
                                    "CPU{sort_indicator(SortColumn::Cpu)}" 
                                }
                                th { 
                                    class: "th sortable",
                                    onclick: move |_| {
                                        if *sort_column.read() == SortColumn::Threads {
                                            let new_order = if *sort_order.read() == SortOrder::Ascending { SortOrder::Descending } else { SortOrder::Ascending };
                                            sort_order.set(new_order);
                                        } else {
                                            sort_column.set(SortColumn::Threads);
                                            sort_order.set(SortOrder::Descending);
                                        }
                                    },
                                    "Threads{sort_indicator(SortColumn::Threads)}" 
                                }
                                th { 
                                    class: "th sortable",
                                    onclick: move |_| {
                                        if *sort_column.read() == SortColumn::Memory {
                                            let new_order = if *sort_order.read() == SortOrder::Ascending { SortOrder::Descending } else { SortOrder::Ascending };
                                            sort_order.set(new_order);
                                        } else {
                                            sort_column.set(SortColumn::Memory);
                                            sort_order.set(SortOrder::Descending);
                                        }
                                    },
                                    "Memory{sort_indicator(SortColumn::Memory)}" 
                                }
                                th { class: "th", "Path" }
                            }
                        }
                        tbody {
                            for process in filtered_processes {
                                ProcessRow { 
                                    process: process.clone(),
                                    is_selected: *selected_pid.read() == Some(process.pid),
                                    max_memory: max_memory,
                                    on_select: move |pid: u32| {
                                        let current = *selected_pid.read();
                                        if current == Some(pid) {
                                            selected_pid.set(None);
                                        } else {
                                            selected_pid.set(Some(pid));
                                        }
                                    },
                                    on_context_menu: move |(x, y, pid, path): (i32, i32, u32, String)| {
                                        selected_pid.set(Some(pid));
                                        context_menu.set(ContextMenuState {
                                            visible: true,
                                            x,
                                            y,
                                            pid: Some(pid),
                                            exe_path: path,
                                        });
                                    },
                                }
                            }
                        }
                    }
                }
            }

            // Context Menu
            if ctx_menu.visible {
                div {
                    class: "context-menu",
                    style: "left: {ctx_menu.x}px; top: {ctx_menu.y}px;",
                    onclick: move |e| e.stop_propagation(),
                    
                    // Kill Process
                    button {
                        class: "context-menu-item context-menu-item-danger",
                        onclick: move |_| {
                            if let Some(pid) = ctx_menu.pid {
                                if kill_process(pid) {
                                    status_message.set(format!("✓ Process {} terminated", pid));
                                    processes.set(get_processes());
                                    selected_pid.set(None);
                                } else {
                                    status_message.set(format!("✗ Failed to terminate process {}", pid));
                                }
                                spawn(async move {
                                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                                    status_message.set(String::new());
                                });
                            }
                            context_menu.set(ContextMenuState::default());
                        },
                        span { "☠️" }
                        span { "Kill Process" }
                    }
                    
                    // Suspend Process
                    button {
                        class: "context-menu-item context-menu-item-warning",
                        onclick: move |_| {
                            if let Some(pid) = ctx_menu.pid {
                                if suspend_process(pid) {
                                    status_message.set(format!("⏸️ Process {} suspended", pid));
                                } else {
                                    status_message.set(format!("✗ Failed to suspend process {}", pid));
                                }
                                spawn(async move {
                                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                                    status_message.set(String::new());
                                });
                            }
                            context_menu.set(ContextMenuState::default());
                        },
                        span { "⏸️" }
                        span { "Suspend Process" }
                    }
                    
                    // Resume Process
                    button {
                        class: "context-menu-item context-menu-item-success",
                        onclick: move |_| {
                            if let Some(pid) = ctx_menu.pid {
                                if resume_process(pid) {
                                    status_message.set(format!("▶️ Process {} resumed", pid));
                                } else {
                                    status_message.set(format!("✗ Failed to resume process {}", pid));
                                }
                                spawn(async move {
                                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                                    status_message.set(String::new());
                                });
                            }
                            context_menu.set(ContextMenuState::default());
                        },
                        span { "▶️" }
                        span { "Resume Process" }
                    }
                    
                    // Separator
                    div { class: "context-menu-separator" }
                    
                    // Open File Location
                    button {
                        class: "context-menu-item",
                        disabled: ctx_menu.exe_path.is_empty(),
                        onclick: {
                            let path = ctx_menu.exe_path.clone();
                            move |_| {
                                open_file_location(&path);
                                context_menu.set(ContextMenuState::default());
                            }
                        },
                        span { "📂" }
                        span { "Open File Location" }
                    }
                    
                    // Copy PID
                    button {
                        class: "context-menu-item",
                        onclick: move |_| {
                            if let Some(pid) = ctx_menu.pid {
                                copy_to_clipboard(&pid.to_string());
                                status_message.set(format!("📋 PID {} copied to clipboard", pid));
                                spawn(async move {
                                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                                    status_message.set(String::new());
                                });
                            }
                            context_menu.set(ContextMenuState::default());
                        },
                        span { "📋" }
                        span { "Copy PID" }
                    }
                    
                    // Copy Path
                    button {
                        class: "context-menu-item",
                        disabled: ctx_menu.exe_path.is_empty(),
                        onclick: {
                            let path = ctx_menu.exe_path.clone();
                            move |_| {
                                copy_to_clipboard(&path);
                                status_message.set("📋 Path copied to clipboard".to_string());
                                spawn(async move {
                                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                                    status_message.set(String::new());
                                });
                                context_menu.set(ContextMenuState::default());
                            }
                        },
                        span { "📝" }
                        span { "Copy Path" }
                    }
                    
                    // Separator
                    div { class: "context-menu-separator" }
                    
                    // View Threads
                    button {
                        class: "context-menu-item",
                        onclick: move |_| {
                            if let Some(pid) = ctx_menu.pid {
                                // Find process name
                                let proc_name = processes.read()
                                    .iter()
                                    .find(|p| p.pid == pid)
                                    .map(|p| p.name.clone())
                                    .unwrap_or_else(|| format!("PID {}", pid));
                                *THREAD_WINDOW_STATE.write() = Some((pid, proc_name));
                            }
                            context_menu.set(ContextMenuState::default());
                        },
                        span { "🧵" }
                        span { "View Threads" }
                    }
                    
                    // View Handles
                    button {
                        class: "context-menu-item",
                        onclick: move |_| {
                            if let Some(pid) = ctx_menu.pid {
                                // Find process name
                                let proc_name = processes.read()
                                    .iter()
                                    .find(|p| p.pid == pid)
                                    .map(|p| p.name.clone())
                                    .unwrap_or_else(|| format!("PID {}", pid));
                                *HANDLE_WINDOW_STATE.write() = Some((pid, proc_name));
                            }
                            context_menu.set(ContextMenuState::default());
                        },
                        span { "🔗" }
                        span { "View Handles" }
                    }
                    
                    // Separator
                    div { class: "context-menu-separator" }
                    
                    // Refresh
                    button {
                        class: "context-menu-item",
                        onclick: move |_| {
                            processes.set(get_processes());
                            system_stats.set(get_system_stats());
                            context_menu.set(ContextMenuState::default());
                        },
                        span { "🔄" }
                        span { "Refresh List" }
                    }
                }
            }
            
            // Thread Window Modal
            if let Some((pid, proc_name)) = THREAD_WINDOW_STATE.read().clone() {
                ThreadWindow { pid: pid, process_name: proc_name }
            }
            
            // Handle Window Modal
            if let Some((pid, proc_name)) = HANDLE_WINDOW_STATE.read().clone() {
                HandleWindow { pid: pid, process_name: proc_name }
            }
        }
    }
}

/// Thread context menu state
#[derive(Clone, Debug, Default)]
pub struct ThreadContextMenuState {
    pub visible: bool,
    pub x: i32,
    pub y: i32,
    pub thread_id: Option<u32>,
}

/// Thread Window component
#[component]
pub fn ThreadWindow(pid: u32, process_name: String) -> Element {
    use process::{get_process_threads, suspend_thread, resume_thread, kill_thread, get_priority_name, ThreadInfo};
    
    let mut threads = use_signal(|| get_process_threads(pid));
    let mut selected_thread = use_signal(|| None::<u32>);
    let mut context_menu = use_signal(|| ThreadContextMenuState::default());
    let mut status_message = use_signal(|| String::new());
    let mut auto_refresh = use_signal(|| true);
    
    // Auto-refresh every 2 seconds
    use_future(move || async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            if *auto_refresh.read() {
                threads.set(get_process_threads(pid));
            }
        }
    });
    
    let ctx_menu = context_menu.read().clone();
    let thread_list: Vec<ThreadInfo> = threads.read().clone();
    let thread_count = thread_list.len();
    
    rsx! {
        // Modal overlay
        div {
            class: "thread-modal-overlay",
            onclick: move |_| {
                *THREAD_WINDOW_STATE.write() = None;
            },
            
            // Modal window
            div {
                class: "thread-modal",
                onclick: move |e| e.stop_propagation(),
                
                // Header
                div {
                    class: "thread-modal-header",
                    div {
                        class: "thread-modal-title",
                        "🧵 Threads - {process_name} (PID: {pid})"
                    }
                    button {
                        class: "thread-modal-close",
                        onclick: move |_| {
                            *THREAD_WINDOW_STATE.write() = None;
                        },
                        "✕"
                    }
                }
                
                // Controls
                div {
                    class: "thread-controls",
                    span { class: "thread-count", "Threads: {thread_count}" }
                    
                    label { class: "checkbox-label",
                        input {
                            r#type: "checkbox",
                            class: "checkbox",
                            checked: *auto_refresh.read(),
                            onchange: move |e| auto_refresh.set(e.checked()),
                        }
                        span { "Auto-refresh" }
                    }
                    
                    button {
                        class: "btn btn-small btn-primary",
                        onclick: move |_| {
                            threads.set(get_process_threads(pid));
                        },
                        "🔄 Refresh"
                    }
                }
                
                // Status message
                if !status_message.read().is_empty() {
                    div { class: "thread-status-message", "{status_message}" }
                }
                
                // Thread table
                div {
                    class: "thread-table-container",
                    table {
                        class: "thread-table",
                        thead {
                            tr {
                                th { class: "th", "Thread ID" }
                                th { class: "th", "Base Priority" }
                                th { class: "th", "Priority" }
                                th { class: "th", "Actions" }
                            }
                        }
                        tbody {
                            for thread in thread_list {
                                {
                                    let tid = thread.thread_id;
                                    let is_selected = *selected_thread.read() == Some(tid);
                                    let row_class = if is_selected { "thread-row selected" } else { "thread-row" };
                                    
                                    rsx! {
                                        tr {
                                            key: "{tid}",
                                            class: "{row_class}",
                                            onclick: move |_| {
                                                let current = *selected_thread.read();
                                                if current == Some(tid) {
                                                    selected_thread.set(None);
                                                } else {
                                                    selected_thread.set(Some(tid));
                                                }
                                            },
                                            oncontextmenu: move |e| {
                                                e.prevent_default();
                                                let coords = e.client_coordinates();
                                                selected_thread.set(Some(tid));
                                                context_menu.set(ThreadContextMenuState {
                                                    visible: true,
                                                    x: coords.x as i32,
                                                    y: coords.y as i32,
                                                    thread_id: Some(tid),
                                                });
                                            },
                                            td { class: "cell cell-tid", "{thread.thread_id}" }
                                            td { class: "cell", "{thread.base_priority}" }
                                            td { class: "cell", "{get_priority_name(thread.priority)}" }
                                            td { class: "cell cell-actions",
                                                button {
                                                    class: "action-btn action-btn-warning",
                                                    title: "Suspend Thread",
                                                    onclick: move |e| {
                                                        e.stop_propagation();
                                                        if suspend_thread(tid) {
                                                            status_message.set(format!("⏸️ Thread {} suspended", tid));
                                                        } else {
                                                            status_message.set(format!("✗ Failed to suspend thread {}", tid));
                                                        }
                                                        spawn(async move {
                                                            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                                                            status_message.set(String::new());
                                                        });
                                                    },
                                                    "⏸️"
                                                }
                                                button {
                                                    class: "action-btn action-btn-success",
                                                    title: "Resume Thread",
                                                    onclick: move |e| {
                                                        e.stop_propagation();
                                                        if resume_thread(tid) {
                                                            status_message.set(format!("▶️ Thread {} resumed", tid));
                                                        } else {
                                                            status_message.set(format!("✗ Failed to resume thread {}", tid));
                                                        }
                                                        spawn(async move {
                                                            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                                                            status_message.set(String::new());
                                                        });
                                                    },
                                                    "▶️"
                                                }
                                                button {
                                                    class: "action-btn action-btn-danger",
                                                    title: "Kill Thread (Dangerous!)",
                                                    onclick: move |e| {
                                                        e.stop_propagation();
                                                        if kill_thread(tid) {
                                                            status_message.set(format!("☠️ Thread {} terminated", tid));
                                                            threads.set(get_process_threads(pid));
                                                        } else {
                                                            status_message.set(format!("✗ Failed to terminate thread {}", tid));
                                                        }
                                                        spawn(async move {
                                                            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                                                            status_message.set(String::new());
                                                        });
                                                    },
                                                    "☠️"
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                
                // Context menu for threads
                if ctx_menu.visible {
                    div {
                        class: "context-menu",
                        style: "left: {ctx_menu.x}px; top: {ctx_menu.y}px;",
                        onclick: move |e| e.stop_propagation(),
                        
                        button {
                            class: "context-menu-item context-menu-item-warning",
                            onclick: move |_| {
                                if let Some(tid) = ctx_menu.thread_id {
                                    if suspend_thread(tid) {
                                        status_message.set(format!("⏸️ Thread {} suspended", tid));
                                    } else {
                                        status_message.set(format!("✗ Failed to suspend thread {}", tid));
                                    }
                                    spawn(async move {
                                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                                        status_message.set(String::new());
                                    });
                                }
                                context_menu.set(ThreadContextMenuState::default());
                            },
                            span { "⏸️" }
                            span { "Suspend Thread" }
                        }
                        
                        button {
                            class: "context-menu-item context-menu-item-success",
                            onclick: move |_| {
                                if let Some(tid) = ctx_menu.thread_id {
                                    if resume_thread(tid) {
                                        status_message.set(format!("▶️ Thread {} resumed", tid));
                                    } else {
                                        status_message.set(format!("✗ Failed to resume thread {}", tid));
                                    }
                                    spawn(async move {
                                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                                        status_message.set(String::new());
                                    });
                                }
                                context_menu.set(ThreadContextMenuState::default());
                            },
                            span { "▶️" }
                            span { "Resume Thread" }
                        }
                        
                        div { class: "context-menu-separator" }
                        
                        button {
                            class: "context-menu-item context-menu-item-danger",
                            onclick: move |_| {
                                if let Some(tid) = ctx_menu.thread_id {
                                    if kill_thread(tid) {
                                        status_message.set(format!("☠️ Thread {} terminated", tid));
                                        threads.set(get_process_threads(pid));
                                    } else {
                                        status_message.set(format!("✗ Failed to terminate thread {}", tid));
                                    }
                                    spawn(async move {
                                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                                        status_message.set(String::new());
                                    });
                                }
                                context_menu.set(ThreadContextMenuState::default());
                            },
                            span { "☠️" }
                            span { "Kill Thread" }
                        }
                        
                        div { class: "context-menu-separator" }
                        
                        button {
                            class: "context-menu-item",
                            onclick: move |_| {
                                if let Some(tid) = ctx_menu.thread_id {
                                    copy_to_clipboard(&tid.to_string());
                                    status_message.set(format!("📋 Thread ID {} copied", tid));
                                    spawn(async move {
                                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                                        status_message.set(String::new());
                                    });
                                }
                                context_menu.set(ThreadContextMenuState::default());
                            },
                            span { "📋" }
                            span { "Copy Thread ID" }
                        }
                    }
                }
            }
        }
    }
}

/// Handle context menu state
#[derive(Clone, Debug, Default)]
pub struct HandleContextMenuState {
    pub visible: bool,
    pub x: i32,
    pub y: i32,
    pub handle_value: Option<u16>,
}

/// Handle Window component
#[component]
pub fn HandleWindow(pid: u32, process_name: String) -> Element {
    use process::{get_process_handles, close_process_handle, get_handle_type_category, HandleInfo};
    
    let mut handles = use_signal(|| get_process_handles(pid));
    let mut selected_handle = use_signal(|| None::<u16>);
    let mut context_menu = use_signal(|| HandleContextMenuState::default());
    let mut status_message = use_signal(|| String::new());
    let mut auto_refresh = use_signal(|| false); // Disabled by default - handle enumeration is expensive
    let mut filter_type = use_signal(|| String::new());
    
    // Auto-refresh every 3 seconds (if enabled)
    use_future(move || async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            if *auto_refresh.read() {
                handles.set(get_process_handles(pid));
            }
        }
    });
    
    let ctx_menu = context_menu.read().clone();
    let filter = filter_type.read().clone();
    
    // Filter handles by type
    let handle_list: Vec<HandleInfo> = handles.read()
        .iter()
        .filter(|h| {
            if filter.is_empty() {
                true
            } else {
                h.object_type_name.to_lowercase().contains(&filter.to_lowercase())
            }
        })
        .cloned()
        .collect();
    let handle_count = handle_list.len();
    let total_handles = handles.read().len();
    
    rsx! {
        // Modal overlay
        div {
            class: "thread-modal-overlay",
            onclick: move |_| {
                *HANDLE_WINDOW_STATE.write() = None;
            },
            
            // Modal window
            div {
                class: "thread-modal handle-modal",
                onclick: move |e| e.stop_propagation(),
                
                // Header
                div {
                    class: "thread-modal-header",
                    div {
                        class: "thread-modal-title",
                        "🔗 Handles - {process_name} (PID: {pid})"
                    }
                    button {
                        class: "thread-modal-close",
                        onclick: move |_| {
                            *HANDLE_WINDOW_STATE.write() = None;
                        },
                        "✕"
                    }
                }
                
                // Controls
                div {
                    class: "thread-controls",
                    span { class: "thread-count", "Handles: {handle_count}/{total_handles}" }
                    
                    input {
                        class: "handle-filter-input",
                        r#type: "text",
                        placeholder: "Filter by type...",
                        value: "{filter_type}",
                        oninput: move |e| filter_type.set(e.value().clone()),
                    }
                    
                    label { class: "checkbox-label",
                        input {
                            r#type: "checkbox",
                            class: "checkbox",
                            checked: *auto_refresh.read(),
                            onchange: move |e| auto_refresh.set(e.checked()),
                        }
                        span { "Auto-refresh" }
                    }
                    
                    button {
                        class: "btn btn-small btn-primary",
                        onclick: move |_| {
                            handles.set(get_process_handles(pid));
                        },
                        "🔄 Refresh"
                    }
                }
                
                // Status message
                if !status_message.read().is_empty() {
                    div { class: "thread-status-message", "{status_message}" }
                }
                
                // Handle table
                div {
                    class: "thread-table-container",
                    table {
                        class: "thread-table",
                        thead {
                            tr {
                                th { class: "th", "Handle" }
                                th { class: "th", "Type" }
                                th { class: "th", "Access" }
                                th { class: "th", "Actions" }
                            }
                        }
                        tbody {
                            for handle in handle_list {
                                {
                                    let hval = handle.handle_value;
                                    let is_selected = *selected_handle.read() == Some(hval);
                                    let row_class = if is_selected { "thread-row selected" } else { "thread-row" };
                                    let type_category = get_handle_type_category(&handle.object_type_name);
                                    let type_class = format!("handle-type handle-type-{}", type_category);
                                    
                                    rsx! {
                                        tr {
                                            key: "{hval}",
                                            class: "{row_class}",
                                            onclick: move |_| {
                                                let current = *selected_handle.read();
                                                if current == Some(hval) {
                                                    selected_handle.set(None);
                                                } else {
                                                    selected_handle.set(Some(hval));
                                                }
                                            },
                                            oncontextmenu: move |e| {
                                                e.prevent_default();
                                                let coords = e.client_coordinates();
                                                selected_handle.set(Some(hval));
                                                context_menu.set(HandleContextMenuState {
                                                    visible: true,
                                                    x: coords.x as i32,
                                                    y: coords.y as i32,
                                                    handle_value: Some(hval),
                                                });
                                            },
                                            td { class: "cell cell-handle", "0x{handle.handle_value:04X}" }
                                            td { class: "cell {type_class}", "{handle.object_type_name}" }
                                            td { class: "cell cell-access", "0x{handle.granted_access:08X}" }
                                            td { class: "cell cell-actions",
                                                button {
                                                    class: "action-btn action-btn-danger",
                                                    title: "Close Handle (Dangerous!)",
                                                    onclick: move |e| {
                                                        e.stop_propagation();
                                                        if close_process_handle(pid, hval) {
                                                            status_message.set(format!("✓ Handle 0x{:04X} closed", hval));
                                                            handles.set(get_process_handles(pid));
                                                        } else {
                                                            status_message.set(format!("✗ Failed to close handle 0x{:04X}", hval));
                                                        }
                                                        spawn(async move {
                                                            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                                                            status_message.set(String::new());
                                                        });
                                                    },
                                                    "✕"
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                
                // Context menu for handles
                if ctx_menu.visible {
                    div {
                        class: "context-menu",
                        style: "left: {ctx_menu.x}px; top: {ctx_menu.y}px;",
                        onclick: move |e| e.stop_propagation(),
                        
                        button {
                            class: "context-menu-item context-menu-item-danger",
                            onclick: move |_| {
                                if let Some(hval) = ctx_menu.handle_value {
                                    if close_process_handle(pid, hval) {
                                        status_message.set(format!("✓ Handle 0x{:04X} closed", hval));
                                        handles.set(get_process_handles(pid));
                                    } else {
                                        status_message.set(format!("✗ Failed to close handle 0x{:04X}", hval));
                                    }
                                    spawn(async move {
                                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                                        status_message.set(String::new());
                                    });
                                }
                                context_menu.set(HandleContextMenuState::default());
                            },
                            span { "✕" }
                            span { "Close Handle" }
                        }
                        
                        div { class: "context-menu-separator" }
                        
                        button {
                            class: "context-menu-item",
                            onclick: move |_| {
                                if let Some(hval) = ctx_menu.handle_value {
                                    copy_to_clipboard(&format!("0x{:04X}", hval));
                                    status_message.set(format!("📋 Handle 0x{:04X} copied", hval));
                                    spawn(async move {
                                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                                        status_message.set(String::new());
                                    });
                                }
                                context_menu.set(HandleContextMenuState::default());
                            },
                            span { "📋" }
                            span { "Copy Handle Value" }
                        }
                    }
                }
            }
        }
    }
}

/// Complete offline CSS styles
pub const CUSTOM_STYLES: &str = r#"
    /* Reset & Base */
    * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
    }

    html, body {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
        color: #eee;
        height: 100%;
        overflow: hidden;
    }

    /* Scrollbar */
    ::-webkit-scrollbar {
        width: 6px;
        height: 6px;
    }
    ::-webkit-scrollbar-track {
        background: transparent;
    }
    ::-webkit-scrollbar-thumb {
        background: rgba(0, 212, 255, 0.3);
        border-radius: 3px;
    }
    ::-webkit-scrollbar-thumb:hover {
        background: rgba(0, 212, 255, 0.5);
    }

    /* Main Container */
    .main-container {
        height: 100vh;
        display: flex;
        flex-direction: column;
        outline: none;
    }

    /* Title Bar */
    .title-bar {
        display: flex;
        justify-content: space-between;
        align-items: center;
        height: 36px;
        background: linear-gradient(to right, #020617, #0f172a);
        border-bottom: 1px solid rgba(34, 211, 238, 0.2);
        user-select: none;
        flex-shrink: 0;
    }
    .title-bar-drag {
        flex: 1;
        height: 100%;
        display: flex;
        align-items: center;
        padding-left: 12px;
        cursor: move;
    }
    .title-text {
        font-size: 14px;
        font-weight: 500;
        color: #22d3ee;
    }
    .title-bar-buttons {
        display: flex;
        height: 100%;
    }
    .title-btn {
        width: 48px;
        height: 100%;
        border: none;
        background: transparent;
        color: #9ca3af;
        font-size: 12px;
        cursor: pointer;
        transition: all 0.15s;
    }
    .title-btn:hover {
        background: rgba(255, 255, 255, 0.1);
        color: white;
    }
    .title-btn-close:hover {
        background: #dc2626;
        color: white;
    }

    /* Stats Bar */
    .stats-bar {
        background: linear-gradient(to right, rgba(15, 23, 42, 0.8), rgba(30, 41, 59, 0.8));
        border-bottom: 1px solid rgba(34, 211, 238, 0.1);
        padding: 8px 20px;
        display: flex;
        align-items: center;
        gap: 24px;
        font-size: 12px;
        flex-shrink: 0;
    }
    .stat-item {
        display: flex;
        align-items: center;
        gap: 8px;
    }
    .stat-item-right {
        margin-left: auto;
    }
    .stat-label {
        color: #6b7280;
    }
    .stat-bar {
        width: 96px;
        height: 8px;
        background: rgba(255, 255, 255, 0.1);
        border-radius: 4px;
        overflow: hidden;
    }
    .stat-bar-fill {
        height: 100%;
        transition: all 0.5s;
    }
    .stat-bar-cpu {
        background: linear-gradient(to right, #22d3ee, #0891b2);
    }
    .stat-bar-ram {
        background: linear-gradient(to right, #a855f7, #7c3aed);
    }
    .stat-value {
        font-family: monospace;
        min-width: 40px;
    }
    .stat-value-cyan { color: #22d3ee; }
    .stat-value-purple { color: #a855f7; min-width: 100px; }
    .stat-value-green { color: #4ade80; }
    .stat-value-yellow { color: #facc15; }

    /* Content Area */
    .content-area {
        max-width: 1152px;
        margin: 0 auto;
        padding: 20px;
        flex: 1;
        overflow: hidden;
        display: flex;
        flex-direction: column;
        width: 100%;
    }

    /* Header */
    .header-box {
        text-align: center;
        margin-bottom: 16px;
        padding: 16px;
        background: rgba(255, 255, 255, 0.05);
        border-radius: 12px;
        backdrop-filter: blur(4px);
        flex-shrink: 0;
    }
    .header-title {
        font-size: 24px;
        margin-bottom: 8px;
        color: #22d3ee;
        font-weight: bold;
    }
    .header-stats {
        display: flex;
        justify-content: center;
        gap: 32px;
        font-size: 14px;
        color: #9ca3af;
    }
    .header-shortcuts {
        color: #4b5563;
        font-size: 12px;
    }
    .status-message {
        margin-top: 12px;
        padding: 8px 16px;
        background: rgba(34, 211, 238, 0.2);
        border-radius: 6px;
        font-size: 14px;
        color: #22d3ee;
        display: inline-block;
    }

    /* Controls */
    .controls {
        display: flex;
        gap: 16px;
        margin-bottom: 16px;
        align-items: center;
        flex-wrap: wrap;
        flex-shrink: 0;
    }
    .search-input {
        flex: 1;
        min-width: 200px;
        padding: 12px 16px;
        border: none;
        border-radius: 8px;
        background: rgba(255, 255, 255, 0.1);
        color: white;
        font-size: 14px;
        outline: none;
        transition: background 0.15s;
    }
    .search-input:focus {
        background: rgba(255, 255, 255, 0.15);
    }
    .search-input::placeholder {
        color: #6b7280;
    }
    .checkbox-label {
        display: flex;
        align-items: center;
        gap: 8px;
        color: #9ca3af;
        font-size: 14px;
        cursor: pointer;
        user-select: none;
    }
    .checkbox {
        width: 16px;
        height: 16px;
        cursor: pointer;
        accent-color: #22d3ee;
    }

    /* Buttons */
    .btn {
        padding: 12px 24px;
        border: none;
        border-radius: 8px;
        font-size: 14px;
        font-weight: 600;
        cursor: pointer;
        transition: all 0.15s;
    }
    .btn-primary {
        background: linear-gradient(to bottom right, #22d3ee, #0891b2);
        color: white;
    }
    .btn-primary:hover {
        transform: translateY(-2px);
        box-shadow: 0 10px 25px rgba(34, 211, 238, 0.4);
    }
    .btn-primary:active {
        transform: translateY(0);
    }
    .btn-danger {
        background: linear-gradient(to bottom right, #ef4444, #b91c1c);
        color: white;
    }
    .btn-danger:hover:not(:disabled) {
        transform: translateY(-2px);
        box-shadow: 0 10px 25px rgba(239, 68, 68, 0.4);
    }
    .btn-danger:active:not(:disabled) {
        transform: translateY(0);
    }
    .btn-danger:disabled {
        opacity: 0.5;
        cursor: not-allowed;
    }

    /* Table */
    .table-container {
        background: rgba(255, 255, 255, 0.05);
        border-radius: 12px;
        flex: 1;
        overflow-y: auto;
        overflow-x: hidden;
        min-height: 0;
    }
    .process-table {
        width: 100%;
        border-collapse: collapse;
    }
    .table-header {
        position: sticky;
        top: 0;
        background: rgba(34, 211, 238, 0.2);
        backdrop-filter: blur(4px);
        z-index: 10;
    }
    .th {
        padding: 12px 16px;
        text-align: left;
        font-weight: 600;
        color: #22d3ee;
        border-bottom: 2px solid rgba(34, 211, 238, 0.3);
        font-size: 14px;
        user-select: none;
    }
    .th.sortable {
        cursor: pointer;
        transition: background 0.15s;
    }
    .th.sortable:hover {
        background: rgba(34, 211, 238, 0.3);
    }

    /* Process Row */
    .process-row {
        cursor: pointer;
        transition: background 0.15s;
        border-bottom: 1px solid rgba(255, 255, 255, 0.05);
    }
    .process-row:hover {
        background: rgba(34, 211, 238, 0.1);
    }
    .process-row.selected {
        border-left: 4px solid #ef4444;
        background: rgba(239, 68, 68, 0.2);
    }
    .process-row.selected:hover {
        background: rgba(239, 68, 68, 0.3);
    }
    .cell {
        padding: 12px 16px;
    }
    .cell-pid {
        font-family: monospace;
        color: #facc15;
        width: 80px;
    }
    .cell-name {
        font-weight: 500;
    }
    .cell-cpu {
        font-family: monospace;
        width: 80px;
        text-align: center;
    }
    .cell-threads {
        font-family: monospace;
        color: #a855f7;
        width: 80px;
        text-align: center;
    }
    .cell-memory {
        width: 176px;
    }
    .cell-path {
        font-size: 12px;
        color: #6b7280;
        max-width: 200px;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    }
    .cell-path:hover {
        color: #9ca3af;
    }

    /* CPU Colors */
    .cpu-low { color: #4ade80; }
    .cpu-medium { color: #facc15; }
    .cpu-high { color: #f87171; }

    /* Memory Bar */
    .memory-bar-container {
        display: flex;
        align-items: center;
        gap: 8px;
    }
    .memory-bar-bg {
        flex: 1;
        height: 8px;
        background: rgba(255, 255, 255, 0.1);
        border-radius: 4px;
        overflow: hidden;
    }
    .memory-bar-fill {
        height: 100%;
        background: linear-gradient(to right, #4ade80, #22d3ee, #ef4444);
        border-radius: 4px;
        transition: width 0.3s;
    }
    .memory-text {
        font-family: monospace;
        color: #4ade80;
        font-size: 12px;
        min-width: 70px;
        text-align: right;
    }

    /* Context Menu */
    .context-menu {
        position: fixed;
        background: #1e293b;
        border: 1px solid rgba(34, 211, 238, 0.3);
        border-radius: 8px;
        box-shadow: 0 25px 50px rgba(0, 0, 0, 0.5);
        padding: 4px 0;
        min-width: 180px;
        z-index: 50;
    }
    .context-menu-item {
        width: 100%;
        padding: 8px 16px;
        text-align: left;
        font-size: 14px;
        color: #d1d5db;
        background: transparent;
        border: none;
        display: flex;
        align-items: center;
        gap: 8px;
        cursor: pointer;
        transition: background 0.15s;
    }
    .context-menu-item:hover:not(:disabled) {
        background: rgba(34, 211, 238, 0.2);
    }
    .context-menu-item:disabled {
        opacity: 0.5;
        cursor: not-allowed;
    }
    .context-menu-item-danger {
        color: #f87171;
    }
    .context-menu-item-danger:hover {
        background: rgba(239, 68, 68, 0.2);
    }
    .context-menu-item-warning {
        color: #fbbf24;
    }
    .context-menu-item-warning:hover {
        background: rgba(251, 191, 36, 0.2);
    }
    .context-menu-item-success {
        color: #4ade80;
    }
    .context-menu-item-success:hover {
        background: rgba(74, 222, 128, 0.2);
    }
    .context-menu-separator {
        height: 1px;
        background: rgba(34, 211, 238, 0.2);
        margin: 4px 0;
    }

    /* Thread Modal */
    .thread-modal-overlay {
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: rgba(0, 0, 0, 0.7);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 100;
    }
    .thread-modal {
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
        border: 1px solid rgba(34, 211, 238, 0.3);
        border-radius: 12px;
        width: 700px;
        max-width: 90vw;
        max-height: 80vh;
        display: flex;
        flex-direction: column;
        box-shadow: 0 25px 50px rgba(0, 0, 0, 0.5);
    }
    .thread-modal-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 16px 20px;
        border-bottom: 1px solid rgba(34, 211, 238, 0.2);
    }
    .thread-modal-title {
        font-size: 18px;
        font-weight: 600;
        color: #22d3ee;
    }
    .thread-modal-close {
        width: 32px;
        height: 32px;
        border: none;
        background: transparent;
        color: #9ca3af;
        font-size: 16px;
        cursor: pointer;
        border-radius: 6px;
        transition: all 0.15s;
    }
    .thread-modal-close:hover {
        background: #dc2626;
        color: white;
    }
    .thread-controls {
        display: flex;
        gap: 16px;
        padding: 12px 20px;
        align-items: center;
        border-bottom: 1px solid rgba(34, 211, 238, 0.1);
    }
    .thread-count {
        color: #9ca3af;
        font-size: 14px;
    }
    .thread-status-message {
        margin: 8px 20px;
        padding: 8px 16px;
        background: rgba(34, 211, 238, 0.2);
        border-radius: 6px;
        font-size: 14px;
        color: #22d3ee;
    }
    .thread-table-container {
        flex: 1;
        overflow-y: auto;
        padding: 0 20px 20px;
    }
    .thread-table {
        width: 100%;
        border-collapse: collapse;
    }
    .thread-row {
        cursor: pointer;
        transition: background 0.15s;
        border-bottom: 1px solid rgba(255, 255, 255, 0.05);
    }
    .thread-row:hover {
        background: rgba(34, 211, 238, 0.1);
    }
    .thread-row.selected {
        border-left: 4px solid #22d3ee;
        background: rgba(34, 211, 238, 0.2);
    }
    .cell-tid {
        font-family: monospace;
        color: #facc15;
    }
    .cell-actions {
        display: flex;
        gap: 8px;
    }
    .action-btn {
        width: 28px;
        height: 28px;
        border: none;
        border-radius: 4px;
        background: rgba(255, 255, 255, 0.1);
        cursor: pointer;
        font-size: 12px;
        transition: all 0.15s;
    }
    .action-btn:hover {
        transform: scale(1.1);
    }
    .action-btn-warning {
        color: #fbbf24;
    }
    .action-btn-warning:hover {
        background: rgba(251, 191, 36, 0.3);
    }
    .action-btn-success {
        color: #4ade80;
    }
    .action-btn-success:hover {
        background: rgba(74, 222, 128, 0.3);
    }
    .action-btn-danger {
        color: #f87171;
    }
    .action-btn-danger:hover {
        background: rgba(239, 68, 68, 0.3);
    }
    .btn-small {
        padding: 6px 12px;
        font-size: 12px;
    }

    /* Handle Window Styles */
    .handle-modal {
        width: 800px;
    }
    .handle-filter-input {
        padding: 6px 12px;
        border: none;
        border-radius: 6px;
        background: rgba(255, 255, 255, 0.1);
        color: white;
        font-size: 13px;
        width: 150px;
        outline: none;
    }
    .handle-filter-input:focus {
        background: rgba(255, 255, 255, 0.15);
    }
    .handle-filter-input::placeholder {
        color: #6b7280;
    }
    .cell-handle {
        font-family: monospace;
        color: #facc15;
    }
    .cell-access {
        font-family: monospace;
        color: #9ca3af;
        font-size: 12px;
    }
    .handle-type {
        font-size: 13px;
        padding: 2px 8px;
        border-radius: 4px;
        display: inline-block;
    }
    .handle-type-file {
        color: #4ade80;
        background: rgba(74, 222, 128, 0.15);
    }
    .handle-type-registry {
        color: #f472b6;
        background: rgba(244, 114, 182, 0.15);
    }
    .handle-type-process {
        color: #fb923c;
        background: rgba(251, 146, 60, 0.15);
    }
    .handle-type-sync {
        color: #a78bfa;
        background: rgba(167, 139, 250, 0.15);
    }
    .handle-type-memory {
        color: #22d3ee;
        background: rgba(34, 211, 238, 0.15);
    }
    .handle-type-security {
        color: #f87171;
        background: rgba(248, 113, 113, 0.15);
    }
    .handle-type-ipc {
        color: #fbbf24;
        background: rgba(251, 191, 36, 0.15);
    }
    .handle-type-namespace {
        color: #60a5fa;
        background: rgba(96, 165, 250, 0.15);
    }
    .handle-type-other {
        color: #9ca3af;
        background: rgba(156, 163, 175, 0.15);
    }
"#;
