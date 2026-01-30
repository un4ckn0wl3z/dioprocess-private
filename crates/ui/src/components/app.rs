//! Main application component

use dioxus::prelude::*;
use process::{
    format_uptime, get_processes, get_system_stats, kill_process, open_file_location,
    resume_process, suspend_process, ProcessInfo,
};

use super::{HandleWindow, ProcessRow, ThreadWindow};
use crate::helpers::copy_to_clipboard;
use crate::state::{
    ContextMenuState, SortColumn, SortOrder, HANDLE_WINDOW_STATE, THREAD_WINDOW_STATE,
};
use crate::styles::CUSTOM_STYLES;

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
    let max_memory = processes
        .read()
        .iter()
        .map(|p| p.memory_mb)
        .fold(0.0_f64, |a, b| a.max(b));

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
            SortColumn::Memory => a
                .memory_mb
                .partial_cmp(&b.memory_mb)
                .unwrap_or(std::cmp::Ordering::Equal),
            SortColumn::Threads => a.thread_count.cmp(&b.thread_count),
            SortColumn::Cpu => a
                .cpu_usage
                .partial_cmp(&b.cpu_usage)
                .unwrap_or(std::cmp::Ordering::Equal),
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
