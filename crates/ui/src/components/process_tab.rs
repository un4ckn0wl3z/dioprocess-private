//! Process tab component

use std::collections::{HashMap, HashSet};

use dioxus::prelude::*;
use misc::{inject_dll, inject_dll_apc_queue, inject_dll_earlybird, inject_dll_manual_map, inject_dll_remote_mapping, inject_dll_thread_hijack, inject_shellcode_classic, unhook_dll_remote_by_path, enumerate_process_modules};
use process::{
    get_processes, get_system_stats, kill_process, open_file_location, resume_process,
    suspend_process, ProcessInfo,
};

use super::{
    CreateProcessWindow, FunctionStompingWindow, GhostProcessWindow, GraphWindow, HandleWindow,
    HookScanWindow, MemoryWindow, ModuleWindow, ProcessRow, ShellcodeInjectWindow,
    StringScanWindow, ThreadWindow, ThreadlessInjectWindow, TokenThiefWindow,
};
use crate::helpers::copy_to_clipboard;
use crate::state::{
    ContextMenuState, ProcessViewMode, SortColumn, SortOrder, CREATE_PROCESS_WINDOW_STATE,
    FUNCTION_STOMPING_WINDOW_STATE, GHOST_PROCESS_WINDOW_STATE, GRAPH_WINDOW_STATE,
    HANDLE_WINDOW_STATE, HOOK_SCAN_WINDOW_STATE, MEMORY_WINDOW_STATE, MODULE_WINDOW_STATE,
    SHELLCODE_INJECT_WINDOW_STATE, STRING_SCAN_WINDOW_STATE, THREAD_WINDOW_STATE,
    THREADLESS_INJECT_WINDOW_STATE, TOKEN_THIEF_WINDOW_STATE,
};

/// A row in the tree view with metadata for rendering connectors
#[derive(Clone)]
struct TreeRow {
    process: ProcessInfo,
    depth: usize,
    is_last: bool,
    ancestor_is_last: Vec<bool>,
    has_children: bool,
    is_expanded: bool,
}

/// Build tree rows from a flat process list
fn build_tree_rows(
    all_processes: &[ProcessInfo],
    search_query: &str,
    sort_column: SortColumn,
    sort_order: SortOrder,
    expanded_pids: &HashSet<u32>,
) -> Vec<TreeRow> {
    let pid_set: HashSet<u32> = all_processes.iter().map(|p| p.pid).collect();

    // Build children map: parent_pid -> list of children
    let mut children_map: HashMap<u32, Vec<&ProcessInfo>> = HashMap::new();
    let mut roots: Vec<&ProcessInfo> = Vec::new();

    for p in all_processes {
        if p.parent_pid == 0 || !pid_set.contains(&p.parent_pid) {
            roots.push(p);
        } else {
            children_map.entry(p.parent_pid).or_default().push(p);
        }
    }

    // Determine which PIDs are visible when searching
    let query = search_query.to_lowercase();
    let has_search = !query.is_empty();
    let visible_pids: HashSet<u32> = if has_search {
        // Find all matching PIDs
        let mut matching: HashSet<u32> = HashSet::new();
        for p in all_processes {
            if p.name.to_lowercase().contains(&query)
                || p.pid.to_string().contains(&query)
                || p.exe_path.to_lowercase().contains(&query)
            {
                matching.insert(p.pid);
            }
        }
        // Add all ancestors of matching PIDs
        let parent_map: HashMap<u32, u32> = all_processes.iter().map(|p| (p.pid, p.parent_pid)).collect();
        let mut visible = matching.clone();
        for &pid in &matching {
            let mut current = pid;
            while let Some(&parent) = parent_map.get(&current) {
                if parent == 0 || !pid_set.contains(&parent) || visible.contains(&parent) {
                    break;
                }
                visible.insert(parent);
                current = parent;
            }
        }
        visible
    } else {
        pid_set.clone()
    };

    let sort_fn = |a: &&ProcessInfo, b: &&ProcessInfo| -> std::cmp::Ordering {
        let cmp = match sort_column {
            SortColumn::Pid => a.pid.cmp(&b.pid),
            SortColumn::Name => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
            SortColumn::Arch => a.arch.to_string().cmp(&b.arch.to_string()),
            SortColumn::Memory => a.memory_mb.partial_cmp(&b.memory_mb).unwrap_or(std::cmp::Ordering::Equal),
            SortColumn::Threads => a.thread_count.cmp(&b.thread_count),
            SortColumn::Cpu => a.cpu_usage.partial_cmp(&b.cpu_usage).unwrap_or(std::cmp::Ordering::Equal),
        };
        match sort_order {
            SortOrder::Ascending => cmp,
            SortOrder::Descending => cmp.reverse(),
        }
    };

    // Sort roots and children
    roots.sort_by(sort_fn);
    for children in children_map.values_mut() {
        children.sort_by(sort_fn);
    }

    // DFS traversal
    let mut result = Vec::new();

    fn visit(
        process: &ProcessInfo,
        depth: usize,
        is_last: bool,
        ancestor_is_last: Vec<bool>,
        children_map: &HashMap<u32, Vec<&ProcessInfo>>,
        expanded_pids: &HashSet<u32>,
        visible_pids: &HashSet<u32>,
        has_search: bool,
        result: &mut Vec<TreeRow>,
    ) {
        if !visible_pids.contains(&process.pid) {
            return;
        }

        let children: Vec<&ProcessInfo> = children_map
            .get(&process.pid)
            .map(|c| c.iter().filter(|p| visible_pids.contains(&p.pid)).copied().collect())
            .unwrap_or_default();
        let has_children = !children.is_empty();
        let is_expanded = expanded_pids.contains(&process.pid);

        result.push(TreeRow {
            process: process.clone(),
            depth,
            is_last,
            ancestor_is_last: ancestor_is_last.clone(),
            has_children,
            is_expanded,
        });

        if is_expanded || (has_search && has_children) {
            let count = children.len();
            for (i, child) in children.iter().enumerate() {
                let child_is_last = i == count - 1;
                let mut child_ancestors = ancestor_is_last.clone();
                child_ancestors.push(is_last);
                visit(
                    child,
                    depth + 1,
                    child_is_last,
                    child_ancestors,
                    children_map,
                    expanded_pids,
                    visible_pids,
                    has_search,
                    result,
                );
            }
        }
    }

    let root_count = roots.len();
    for (i, root) in roots.iter().enumerate() {
        let is_last = i == root_count - 1;
        visit(
            root,
            0,
            is_last,
            Vec::new(),
            &children_map,
            expanded_pids,
            &visible_pids,
            has_search,
            &mut result,
        );
    }

    result
}

/// Process Tab component
#[component]
pub fn ProcessTab() -> Element {
    let mut processes = use_signal(|| get_processes());
    let mut system_stats = use_signal(|| get_system_stats());
    let mut search_query = use_signal(|| String::new());
    let mut sort_column = use_signal(|| SortColumn::Memory);
    let mut sort_order = use_signal(|| SortOrder::Descending);
    let mut auto_refresh = use_signal(|| true);
    let mut selected_pid = use_signal(|| None::<u32>);
    let mut status_message = use_signal(|| String::new());
    let mut context_menu = use_signal(|| ContextMenuState::default());
    let mut view_mode = use_signal(|| ProcessViewMode::Flat);
    let mut expanded_pids = use_signal(|| HashSet::<u32>::new());

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
        if e.key() == Key::Escape {
            context_menu.set(ContextMenuState::default());
            return;
        }

        if e.key() == Key::F5 {
            processes.set(get_processes());
            system_stats.set(get_system_stats());
            return;
        }

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

    let max_memory = processes
        .read()
        .iter()
        .map(|p| p.memory_mb)
        .fold(0.0_f64, |a, b| a.max(b));

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

    filtered_processes.sort_by(|a, b| {
        let cmp = match *sort_column.read() {
            SortColumn::Pid => a.pid.cmp(&b.pid),
            SortColumn::Name => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
            SortColumn::Arch => a.arch.to_string().cmp(&b.arch.to_string()),
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

    let current_sort_col = *sort_column.read();
    let current_sort_ord = *sort_order.read();
    let ctx_menu = context_menu.read().clone();
    let export_processes = filtered_processes.clone();

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
        div {
            class: "process-tab",
            tabindex: "0",
            onkeydown: handle_keydown,
            onclick: move |_| context_menu.set(ContextMenuState::default()),

            // Header
            div { class: "header-box",
                h1 { class: "header-title", "🖥️ Process Monitor" }
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
                    placeholder: "Search by name, PID, or path...",
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
                                status_message.set(format!("✗ Failed to terminate process {}", pid));
                            }
                            spawn(async move {
                                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                                status_message.set(String::new());
                            });
                        }
                    },
                    "Kill Process"
                }

                button {
                    class: "btn btn-secondary",
                    onclick: {
                        let procs = export_processes.clone();
                        move |_| {
                            let procs = procs.clone();
                            spawn(async move {
                                let file = rfd::AsyncFileDialog::new()
                                    .add_filter("CSV", &["csv"])
                                    .set_file_name("processes.csv")
                                    .set_title("Export Processes")
                                    .save_file()
                                    .await;
                                if let Some(file) = file {
                                    let path = file.path().to_path_buf();
                                    let mut csv = String::from("PID,Name,Arch,CPU %,Threads,Memory (MB),Path\n");
                                    for p in &procs {
                                        csv.push_str(&format!(
                                            "{},\"{}\",{},{:.1},{},{:.2},\"{}\"\n",
                                            p.pid,
                                            p.name.replace('"', "\"\""),
                                            p.arch,
                                            p.cpu_usage,
                                            p.thread_count,
                                            p.memory_mb,
                                            p.exe_path.replace('"', "\"\"")
                                        ));
                                    }
                                    match std::fs::write(&path, csv) {
                                        Ok(()) => {
                                            status_message.set(format!("Exported {} processes to {}", procs.len(), path.display()));
                                        }
                                        Err(e) => {
                                            status_message.set(format!("Export failed: {}", e));
                                        }
                                    }
                                    spawn(async move {
                                        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                                        status_message.set(String::new());
                                    });
                                }
                            });
                        }
                    },
                    "Export CSV"
                }

                button {
                    class: "btn btn-secondary",
                    onclick: move |_| {
                        *CREATE_PROCESS_WINDOW_STATE.write() = true;
                    },
                    "Create Process"
                }

                button {
                    class: "btn btn-secondary",
                    onclick: move |_| {
                        *GHOST_PROCESS_WINDOW_STATE.write() = true;
                    },
                    "Process Ghosting"
                }

                button {
                    class: if *view_mode.read() == ProcessViewMode::Tree { "btn btn-secondary active" } else { "btn btn-secondary" },
                    onclick: move |_| {
                        let current = *view_mode.read();
                        match current {
                            ProcessViewMode::Flat => view_mode.set(ProcessViewMode::Tree),
                            ProcessViewMode::Tree => view_mode.set(ProcessViewMode::Flat),
                        }
                    },
                    "Tree View"
                }

                if *view_mode.read() == ProcessViewMode::Tree {
                    button {
                        class: "btn btn-secondary",
                        onclick: move |_| {
                            let all_pids: HashSet<u32> = processes.read().iter().map(|p| p.pid).collect();
                            expanded_pids.set(all_pids);
                        },
                        "Expand All"
                    }
                    button {
                        class: "btn btn-secondary",
                        onclick: move |_| {
                            expanded_pids.set(HashSet::new());
                        },
                        "Collapse All"
                    }
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
                                    if *sort_column.read() == SortColumn::Arch {
                                        let new_order = if *sort_order.read() == SortOrder::Ascending { SortOrder::Descending } else { SortOrder::Ascending };
                                        sort_order.set(new_order);
                                    } else {
                                        sort_column.set(SortColumn::Arch);
                                        sort_order.set(SortOrder::Descending);
                                    }
                                },
                                "Arch{sort_indicator(SortColumn::Arch)}"
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
                        if *view_mode.read() == ProcessViewMode::Tree {
                            {
                                let tree_rows = build_tree_rows(
                                    &processes.read(),
                                    &search_query.read(),
                                    *sort_column.read(),
                                    *sort_order.read(),
                                    &expanded_pids.read(),
                                );
                                rsx! {
                                    for row in tree_rows {
                                        ProcessRow {
                                            process: row.process.clone(),
                                            is_selected: *selected_pid.read() == Some(row.process.pid),
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
                                            tree_depth: Some(row.depth),
                                            tree_is_last: Some(row.is_last),
                                            tree_ancestor_is_last: Some(row.ancestor_is_last.clone()),
                                            tree_has_children: Some(row.has_children),
                                            tree_is_expanded: Some(row.is_expanded),
                                            on_toggle_expand: move |pid: u32| {
                                                let mut set = expanded_pids.read().clone();
                                                if set.contains(&pid) {
                                                    set.remove(&pid);
                                                } else {
                                                    set.insert(pid);
                                                }
                                                expanded_pids.set(set);
                                            },
                                        }
                                    }
                                }
                            }
                        } else {
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
                    style: "left: {ctx_menu.x}px; top: clamp(5px, {ctx_menu.y}px, calc(100vh - 380px));",
                    onclick: move |e| e.stop_propagation(),

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

                    div { class: "context-menu-separator" }

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

                    button {
                        class: "context-menu-item",
                        onclick: move |_| {
                            if let Some(pid) = ctx_menu.pid {
                                copy_to_clipboard(&pid.to_string());
                                status_message.set(format!("📋 PID {} copied", pid));
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

                    button {
                        class: "context-menu-item",
                        disabled: ctx_menu.exe_path.is_empty(),
                        onclick: {
                            let path = ctx_menu.exe_path.clone();
                            move |_| {
                                copy_to_clipboard(&path);
                                status_message.set("📋 Path copied".to_string());
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

                    div { class: "context-menu-separator" }

                    // Inspect submenu
                    div {
                        class: "context-menu-submenu",
                        div {
                            class: "context-menu-submenu-trigger",
                            span { "🔍" }
                            span { "Inspect" }
                            span { class: "arrow", "▶" }
                        }
                        div {
                            class: "context-menu-submenu-content",
                            button {
                                class: "context-menu-item",
                                onclick: move |_| {
                                    if let Some(pid) = ctx_menu.pid {
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
                                span { "Threads" }
                            }

                            button {
                                class: "context-menu-item",
                                onclick: move |_| {
                                    if let Some(pid) = ctx_menu.pid {
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
                                span { "Handles" }
                            }

                            button {
                                class: "context-menu-item",
                                onclick: move |_| {
                                    if let Some(pid) = ctx_menu.pid {
                                        let proc_name = processes.read()
                                            .iter()
                                            .find(|p| p.pid == pid)
                                            .map(|p| p.name.clone())
                                            .unwrap_or_else(|| format!("PID {}", pid));
                                        *MODULE_WINDOW_STATE.write() = Some((pid, proc_name));
                                    }
                                    context_menu.set(ContextMenuState::default());
                                },
                                span { "📦" }
                                span { "Modules" }
                            }

                            button {
                                class: "context-menu-item",
                                onclick: move |_| {
                                    if let Some(pid) = ctx_menu.pid {
                                        let proc_name = processes.read()
                                            .iter()
                                            .find(|p| p.pid == pid)
                                            .map(|p| p.name.clone())
                                            .unwrap_or_else(|| format!("PID {}", pid));
                                        *MEMORY_WINDOW_STATE.write() = Some((pid, proc_name));
                                    }
                                    context_menu.set(ContextMenuState::default());
                                },
                                span { "🧠" }
                                span { "Memory" }
                            }

                            button {
                                class: "context-menu-item",
                                onclick: move |_| {
                                    if let Some(pid) = ctx_menu.pid {
                                        let proc_name = processes.read()
                                            .iter()
                                            .find(|p| p.pid == pid)
                                            .map(|p| p.name.clone())
                                            .unwrap_or_else(|| format!("PID {}", pid));
                                        *GRAPH_WINDOW_STATE.write() = Some((pid, proc_name));
                                    }
                                    context_menu.set(ContextMenuState::default());
                                },
                                span { "📈" }
                                span { "Performance" }
                            }

                            button {
                                class: "context-menu-item",
                                onclick: move |_| {
                                    if let Some(pid) = ctx_menu.pid {
                                        let proc_name = processes.read()
                                            .iter()
                                            .find(|p| p.pid == pid)
                                            .map(|p| p.name.clone())
                                            .unwrap_or_else(|| format!("PID {}", pid));
                                        *HOOK_SCAN_WINDOW_STATE.write() = Some((pid, proc_name));
                                    }
                                    context_menu.set(ContextMenuState::default());
                                },
                                span { "🔍" }
                                span { "Hook Scan" }
                            }

                            button {
                                class: "context-menu-item",
                                onclick: move |_| {
                                    if let Some(pid) = ctx_menu.pid {
                                        let proc_name = processes.read()
                                            .iter()
                                            .find(|p| p.pid == pid)
                                            .map(|p| p.name.clone())
                                            .unwrap_or_else(|| format!("PID {}", pid));
                                        *STRING_SCAN_WINDOW_STATE.write() = Some((pid, proc_name));
                                    }
                                    context_menu.set(ContextMenuState::default());
                                },
                                span { "Abc" }
                                span { "String Scan" }
                            }
                        }
                    }

                    div { class: "context-menu-separator" }

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

                    div { class: "context-menu-separator" }

                    // Miscellaneous submenu
                    div {
                        class: "context-menu-submenu",
                        div {
                            class: "context-menu-submenu-trigger",
                            span { "⚙️" }
                            span { "Miscellaneous" }
                            span { class: "arrow", "▶" }
                        }
                        div {
                            class: "context-menu-submenu-content",
                            // DLL Injection sub-submenu
                            div {
                                class: "context-menu-submenu",
                                div {
                                    class: "context-menu-submenu-trigger",
                                    span { "💉" }
                                    span { "DLL Injection" }
                                    span { class: "arrow", "▶" }
                                }
                                div {
                                    class: "context-menu-submenu-content",
                                    // LoadLibrary method
                                    button {
                                        class: "context-menu-item",
                                        onclick: move |_| {
                                            let target_pid = ctx_menu.pid;
                                            context_menu.set(ContextMenuState::default());

                                            if let Some(pid) = target_pid {
                                                spawn(async move {
                                                    let file = rfd::AsyncFileDialog::new()
                                                        .add_filter("DLL Files", &["dll"])
                                                        .set_title("Select DLL to inject (LoadLibrary)")
                                                        .pick_file()
                                                        .await;

                                                    if let Some(file) = file {
                                                        let path = file.path().to_string_lossy().to_string();
                                                        match inject_dll(pid, &path) {
                                                            Ok(()) => {
                                                                status_message.set(format!(
                                                                    "✓ DLL injected into process {} (LoadLibrary)",
                                                                    pid
                                                                ));
                                                            }
                                                            Err(e) => {
                                                                status_message.set(format!(
                                                                    "✗ DLL injection failed: {}",
                                                                    e
                                                                ));
                                                            }
                                                        }
                                                        spawn(async move {
                                                            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                                                            status_message.set(String::new());
                                                        });
                                                    }
                                                });
                                            }
                                        },
                                        span { "💉" }
                                        span { "LoadLibrary" }
                                    }

                                    // Thread Hijack method
                                    button {
                                        class: "context-menu-item",
                                        onclick: move |_| {
                                            let target_pid = ctx_menu.pid;
                                            context_menu.set(ContextMenuState::default());

                                            if let Some(pid) = target_pid {
                                                spawn(async move {
                                                    let file = rfd::AsyncFileDialog::new()
                                                        .add_filter("DLL Files", &["dll"])
                                                        .set_title("Select DLL to inject (Thread Hijack)")
                                                        .pick_file()
                                                        .await;

                                                    if let Some(file) = file {
                                                        let path = file.path().to_string_lossy().to_string();
                                                        match inject_dll_thread_hijack(pid, &path) {
                                                            Ok(()) => {
                                                                status_message.set(format!(
                                                                    "✓ DLL injected into process {} (Thread Hijack)",
                                                                    pid
                                                                ));
                                                            }
                                                            Err(e) => {
                                                                status_message.set(format!(
                                                                    "✗ Thread hijack injection failed: {}",
                                                                    e
                                                                ));
                                                            }
                                                        }
                                                        spawn(async move {
                                                            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                                                            status_message.set(String::new());
                                                        });
                                                    }
                                                });
                                            }
                                        },
                                        span { "🧵" }
                                        span { "Thread Hijack" }
                                    }

                                    // APC Queue method
                                    button {
                                        class: "context-menu-item",
                                        onclick: move |_| {
                                            let target_pid = ctx_menu.pid;
                                            context_menu.set(ContextMenuState::default());

                                            if let Some(pid) = target_pid {
                                                spawn(async move {
                                                    let file = rfd::AsyncFileDialog::new()
                                                        .add_filter("DLL Files", &["dll"])
                                                        .set_title("Select DLL to inject (APC Queue)")
                                                        .pick_file()
                                                        .await;

                                                    if let Some(file) = file {
                                                        let path = file.path().to_string_lossy().to_string();
                                                        match inject_dll_apc_queue(pid, &path) {
                                                            Ok(()) => {
                                                                status_message.set(format!(
                                                                    "✓ DLL injected into process {} (APC Queue)",
                                                                    pid
                                                                ));
                                                            }
                                                            Err(e) => {
                                                                status_message.set(format!(
                                                                    "✗ APC queue injection failed: {}",
                                                                    e
                                                                ));
                                                            }
                                                        }
                                                        spawn(async move {
                                                            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                                                            status_message.set(String::new());
                                                        });
                                                    }
                                                });
                                            }
                                        },
                                        span { "📬" }
                                        span { "APC Queue" }
                                    }

                                    // EarlyBird APC method
                                    button {
                                        class: "context-menu-item",
                                        onclick: move |_| {
                                            let target_pid = ctx_menu.pid;
                                            context_menu.set(ContextMenuState::default());

                                            if let Some(pid) = target_pid {
                                                spawn(async move {
                                                    let file = rfd::AsyncFileDialog::new()
                                                        .add_filter("DLL Files", &["dll"])
                                                        .set_title("Select DLL to inject (EarlyBird)")
                                                        .pick_file()
                                                        .await;

                                                    if let Some(file) = file {
                                                        let path = file.path().to_string_lossy().to_string();
                                                        match inject_dll_earlybird(pid, &path) {
                                                            Ok(()) => {
                                                                status_message.set(format!(
                                                                    "✓ DLL injected into process {} (EarlyBird)",
                                                                    pid
                                                                ));
                                                            }
                                                            Err(e) => {
                                                                status_message.set(format!(
                                                                    "✗ EarlyBird injection failed: {}",
                                                                    e
                                                                ));
                                                            }
                                                        }
                                                        spawn(async move {
                                                            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                                                            status_message.set(String::new());
                                                        });
                                                    }
                                                });
                                            }
                                        },
                                        span { "🐦" }
                                        span { "EarlyBird" }
                                    }

                                    // Remote Mapping method
                                    button {
                                        class: "context-menu-item",
                                        onclick: move |_| {
                                            let target_pid = ctx_menu.pid;
                                            context_menu.set(ContextMenuState::default());

                                            if let Some(pid) = target_pid {
                                                spawn(async move {
                                                    let file = rfd::AsyncFileDialog::new()
                                                        .add_filter("DLL Files", &["dll"])
                                                        .set_title("Select DLL to inject (Remote Mapping)")
                                                        .pick_file()
                                                        .await;

                                                    if let Some(file) = file {
                                                        let path = file.path().to_string_lossy().to_string();
                                                        match inject_dll_remote_mapping(pid, &path) {
                                                            Ok(()) => {
                                                                status_message.set(format!(
                                                                    "✓ DLL injected into process {} (Remote Mapping)",
                                                                    pid
                                                                ));
                                                            }
                                                            Err(e) => {
                                                                status_message.set(format!(
                                                                    "✗ Remote mapping injection failed: {}",
                                                                    e
                                                                ));
                                                            }
                                                        }
                                                        spawn(async move {
                                                            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                                                            status_message.set(String::new());
                                                        });
                                                    }
                                                });
                                            }
                                        },
                                        span { "📡" }
                                        span { "Remote Mapping" }
                                    }

                                    // Function Stomping method (opens dedicated window)
                                    button {
                                        class: "context-menu-item",
                                        onclick: move |_| {
                                            if let Some(pid) = ctx_menu.pid {
                                                let proc_name = processes.read()
                                                    .iter()
                                                    .find(|p| p.pid == pid)
                                                    .map(|p| p.name.clone())
                                                    .unwrap_or_else(|| format!("PID {}", pid));
                                                *FUNCTION_STOMPING_WINDOW_STATE.write() = Some((pid, proc_name));
                                            }
                                            context_menu.set(ContextMenuState::default());
                                        },
                                        span { "🦶" }
                                        span { "Function Stomping" }
                                    }

                                    // Manual Map method
                                    button {
                                        class: "context-menu-item",
                                        onclick: move |_| {
                                            let target_pid = ctx_menu.pid;
                                            context_menu.set(ContextMenuState::default());

                                            if let Some(pid) = target_pid {
                                                spawn(async move {
                                                    let file = rfd::AsyncFileDialog::new()
                                                        .add_filter("DLL Files", &["dll"])
                                                        .set_title("Select DLL to inject (Manual Map)")
                                                        .pick_file()
                                                        .await;

                                                    if let Some(file) = file {
                                                        let path = file.path().to_string_lossy().to_string();
                                                        match inject_dll_manual_map(pid, &path) {
                                                            Ok(()) => {
                                                                status_message.set(format!(
                                                                    "✓ DLL injected into process {} (Manual Map)",
                                                                    pid
                                                                ));
                                                            }
                                                            Err(e) => {
                                                                status_message.set(format!(
                                                                    "✗ Manual map injection failed: {}",
                                                                    e
                                                                ));
                                                            }
                                                        }
                                                        spawn(async move {
                                                            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                                                            status_message.set(String::new());
                                                        });
                                                    }
                                                });
                                            }
                                        },
                                        span { "🗺️" }
                                        span { "Manual Map" }
                                    }
                                }
                            }

                            // Shellcode Injection sub-submenu
                            div {
                                class: "context-menu-submenu",
                                div {
                                    class: "context-menu-submenu-trigger",
                                    span { "🎯" }
                                    span { "Shellcode Injection" }
                                    span { class: "arrow", "▶" }
                                }
                                div {
                                    class: "context-menu-submenu-content",
                                    // Classic method
                                    button {
                                        class: "context-menu-item",
                                        onclick: move |_| {
                                            let target_pid = ctx_menu.pid;
                                            context_menu.set(ContextMenuState::default());

                                            if let Some(pid) = target_pid {
                                                spawn(async move {
                                                    let file = rfd::AsyncFileDialog::new()
                                                        .add_filter("Shellcode Binary", &["bin"])
                                                        .add_filter("All Files", &["*"])
                                                        .set_title("Select Shellcode (.bin)")
                                                        .pick_file()
                                                        .await;

                                                    if let Some(file) = file {
                                                        let path = file.path().to_string_lossy().to_string();
                                                        match inject_shellcode_classic(pid, &path) {
                                                            Ok(()) => {
                                                                status_message.set(format!(
                                                                    "✓ Shellcode injected into process {} (Classic)",
                                                                    pid
                                                                ));
                                                            }
                                                            Err(e) => {
                                                                status_message.set(format!(
                                                                    "✗ Shellcode injection failed: {}",
                                                                    e
                                                                ));
                                                            }
                                                        }
                                                        spawn(async move {
                                                            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                                                            status_message.set(String::new());
                                                        });
                                                    }
                                                });
                                            }
                                        },
                                        span { "🎯" }
                                        span { "Classic" }
                                    }

                                    // Web Staging method (opens dedicated window)
                                    button {
                                        class: "context-menu-item",
                                        onclick: move |_| {
                                            if let Some(pid) = ctx_menu.pid {
                                                let proc_name = processes.read()
                                                    .iter()
                                                    .find(|p| p.pid == pid)
                                                    .map(|p| p.name.clone())
                                                    .unwrap_or_else(|| format!("PID {}", pid));
                                                *SHELLCODE_INJECT_WINDOW_STATE.write() = Some((pid, proc_name));
                                            }
                                            context_menu.set(ContextMenuState::default());
                                        },
                                        span { "🌐" }
                                        span { "Web Staging" }
                                    }

                                    // Threadless method (opens dedicated window)
                                    button {
                                        class: "context-menu-item",
                                        onclick: move |_| {
                                            if let Some(pid) = ctx_menu.pid {
                                                let proc_name = processes.read()
                                                    .iter()
                                                    .find(|p| p.pid == pid)
                                                    .map(|p| p.name.clone())
                                                    .unwrap_or_else(|| format!("PID {}", pid));
                                                *THREADLESS_INJECT_WINDOW_STATE.write() = Some((pid, proc_name));
                                            }
                                            context_menu.set(ContextMenuState::default());
                                        },
                                        span { "🪝" }
                                        span { "Threadless" }
                                    }
                                }
                            }

                            // DLL Unhooking sub-submenu
                            div {
                                class: "context-menu-submenu",
                                div {
                                    class: "context-menu-submenu-trigger",
                                    span { "🔓" }
                                    span { "DLL Unhook" }
                                    span { class: "arrow", "▶" }
                                }
                                div {
                                    class: "context-menu-submenu-content context-menu-columns",
                                    // Dynamically list all loaded modules in columns of 10
                                    {
                                        let modules: Vec<_> = ctx_menu.pid.map(|pid| enumerate_process_modules(pid).unwrap_or_default()).unwrap_or_default();
                                        let chunks: Vec<Vec<_>> = modules.chunks(10).map(|c| c.to_vec()).collect();
                                        chunks.into_iter().enumerate().map(|(col_idx, chunk)| {
                                            rsx! {
                                                div {
                                                    key: "col-{col_idx}",
                                                    class: "context-menu-column",
                                                    {chunk.into_iter().map(|(name, full_path, base, _size)| {
                                                        let dll_name_for_key = name.clone();
                                                        let dll_name_for_closure = name.clone();
                                                        let dll_path = full_path.clone();
                                                        let dll_base = base;
                                                        let display_name = name.clone();
                                                        let target_pid = ctx_menu.pid;
                                                        rsx! {
                                                            button {
                                                                key: "{dll_name_for_key}",
                                                                class: "context-menu-item",
                                                                onclick: move |_| {
                                                                    context_menu.set(ContextMenuState::default());
                                                                    if let Some(pid) = target_pid {
                                                                        let path = std::path::Path::new(&dll_path);
                                                                        let name = dll_name_for_closure.clone();
                                                                        match unhook_dll_remote_by_path(pid, path, &name, dll_base) {
                                                                            Ok(result) => {
                                                                                status_message.set(format!(
                                                                                    "✓ {} unhooked in PID {} ({} bytes replaced)",
                                                                                    result.dll_name, pid, result.bytes_replaced
                                                                                ));
                                                                            }
                                                                            Err(e) => {
                                                                                status_message.set(format!(
                                                                                    "✗ Unhook {} failed: {}",
                                                                                    name, e
                                                                                ));
                                                                            }
                                                                        }
                                                                    }
                                                                    spawn(async move {
                                                                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                                                                        status_message.set(String::new());
                                                                    });
                                                                },
                                                                span { "📦" }
                                                                span { "{display_name}" }
                                                            }
                                                        }
                                                    })}
                                                }
                                            }
                                        })
                                    }
                                }
                            }

                            // Steal Token button
                            button {
                                class: "context-menu-item",
                                onclick: move |_| {
                                    if let Some(pid) = ctx_menu.pid {
                                        let proc_name = processes.read()
                                            .iter()
                                            .find(|p| p.pid == pid)
                                            .map(|p| p.name.clone())
                                            .unwrap_or_else(|| format!("PID {}", pid));
                                        *TOKEN_THIEF_WINDOW_STATE.write() = Some((pid, proc_name));
                                    }
                                    context_menu.set(ContextMenuState::default());
                                },
                                span { "🔑" }
                                span { "Steal Token" }
                            }
                        }
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

            // Module Window Modal
            if let Some((pid, proc_name)) = MODULE_WINDOW_STATE.read().clone() {
                ModuleWindow { pid: pid, process_name: proc_name }
            }

            // Memory Window Modal
            if let Some((pid, proc_name)) = MEMORY_WINDOW_STATE.read().clone() {
                MemoryWindow { pid: pid, process_name: proc_name }
            }

            // Graph Window Modal
            if let Some((pid, proc_name)) = GRAPH_WINDOW_STATE.read().clone() {
                GraphWindow { pid: pid, process_name: proc_name }
            }

            // Hook Scan Window Modal
            if let Some((pid, proc_name)) = HOOK_SCAN_WINDOW_STATE.read().clone() {
                HookScanWindow { pid: pid, process_name: proc_name }
            }

            // String Scan Window Modal
            if let Some((pid, proc_name)) = STRING_SCAN_WINDOW_STATE.read().clone() {
                StringScanWindow { pid: pid, process_name: proc_name }
            }

            // Create Process Window Modal
            if *CREATE_PROCESS_WINDOW_STATE.read() {
                CreateProcessWindow {}
            }

            // Token Thief Window Modal
            if let Some((pid, proc_name)) = TOKEN_THIEF_WINDOW_STATE.read().clone() {
                TokenThiefWindow { pid: pid, process_name: proc_name }
            }

            // Function Stomping Window Modal
            if let Some((pid, proc_name)) = FUNCTION_STOMPING_WINDOW_STATE.read().clone() {
                FunctionStompingWindow { pid: pid, process_name: proc_name }
            }

            // Shellcode Inject Window Modal (Web Staging)
            if let Some((pid, proc_name)) = SHELLCODE_INJECT_WINDOW_STATE.read().clone() {
                ShellcodeInjectWindow { pid: pid, process_name: proc_name }
            }

            // Threadless Inject Window Modal
            if let Some((pid, proc_name)) = THREADLESS_INJECT_WINDOW_STATE.read().clone() {
                ThreadlessInjectWindow { pid: pid, process_name: proc_name }
            }

            // Create Ghosting Window Modal
            if *GHOST_PROCESS_WINDOW_STATE.read() {
                GhostProcessWindow {}
            }

        }
    }
}
