//! Kernel Callback Monitor tab component

use callback::{is_driver_loaded, read_events, CallbackEvent, EventCategory, EventType};
use dioxus::prelude::*;

use crate::helpers::copy_to_clipboard;

/// Maximum events to keep in the list
const MAX_EVENTS: usize = 10_000;

/// Sort column for callback table
#[derive(Clone, Copy, PartialEq, Debug)]
enum CallbackSortColumn {
    Time,
    Type,
    Pid,
    ProcessName,
    Details,
}

/// Sort order
#[derive(Clone, Copy, PartialEq, Debug)]
enum SortOrder {
    Ascending,
    Descending,
}

/// Context menu state
#[derive(Clone, Debug, Default)]
struct ContextMenuState {
    visible: bool,
    x: i32,
    y: i32,
    event_index: Option<usize>,
}

/// Callback Tab component
#[component]
pub fn CallbackTab() -> Element {
    let mut events = use_signal(Vec::<CallbackEvent>::new);
    let mut search_query = use_signal(|| String::new());
    let mut sort_column = use_signal(|| CallbackSortColumn::Time);
    let mut sort_order = use_signal(|| SortOrder::Descending);
    let mut auto_refresh = use_signal(|| true);
    let mut type_filter = use_signal(|| String::new());
    let mut selected_row = use_signal(|| None::<usize>);
    let mut status_message = use_signal(|| String::new());
    let mut context_menu = use_signal(ContextMenuState::default);
    let mut driver_loaded = use_signal(|| is_driver_loaded());

    // Auto-refresh every 1 second
    use_future(move || async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            driver_loaded.set(is_driver_loaded());

            if *auto_refresh.read() && *driver_loaded.read() {
                match read_events() {
                    Ok(new_events) => {
                        if !new_events.is_empty() {
                            let mut current = events.read().clone();
                            current.extend(new_events);
                            // Keep only the most recent MAX_EVENTS
                            if current.len() > MAX_EVENTS {
                                current.drain(0..current.len() - MAX_EVENTS);
                            }
                            events.set(current);
                        }
                    }
                    Err(e) => {
                        // Only show error once if driver goes offline
                        if *driver_loaded.read() {
                            status_message.set(format!("Error: {}", e));
                            spawn(async move {
                                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                                status_message.set(String::new());
                            });
                        }
                    }
                }
            }
        }
    });

    // Filter and sort events
    let mut filtered_events: Vec<(usize, CallbackEvent)> = events
        .read()
        .iter()
        .enumerate()
        .filter(|(_, e)| {
            // Type filter
            let type_match = match type_filter.read().as_str() {
                // Categories
                "cat_process" => e.event_type.category() == EventCategory::Process,
                "cat_thread" => e.event_type.category() == EventCategory::Thread,
                "cat_image" => e.event_type.category() == EventCategory::Image,
                "cat_handle" => e.event_type.category() == EventCategory::Handle,
                "cat_registry" => e.event_type.category() == EventCategory::Registry,
                // Individual process events
                "process_create" => e.event_type == EventType::ProcessCreate,
                "process_exit" => e.event_type == EventType::ProcessExit,
                // Individual thread events
                "thread_create" => e.event_type == EventType::ThreadCreate,
                "thread_exit" => e.event_type == EventType::ThreadExit,
                // Image load
                "image_load" => e.event_type == EventType::ImageLoad,
                // Handle operations
                "process_handle_create" => e.event_type == EventType::ProcessHandleCreate,
                "process_handle_dup" => e.event_type == EventType::ProcessHandleDuplicate,
                "thread_handle_create" => e.event_type == EventType::ThreadHandleCreate,
                "thread_handle_dup" => e.event_type == EventType::ThreadHandleDuplicate,
                // Registry operations
                "reg_create" => e.event_type == EventType::RegistryCreate,
                "reg_open" => e.event_type == EventType::RegistryOpen,
                "reg_setvalue" => e.event_type == EventType::RegistrySetValue,
                "reg_deletekey" => e.event_type == EventType::RegistryDeleteKey,
                "reg_deletevalue" => e.event_type == EventType::RegistryDeleteValue,
                "reg_rename" => e.event_type == EventType::RegistryRenameKey,
                "reg_query" => e.event_type == EventType::RegistryQueryValue,
                "all" => true,
                _ => true,
            };

            // Search filter
            let query = search_query.read().to_lowercase();
            let search_match = if query.is_empty() {
                true
            } else {
                e.process_id.to_string().contains(&query)
                    || e.process_name.to_lowercase().contains(&query)
                    || e.command_line
                        .as_ref()
                        .map(|c| c.to_lowercase().contains(&query))
                        .unwrap_or(false)
                    || e.thread_id
                        .map(|tid| tid.to_string().contains(&query))
                        .unwrap_or(false)
                    || e.image_name
                        .as_ref()
                        .map(|n| n.to_lowercase().contains(&query))
                        .unwrap_or(false)
                    || e.key_name
                        .as_ref()
                        .map(|k| k.to_lowercase().contains(&query))
                        .unwrap_or(false)
                    || e.value_name
                        .as_ref()
                        .map(|v| v.to_lowercase().contains(&query))
                        .unwrap_or(false)
                    || e.source_image_name
                        .as_ref()
                        .map(|s| s.to_lowercase().contains(&query))
                        .unwrap_or(false)
            };

            type_match && search_match
        })
        .map(|(i, e)| (i, e.clone()))
        .collect();

    // Sort
    filtered_events.sort_by(|(_, a), (_, b)| {
        let cmp = match *sort_column.read() {
            CallbackSortColumn::Time => a.timestamp.cmp(&b.timestamp),
            CallbackSortColumn::Type => a.event_type.to_string().cmp(&b.event_type.to_string()),
            CallbackSortColumn::Pid => a.process_id.cmp(&b.process_id),
            CallbackSortColumn::ProcessName => a
                .process_name
                .to_lowercase()
                .cmp(&b.process_name.to_lowercase()),
            CallbackSortColumn::Details => a.get_details().cmp(&b.get_details()),
        };
        match *sort_order.read() {
            SortOrder::Ascending => cmp,
            SortOrder::Descending => cmp.reverse(),
        }
    });

    let event_count = filtered_events.len();
    let total_count = events.read().len();
    let is_driver_loaded = *driver_loaded.read();
    let current_sort_col = *sort_column.read();
    let current_sort_ord = *sort_order.read();
    let ctx_menu = context_menu.read().clone();
    let export_events = filtered_events.clone();
    let filtered_events_empty = filtered_events.is_empty();

    let sort_indicator = |column: CallbackSortColumn| -> &'static str {
        if current_sort_col == column {
            match current_sort_ord {
                SortOrder::Ascending => " ▲",
                SortOrder::Descending => " ▼",
            }
        } else {
            ""
        }
    };

    // Keyboard shortcuts handler
    let handle_keydown = move |e: KeyboardEvent| {
        if e.key() == Key::Escape {
            context_menu.set(ContextMenuState::default());
        }
        if e.key() == Key::F5 {
            if is_driver_loaded {
                match read_events() {
                    Ok(new_events) => {
                        let mut current = events.read().clone();
                        current.extend(new_events);
                        if current.len() > MAX_EVENTS {
                            current.drain(0..current.len() - MAX_EVENTS);
                        }
                        events.set(current);
                        status_message.set(format!("Refreshed - {} events", events.read().len()));
                    }
                    Err(e) => {
                        status_message.set(format!("Error: {}", e));
                    }
                }
                spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    status_message.set(String::new());
                });
            }
        }
    };

    // Get selected event data for context menu (clone the data we need)
    let selected_event_pid = ctx_menu.event_index.and_then(|idx| events.read().get(idx).map(|e| e.process_id));
    let selected_event_name = ctx_menu.event_index.and_then(|idx| events.read().get(idx).map(|e| e.process_name.clone()));
    let selected_event_cmd = ctx_menu.event_index.and_then(|idx| events.read().get(idx).and_then(|e| e.command_line.clone()));
    let has_command_line = selected_event_cmd.is_some();

    rsx! {
        div {
            class: "callback-tab",
            tabindex: "0",
            onkeydown: handle_keydown,
            onclick: move |_| context_menu.set(ContextMenuState::default()),

            // Header
            div { class: "header-box",
                h1 { class: "header-title", "Kernel Callback Monitor" }
                div { class: "header-stats",
                    span { "Events: {event_count}/{total_count}" }
                    span { class: "header-shortcuts", "F5: Refresh | Esc: Close menu" }
                    // Driver status indicator
                    span {
                        class: if is_driver_loaded { "driver-status driver-status-loaded" } else { "driver-status driver-status-not-loaded" },
                        if is_driver_loaded {
                            "Driver: Loaded"
                        } else {
                            "Driver: Not Loaded"
                        }
                    }
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
                    placeholder: "Search by PID, process name, command line...",
                    value: "{search_query}",
                    oninput: move |e| search_query.set(e.value().clone()),
                }

                select {
                    class: "filter-select callback-filter-select",
                    value: "{type_filter}",
                    onchange: move |e| type_filter.set(e.value().clone()),
                    option { value: "all", "All Events" }
                    // Categories
                    optgroup { label: "Categories",
                        option { value: "cat_process", "Process Events" }
                        option { value: "cat_thread", "Thread Events" }
                        option { value: "cat_image", "Image Load Events" }
                        option { value: "cat_handle", "Handle Events" }
                        option { value: "cat_registry", "Registry Events" }
                    }
                    // Process events
                    optgroup { label: "Process",
                        option { value: "process_create", "Process Create" }
                        option { value: "process_exit", "Process Exit" }
                    }
                    // Thread events
                    optgroup { label: "Thread",
                        option { value: "thread_create", "Thread Create" }
                        option { value: "thread_exit", "Thread Exit" }
                    }
                    // Image load
                    optgroup { label: "Image",
                        option { value: "image_load", "Image Load" }
                    }
                    // Handle events
                    optgroup { label: "Handle Operations",
                        option { value: "process_handle_create", "Process Handle Create" }
                        option { value: "process_handle_dup", "Process Handle Duplicate" }
                        option { value: "thread_handle_create", "Thread Handle Create" }
                        option { value: "thread_handle_dup", "Thread Handle Duplicate" }
                    }
                    // Registry events
                    optgroup { label: "Registry",
                        option { value: "reg_create", "Registry Create" }
                        option { value: "reg_open", "Registry Open" }
                        option { value: "reg_setvalue", "Registry SetValue" }
                        option { value: "reg_deletekey", "Registry DeleteKey" }
                        option { value: "reg_deletevalue", "Registry DeleteValue" }
                        option { value: "reg_rename", "Registry Rename" }
                        option { value: "reg_query", "Registry Query" }
                    }
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
                    disabled: !is_driver_loaded,
                    onclick: move |_| {
                        if is_driver_loaded {
                            match read_events() {
                                Ok(new_events) => {
                                    let mut current = events.read().clone();
                                    current.extend(new_events);
                                    if current.len() > MAX_EVENTS {
                                        current.drain(0..current.len() - MAX_EVENTS);
                                    }
                                    events.set(current);
                                    status_message.set(format!("Refreshed - {} events", events.read().len()));
                                }
                                Err(e) => {
                                    status_message.set(format!("Error: {}", e));
                                }
                            }
                            spawn(async move {
                                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                                status_message.set(String::new());
                            });
                        }
                    },
                    "Refresh"
                }

                button {
                    class: "btn btn-secondary",
                    disabled: events.read().is_empty(),
                    onclick: move |_| {
                        events.set(Vec::new());
                        selected_row.set(None);
                        status_message.set("Events cleared".to_string());
                        spawn(async move {
                            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                            status_message.set(String::new());
                        });
                    },
                    "Clear"
                }

                button {
                    class: "btn btn-secondary",
                    disabled: filtered_events_empty,
                    onclick: {
                        let evts = export_events.clone();
                        move |_| {
                            let evts = evts.clone();
                            spawn(async move {
                                let file = rfd::AsyncFileDialog::new()
                                    .add_filter("CSV", &["csv"])
                                    .set_file_name("callback_events.csv")
                                    .set_title("Export Callback Events")
                                    .save_file()
                                    .await;
                                if let Some(file) = file {
                                    let path = file.path().to_path_buf();
                                    let mut csv = String::from("Timestamp,Type,PID,Process Name,Details\n");
                                    for (_, e) in &evts {
                                        csv.push_str(&format!(
                                            "{},{},{},\"{}\",\"{}\"\n",
                                            e.format_timestamp(),
                                            e.event_type,
                                            e.process_id,
                                            e.process_name.replace('"', "\"\""),
                                            e.get_details().replace('"', "\"\"")
                                        ));
                                    }
                                    match std::fs::write(&path, csv) {
                                        Ok(()) => {
                                            status_message.set(format!("Exported {} events to {}", evts.len(), path.display()));
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
            }

            // Events table
            div { class: "table-container",
                if !is_driver_loaded {
                    div { class: "driver-not-loaded-notice",
                        h2 { "DioProcess Driver Not Loaded" }
                        p { "To use the Callback Monitor, load the kernel driver:" }
                        pre { class: "driver-instructions",
                            "sc create DioProcess type= kernel binPath= \"C:\\path\\to\\DioProcess.sys\"\nsc start DioProcess"
                        }
                        p { class: "driver-note", "Note: Requires administrator privileges and test signing mode for unsigned drivers." }
                    }
                } else {
                    table { class: "process-table callback-table",
                        thead { class: "table-header",
                            tr {
                                th {
                                    class: "th sortable",
                                    onclick: move |_| {
                                        if *sort_column.read() == CallbackSortColumn::Time {
                                            let new_order = if *sort_order.read() == SortOrder::Ascending { SortOrder::Descending } else { SortOrder::Ascending };
                                            sort_order.set(new_order);
                                        } else {
                                            sort_column.set(CallbackSortColumn::Time);
                                            sort_order.set(SortOrder::Descending);
                                        }
                                    },
                                    "Time{sort_indicator(CallbackSortColumn::Time)}"
                                }
                                th {
                                    class: "th sortable",
                                    onclick: move |_| {
                                        if *sort_column.read() == CallbackSortColumn::Type {
                                            let new_order = if *sort_order.read() == SortOrder::Ascending { SortOrder::Descending } else { SortOrder::Ascending };
                                            sort_order.set(new_order);
                                        } else {
                                            sort_column.set(CallbackSortColumn::Type);
                                            sort_order.set(SortOrder::Ascending);
                                        }
                                    },
                                    "Type{sort_indicator(CallbackSortColumn::Type)}"
                                }
                                th {
                                    class: "th sortable",
                                    onclick: move |_| {
                                        if *sort_column.read() == CallbackSortColumn::Pid {
                                            let new_order = if *sort_order.read() == SortOrder::Ascending { SortOrder::Descending } else { SortOrder::Ascending };
                                            sort_order.set(new_order);
                                        } else {
                                            sort_column.set(CallbackSortColumn::Pid);
                                            sort_order.set(SortOrder::Ascending);
                                        }
                                    },
                                    "PID{sort_indicator(CallbackSortColumn::Pid)}"
                                }
                                th {
                                    class: "th sortable",
                                    onclick: move |_| {
                                        if *sort_column.read() == CallbackSortColumn::ProcessName {
                                            let new_order = if *sort_order.read() == SortOrder::Ascending { SortOrder::Descending } else { SortOrder::Ascending };
                                            sort_order.set(new_order);
                                        } else {
                                            sort_column.set(CallbackSortColumn::ProcessName);
                                            sort_order.set(SortOrder::Ascending);
                                        }
                                    },
                                    "Process{sort_indicator(CallbackSortColumn::ProcessName)}"
                                }
                                th {
                                    class: "th sortable",
                                    onclick: move |_| {
                                        if *sort_column.read() == CallbackSortColumn::Details {
                                            let new_order = if *sort_order.read() == SortOrder::Ascending { SortOrder::Descending } else { SortOrder::Ascending };
                                            sort_order.set(new_order);
                                        } else {
                                            sort_column.set(CallbackSortColumn::Details);
                                            sort_order.set(SortOrder::Ascending);
                                        }
                                    },
                                    "Details{sort_indicator(CallbackSortColumn::Details)}"
                                }
                            }
                        }
                        tbody {
                            for (idx, event) in filtered_events {
                                {
                                    let is_selected = *selected_row.read() == Some(idx);
                                    let row_class = if is_selected { "process-row selected" } else { "process-row" };
                                    let event_type_class = match event.event_type {
                                        EventType::ProcessCreate => "event-type-process-create",
                                        EventType::ProcessExit => "event-type-process-exit",
                                        EventType::ThreadCreate => "event-type-thread-create",
                                        EventType::ThreadExit => "event-type-thread-exit",
                                        EventType::ImageLoad => "event-type-image-load",
                                        EventType::ProcessHandleCreate | EventType::ProcessHandleDuplicate => "event-type-handle-process",
                                        EventType::ThreadHandleCreate | EventType::ThreadHandleDuplicate => "event-type-handle-thread",
                                        EventType::RegistryCreate | EventType::RegistryOpen => "event-type-registry-read",
                                        EventType::RegistrySetValue | EventType::RegistryDeleteKey | EventType::RegistryDeleteValue | EventType::RegistryRenameKey => "event-type-registry-write",
                                        EventType::RegistryQueryValue => "event-type-registry-read",
                                    };
                                    let time_str = event.format_timestamp();
                                    let details = event.get_details();
                                    let cmd_tooltip = event.command_line.as_deref().unwrap_or("").to_string();

                                    rsx! {
                                        tr {
                                            key: "{idx}-{event.timestamp}",
                                            class: "{row_class}",
                                            onclick: move |_| {
                                                let current = *selected_row.read();
                                                if current == Some(idx) {
                                                    selected_row.set(None);
                                                } else {
                                                    selected_row.set(Some(idx));
                                                }
                                            },
                                            oncontextmenu: move |e| {
                                                e.prevent_default();
                                                let coords = e.client_coordinates();
                                                selected_row.set(Some(idx));
                                                context_menu.set(ContextMenuState {
                                                    visible: true,
                                                    x: coords.x as i32,
                                                    y: coords.y as i32,
                                                    event_index: Some(idx),
                                                });
                                            },
                                            td { class: "cell cell-time", "{time_str}" }
                                            td { class: "cell cell-event-type {event_type_class}", "{event.event_type}" }
                                            td { class: "cell cell-pid", "{event.process_id}" }
                                            td { class: "cell cell-name", "{event.process_name}" }
                                            td {
                                                class: "cell cell-details",
                                                title: "{cmd_tooltip}",
                                                "{details}"
                                            }
                                        }
                                    }
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

                    button {
                        class: "context-menu-item",
                        onclick: {
                            let pid = selected_event_pid;
                            move |_| {
                                if let Some(p) = pid {
                                    copy_to_clipboard(&p.to_string());
                                    status_message.set(format!("Copied PID: {}", p));
                                    spawn(async move {
                                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                                        status_message.set(String::new());
                                    });
                                }
                                context_menu.set(ContextMenuState::default());
                            }
                        },
                        span { "Copy PID" }
                    }

                    button {
                        class: "context-menu-item",
                        onclick: {
                            let name = selected_event_name.clone();
                            move |_| {
                                if let Some(ref n) = name {
                                    copy_to_clipboard(n);
                                    status_message.set(format!("Copied: {}", n));
                                    spawn(async move {
                                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                                        status_message.set(String::new());
                                    });
                                }
                                context_menu.set(ContextMenuState::default());
                            }
                        },
                        span { "Copy Process Name" }
                    }

                    if has_command_line {
                        button {
                            class: "context-menu-item",
                            onclick: {
                                let cmd = selected_event_cmd.clone();
                                move |_| {
                                    if let Some(ref c) = cmd {
                                        copy_to_clipboard(c);
                                        status_message.set("Copied command line".to_string());
                                        spawn(async move {
                                            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                                            status_message.set(String::new());
                                        });
                                    }
                                    context_menu.set(ContextMenuState::default());
                                }
                            },
                            span { "Copy Command Line" }
                        }
                    }

                    div { class: "context-menu-separator" }

                    button {
                        class: "context-menu-item",
                        onclick: {
                            let pid = selected_event_pid;
                            move |_| {
                                if let Some(p) = pid {
                                    search_query.set(p.to_string());
                                }
                                context_menu.set(ContextMenuState::default());
                            }
                        },
                        span { "Filter by this PID" }
                    }

                    button {
                        class: "context-menu-item",
                        onclick: {
                            let name = selected_event_name.clone();
                            move |_| {
                                if let Some(ref n) = name {
                                    search_query.set(n.clone());
                                }
                                context_menu.set(ContextMenuState::default());
                            }
                        },
                        span { "Filter by Process Name" }
                    }
                }
            }
        }
    }
}
