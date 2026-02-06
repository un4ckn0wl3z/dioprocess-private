//! System Events tab component (Kernel Callback Monitor)

use callback::{
    get_collection_state, is_driver_loaded, read_events, start_collection,
    stop_collection, CallbackEvent, EventCategory, EventFilter,
    EventStorage, EventType,
};
use dioxus::prelude::*;
use std::sync::Arc;

use crate::helpers::copy_to_clipboard;

/// Page size for database queries
const PAGE_SIZE: usize = 500;

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
    // Initialize storage once
    let storage: Signal<Option<Arc<EventStorage>>> = use_signal(|| {
        EventStorage::open_default().ok().map(Arc::new)
    });

    let mut events = use_signal(Vec::<CallbackEvent>::new);
    let mut total_count = use_signal(|| 0usize);
    let mut search_query = use_signal(|| String::new());
    let mut sort_column = use_signal(|| CallbackSortColumn::Time);
    let mut sort_order = use_signal(|| SortOrder::Descending);
    let mut auto_refresh = use_signal(|| true);
    let mut type_filter = use_signal(|| String::new());
    let mut selected_row = use_signal(|| None::<usize>);
    let mut status_message = use_signal(|| String::new());
    let mut context_menu = use_signal(ContextMenuState::default);
    let mut driver_loaded = use_signal(|| is_driver_loaded());
    let mut current_page = use_signal(|| 0usize);
    // Trigger signal to force refresh from DB
    let mut refresh_trigger = use_signal(|| 0u64);
    // Collection state - initialized from driver
    let mut collection_active = use_signal(|| false);

    // Helper to build filter from current UI state
    let build_filter = |tf: &str, sq: &str| {
        let mut filter = EventFilter::new();

        if !sq.is_empty() {
            filter = filter.with_search(sq.to_string());
        }

        match tf {
            "cat_process" => filter = filter.with_category(EventCategory::Process),
            "cat_thread" => filter = filter.with_category(EventCategory::Thread),
            "cat_image" => filter = filter.with_category(EventCategory::Image),
            "cat_handle" => filter = filter.with_category(EventCategory::Handle),
            "cat_registry" => filter = filter.with_category(EventCategory::Registry),
            "process_create" => filter = filter.with_type(EventType::ProcessCreate),
            "process_exit" => filter = filter.with_type(EventType::ProcessExit),
            "thread_create" => filter = filter.with_type(EventType::ThreadCreate),
            "thread_exit" => filter = filter.with_type(EventType::ThreadExit),
            "image_load" => filter = filter.with_type(EventType::ImageLoad),
            "process_handle_create" => filter = filter.with_type(EventType::ProcessHandleCreate),
            "process_handle_dup" => filter = filter.with_type(EventType::ProcessHandleDuplicate),
            "thread_handle_create" => filter = filter.with_type(EventType::ThreadHandleCreate),
            "thread_handle_dup" => filter = filter.with_type(EventType::ThreadHandleDuplicate),
            "reg_create" => filter = filter.with_type(EventType::RegistryCreate),
            "reg_open" => filter = filter.with_type(EventType::RegistryOpen),
            "reg_setvalue" => filter = filter.with_type(EventType::RegistrySetValue),
            "reg_deletekey" => filter = filter.with_type(EventType::RegistryDeleteKey),
            "reg_deletevalue" => filter = filter.with_type(EventType::RegistryDeleteValue),
            "reg_rename" => filter = filter.with_type(EventType::RegistryRenameKey),
            "reg_query" => filter = filter.with_type(EventType::RegistryQueryValue),
            _ => {}
        }

        filter
    };

    // Effect to refresh from DB when trigger changes
    use_effect(move || {
        let _ = *refresh_trigger.read(); // Subscribe to trigger
        let tf = type_filter.read().clone();
        let sq = search_query.read().clone();
        let page = *current_page.read();

        if let Some(ref store) = *storage.read() {
            let filter = build_filter(&tf, &sq);
            let fetched = store.query_events(&filter, PAGE_SIZE, page * PAGE_SIZE);
            let count = store.count_events(&filter);
            events.set(fetched);
            total_count.set(count);
        }
    });

    // Effect to query driver collection state when driver_loaded changes
    use_effect(move || {
        let loaded = *driver_loaded.read();
        if loaded {
            if let Ok(state) = get_collection_state() {
                collection_active.set(state.is_collecting);
            }
        } else {
            collection_active.set(false);
        }
    });

    // Auto-refresh every 1 second
    use_future(move || async move {
        let mut cleanup_counter = 0u32;

        loop {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            driver_loaded.set(is_driver_loaded());

            // Update collection state from driver
            if *driver_loaded.read() {
                if let Ok(state) = get_collection_state() {
                    collection_active.set(state.is_collecting);
                }
            }

            // Only read events if collection is active, auto-refresh is enabled, and driver is loaded
            if *auto_refresh.read() && *driver_loaded.read() && *collection_active.read() {
                match read_events() {
                    Ok(new_events) => {
                        if !new_events.is_empty() {
                            if let Some(ref store) = *storage.read() {
                                store.add_events(new_events);
                            }
                        }
                    }
                    Err(e) => {
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

            // Always trigger UI refresh when auto-refresh is enabled
            if *auto_refresh.read() {
                refresh_trigger += 1;
            }

            // Cleanup every hour (3600 iterations)
            cleanup_counter += 1;
            if cleanup_counter >= 3600 {
                cleanup_counter = 0;
                if let Some(ref store) = *storage.read() {
                    callback::storage::run_retention_cleanup(store);
                }
            }
        }
    });

    // Events are now fetched from database with filtering applied
    let displayed_events: Vec<(usize, CallbackEvent)> = events
        .read()
        .iter()
        .enumerate()
        .map(|(i, e)| (i, e.clone()))
        .collect();

    let event_count = displayed_events.len();
    let total = *total_count.read();
    let page = *current_page.read();
    let total_pages = (total + PAGE_SIZE - 1) / PAGE_SIZE;
    let is_driver_loaded = *driver_loaded.read();
    let is_collection_active = *collection_active.read();
    let current_sort_col = *sort_column.read();
    let current_sort_ord = *sort_order.read();
    let ctx_menu = context_menu.read().clone();
    let export_events = displayed_events.clone();
    let displayed_events_empty = displayed_events.is_empty();
    let db_size = storage.read().as_ref().map(|s| s.db_size()).unwrap_or(0);
    let db_size_mb = db_size as f64 / (1024.0 * 1024.0);

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
                        if let Some(ref store) = *storage.read() {
                            store.add_events(new_events);
                        }
                        refresh_trigger += 1;
                        status_message.set(format!("Refreshed - {} events", *total_count.read()));
                    }
                    Err(err) => {
                        status_message.set(format!("Error: {}", err));
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
                h1 { class: "header-title",
                    "System Events"
                    span { class: "experimental-badge", "Experimental" }
                }
                div { class: "header-stats",
                    span { "Showing: {event_count} | Total: {total} | DB: {db_size_mb:.1} MB" }
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
                    // Collection status indicator
                    if is_driver_loaded {
                        span {
                            class: if is_collection_active { "collection-status collection-active" } else { "collection-status collection-inactive" },
                            if is_collection_active {
                                "Collecting"
                            } else {
                                "Paused"
                            }
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

                // Start/Stop Collection button
                button {
                    class: if is_collection_active { "btn btn-danger" } else { "btn btn-success" },
                    disabled: !is_driver_loaded,
                    onclick: move |_| {
                        if is_collection_active {
                            match stop_collection() {
                                Ok(()) => {
                                    collection_active.set(false);
                                    status_message.set("Collection stopped".to_string());
                                }
                                Err(e) => {
                                    status_message.set(format!("Failed to stop collection: {}", e));
                                }
                            }
                        } else {
                            match start_collection() {
                                Ok(()) => {
                                    collection_active.set(true);
                                    status_message.set("Collection started".to_string());
                                }
                                Err(e) => {
                                    status_message.set(format!("Failed to start collection: {}", e));
                                }
                            }
                        }
                        spawn(async move {
                            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                            status_message.set(String::new());
                        });
                    },
                    if is_collection_active {
                        "Stop Collection"
                    } else {
                        "Start Collection"
                    }
                }

                button {
                    class: "btn btn-primary",
                    disabled: !is_driver_loaded,
                    onclick: move |_| {
                        if is_driver_loaded {
                            match read_events() {
                                Ok(new_events) => {
                                    if let Some(ref store) = *storage.read() {
                                        store.add_events(new_events);
                                    }
                                    refresh_trigger += 1;
                                    status_message.set(format!("Refreshed - {} total events", *total_count.read()));
                                }
                                Err(err) => {
                                    status_message.set(format!("Error: {}", err));
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
                    disabled: total == 0,
                    onclick: move |_| {
                        if let Some(ref store) = *storage.read() {
                            store.clear_all();
                        }
                        selected_row.set(None);
                        current_page.set(0);
                        refresh_trigger += 1;
                        status_message.set("All events cleared".to_string());
                        spawn(async move {
                            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                            status_message.set(String::new());
                        });
                    },
                    "Clear All"
                }

                button {
                    class: "btn btn-secondary",
                    disabled: displayed_events_empty,
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

                // Pagination controls
                if total_pages > 1 {
                    div { class: "pagination-controls",
                        button {
                            class: "btn btn-small",
                            disabled: page == 0,
                            onclick: move |_| {
                                current_page.set(0);
                                refresh_trigger += 1;
                            },
                            "<<"
                        }
                        button {
                            class: "btn btn-small",
                            disabled: page == 0,
                            onclick: move |_| {
                                current_page.set(page.saturating_sub(1));
                                refresh_trigger += 1;
                            },
                            "<"
                        }
                        span { class: "page-info", "Page {page + 1}/{total_pages}" }
                        button {
                            class: "btn btn-small",
                            disabled: page + 1 >= total_pages,
                            onclick: move |_| {
                                current_page.set(page + 1);
                                refresh_trigger += 1;
                            },
                            ">"
                        }
                        button {
                            class: "btn btn-small",
                            disabled: page + 1 >= total_pages,
                            onclick: move |_| {
                                current_page.set(total_pages.saturating_sub(1));
                                refresh_trigger += 1;
                            },
                            ">>"
                        }
                    }
                }
            }

            // Events table
            div { class: "table-container",
                if !is_driver_loaded {
                    div { class: "driver-not-loaded-notice",
                        h2 { "DioProcess Driver Not Loaded" }
                        p { "To use System Events, load the kernel driver:" }
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
                            for (idx, event) in displayed_events {
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
