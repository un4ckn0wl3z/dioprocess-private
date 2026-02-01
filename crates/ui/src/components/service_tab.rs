//! Windows services tab component

use dioxus::prelude::*;
use service::{
    create_service, delete_service, get_services, start_service, stop_service, ServiceInfo,
    ServiceStartType, ServiceStatus,
};

use crate::helpers::copy_to_clipboard;

/// Service context menu state
#[derive(Clone, Debug, Default)]
struct ServiceContextMenuState {
    visible: bool,
    x: i32,
    y: i32,
    name: String,
    binary_path: String,
    status: Option<ServiceStatus>,
}

/// Sort column for service table
#[derive(Clone, Copy, PartialEq, Debug)]
enum ServiceSortColumn {
    Name,
    DisplayName,
    Status,
    StartType,
    Pid,
    BinaryPath,
    Description,
}

/// Sort order
#[derive(Clone, Copy, PartialEq, Debug)]
enum SortOrder {
    Ascending,
    Descending,
}

/// Create service form state
#[derive(Clone, Debug, Default)]
struct CreateServiceForm {
    visible: bool,
    name: String,
    display_name: String,
    binary_path: String,
    start_type: String, // "auto", "manual", "disabled"
}

/// Service Tab component
#[component]
pub fn ServiceTab() -> Element {
    let mut services = use_signal(|| get_services());
    let mut search_query = use_signal(|| String::new());
    let mut sort_column = use_signal(|| ServiceSortColumn::Name);
    let mut sort_order = use_signal(|| SortOrder::Ascending);
    let mut auto_refresh = use_signal(|| true);
    let mut selected_service = use_signal(|| None::<String>); // service name
    let mut status_message = use_signal(|| String::new());
    let mut context_menu = use_signal(|| ServiceContextMenuState::default());
    let mut status_filter = use_signal(|| String::new()); // "", "running", "stopped"
    let mut start_type_filter = use_signal(|| String::new()); // "", "auto", "manual", "disabled"
    let mut create_form = use_signal(|| CreateServiceForm::default());

    // Auto-refresh every 3 seconds
    use_future(move || async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            if *auto_refresh.read() {
                services.set(get_services());
            }
        }
    });

    // Keyboard shortcuts handler
    let handle_keydown = move |e: KeyboardEvent| {
        // Don't handle shortcuts when create form is open
        if create_form.read().visible {
            return;
        }

        if e.key() == Key::Escape {
            context_menu.set(ServiceContextMenuState::default());
            return;
        }

        if e.key() == Key::F5 {
            services.set(get_services());
            return;
        }

        if e.key() == Key::Delete {
            let svc = selected_service.read().clone();
            if let Some(name) = svc {
                if delete_service(&name) {
                    status_message.set(format!("✓ Service '{}' deleted", name));
                    services.set(get_services());
                    selected_service.set(None);
                } else {
                    status_message.set(format!("✗ Failed to delete service '{}'", name));
                }
                spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                    status_message.set(String::new());
                });
            }
        }
    };

    // Filter and sort services
    let mut filtered_services: Vec<ServiceInfo> = services
        .read()
        .iter()
        .filter(|s| {
            // Status filter
            let status_match = match status_filter.read().as_str() {
                "running" => s.status == ServiceStatus::Running,
                "stopped" => s.status == ServiceStatus::Stopped,
                "paused" => s.status == ServiceStatus::Paused,
                "all" | "" => true,
                _ => true,
            };

            // Start type filter
            let start_match = match start_type_filter.read().as_str() {
                "auto" => s.start_type == ServiceStartType::Auto,
                "manual" => s.start_type == ServiceStartType::Manual,
                "disabled" => s.start_type == ServiceStartType::Disabled,
                "all" | "" => true,
                _ => true,
            };

            // Search filter
            let query = search_query.read().to_lowercase();
            let search_match = if query.is_empty() {
                true
            } else {
                s.name.to_lowercase().contains(&query)
                    || s.display_name.to_lowercase().contains(&query)
                    || s.description.to_lowercase().contains(&query)
                    || s.binary_path.to_lowercase().contains(&query)
                    || s.pid.to_string().contains(&query)
            };

            status_match && start_match && search_match
        })
        .cloned()
        .collect();

    // Sort
    filtered_services.sort_by(|a, b| {
        let cmp = match *sort_column.read() {
            ServiceSortColumn::Name => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
            ServiceSortColumn::DisplayName => a
                .display_name
                .to_lowercase()
                .cmp(&b.display_name.to_lowercase()),
            ServiceSortColumn::Status => a.status.to_string().cmp(&b.status.to_string()),
            ServiceSortColumn::StartType => {
                a.start_type.to_string().cmp(&b.start_type.to_string())
            }
            ServiceSortColumn::Pid => a.pid.cmp(&b.pid),
            ServiceSortColumn::BinaryPath => {
                a.binary_path.to_lowercase().cmp(&b.binary_path.to_lowercase())
            }
            ServiceSortColumn::Description => {
                a.description.to_lowercase().cmp(&b.description.to_lowercase())
            }
        };
        match *sort_order.read() {
            SortOrder::Ascending => cmp,
            SortOrder::Descending => cmp.reverse(),
        }
    });

    let service_count = filtered_services.len();
    let total_count = services.read().len();

    let current_sort_col = *sort_column.read();
    let current_sort_ord = *sort_order.read();
    let ctx_menu = context_menu.read().clone();
    let form = create_form.read().clone();

    let sort_indicator = |column: ServiceSortColumn| -> &'static str {
        if current_sort_col == column {
            match current_sort_ord {
                SortOrder::Ascending => " ▲",
                SortOrder::Descending => " ▼",
            }
        } else {
            ""
        }
    };

    // Helper to toggle sort
    let make_sort_handler = move |col: ServiceSortColumn| {
        move |_: MouseEvent| {
            if *sort_column.read() == col {
                let new_order = if *sort_order.read() == SortOrder::Ascending {
                    SortOrder::Descending
                } else {
                    SortOrder::Ascending
                };
                sort_order.set(new_order);
            } else {
                sort_column.set(col);
                sort_order.set(SortOrder::Ascending);
            }
        }
    };

    rsx! {
        div {
            class: "service-tab",
            tabindex: "0",
            onkeydown: handle_keydown,
            onclick: move |_| context_menu.set(ServiceContextMenuState::default()),

            // Header
            div { class: "header-box",
                h1 { class: "header-title", "⚙️ Windows Services" }
                div { class: "header-stats",
                    span { "Showing: {service_count}/{total_count} services" }
                    span { class: "header-shortcuts", "F5: Refresh | Del: Delete Service | Esc: Close menu" }
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
                    placeholder: "Search by name, description, path...",
                    value: "{search_query}",
                    oninput: move |e| search_query.set(e.value().clone()),
                }

                select {
                    class: "filter-select",
                    value: "{status_filter}",
                    onchange: move |e| status_filter.set(e.value().clone()),
                    option { value: "all", "All States" }
                    option { value: "running", "Running" }
                    option { value: "stopped", "Stopped" }
                    option { value: "paused", "Paused" }
                }

                select {
                    class: "filter-select",
                    value: "{start_type_filter}",
                    onchange: move |e| start_type_filter.set(e.value().clone()),
                    option { value: "all", "All Start Types" }
                    option { value: "auto", "Automatic" }
                    option { value: "manual", "Manual" }
                    option { value: "disabled", "Disabled" }
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
                        services.set(get_services());
                    },
                    "🔄 Refresh"
                }

                button {
                    class: "btn btn-primary",
                    onclick: move |_| {
                        create_form.set(CreateServiceForm {
                            visible: true,
                            name: String::new(),
                            display_name: String::new(),
                            binary_path: String::new(),
                            start_type: "manual".to_string(),
                        });
                    },
                    "➕ Create Service"
                }
            }

            // Service table
            div { class: "table-container",
                table { class: "process-table service-table",
                    thead { class: "table-header",
                        tr {
                            th {
                                class: "th sortable",
                                onclick: make_sort_handler(ServiceSortColumn::Name),
                                "Name{sort_indicator(ServiceSortColumn::Name)}"
                            }
                            th {
                                class: "th sortable",
                                onclick: make_sort_handler(ServiceSortColumn::DisplayName),
                                "Display Name{sort_indicator(ServiceSortColumn::DisplayName)}"
                            }
                            th {
                                class: "th sortable",
                                onclick: make_sort_handler(ServiceSortColumn::Status),
                                "Status{sort_indicator(ServiceSortColumn::Status)}"
                            }
                            th {
                                class: "th sortable",
                                onclick: make_sort_handler(ServiceSortColumn::StartType),
                                "Start Type{sort_indicator(ServiceSortColumn::StartType)}"
                            }
                            th {
                                class: "th sortable",
                                onclick: make_sort_handler(ServiceSortColumn::Pid),
                                "PID{sort_indicator(ServiceSortColumn::Pid)}"
                            }
                            th {
                                class: "th sortable",
                                onclick: make_sort_handler(ServiceSortColumn::BinaryPath),
                                "Binary Path{sort_indicator(ServiceSortColumn::BinaryPath)}"
                            }
                            th {
                                class: "th sortable",
                                onclick: make_sort_handler(ServiceSortColumn::Description),
                                "Description{sort_indicator(ServiceSortColumn::Description)}"
                            }
                        }
                    }
                    tbody {
                        for svc in filtered_services {
                            {
                                let name = svc.name.clone();
                                let name_ctx = svc.name.clone();
                                let binary_path_ctx = svc.binary_path.clone();
                                let is_selected = *selected_service.read() == Some(name.clone());
                                let row_class = if is_selected { "process-row selected" } else { "process-row" };

                                let status_class = match svc.status {
                                    ServiceStatus::Running => "svc-running",
                                    ServiceStatus::Stopped => "svc-stopped",
                                    ServiceStatus::Paused => "svc-paused",
                                    ServiceStatus::StartPending | ServiceStatus::StopPending |
                                    ServiceStatus::PausePending | ServiceStatus::ContinuePending => "svc-pending",
                                    ServiceStatus::Unknown => "svc-unknown",
                                };

                                let start_type_class = match svc.start_type {
                                    ServiceStartType::Auto => "svc-start-auto",
                                    ServiceStartType::Manual => "svc-start-manual",
                                    ServiceStartType::Disabled => "svc-start-disabled",
                                    _ => "svc-start-other",
                                };

                                let pid_display = if svc.pid == 0 {
                                    "-".to_string()
                                } else {
                                    svc.pid.to_string()
                                };

                                let svc_status = svc.status;

                                rsx! {
                                    tr {
                                        key: "{name}",
                                        class: "{row_class}",
                                        onclick: {
                                            let name = name.clone();
                                            move |_| {
                                                let current = selected_service.read().clone();
                                                if current == Some(name.clone()) {
                                                    selected_service.set(None);
                                                } else {
                                                    selected_service.set(Some(name.clone()));
                                                }
                                            }
                                        },
                                        oncontextmenu: {
                                            let name = name.clone();
                                            move |e: MouseEvent| {
                                                e.prevent_default();
                                                let coords = e.client_coordinates();
                                                selected_service.set(Some(name.clone()));
                                                context_menu.set(ServiceContextMenuState {
                                                    visible: true,
                                                    x: coords.x as i32,
                                                    y: coords.y as i32,
                                                    name: name_ctx.clone(),
                                                    binary_path: binary_path_ctx.clone(),
                                                    status: Some(svc_status),
                                                });
                                            }
                                        },
                                        td { class: "cell cell-svc-name", title: "{svc.name}", "{svc.name}" }
                                        td { class: "cell cell-svc-display", title: "{svc.display_name}", "{svc.display_name}" }
                                        td { class: "cell cell-svc-status {status_class}", "{svc.status}" }
                                        td { class: "cell cell-svc-start-type {start_type_class}", "{svc.start_type}" }
                                        td { class: "cell cell-svc-pid", "{pid_display}" }
                                        td { class: "cell cell-svc-path", title: "{svc.binary_path}", "{svc.binary_path}" }
                                        td { class: "cell cell-svc-desc", title: "{svc.description}", "{svc.description}" }
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

                    // Start service
                    button {
                        class: "context-menu-item context-menu-item-success",
                        disabled: ctx_menu.status == Some(ServiceStatus::Running),
                        onclick: {
                            let name = ctx_menu.name.clone();
                            move |_| {
                                if start_service(&name) {
                                    status_message.set(format!("✓ Service '{}' started", name));
                                    services.set(get_services());
                                } else {
                                    status_message.set(format!("✗ Failed to start service '{}'", name));
                                }
                                spawn(async move {
                                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                                    status_message.set(String::new());
                                });
                                context_menu.set(ServiceContextMenuState::default());
                            }
                        },
                        span { "▶" }
                        span { "Start Service" }
                    }

                    // Stop service
                    button {
                        class: "context-menu-item context-menu-item-warning",
                        disabled: ctx_menu.status == Some(ServiceStatus::Stopped),
                        onclick: {
                            let name = ctx_menu.name.clone();
                            move |_| {
                                if stop_service(&name) {
                                    status_message.set(format!("✓ Service '{}' stopped", name));
                                    services.set(get_services());
                                } else {
                                    status_message.set(format!("✗ Failed to stop service '{}'", name));
                                }
                                spawn(async move {
                                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                                    status_message.set(String::new());
                                });
                                context_menu.set(ServiceContextMenuState::default());
                            }
                        },
                        span { "⏹" }
                        span { "Stop Service" }
                    }

                    div { class: "context-menu-separator" }

                    // Delete service
                    button {
                        class: "context-menu-item context-menu-item-danger",
                        onclick: {
                            let name = ctx_menu.name.clone();
                            move |_| {
                                if delete_service(&name) {
                                    status_message.set(format!("✓ Service '{}' deleted", name));
                                    services.set(get_services());
                                    selected_service.set(None);
                                } else {
                                    status_message.set(format!("✗ Failed to delete service '{}'", name));
                                }
                                spawn(async move {
                                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                                    status_message.set(String::new());
                                });
                                context_menu.set(ServiceContextMenuState::default());
                            }
                        },
                        span { "🗑" }
                        span { "Delete Service" }
                    }

                    div { class: "context-menu-separator" }

                    // Copy Name
                    button {
                        class: "context-menu-item",
                        onclick: {
                            let name = ctx_menu.name.clone();
                            move |_| {
                                copy_to_clipboard(&name);
                                status_message.set(format!("📋 Name '{}' copied", name));
                                spawn(async move {
                                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                                    status_message.set(String::new());
                                });
                                context_menu.set(ServiceContextMenuState::default());
                            }
                        },
                        span { "📋" }
                        span { "Copy Name" }
                    }

                    // Copy Path
                    button {
                        class: "context-menu-item",
                        disabled: ctx_menu.binary_path.is_empty(),
                        onclick: {
                            let path = ctx_menu.binary_path.clone();
                            move |_| {
                                copy_to_clipboard(&path);
                                status_message.set("📋 Path copied".to_string());
                                spawn(async move {
                                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                                    status_message.set(String::new());
                                });
                                context_menu.set(ServiceContextMenuState::default());
                            }
                        },
                        span { "📝" }
                        span { "Copy Path" }
                    }
                }
            }

            // Create Service Modal
            if form.visible {
                div {
                    class: "create-svc-modal-overlay",
                    onclick: move |_| create_form.set(CreateServiceForm::default()),

                    div {
                        class: "create-svc-modal",
                        onclick: move |e| e.stop_propagation(),

                        div {
                            class: "create-svc-modal-header",
                            h2 { class: "create-svc-modal-title", "➕ Create New Service" }
                            button {
                                class: "create-svc-modal-close",
                                onclick: move |_| create_form.set(CreateServiceForm::default()),
                                "✕"
                            }
                        }

                        div { class: "create-svc-form",
                            div { class: "create-svc-field",
                                label { class: "create-svc-label", "Service Name" }
                                input {
                                    class: "create-svc-input",
                                    r#type: "text",
                                    placeholder: "MyService",
                                    value: "{create_form.read().name}",
                                    oninput: move |e| {
                                        let mut f = create_form.read().clone();
                                        f.name = e.value().clone();
                                        create_form.set(f);
                                    },
                                }
                            }

                            div { class: "create-svc-field",
                                label { class: "create-svc-label", "Display Name" }
                                input {
                                    class: "create-svc-input",
                                    r#type: "text",
                                    placeholder: "My Service Display Name",
                                    value: "{create_form.read().display_name}",
                                    oninput: move |e| {
                                        let mut f = create_form.read().clone();
                                        f.display_name = e.value().clone();
                                        create_form.set(f);
                                    },
                                }
                            }

                            div { class: "create-svc-field",
                                label { class: "create-svc-label", "Binary Path" }
                                div { class: "create-svc-path-row",
                                    input {
                                        class: "create-svc-input",
                                        r#type: "text",
                                        placeholder: "C:\\Path\\To\\Service.exe",
                                        value: "{create_form.read().binary_path}",
                                        oninput: move |e| {
                                            let mut f = create_form.read().clone();
                                            f.binary_path = e.value().clone();
                                            create_form.set(f);
                                        },
                                    }
                                    button {
                                        class: "create-svc-btn-browse",
                                        onclick: move |_| {
                                            let file = rfd::FileDialog::new()
                                                .add_filter("Executable", &["exe"])
                                                .pick_file();
                                            if let Some(path) = file {
                                                let mut f = create_form.read().clone();
                                                f.binary_path = path.to_string_lossy().into_owned();
                                                create_form.set(f);
                                            }
                                        },
                                        "Browse..."
                                    }
                                }
                            }

                            div { class: "create-svc-field",
                                label { class: "create-svc-label", "Start Type" }
                                select {
                                    class: "filter-select",
                                    value: "{create_form.read().start_type}",
                                    onchange: move |e| {
                                        let mut f = create_form.read().clone();
                                        f.start_type = e.value().clone();
                                        create_form.set(f);
                                    },
                                    option { value: "auto", "Automatic" }
                                    option { value: "manual", selected: true, "Manual" }
                                    option { value: "disabled", "Disabled" }
                                }
                            }
                        }

                        div { class: "create-svc-actions",
                            button {
                                class: "btn-cancel",
                                onclick: move |_| create_form.set(CreateServiceForm::default()),
                                "Cancel"
                            }
                            button {
                                class: "btn btn-primary",
                                onclick: move |_| {
                                    let f = create_form.read().clone();
                                    if f.name.is_empty() || f.binary_path.is_empty() {
                                        status_message.set("✗ Name and binary path are required".to_string());
                                        spawn(async move {
                                            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                                            status_message.set(String::new());
                                        });
                                        return;
                                    }

                                    let start_type = match f.start_type.as_str() {
                                        "auto" => ServiceStartType::Auto,
                                        "disabled" => ServiceStartType::Disabled,
                                        _ => ServiceStartType::Manual,
                                    };

                                    let display = if f.display_name.is_empty() {
                                        f.name.clone()
                                    } else {
                                        f.display_name.clone()
                                    };

                                    if create_service(&f.name, &display, &f.binary_path, start_type) {
                                        status_message.set(format!("✓ Service '{}' created", f.name));
                                        services.set(get_services());
                                    } else {
                                        status_message.set(format!("✗ Failed to create service '{}'", f.name));
                                    }
                                    spawn(async move {
                                        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                                        status_message.set(String::new());
                                    });
                                    create_form.set(CreateServiceForm::default());
                                },
                                "Create"
                            }
                        }
                    }
                }
            }
        }
    }
}
