//! File Hiding sub-tab - Hide files/folders via kernel minifilter

use callback::{filehide_add, filehide_list, filehide_remove, HiddenFileInfo};
use dioxus::prelude::*;
use rfd::AsyncFileDialog;

use crate::config::get_config_storage;
use crate::helpers::copy_to_clipboard;

/// Context menu state
#[derive(Clone, Debug, Default)]
struct FileHideContextMenu {
    visible: bool,
    x: i32,
    y: i32,
    path: String,
}

/// File Hiding sub-tab component
#[component]
pub fn FileHideTab(driver_loaded: bool) -> Element {
    let mut hidden_files = use_signal(|| Vec::<HiddenFileInfo>::new());
    let mut status_message = use_signal(|| String::new());
    let mut is_loading = use_signal(|| false);
    let mut path_input = use_signal(|| String::new());
    let mut search_query = use_signal(|| String::new());
    let mut context_menu = use_signal(|| FileHideContextMenu::default());
    let mut selected_path = use_signal(|| None::<String>);
    let mut initialized = use_signal(|| false);

    // On mount: load persisted paths from SQLite, re-arm to driver, refresh list
    use_effect(move || {
        if *initialized.read() {
            return;
        }
        initialized.set(true);

        if !driver_loaded {
            return;
        }

        spawn(async move {
            // Load persisted paths and re-arm them in the driver
            let stored_paths = tokio::task::spawn_blocking(|| {
                get_config_storage().load_hidden_paths()
            })
            .await
            .unwrap_or_default();

            for path in &stored_paths {
                let p = path.clone();
                let _ = tokio::task::spawn_blocking(move || filehide_add(&p)).await;
            }

            // Refresh list from driver
            match tokio::task::spawn_blocking(filehide_list).await {
                Ok(Ok(files)) => {
                    let count = files.len();
                    hidden_files.set(files);
                    if count > 0 {
                        status_message
                            .set(format!("Restored {} hidden path(s) from config", count));
                    }
                }
                _ => {}
            }
        });
    });

    // Refresh the list from driver
    let refresh_list = move || {
        spawn(async move {
            match tokio::task::spawn_blocking(filehide_list).await {
                Ok(Ok(files)) => {
                    hidden_files.set(files);
                }
                Ok(Err(e)) => {
                    status_message.set(format!("Error listing: {}", e));
                }
                Err(e) => {
                    status_message.set(format!("Task error: {}", e));
                }
            }
        });
    };

    // Hide a path
    let mut do_hide = move || {
        let path = path_input.read().trim().to_string();
        if path.is_empty() {
            status_message.set("Enter a file or folder path".to_string());
            return;
        }

        is_loading.set(true);
        status_message.set(String::new());

        spawn(async move {
            let p = path.clone();
            match tokio::task::spawn_blocking(move || filehide_add(&p)).await {
                Ok(Ok(())) => {
                    // Persist to SQLite
                    let p2 = path.clone();
                    let _ = tokio::task::spawn_blocking(move || {
                        get_config_storage().add_hidden_path(&p2)
                    })
                    .await;

                    status_message.set(format!("Hidden: {}", path));
                    path_input.set(String::new());

                    // Refresh list
                    if let Ok(Ok(files)) = tokio::task::spawn_blocking(filehide_list).await {
                        hidden_files.set(files);
                    }
                }
                Ok(Err(e)) => {
                    status_message.set(format!("Error: {}", e));
                }
                Err(e) => {
                    status_message.set(format!("Task error: {}", e));
                }
            }
            is_loading.set(false);
        });
    };

    // Unhide a specific path
    let mut handle_unhide = move |path: String| {
        status_message.set(String::new());

        spawn(async move {
            let p = path.clone();
            match tokio::task::spawn_blocking(move || filehide_remove(&p)).await {
                Ok(Ok(())) => {
                    // Remove from SQLite
                    let p2 = path.clone();
                    let _ = tokio::task::spawn_blocking(move || {
                        get_config_storage().remove_hidden_path(&p2)
                    })
                    .await;

                    status_message.set(format!("Unhidden: {}", path));

                    // Refresh list
                    if let Ok(Ok(files)) = tokio::task::spawn_blocking(filehide_list).await {
                        hidden_files.set(files);
                    }
                }
                Ok(Err(e)) => {
                    status_message.set(format!("Error: {}", e));
                }
                Err(e) => {
                    status_message.set(format!("Task error: {}", e));
                }
            }
        });
    };

    // Browse for file
    let browse_file = move |_| {
        spawn(async move {
            if let Some(file) = AsyncFileDialog::new().pick_file().await {
                path_input.set(file.path().to_string_lossy().to_string());
            }
        });
    };

    // Browse for folder
    let browse_folder = move |_| {
        spawn(async move {
            if let Some(folder) = AsyncFileDialog::new().pick_folder().await {
                path_input.set(folder.path().to_string_lossy().to_string());
            }
        });
    };

    // Filter hidden files by search query
    let filtered_files: Vec<HiddenFileInfo> = {
        let query = search_query.read().to_lowercase();
        if query.is_empty() {
            hidden_files.read().clone()
        } else {
            hidden_files
                .read()
                .iter()
                .filter(|f| f.path.to_lowercase().contains(&query))
                .cloned()
                .collect()
        }
    };

    // Close context menu on click
    let close_context_menu = move |_: MouseEvent| {
        if context_menu.read().visible {
            context_menu.set(FileHideContextMenu::default());
        }
    };

    rsx! {
        div {
            class: "service-tab",
            onclick: close_context_menu,

            // Controls bar
            div {
                class: "controls",

                // Path input
                input {
                    class: "search-input",
                    style: "flex: 1; min-width: 300px;",
                    r#type: "text",
                    placeholder: "File or folder path (e.g., C:\\secret\\file.txt)",
                    value: "{path_input}",
                    disabled: !driver_loaded,
                    oninput: move |e| path_input.set(e.value()),
                    onkeydown: move |e: KeyboardEvent| {
                        if e.key() == Key::Enter {
                            do_hide();
                        }
                    },
                }

                button {
                    class: "btn btn-secondary",
                    disabled: !driver_loaded,
                    onclick: browse_file,
                    "Browse File"
                }

                button {
                    class: "btn btn-secondary",
                    disabled: !driver_loaded,
                    onclick: browse_folder,
                    "Browse Folder"
                }

                button {
                    class: "btn btn-primary",
                    disabled: !driver_loaded || *is_loading.read() || path_input.read().trim().is_empty(),
                    onclick: move |_| do_hide(),
                    if *is_loading.read() { "Hiding..." } else { "Hide" }
                }

                button {
                    class: "btn btn-secondary",
                    disabled: !driver_loaded,
                    onclick: move |_| refresh_list(),
                    "Refresh"
                }
            }

            // Search filter
            div {
                class: "controls",
                input {
                    class: "search-input",
                    r#type: "text",
                    placeholder: "Filter hidden paths...",
                    value: "{search_query}",
                    oninput: move |e| search_query.set(e.value()),
                }

                span { class: "header-stats",
                    "{filtered_files.len()} hidden path(s)"
                }

                if !status_message.read().is_empty() {
                    span {
                        class: if status_message.read().starts_with("Error") || status_message.read().starts_with("Task") {
                            "status-error"
                        } else {
                            "status-success"
                        },
                        "{status_message}"
                    }
                }
            }

            // Table
            div { class: "table-container",
                table { class: "process-table",
                    thead {
                        tr {
                            th { style: "width: 50px;", "#" }
                            th { "Hidden Path" }
                            th { style: "width: 100px;", "Action" }
                        }
                    }
                    tbody {
                        if filtered_files.is_empty() {
                            tr {
                                td { colspan: "3", style: "text-align: center; color: var(--text-secondary); padding: 20px;",
                                    if !driver_loaded {
                                        "Driver not loaded - file hiding unavailable"
                                    } else {
                                        "No hidden files. Enter a path above to hide a file or folder."
                                    }
                                }
                            }
                        }
                        for (idx, file) in filtered_files.iter().enumerate() {
                            {
                                let file_path = file.path.clone();
                                let file_path_ctx = file.path.clone();
                                let file_path_sel = file.path.clone();
                                let is_selected = selected_path.read().as_ref() == Some(&file.path);
                                rsx! {
                                    tr {
                                        class: if is_selected { "selected" } else { "" },
                                        onclick: move |_| {
                                            selected_path.set(Some(file_path_sel.clone()));
                                        },
                                        oncontextmenu: move |e| {
                                            e.prevent_default();
                                            let coords = e.page_coordinates();
                                            context_menu.set(FileHideContextMenu {
                                                visible: true,
                                                x: coords.x as i32,
                                                y: coords.y as i32,
                                                path: file_path_ctx.clone(),
                                            });
                                        },
                                        td { "{idx + 1}" }
                                        td {
                                            class: "monospace",
                                            "{file.path}"
                                        }
                                        td {
                                            button {
                                                class: "btn btn-danger btn-sm",
                                                onclick: move |e| {
                                                    e.stop_propagation();
                                                    handle_unhide(file_path.clone());
                                                },
                                                "Unhide"
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Context menu
            if context_menu.read().visible {
                {
                    let menu = context_menu.read().clone();
                    let path_copy = menu.path.clone();
                    let path_unhide = menu.path.clone();
                    rsx! {
                        div {
                            class: "context-menu",
                            style: "position: fixed; left: clamp(0px, {menu.x}px, calc(100vw - 200px)); top: clamp(0px, {menu.y}px, calc(100vh - 120px)); z-index: 10000;",

                            div {
                                class: "context-menu-item",
                                onclick: move |_| {
                                    copy_to_clipboard(&path_copy);
                                    context_menu.set(FileHideContextMenu::default());
                                },
                                "Copy Path"
                            }
                            div { class: "context-menu-separator" }
                            div {
                                class: "context-menu-item context-menu-item-danger",
                                onclick: move |_| {
                                    handle_unhide(path_unhide.clone());
                                    context_menu.set(FileHideContextMenu::default());
                                },
                                "Unhide"
                            }
                        }
                    }
                }
            }
        }
    }
}
