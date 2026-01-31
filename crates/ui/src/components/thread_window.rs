//! Thread window component

use dioxus::prelude::*;
use process::{
    get_priority_name, get_process_threads, kill_thread, resume_thread, suspend_thread, ThreadInfo,
};

use crate::helpers::copy_to_clipboard;
use crate::state::{ThreadContextMenuState, THREAD_WINDOW_STATE};

/// Thread Window component
#[component]
pub fn ThreadWindow(pid: u32, process_name: String) -> Element {
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
