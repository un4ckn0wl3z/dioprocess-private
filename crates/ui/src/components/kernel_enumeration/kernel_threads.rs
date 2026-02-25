//! Kernel Process/Thread Enumeration sub-tab

use callback::{
    enumerate_system_threads, resolve_ethread_offsets, resolve_kernel_symbol, resume_thread,
    set_ethread_offsets, suspend_thread, terminate_thread, SystemThreadInfo,
};
use dioxus::prelude::*;

use super::SortOrder;

/// Sort column for system threads
#[derive(Clone, Copy, PartialEq, Debug)]
enum ThreadSortColumn {
    ThreadId,
    Win32StartAddress,
    State,
}

/// Thread state names
fn thread_state_name(state: u8) -> &'static str {
    match state {
        0 => "Initialized",
        1 => "Ready",
        2 => "Running",
        3 => "Standby",
        4 => "Terminated",
        5 => "Waiting",
        6 => "Transition",
        7 => "DeferredReady",
        _ => "Unknown",
    }
}

/// Wait reason names
fn wait_reason_name(reason: u8) -> &'static str {
    match reason {
        0 => "Executive",
        5 => "Suspended",
        6 => "UserRequest",
        15 => "WrQueue",
        32 => "WrKernel",
        _ => "-",
    }
}

/// Kernel Process/Thread Enumeration sub-tab
#[component]
pub fn KernelThreadsTab(driver_loaded: bool) -> Element {
    let mut threads = use_signal(|| Vec::<SystemThreadInfo>::new());
    let mut status_message = use_signal(|| String::new());
    let mut is_enumerating = use_signal(|| false);
    let mut sort_column = use_signal(|| ThreadSortColumn::ThreadId);
    let mut sort_order = use_signal(|| SortOrder::Ascending);
    let mut search_query = use_signal(|| String::new());
    let mut selected_tid = use_signal(|| None::<u32>);

    // Handle enumerate button click
    let handle_enumerate = move |_| {
        if *is_enumerating.read() {
            return;
        }

        is_enumerating.set(true);
        status_message.set("Resolving ETHREAD offsets...".to_string());

        spawn(async move {
            // First resolve ETHREAD offsets from PDB
            let _ = tokio::task::spawn_blocking(|| {
                if let Ok(offsets) = resolve_ethread_offsets() {
                    let _ = set_ethread_offsets(
                        offsets.win32_start_address_offset,
                        offsets.state_offset,
                        offsets.wait_reason_offset,
                    );
                }
            }).await;

            status_message.set("Enumerating system threads...".to_string());

            // Enumerate system threads
            let result = tokio::task::spawn_blocking(enumerate_system_threads).await;

            match result {
                Ok(Ok(thread_list)) => {
                    let count = thread_list.len();
                    threads.set(thread_list);
                    status_message.set(format!("Found {} system threads", count));
                }
                Ok(Err(e)) => {
                    status_message.set(format!("Error: {}", e));
                }
                Err(e) => {
                    status_message.set(format!("Task error: {}", e));
                }
            }

            is_enumerating.set(false);
        });
    };

    // Sort threads
    let sorted_threads: Vec<SystemThreadInfo> = {
        let mut list = threads.read().clone();
        let query = search_query.read().to_lowercase();

        // Filter by search query
        if !query.is_empty() {
            list.retain(|t| {
                t.driver_name_str().to_lowercase().contains(&query)
                    || format!("{}", t.thread_id).contains(&query)
            });
        }

        // Sort
        let col = *sort_column.read();
        let order = *sort_order.read();
        list.sort_by(|a, b| {
            let cmp = match col {
                ThreadSortColumn::ThreadId => a.thread_id.cmp(&b.thread_id),
                ThreadSortColumn::Win32StartAddress => a.win32_start_address.cmp(&b.win32_start_address),
                ThreadSortColumn::State => a.state.cmp(&b.state),
            };
            if order == SortOrder::Descending {
                cmp.reverse()
            } else {
                cmp
            }
        });
        list
    };

    // Sort indicator
    let sort_indicator = |col: ThreadSortColumn| -> &'static str {
        if *sort_column.read() == col {
            if *sort_order.read() == SortOrder::Ascending { " ▲" } else { " ▼" }
        } else {
            ""
        }
    };

    // Make sort handler
    let make_sort_handler = move |col: ThreadSortColumn| {
        move |_| {
            if *sort_column.read() == col {
                sort_order.set(if *sort_order.read() == SortOrder::Ascending {
                    SortOrder::Descending
                } else {
                    SortOrder::Ascending
                });
            } else {
                sort_column.set(col);
                sort_order.set(SortOrder::Ascending);
            }
        }
    };

    let thread_count = sorted_threads.len();
    let total_count = threads.read().len();
    let is_running = *is_enumerating.read();
    let status_msg = status_message.read().clone();
    let query_text = search_query.read().clone();

    rsx! {
        div { class: "callback-enum-content",
            // Controls row
            div { class: "controls",
                input {
                    class: "search-input",
                    r#type: "text",
                    placeholder: "Search by driver name or TID...",
                    value: "{query_text}",
                    oninput: move |e| search_query.set(e.value().clone()),
                }

                button {
                    class: "btn btn-primary",
                    disabled: !driver_loaded || is_running,
                    onclick: handle_enumerate,
                    if is_running { "Enumerating..." } else { "Refresh" }
                }

                // Status message inline
                if !status_msg.is_empty() {
                    span { class: "status-message", "{status_msg}" }
                }
            }

            // Thread table
            div { class: "table-container",
                table { class: "process-table",
                    thead { class: "table-header",
                        tr {
                            th {
                                class: "th sortable",
                                onclick: make_sort_handler(ThreadSortColumn::ThreadId),
                                "TID{sort_indicator(ThreadSortColumn::ThreadId)}"
                            }
                            th {
                                class: "th sortable",
                                onclick: make_sort_handler(ThreadSortColumn::Win32StartAddress),
                                "Start Address{sort_indicator(ThreadSortColumn::Win32StartAddress)}"
                            }
                            th {
                                class: "th sortable",
                                onclick: make_sort_handler(ThreadSortColumn::State),
                                "State{sort_indicator(ThreadSortColumn::State)}"
                            }
                            th { class: "th", "Wait" }
                            th { class: "th", "Actions" }
                        }
                    }

                    tbody {
                        if sorted_threads.is_empty() && !threads.read().is_empty() {
                            tr {
                                td { colspan: "5", class: "no-results",
                                    "No threads match your search"
                                }
                            }
                        } else if threads.read().is_empty() {
                            tr {
                                td { colspan: "5", class: "no-results",
                                    if driver_loaded {
                                        "Click 'Refresh' to enumerate system threads (PID 4)"
                                    } else {
                                        "Driver not loaded - Load DioProcess.sys to use this feature"
                                    }
                                }
                            }
                        } else {
                            for thread in sorted_threads.iter() {
                                {
                                    let tid = thread.thread_id;
                                    let start_addr = if thread.win32_start_address != 0 { 
                                        thread.win32_start_address 
                                    } else { 
                                        thread.start_address 
                                    };
                                    let driver = thread.driver_name_str().to_string();
                                    // Resolve symbol for ntoskrnl addresses
                                    let start_address_str = if !driver.is_empty() {
                                        resolve_kernel_symbol(start_addr, &driver, thread.driver_base)
                                    } else {
                                        format!("0x{:016X}", start_addr)
                                    };
                                    let state = thread_state_name(thread.state);
                                    let wait = if thread.state == 5 { wait_reason_name(thread.wait_reason) } else { "" };
                                    let state_class = if thread.state == 2 { "cpu-low" } 
                                                      else if thread.state == 5 { "cpu-medium" }
                                                      else { "" };
                                    let is_selected = *selected_tid.read() == Some(tid);
                                    
                                    rsx! {
                                        tr {
                                            key: "{tid}",
                                            class: if is_selected { "process-row selected" } else { "process-row" },
                                            onclick: move |_| {
                                                let current = *selected_tid.read();
                                                if current == Some(tid) {
                                                    selected_tid.set(None);
                                                } else {
                                                    selected_tid.set(Some(tid));
                                                }
                                            },
                                            td { class: "cell", "{tid}" }
                                            td { class: "cell mono", "{start_address_str}" }
                                            td { class: "cell",
                                                span { class: "{state_class}", "{state}" }
                                            }
                                            td { class: "cell", "{wait}" }
                                            td { class: "cell",
                                                div { class: "action-buttons",
                                                    button {
                                                        class: "btn-action",
                                                        title: "Suspend thread",
                                                        onclick: move |e| {
                                                            e.stop_propagation();
                                                            let t = tid;
                                                            spawn(async move {
                                                                let _ = tokio::task::spawn_blocking(move || suspend_thread(t)).await;
                                                            });
                                                        },
                                                        "⏸"
                                                    }
                                                    button {
                                                        class: "btn-action",
                                                        title: "Resume thread",
                                                        onclick: move |e| {
                                                            e.stop_propagation();
                                                            let t = tid;
                                                            spawn(async move {
                                                                let _ = tokio::task::spawn_blocking(move || resume_thread(t)).await;
                                                            });
                                                        },
                                                        "▶"
                                                    }
                                                    button {
                                                        class: "btn-action btn-danger",
                                                        title: "Terminate thread",
                                                        onclick: move |e| {
                                                            e.stop_propagation();
                                                            let t = tid;
                                                            spawn(async move {
                                                                let _ = tokio::task::spawn_blocking(move || terminate_thread(t)).await;
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
                }
            }

            // Footer with count
            if total_count > 0 {
                div { class: "table-footer",
                    "Showing {thread_count} of {total_count} threads"
                }
            }
        }
    }
}
