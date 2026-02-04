//! Process row component

use dioxus::prelude::*;
use process::ProcessInfo;

/// Process row component
#[component]
pub fn ProcessRow(
    process: ProcessInfo,
    is_selected: bool,
    max_memory: f64,
    on_select: EventHandler<u32>,
    on_context_menu: EventHandler<(i32, i32, u32, String)>,
    #[props(default)] tree_depth: Option<usize>,
    #[props(default)] tree_is_last: Option<bool>,
    #[props(default)] tree_ancestor_is_last: Option<Vec<bool>>,
    #[props(default)] tree_has_children: Option<bool>,
    #[props(default)] tree_is_expanded: Option<bool>,
    #[props(default)] on_toggle_expand: EventHandler<u32>,
) -> Element {
    let memory_percent = if max_memory > 0.0 {
        process.memory_mb / max_memory * 100.0
    } else {
        0.0
    };
    let pid = process.pid;
    let exe_path = process.exe_path.clone();
    let exe_path_for_context = process.exe_path.clone();
    let exe_filename = process
        .exe_path
        .split('\\')
        .last()
        .unwrap_or(&process.exe_path)
        .to_string();

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

    let is_tree_mode = tree_depth.is_some();

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
            td { class: "cell cell-name",
                if is_tree_mode {
                    div { class: "tree-name-container",
                        // Render guide lines for ancestor depth levels
                        {
                            let ancestors = tree_ancestor_is_last.clone().unwrap_or_default();
                            rsx! {
                                for ancestor_is_last in ancestors {
                                    span { class: "tree-guide",
                                        if ancestor_is_last { "\u{00A0}" } else { "\u{2502}" }
                                    }
                                }
                            }
                        }
                        // Render connector for non-root nodes
                        if tree_depth.unwrap_or(0) > 0 {
                            span { class: "tree-connector",
                                if tree_is_last.unwrap_or(false) { "\u{2514}\u{2500}" } else { "\u{251C}\u{2500}" }
                            }
                        }
                        // Render expand/collapse toggle or placeholder
                        if tree_has_children.unwrap_or(false) {
                            span {
                                class: "tree-toggle",
                                onclick: move |e| {
                                    e.stop_propagation();
                                    on_toggle_expand.call(pid);
                                },
                                if tree_is_expanded.unwrap_or(false) { "\u{25BC}" } else { "\u{25B6}" }
                            }
                        } else {
                            span { class: "tree-toggle-placeholder" }
                        }
                        span { class: "tree-process-name", "{process.name}" }
                    }
                } else {
                    "{process.name}"
                }
            }
            td { class: "cell cell-arch", "{process.arch}" }
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
