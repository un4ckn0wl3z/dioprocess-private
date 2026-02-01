//! Process graph window component - real-time CPU and memory monitoring

use dioxus::prelude::*;
use process::get_process_stats;

use crate::state::GRAPH_WINDOW_STATE;

const GRAPH_HISTORY_SIZE: usize = 60; // 60 data points (1 minute at 1s interval)
const GRAPH_WIDTH: f64 = 400.0;
const GRAPH_HEIGHT: f64 = 120.0;

/// Graph Window component
#[component]
pub fn GraphWindow(pid: u32, process_name: String) -> Element {
    let mut cpu_history = use_signal(|| vec![0.0f32; GRAPH_HISTORY_SIZE]);
    let mut mem_history = use_signal(|| vec![0.0f64; GRAPH_HISTORY_SIZE]);
    let mut current_stats = use_signal(|| get_process_stats(pid));
    let mut max_memory = use_signal(|| 100.0f64); // Track max memory for scaling
    let mut paused = use_signal(|| false);

    // Update every second
    use_future(move || async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            if !*paused.read() {
                let stats = get_process_stats(pid);
                current_stats.set(stats.clone());

                // Update CPU history
                let mut cpu = cpu_history.write();
                cpu.remove(0);
                cpu.push(stats.cpu_usage);

                // Update memory history
                let mut mem = mem_history.write();
                mem.remove(0);
                mem.push(stats.memory_mb);

                // Update max memory for scaling
                let current_max = mem.iter().cloned().fold(0.0f64, f64::max);
                if current_max > *max_memory.read() * 0.8 || current_max < *max_memory.read() * 0.3 {
                    max_memory.set((current_max * 1.2).max(10.0));
                }
            }
        }
    });

    let stats = current_stats.read().clone();
    let cpu_data = cpu_history.read().clone();
    let mem_data = mem_history.read().clone();
    let mem_max = *max_memory.read();
    let is_paused = *paused.read();

    // Generate SVG path for CPU graph
    let cpu_path = generate_graph_path(&cpu_data, 100.0);
    // Generate SVG path for memory graph
    let mem_path = generate_graph_path_f64(&mem_data, mem_max);

    rsx! {
        // Modal overlay
        div {
            class: "thread-modal-overlay",
            onclick: move |_| {
                *GRAPH_WINDOW_STATE.write() = None;
            },

            // Modal window
            div {
                class: "thread-modal graph-modal",
                onclick: move |e| e.stop_propagation(),

                // Header
                div {
                    class: "thread-modal-header",
                    div {
                        class: "thread-modal-title",
                        "Performance - {process_name} (PID: {pid})"
                    }
                    button {
                        class: "thread-modal-close",
                        onclick: move |_| {
                            *GRAPH_WINDOW_STATE.write() = None;
                        },
                        "X"
                    }
                }

                // Content
                div {
                    class: "graph-content",

                    // Controls
                    div {
                        class: "graph-controls",
                        button {
                            class: if is_paused { "btn btn-small btn-primary" } else { "btn btn-small btn-secondary" },
                            onclick: move |_| paused.set(!is_paused),
                            if is_paused { "Resume" } else { "Pause" }
                        }
                        span {
                            class: "graph-interval",
                            "Update: 1s | History: 60s"
                        }
                    }

                    // CPU Graph
                    div {
                        class: "graph-section",
                        div {
                            class: "graph-header",
                            span { class: "graph-label", "CPU Usage" }
                            span { class: "graph-value graph-value-cpu", "{stats.cpu_usage:.1}%" }
                        }
                        div {
                            class: "graph-container",
                            svg {
                                width: "100%",
                                height: "{GRAPH_HEIGHT}",
                                view_box: "0 0 {GRAPH_WIDTH} {GRAPH_HEIGHT}",
                                preserve_aspect_ratio: "none",
                                // Background grid
                                line { x1: "0", y1: "{GRAPH_HEIGHT * 0.25}", x2: "{GRAPH_WIDTH}", y2: "{GRAPH_HEIGHT * 0.25}", class: "graph-grid" }
                                line { x1: "0", y1: "{GRAPH_HEIGHT * 0.5}", x2: "{GRAPH_WIDTH}", y2: "{GRAPH_HEIGHT * 0.5}", class: "graph-grid" }
                                line { x1: "0", y1: "{GRAPH_HEIGHT * 0.75}", x2: "{GRAPH_WIDTH}", y2: "{GRAPH_HEIGHT * 0.75}", class: "graph-grid" }
                                // Graph line
                                path {
                                    d: "{cpu_path}",
                                    class: "graph-line graph-line-cpu"
                                }
                                // Fill area
                                path {
                                    d: "{cpu_path} L {GRAPH_WIDTH} {GRAPH_HEIGHT} L 0 {GRAPH_HEIGHT} Z",
                                    class: "graph-fill graph-fill-cpu"
                                }
                            }
                            div {
                                class: "graph-y-labels",
                                span { "100%" }
                                span { "50%" }
                                span { "0%" }
                            }
                        }
                    }

                    // Memory Graph
                    div {
                        class: "graph-section",
                        div {
                            class: "graph-header",
                            span { class: "graph-label", "Memory Usage" }
                            span { class: "graph-value graph-value-mem", "{stats.memory_mb:.1} MB" }
                        }
                        div {
                            class: "graph-container",
                            svg {
                                width: "100%",
                                height: "{GRAPH_HEIGHT}",
                                view_box: "0 0 {GRAPH_WIDTH} {GRAPH_HEIGHT}",
                                preserve_aspect_ratio: "none",
                                // Background grid
                                line { x1: "0", y1: "{GRAPH_HEIGHT * 0.25}", x2: "{GRAPH_WIDTH}", y2: "{GRAPH_HEIGHT * 0.25}", class: "graph-grid" }
                                line { x1: "0", y1: "{GRAPH_HEIGHT * 0.5}", x2: "{GRAPH_WIDTH}", y2: "{GRAPH_HEIGHT * 0.5}", class: "graph-grid" }
                                line { x1: "0", y1: "{GRAPH_HEIGHT * 0.75}", x2: "{GRAPH_WIDTH}", y2: "{GRAPH_HEIGHT * 0.75}", class: "graph-grid" }
                                // Graph line
                                path {
                                    d: "{mem_path}",
                                    class: "graph-line graph-line-mem"
                                }
                                // Fill area
                                path {
                                    d: "{mem_path} L {GRAPH_WIDTH} {GRAPH_HEIGHT} L 0 {GRAPH_HEIGHT} Z",
                                    class: "graph-fill graph-fill-mem"
                                }
                            }
                            div {
                                class: "graph-y-labels",
                                span { "{mem_max:.0} MB" }
                                span { "{mem_max / 2.0:.0} MB" }
                                span { "0 MB" }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Generate SVG path from f32 data points (0-max range)
fn generate_graph_path(data: &[f32], max_value: f32) -> String {
    if data.is_empty() {
        return String::new();
    }

    let step = GRAPH_WIDTH / (data.len() - 1) as f64;
    let mut path = String::new();

    for (i, &value) in data.iter().enumerate() {
        let x = i as f64 * step;
        let y = GRAPH_HEIGHT - (value as f64 / max_value as f64 * GRAPH_HEIGHT).min(GRAPH_HEIGHT);

        if i == 0 {
            path.push_str(&format!("M {} {}", x, y));
        } else {
            path.push_str(&format!(" L {} {}", x, y));
        }
    }

    path
}

/// Generate SVG path from f64 data points (0-max range)
fn generate_graph_path_f64(data: &[f64], max_value: f64) -> String {
    if data.is_empty() || max_value <= 0.0 {
        return String::new();
    }

    let step = GRAPH_WIDTH / (data.len() - 1) as f64;
    let mut path = String::new();

    for (i, &value) in data.iter().enumerate() {
        let x = i as f64 * step;
        let y = GRAPH_HEIGHT - (value / max_value * GRAPH_HEIGHT).min(GRAPH_HEIGHT);

        if i == 0 {
            path.push_str(&format!("M {} {}", x, y));
        } else {
            path.push_str(&format!(" L {} {}", x, y));
        }
    }

    path
}
