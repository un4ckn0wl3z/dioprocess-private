//! Main application component with routing

use dioxus::prelude::*;
use process::{format_uptime, get_system_stats};

use crate::routes::Route;
use crate::styles::CUSTOM_STYLES;

/// Main application component
#[component]
pub fn App() -> Element {
    rsx! {
        Router::<Route> {}
    }
}

/// Layout component wrapping all routes
#[component]
pub fn Layout() -> Element {
    let mut system_stats = use_signal(|| get_system_stats());
    let mut about_popup = use_signal(|| false);
    let route: Route = use_route();

    // Auto-refresh system stats every 3 seconds
    use_future(move || async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            system_stats.set(get_system_stats());
        }
    });

    let stats = system_stats.read().clone();
    let version = option_env!("CARGO_PKG_VERSION").unwrap_or("unknown");

    // Determine active tab
    let is_process_tab = matches!(route, Route::ProcessTab {});
    let is_network_tab = matches!(route, Route::NetworkTab {});
    let is_service_tab = matches!(route, Route::ServiceTab {});

    let about_message = format!(
        r#"
    DioProcess is a modern Windows system monitor
    built with Rust, Dioxus, and Windows APIs.

    Process • Network • Threads • Modules
    Injection • Inspection • Control

    Version: {}
    "#,
        version
    );

    rsx! {
            style { {CUSTOM_STYLES} }

            div {
                class: "main-container",

                // Custom title bar
                div { class: "title-bar",
                    div {
                        class: "title-bar-drag",
                        onmousedown: move |_| {
                            let window = dioxus::desktop::window();
                            let _ = window.drag_window();
                        },
                        span { class: "title-text", "🖥️ DioProcess | Windows System Monitor Tool v{version}" }
                    }
                    div { class: "title-bar-buttons",
                        button {
                            class: "title-btn",
                            onclick: move |_| {
                                about_popup.set(true);
                            },
                            "?"
                        }
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

                    div { class: "stat-item",
                        span { class: "stat-label", "Uptime" }
                        span { class: "stat-value stat-value-green", "{format_uptime(stats.uptime_seconds)}" }
                    }

                    div { class: "stat-item stat-item-right",
                        span { class: "stat-label", "Processes" }
                        span { class: "stat-value stat-value-yellow", "{stats.process_count}" }
                    }
                }

                // Tab Navigation
                div { class: "tab-bar",
                    Link {
                        to: Route::ProcessTab {},
                        class: if is_process_tab { "tab-item tab-active" } else { "tab-item" },
                        "🖥️ Processes"
                    }
                    Link {
                        to: Route::NetworkTab {},
                        class: if is_network_tab { "tab-item tab-active" } else { "tab-item" },
                        "🌐 Network"
                    }
                    Link {
                        to: Route::ServiceTab {},
                        class: if is_service_tab { "tab-item tab-active" } else { "tab-item" },
                        "⚙️ Services"
                    }
                }

                // Content Area with Router Outlet
                div { class: "content-area",
                    Outlet::<Route> {}
                }

                if *about_popup.read() {

            div {
                class: "about-modal-overlay",
                onclick: |e| e.stop_propagation(),

                div {
                    class: "about-modal",
                    onclick: |e| e.stop_propagation(),

                    div {
                        class: "about-modal-header",

                        h2 {
                            class: "about-modal-title",
                            "🖥️ About: DioProcess - Windows System Monitor"
                        }

                        button {
                            class: "about-modal-close",
                            onclick: move |_| about_popup.set(false),
                            "✕"
                        }
                    }

                    span {
                        style: "white-space: pre-line; padding: 10px; color: #e5e7eb; ",
                        "{about_message}"
                    }

                    span {
                        style: "padding: 10px; color: #e5e7eb;",
                        "Developer: "
                        a {
                            href: "https://github.com/un4ckn0wl3z",
                            target: "_blank",
                            class: "about-link",
                            "un4ckn0wl3z"
                        }
                    }

                    span {
                        style: "padding: 10px; color: #e5e7eb;",
                        "Website: "
                        a {
                            href: "https://un4ckn0wl3z.dev/",
                            target: "_blank",
                            class: "about-link",
                            "un4ckn0wl3z.dev"
                        }
                    }

                }
            }

                }
            }
        }
}
