//! Main application component with routing

use dioxus::prelude::*;
use process::{format_uptime, get_system_stats};
use callback::is_driver_loaded;
use std::process::Command;

use crate::config::{load_theme, save_theme, Theme};
use crate::routes::Route;
use crate::styles::get_theme_css;

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
    let mut current_theme = use_signal(|| load_theme());
    let mut driver_loaded = use_signal(|| is_driver_loaded());
    let mut install_status = use_signal(|| String::new());
    let mut installing = use_signal(|| false);
    let route: Route = use_route();

    // Auto-refresh system stats and driver status every 3 seconds
    use_future(move || async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            system_stats.set(get_system_stats());
            driver_loaded.set(is_driver_loaded());
        }
    });

    let stats = system_stats.read().clone();
    let version = option_env!("CARGO_PKG_VERSION").unwrap_or("unknown");
    let theme_css = get_theme_css(*current_theme.read());

    // Determine active tab
    let is_process_tab = matches!(route, Route::ProcessTab {});
    let is_network_tab = matches!(route, Route::NetworkTab {});
    let is_service_tab = matches!(route, Route::ServiceTab {});
    let is_utilities_tab = matches!(route, Route::UtilitiesTab {});
    let is_kernel_utilities_tab = matches!(route, Route::KernelUtilitiesTab {});
    let is_callback_tab = matches!(route, Route::CallbackTab {});

    let about_message = format!(
        r#"
    DioProcess
    Advanced Windows System Monitor & Process Analysis Tool
    
    Advanced process & system control features
    (for research, security testing & OS internals exploration)

    Built with Rust • Dioxus 0.6 • Native Windows APIs
    Requires administrator privileges

    Version: {}
    "#,
        version
    );
    rsx! {
            style { {theme_css} }

            div {
                class: "main-container",

                // Custom title bar
                div { class: "title-bar",
                    div {
                        class: "title-bar-drag",
                        span { class: "title-text", "DioProcess | Windows System Monitor Tool v{version}" }
                    }
                    // Theme selector
                    div { class: "theme-selector",
                        select {
                            class: "theme-select",
                            value: "{current_theme.read().display_name()}",
                            onchange: move |evt| {
                                let value = evt.value();
                                let new_theme = match value.as_str() {
                                    "Aura Glow" => Theme::AuraGlow,
                                    "Cyber" => Theme::Cyber,
                                    _ => Theme::AuraGlow,
                                };
                                current_theme.set(new_theme);
                                save_theme(new_theme);
                            },
                            for theme in Theme::all() {
                                option {
                                    value: "{theme.display_name()}",
                                    selected: *current_theme.read() == *theme,
                                    "{theme.display_name()}"
                                }
                            }
                        }
                    }

                    // Driver Install/Uninstall Button
                    if !*driver_loaded.read() {
                        button {
                            class: if *installing.read() { "driver-install-btn installing" } else { "driver-install-btn flashing" },
                            disabled: *installing.read(),
                            onclick: move |_| {
                                installing.set(true);
                                install_status.set(String::new());
                                spawn(async move {
                                    let result = tokio::task::spawn_blocking(move || {
                                        // Base64 encoded PAT
                                        const PAT_B64: &str = "Z2l0aHViX3BhdF8xMUFEMlFYT0Ewc1JIdk1WRHllVURpX3F1V3RIZWlmRFlVdTFtbEVNSWJZQmRWRVVpdjJwR3pzbFBibHk1V1kzUDlCTUFJNzZESzJTY3NxOXZo";

                                        let pat = match base64_decode(PAT_B64) {
                                            Ok(p) => p,
                                            Err(_) => return Err("Installation failed".to_string()),
                                        };

                                        let appdata = match std::env::var("LOCALAPPDATA") {
                                            Ok(p) => std::path::PathBuf::from(p),
                                            Err(_) => return Err("Installation failed".to_string()),
                                        };
                                        let dioprocess_dir = appdata.join("DioProcess");
                                        let zip_path = dioprocess_dir.join("dpdrv.zip");
                                        let extract_dir = dioprocess_dir.join("dpdrv-main");

                                        // Create directory
                                        let _ = std::fs::create_dir_all(&dioprocess_dir);

                                        // Clean up
                                        let _ = std::fs::remove_file(&zip_path);
                                        let _ = std::fs::remove_dir_all(&extract_dir);

                                        // Download zip
                                        let zip_url = format!(
                                            "https://{}@github.com/un4ckn0wl3z/dpdrv/archive/refs/heads/main.zip",
                                            pat
                                        );
                                        let download_cmd = format!(
                                            "$ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest -Uri '{}' -OutFile '{}'",
                                            zip_url, zip_path.display()
                                        );
                                        let _ = Command::new("powershell")
                                            .args(["-NoProfile", "-Command", &download_cmd])
                                            .output();

                                        if !zip_path.exists() {
                                            return Err("Download failed".to_string());
                                        }

                                        // Extract zip
                                        let extract_cmd = format!(
                                            "Expand-Archive -Path '{}' -DestinationPath '{}' -Force",
                                            zip_path.display(), dioprocess_dir.display()
                                        );
                                        let _ = Command::new("powershell")
                                            .args(["-NoProfile", "-Command", &extract_cmd])
                                            .output();

                                        // Delete zip
                                        let _ = std::fs::remove_file(&zip_path);

                                        // Run install script
                                        let install_script = extract_dir.join("install.ps1");
                                        if !install_script.exists() {
                                            let _ = std::fs::remove_dir_all(&extract_dir);
                                            return Err("Installation failed".to_string());
                                        }

                                        let install_result = Command::new("powershell")
                                            .args([
                                                "-NoProfile",
                                                "-ExecutionPolicy", "Bypass",
                                                "-File", install_script.to_str().unwrap_or("")
                                            ])
                                            .output();

                                        match install_result {
                                            Ok(output) if output.status.success() => {
                                                Ok("Driver installed!".to_string())
                                            }
                                            _ => {
                                                let _ = std::fs::remove_dir_all(&extract_dir);
                                                Err("Installation failed".to_string())
                                            }
                                        }
                                    }).await;

                                    match result {
                                        Ok(Ok(msg)) => {
                                            install_status.set(msg);
                                            driver_loaded.set(is_driver_loaded());
                                        }
                                        Ok(Err(e)) => {
                                            install_status.set(e);
                                        }
                                        Err(_) => {
                                            install_status.set("Installation failed".to_string());
                                        }
                                    }
                                    installing.set(false);

                                    // Clear status after 5 seconds
                                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                                    install_status.set(String::new());
                                });
                            },
                            if *installing.read() {
                                "Installing..."
                            } else {
                                "Install Driver"
                            }
                        }
                    } else {
                        // Uninstall button
                        button {
                            class: if *installing.read() { "driver-uninstall-btn installing" } else { "driver-uninstall-btn" },
                            disabled: *installing.read(),
                            onclick: move |_| {
                                installing.set(true);
                                install_status.set(String::new());
                                spawn(async move {
                                    let result = tokio::task::spawn_blocking(move || {
                                        let _ = Command::new("sc").args(["stop", "dpdrv"]).output();
                                        std::thread::sleep(std::time::Duration::from_millis(500));
                                        let delete_result = Command::new("sc").args(["delete", "dpdrv"]).output();

                                        match delete_result {
                                            Ok(output) if output.status.success() => Ok("Driver uninstalled!".to_string()),
                                            _ => Err("Uninstall failed".to_string())
                                        }
                                    }).await;

                                    match result {
                                        Ok(Ok(msg)) => {
                                            install_status.set(msg);
                                            driver_loaded.set(is_driver_loaded());
                                        }
                                        Ok(Err(e)) => {
                                            install_status.set(e);
                                        }
                                        Err(_) => {
                                            install_status.set("Uninstall failed".to_string());
                                        }
                                    }
                                    installing.set(false);

                                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                                    install_status.set(String::new());
                                });
                            },
                            if *installing.read() {
                                "Uninstalling..."
                            } else {
                                "Uninstall Driver"
                            }
                        }
                    }

                    // Show install status message
                    if !install_status.read().is_empty() {
                        span { class: "install-status", "{install_status}" }
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
                        "Processes"
                    }
                    Link {
                        to: Route::NetworkTab {},
                        class: if is_network_tab { "tab-item tab-active" } else { "tab-item" },
                        "Network"
                    }
                    Link {
                        to: Route::ServiceTab {},
                        class: if is_service_tab { "tab-item tab-active" } else { "tab-item" },
                        "Services"
                    }
                    Link {
                        to: Route::UtilitiesTab {},
                        class: if is_utilities_tab { "tab-item tab-active" } else { "tab-item" },
                        "Usermode Utilities"
                    }
                    Link {
                        to: Route::KernelUtilitiesTab {},
                        class: if is_kernel_utilities_tab { "tab-item tab-active" } else { "tab-item" },
                        "Kernel Utilities"
                    }
                    Link {
                        to: Route::CallbackTab {},
                        class: if is_callback_tab { "tab-item tab-active" } else { "tab-item" },
                        "System Events"
                        span { class: "experimental-badge", "Experimental" }
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


                    span {
                        style: "padding: 10px; color: #e5e7eb;",
                        "Discord (Damned Software): "
                        a {
                            href: "https://discord.gg/zsqrEfCReh",
                            target: "_blank",
                            class: "about-link",
                            "https://discord.gg/zsqrEfCReh"
                        }
                    }

                }
            }

                }
            }
        }
}

/// Simple base64 decode function (no external dependency)
fn base64_decode(input: &str) -> Result<String, String> {
    fn decode_char(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            b'=' => Some(0),
            _ => None,
        }
    }

    let input = input.as_bytes();
    let mut output = Vec::with_capacity(input.len() * 3 / 4);

    for chunk in input.chunks(4) {
        if chunk.len() < 4 {
            return Err("Invalid base64 length".to_string());
        }

        let a = decode_char(chunk[0]).ok_or("Invalid base64 character")?;
        let b = decode_char(chunk[1]).ok_or("Invalid base64 character")?;
        let c = decode_char(chunk[2]).ok_or("Invalid base64 character")?;
        let d = decode_char(chunk[3]).ok_or("Invalid base64 character")?;

        output.push((a << 2) | (b >> 4));
        if chunk[2] != b'=' {
            output.push((b << 4) | (c >> 2));
        }
        if chunk[3] != b'=' {
            output.push((c << 6) | d);
        }
    }

    String::from_utf8(output).map_err(|e| format!("Invalid UTF-8: {}", e))
}
