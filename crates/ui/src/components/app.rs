//! Main application component with routing

use dioxus::prelude::*;
use process::{format_uptime, get_system_stats};
use callback::is_driver_loaded;
use std::process::Command;

use crate::config::{delete_pat, has_pat, load_pat, load_theme, save_pat, save_theme, Theme};
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
    let mut show_license_modal = use_signal(|| false);
    let mut license_input = use_signal(|| String::new());
    let mut license_error = use_signal(|| String::new());
    let mut show_install_warning = use_signal(|| false);
    let mut license_validated = use_signal(|| false);
    let route: Route = use_route();

    // Validate license on startup
    use_future(move || async move {
        if has_pat() {
            let result = tokio::task::spawn_blocking(|| {
                if let Some(pat) = load_pat() {
                    // Test the PAT by making a simple API call
                    let response = ureq::get("https://api.github.com/user")
                        .set("Authorization", &format!("Bearer {}", pat))
                        .set("User-Agent", "DioProcess")
                        .call();

                    match response {
                        Ok(r) if r.status() == 200 => true,
                        _ => false,
                    }
                } else {
                    false
                }
            }).await;

            match result {
                Ok(true) => {
                    license_validated.set(true);
                }
                _ => {
                    // License is invalid or expired, delete it
                    delete_pat();

                    // Stop and remove driver if running
                    if is_driver_loaded() {
                        let _ = tokio::task::spawn_blocking(|| {
                            let _ = Command::new("sc").args(["stop", "dpdrv"]).output();
                            std::thread::sleep(std::time::Duration::from_millis(500));
                            let _ = Command::new("sc").args(["delete", "dpdrv"]).output();
                        }).await;
                        driver_loaded.set(false);
                    }

                    install_status.set("License expired - driver removed".to_string());
                    // Clear status after 5 seconds
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    install_status.set(String::new());
                }
            }
        }
    });

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
                                // Show warning modal first
                                show_install_warning.set(true);
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

                    // Manage License button (always visible if license exists)
                    if has_pat() {
                        button {
                            class: "license-btn",
                            onclick: move |_| {
                                show_license_modal.set(true);
                            },
                            "🔑"
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

                // Install Warning Modal
                if *show_install_warning.read() {
                    div {
                        class: "about-modal-overlay",
                        onclick: move |_| show_install_warning.set(false),

                        div {
                            class: "about-modal",
                            style: "max-width: 500px;",
                            onclick: |e| e.stop_propagation(),

                            div {
                                class: "about-modal-header",

                                h2 {
                                    class: "about-modal-title",
                                    style: "color: #fbbf24;",
                                    "⚠️ WARNING"
                                }

                                button {
                                    class: "about-modal-close",
                                    onclick: move |_| show_install_warning.set(false),
                                    "✕"
                                }
                            }

                            div {
                                style: "padding: 20px; display: flex; flex-direction: column; gap: 15px;",

                                div {
                                    style: "color: #fbbf24; font-weight: bold; font-size: 14px;",
                                    "Before installing the driver, you MUST:"
                                }

                                ul {
                                    style: "color: #e5e7eb; margin: 0; padding-left: 20px; line-height: 1.8;",
                                    li { "Disable Hyper-V: " code { style: "background: #374151; padding: 2px 6px; border-radius: 3px;", "bcdedit /set hypervisorlaunchtype off" } }
                                    li { "Disable Secure Boot in BIOS/UEFI" }
                                    li { "Disable Windows driver protections (Integrity Checks / Vulnerable Driver Blocklist)" }
                                }

                                div {
                                    style: "background: rgba(239, 68, 68, 0.2); border: 1px solid #ef4444; border-radius: 5px; padding: 12px; margin-top: 10px;",
                                    span {
                                        style: "color: #fca5a5; font-size: 13px;",
                                        "⚠️ Use ONLY on test systems. You are responsible for any damage."
                                    }
                                }

                                div {
                                    style: "display: flex; gap: 10px; justify-content: flex-end; margin-top: 10px;",

                                    button {
                                        class: "btn btn-secondary",
                                        onclick: move |_| show_install_warning.set(false),
                                        "Cancel"
                                    }

                                    button {
                                        class: "btn btn-danger",
                                        onclick: move |_| {
                                            show_install_warning.set(false);

                                            // Check if license key is configured
                                            if !has_pat() {
                                                show_license_modal.set(true);
                                                return;
                                            }

                                            installing.set(true);
                                            install_status.set(String::new());
                                            spawn(async move {
                                                let result = tokio::task::spawn_blocking(move || {
                                                    let pat = match load_pat() {
                                                        Some(p) => p,
                                                        None => return Err("Error: E1001".to_string()),
                                                    };

                                                    let appdata = match std::env::var("LOCALAPPDATA") {
                                                        Ok(p) => std::path::PathBuf::from(p),
                                                        Err(_) => return Err("Error: E1002".to_string()),
                                                    };
                                                    let dioprocess_dir = appdata.join("DioProcess");
                                                    let zip_path = dioprocess_dir.join("dpdrv.zip");

                                                    // Create directory
                                                    let _ = std::fs::create_dir_all(&dioprocess_dir);

                                                    // Clean up old files
                                                    let _ = std::fs::remove_file(&zip_path);
                                                    if let Ok(entries) = std::fs::read_dir(&dioprocess_dir) {
                                                        for entry in entries.flatten() {
                                                            let name = entry.file_name();
                                                            let name_str = name.to_string_lossy();
                                                            if name_str.starts_with("un4ckn0wl3z-dpdrv-") {
                                                                let _ = std::fs::remove_dir_all(entry.path());
                                                            }
                                                        }
                                                    }

                                                    // Fetch package
                                                    let zip_url = "https://api.github.com/repos/un4ckn0wl3z/dpdrv/zipball/main";

                                                    let response = match ureq::get(zip_url)
                                                        .set("Authorization", &format!("Bearer {}", pat))
                                                        .set("User-Agent", "DioProcess")
                                                        .set("Accept", "application/vnd.github+json")
                                                        .call()
                                                    {
                                                        Ok(r) => r,
                                                        Err(_) => return Err("Error: E1003".to_string()),
                                                    };

                                                    // Write package
                                                    let mut file = match std::fs::File::create(&zip_path) {
                                                        Ok(f) => f,
                                                        Err(_) => return Err("Error: E1004".to_string()),
                                                    };

                                                    if let Err(_) = std::io::copy(&mut response.into_reader(), &mut file) {
                                                        return Err("Error: E1004".to_string());
                                                    }

                                                    if !zip_path.exists() {
                                                        return Err("Error: E1003".to_string());
                                                    }

                                                    // Process package
                                                    let zip_file = match std::fs::File::open(&zip_path) {
                                                        Ok(f) => f,
                                                        Err(_) => return Err("Error: E1005".to_string()),
                                                    };

                                                    let mut archive = match zip::ZipArchive::new(zip_file) {
                                                        Ok(a) => a,
                                                        Err(_) => return Err("Error: E1005".to_string()),
                                                    };

                                                    for i in 0..archive.len() {
                                                        let mut file = match archive.by_index(i) {
                                                            Ok(f) => f,
                                                            Err(_) => continue,
                                                        };

                                                        let outpath = match file.enclosed_name() {
                                                            Some(p) => dioprocess_dir.join(p),
                                                            None => continue,
                                                        };

                                                        if file.name().ends_with('/') {
                                                            let _ = std::fs::create_dir_all(&outpath);
                                                        } else {
                                                            if let Some(parent) = outpath.parent() {
                                                                let _ = std::fs::create_dir_all(parent);
                                                            }
                                                            if let Ok(mut outfile) = std::fs::File::create(&outpath) {
                                                                let _ = std::io::copy(&mut file, &mut outfile);
                                                            }
                                                        }
                                                    }

                                                    let _ = std::fs::remove_file(&zip_path);

                                                    // Locate setup
                                                    let extract_dir = match std::fs::read_dir(&dioprocess_dir) {
                                                        Ok(entries) => {
                                                            let mut found = None;
                                                            for entry in entries.flatten() {
                                                                let name = entry.file_name();
                                                                let name_str = name.to_string_lossy();
                                                                if name_str.starts_with("un4ckn0wl3z-dpdrv-") && entry.path().is_dir() {
                                                                    found = Some(entry.path());
                                                                    break;
                                                                }
                                                            }
                                                            match found {
                                                                Some(p) => p,
                                                                None => return Err("Error: E1005".to_string()),
                                                            }
                                                        }
                                                        Err(_) => return Err("Error: E1005".to_string()),
                                                    };

                                                    // Run setup
                                                    let install_script = extract_dir.join("install.cmd");
                                                    if !install_script.exists() {
                                                        let _ = std::fs::remove_dir_all(&extract_dir);
                                                        return Err("Error: E1006".to_string());
                                                    }

                                                    let install_result = Command::new("cmd")
                                                        .args(["/C", install_script.to_str().unwrap_or("")])
                                                        .current_dir(&extract_dir)
                                                        .output();

                                                    // Log output
                                                    let log_path = dioprocess_dir.join("install.log");
                                                    let write_log = |output: &std::process::Output| {
                                                        use std::io::Write;
                                                        if let Ok(mut file) = std::fs::OpenOptions::new()
                                                            .create(true)
                                                            .append(true)
                                                            .open(&log_path)
                                                        {
                                                            let timestamp = std::time::SystemTime::now()
                                                                .duration_since(std::time::UNIX_EPOCH)
                                                                .map(|d| d.as_secs())
                                                                .unwrap_or(0);
                                                            let _ = writeln!(file, "\n=== {} ===", timestamp);
                                                            let _ = writeln!(file, "Code: {:?}", output.status.code());
                                                            let _ = file.write_all(&output.stdout);
                                                            let _ = file.write_all(&output.stderr);
                                                            let _ = writeln!(file, "===\n");
                                                        }
                                                    };

                                                    match install_result {
                                                        Ok(output) if output.status.success() => {
                                                            write_log(&output);
                                                            let _ = std::fs::remove_dir_all(&extract_dir);
                                                            Ok("Driver installed!".to_string())
                                                        }
                                                        Ok(output) => {
                                                            write_log(&output);
                                                            let code = output.status.code().unwrap_or(-1);
                                                            let _ = std::fs::remove_dir_all(&extract_dir);
                                                            Err(format!("Error: E1007 ({})", code))
                                                        }
                                                        Err(_) => {
                                                            let _ = std::fs::remove_dir_all(&extract_dir);
                                                            Err("Error: E1006".to_string())
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
                                                        install_status.set("Error: E1000".to_string());
                                                    }
                                                }
                                                installing.set(false);

                                                // Clear status after 5 seconds
                                                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                                                install_status.set(String::new());
                                            });
                                        },
                                        "I Understand, Proceed"
                                    }
                                }
                            }
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
                        "Kernel Enumeration"
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

                // License Key Input Modal
                if *show_license_modal.read() {
                    div {
                        class: "about-modal-overlay",
                        onclick: move |_| show_license_modal.set(false),

                        div {
                            class: "about-modal",
                            onclick: |e| e.stop_propagation(),

                            div {
                                class: "about-modal-header",

                                h2 {
                                    class: "about-modal-title",
                                    "License Key"
                                }

                                button {
                                    class: "about-modal-close",
                                    onclick: move |_| {
                                        show_license_modal.set(false);
                                        license_error.set(String::new());
                                    },
                                    "✕"
                                }
                            }

                            div {
                                style: "padding: 20px; display: flex; flex-direction: column; gap: 15px;",

                                span {
                                    style: "color: #e5e7eb;",
                                    "Enter your license key to download the driver:"
                                }

                                input {
                                    r#type: "password",
                                    placeholder: "Enter license key...",
                                    value: "{license_input}",
                                    oninput: move |evt| license_input.set(evt.value()),
                                    style: "padding: 10px; border-radius: 5px; border: 1px solid #4b5563; background: #1f2937; color: #e5e7eb; font-family: monospace;",
                                }

                                if !license_error.read().is_empty() {
                                    span {
                                        style: "color: #ef4444;",
                                        "{license_error}"
                                    }
                                }

                                div {
                                    style: "display: flex; gap: 10px; justify-content: flex-end;",

                                    if has_pat() {
                                        button {
                                            class: "btn btn-danger",
                                            onclick: move |_| {
                                                delete_pat();
                                                license_input.set(String::new());
                                                license_error.set(String::new());
                                                install_status.set("License key revoked".to_string());
                                                show_license_modal.set(false);
                                            },
                                            "Revoke License"
                                        }
                                    }

                                    button {
                                        class: "btn btn-secondary",
                                        onclick: move |_| {
                                            show_license_modal.set(false);
                                            license_error.set(String::new());
                                        },
                                        "Cancel"
                                    }

                                    button {
                                        class: "btn btn-primary",
                                        onclick: move |_| {
                                            let license_value = license_input.read().clone();
                                            if license_value.is_empty() {
                                                license_error.set("License key cannot be empty".to_string());
                                                return;
                                            }
                                            if !license_value.starts_with("github_pat_") && !license_value.starts_with("ghp_") {
                                                license_error.set("Invalid license key format".to_string());
                                                return;
                                            }
                                            save_pat(&license_value);
                                            license_input.set(String::new());
                                            license_error.set(String::new());
                                            show_license_modal.set(false);
                                        },
                                        "Activate"
                                    }
                                }

                                div {
                                    style: "margin-top: 10px; padding-top: 15px; border-top: 1px solid #4b5563;",
                                    span {
                                        style: "color: #9ca3af; font-size: 12px;",
                                        "Need a license key? Contact developer at "
                                        a {
                                            href: "https://discord.gg/zsqrEfCReh",
                                            target: "_blank",
                                            style: "color: #8b5cf6;",
                                            "Damned Software Discord"
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

