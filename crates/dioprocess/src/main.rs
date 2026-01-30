//! Windows Process Monitor
//! A desktop application built with Dioxus and windows-rs
#![windows_subsystem = "windows"]
use dioxus::desktop::{LogicalSize, WindowBuilder};
use ui::App;

fn main() {
    dioxus::LaunchBuilder::desktop()
        .with_cfg(
            dioxus::desktop::Config::new()
                .with_disable_context_menu(true)
                .with_window(
                    WindowBuilder::new()
                        .with_title("Process Monitor")
                        .with_decorations(false)
                        .with_inner_size(LogicalSize::new(1100.0, 700.0))
                        .with_resizable(true),
                ),
        )
        .launch(App);
}
