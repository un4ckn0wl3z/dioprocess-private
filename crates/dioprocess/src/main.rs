//! Windows Process Monitor
//! A desktop application built with Dioxus and windows-rs
#![windows_subsystem = "windows"]
use std::env;

use dioxus::desktop::{LogicalSize, WindowBuilder};
use ui::App;

fn random_title() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    let mut state = seed;
    let chars: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let len = 8 + (state % 5) as usize; // 8-12 characters
    let mut result = String::with_capacity(len);
    for _ in 0..len {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let idx = (state >> 33) as usize % chars.len();
        result.push(chars[idx] as char);
    }
    result
}

fn main() {
    let user_data_dir = env::var("LOCALAPPDATA").expect("env var LOCALAPPDATA not found");
    dioxus::LaunchBuilder::desktop()
        .with_cfg(
            dioxus::desktop::Config::new()
                .with_disable_context_menu(true)
                .with_data_directory(user_data_dir)
                .with_window(
                    WindowBuilder::new()
                        .with_title(random_title())
                        .with_decorations(false)
                        .with_inner_size(LogicalSize::new(1100.0, 700.0))
                        .with_resizable(true),
                ),
        )
        .launch(App);
}
