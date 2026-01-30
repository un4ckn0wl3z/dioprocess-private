//! UI library for Process Monitor
//! Contains Dioxus components with custom CSS (offline)

mod components;
mod helpers;
mod state;
mod styles;

pub use components::App;
pub use helpers::copy_to_clipboard;
pub use state::*;
pub use styles::CUSTOM_STYLES;
