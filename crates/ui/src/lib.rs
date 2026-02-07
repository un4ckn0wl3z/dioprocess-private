//! UI library for Process Monitor
//! Contains Dioxus components with custom CSS (offline)

mod components;
pub mod config;
mod helpers;
pub mod routes;
mod state;
mod styles;

pub use components::App;
pub use config::{load_theme, save_theme, Theme};
pub use helpers::copy_to_clipboard;
pub use routes::Route;
pub use state::*;
pub use styles::get_theme_css;
