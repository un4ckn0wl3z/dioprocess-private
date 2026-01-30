//! Route definitions for the application

use dioxus::prelude::*;

use crate::components::{Layout, NetworkTab, ProcessTab};

/// Application routes
#[derive(Clone, Routable, Debug, PartialEq)]
pub enum Route {
    #[layout(Layout)]
    #[route("/")]
    ProcessTab {},
    #[route("/network")]
    NetworkTab {},
}
