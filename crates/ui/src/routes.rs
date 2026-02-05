//! Route definitions for the application

use dioxus::prelude::*;

use crate::components::{CallbackTab, Layout, NetworkTab, ProcessTab, ServiceTab};

/// Application routes
#[derive(Clone, Routable, Debug, PartialEq)]
pub enum Route {
    #[layout(Layout)]
    #[route("/")]
    ProcessTab {},
    #[route("/network")]
    NetworkTab {},
    #[route("/services")]
    ServiceTab {},
    #[route("/callback")]
    CallbackTab {},
}
