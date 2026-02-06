//! Route definitions for the application

use dioxus::prelude::*;

use crate::components::{
    CallbackTab, KernelUtilitiesTab, Layout, NetworkTab, ProcessTab, ServiceTab, UtilitiesTab,
};

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
    #[route("/utilities")]
    UtilitiesTab {},
    #[route("/kernel-utilities")]
    KernelUtilitiesTab {},
    #[route("/callback")]
    CallbackTab {},
}
