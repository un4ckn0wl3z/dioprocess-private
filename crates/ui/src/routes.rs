//! Route definitions for the application

use dioxus::prelude::*;

use crate::components::{
    CallbackTab, HvScannerTab, HypervisorTab, KernelUtilitiesTab, Layout, MemoryScannerTab,
    MemoryTranslateTab, NetworkTab, ProcessTab, ScriptsTab, ServiceTab, UefiTab, UtilitiesTab,
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
    #[route("/hypervisor")]
    HypervisorTab {},
    #[route("/memory-translate")]
    MemoryTranslateTab {},
    #[route("/memory-scanner")]
    MemoryScannerTab {},
    #[route("/hv-scanner")]
    HvScannerTab {},
    #[route("/uefi")]
    UefiTab {},
    #[route("/callback")]
    CallbackTab {},
    #[route("/scripts")]
    ScriptsTab {},
}
