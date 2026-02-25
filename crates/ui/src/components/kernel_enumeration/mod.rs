//! Kernel Enumeration Tab - Advanced kernel-mode enumeration features with sub-tabs

mod all_kernel_threads;
mod callback_enum;
mod drivers;
mod etwti;
mod filehide;
mod hypervisor;
mod kernel_threads;
mod minifilters;
mod pspcidtable;
mod respawn_monitor;

use dioxus::prelude::*;

use all_kernel_threads::AllKernelThreadsTab;
use callback_enum::CallbackEnumTab;
use drivers::DriversTab;
use etwti::EtwtiTab;
use filehide::FileHideTab;
use kernel_threads::KernelThreadsTab;
use minifilters::MinifiltersTab;
use pspcidtable::PspCidTableTab;
use respawn_monitor::RespawnMonitorTab;

// Re-export HypervisorTab as its own top-level tab
pub use hypervisor::HypervisorTab;

/// Sub-tab selection
#[derive(Clone, Copy, PartialEq, Debug)]
enum KernelUtilityTab {
    CallbackEnum,
    PspCidTable,
    KernelThreads,
    AllKernelThreads,
    Minifilters,
    Drivers,
    HideFiles,
    RespawnMonitor,
    Etwti,
}

/// Sort order (shared across sub-tabs)
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum SortOrder {
    Ascending,
    Descending,
}

/// Kernel Enumeration tab component
#[component]
pub fn KernelUtilitiesTab() -> Element {
    let driver_loaded = callback::is_driver_loaded();
    let mut active_tab = use_signal(|| KernelUtilityTab::CallbackEnum);

    rsx! {
        div {
            class: "service-tab",
            tabindex: "0",

            // Header
            div { class: "header-box",
                h1 { class: "header-title", "Kernel Enumeration" }
                div { class: "header-stats",
                    span {
                        class: if driver_loaded { "driver-status driver-status-loaded" } else { "driver-status driver-status-not-loaded" },
                        if driver_loaded {
                            "Driver: Loaded"
                        } else {
                            "Driver: Not Loaded"
                        }
                    }
                    span { class: "header-shortcuts", "F5: Refresh | Esc: Close menu" }
                }
            }

            // Sub-tabs (styled like controls bar)
            div {
                class: "controls",
                style: "border-bottom: 1px solid var(--border-secondary); padding-bottom: 12px;",
                button {
                    class: if *active_tab.read() == KernelUtilityTab::CallbackEnum { "btn btn-secondary active" } else { "btn btn-secondary" },
                    onclick: move |_| active_tab.set(KernelUtilityTab::CallbackEnum),
                    "Callback Enumeration"
                }

                button {
                    class: if *active_tab.read() == KernelUtilityTab::PspCidTable { "btn btn-secondary active" } else { "btn btn-secondary" },
                    onclick: move |_| active_tab.set(KernelUtilityTab::PspCidTable),
                    "PspCidTable Enumeration"
                }

                button {
                    class: if *active_tab.read() == KernelUtilityTab::KernelThreads { "btn btn-secondary active" } else { "btn btn-secondary" },
                    onclick: move |_| active_tab.set(KernelUtilityTab::KernelThreads),
                    "System Threads"
                }

                button {
                    class: if *active_tab.read() == KernelUtilityTab::AllKernelThreads { "btn btn-secondary active" } else { "btn btn-secondary" },
                    onclick: move |_| active_tab.set(KernelUtilityTab::AllKernelThreads),
                    "All Kernel Threads"
                }

                button {
                    class: if *active_tab.read() == KernelUtilityTab::Minifilters { "btn btn-secondary active" } else { "btn btn-secondary" },
                    onclick: move |_| active_tab.set(KernelUtilityTab::Minifilters),
                    "Minifilters Enumeration"
                }

                button {
                    class: if *active_tab.read() == KernelUtilityTab::Drivers { "btn btn-secondary active" } else { "btn btn-secondary" },
                    onclick: move |_| active_tab.set(KernelUtilityTab::Drivers),
                    "Drivers Enumeration"
                }

                button {
                    class: if *active_tab.read() == KernelUtilityTab::HideFiles { "btn btn-secondary active" } else { "btn btn-secondary" },
                    onclick: move |_| active_tab.set(KernelUtilityTab::HideFiles),
                    "Hide Files"
                }

                button {
                    class: if *active_tab.read() == KernelUtilityTab::RespawnMonitor { "btn btn-secondary active" } else { "btn btn-secondary" },
                    onclick: move |_| active_tab.set(KernelUtilityTab::RespawnMonitor),
                    "Respawn Monitor"
                }

                button {
                    class: if *active_tab.read() == KernelUtilityTab::Etwti { "btn btn-secondary active" } else { "btn btn-secondary" },
                    onclick: move |_| active_tab.set(KernelUtilityTab::Etwti),
                    "ETWTI"
                }
            }

            // Tab content
            match *active_tab.read() {
                KernelUtilityTab::CallbackEnum => rsx! { CallbackEnumTab { driver_loaded } },
                KernelUtilityTab::PspCidTable => rsx! { PspCidTableTab { driver_loaded } },
                KernelUtilityTab::KernelThreads => rsx! { KernelThreadsTab { driver_loaded } },
                KernelUtilityTab::AllKernelThreads => rsx! { AllKernelThreadsTab { driver_loaded } },
                KernelUtilityTab::Minifilters => rsx! { MinifiltersTab { driver_loaded } },
                KernelUtilityTab::Drivers => rsx! { DriversTab { driver_loaded } },
                KernelUtilityTab::HideFiles => rsx! { FileHideTab { driver_loaded } },
                KernelUtilityTab::RespawnMonitor => rsx! { RespawnMonitorTab { driver_loaded } },
                KernelUtilityTab::Etwti => rsx! { EtwtiTab { driver_loaded } },
            }
        }
    }
}
