mod create;
mod ppid_spoof;
mod hollow;
mod ghost;
mod ghostly_hollow;

pub use create::create_process;
pub use ppid_spoof::create_ppid_spoofed_process;
pub use hollow::hollow_process;
pub use ghost::ghost_process;
pub use ghostly_hollow::ghostly_hollow_process;
