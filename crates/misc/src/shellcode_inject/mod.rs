mod classic;
mod threadless;
mod web_staging;

pub use classic::inject_shellcode_classic;
pub use threadless::inject_shellcode_threadless;
pub use web_staging::inject_shellcode_url;
