mod classic;
mod web_staging;

pub use classic::inject_shellcode_classic;
pub use web_staging::inject_shellcode_url;
