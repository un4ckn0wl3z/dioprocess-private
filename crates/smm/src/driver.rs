//! SMM driver communication functions

use std::ffi::c_void;
use std::ptr::null_mut;
use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::IO::DeviceIoControl;
use windows::core::PCWSTR;

use crate::error::SmmError;
use crate::types::*;

// Same driver as DioProcess - SMM is part of the driver
const SMM_DRIVER_NAME: &str = r"\\.\DioProcess";

fn get_current_pid() -> u32 {
    unsafe { windows::Win32::System::Threading::GetCurrentProcessId() }
}

fn open_driver() -> Result<HANDLE, SmmError> {
    let wide_name: Vec<u16> = SMM_DRIVER_NAME.encode_utf16().chain(std::iter::once(0)).collect();

    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide_name.as_ptr()),
            0x80000000 | 0x40000000, // GENERIC_READ | GENERIC_WRITE
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            HANDLE::default(),
        )?
    };

    if handle == INVALID_HANDLE_VALUE {
        return Err(SmmError::DriverOpenFailed("Invalid handle".to_string()));
    }

    Ok(handle)
}

fn send_ioctl<T, U>(
    handle: HANDLE,
    ioctl_code: u32,
    input: &T,
    output: Option<&mut U>,
) -> Result<u32, SmmError> {
    let mut bytes_returned: u32 = 0;

    let (out_ptr, out_size) = if let Some(out) = output {
        (out as *mut U as *mut c_void, std::mem::size_of::<U>() as u32)
    } else {
        (null_mut(), 0)
    };

    let result = unsafe {
        DeviceIoControl(
            handle,
            ioctl_code,
            Some(input as *const T as *const c_void),
            std::mem::size_of::<T>() as u32,
            Some(out_ptr),
            out_size,
            Some(&mut bytes_returned),
            None,
        )
    };

    if result.is_err() {
        return Err(SmmError::IoctlFailed(format!("IOCTL 0x{:X} failed", ioctl_code)));
    }

    Ok(bytes_returned)
}

/// Check if the SMM driver (DioProcess) is loaded
pub fn is_smm_driver_loaded() -> bool {
    match open_driver() {
        Ok(handle) => {
            unsafe { let _ = CloseHandle(handle); }
            true
        }
        Err(_) => false,
    }
}

/// Ping SMI handler to check if SMM is available
pub fn smm_ping() -> Result<(), SmmError> {
    let handle = open_driver()?;
    let dummy: u32 = 0;

    let result = send_ioctl(handle, IOCTL_SMM_PING, &dummy, None::<&mut u32>);
    unsafe { let _ = CloseHandle(handle); }

    result.map(|_| ()).map_err(|_| SmmError::SmiHandlerUnavailable)
}

/// Cache session info (must be called before other operations)
pub fn smm_cache_session() -> Result<(), SmmError> {
    let handle = open_driver()?;
    let request = SmmCacheSessionRequest {
        controller_pid: get_current_pid(),
    };

    let result = send_ioctl(handle, IOCTL_SMM_CACHE_SESSION, &request, None::<&mut u32>);
    unsafe { let _ = CloseHandle(handle); }

    result.map(|_| ()).map_err(|_| SmmError::CacheSessionFailed)
}

/// Read physical memory via SMM
pub fn smm_phys_read(address: u64, length: u32) -> Result<Vec<u8>, SmmError> {
    if length == 0 || length > MAX_SMM_TRANSFER_SIZE {
        return Err(SmmError::ReadLengthExceeded);
    }
    if address == 0 {
        return Err(SmmError::InvalidParameter("Address cannot be 0".to_string()));
    }

    let handle = open_driver()?;
    let mut buffer: Vec<u8> = vec![0u8; length as usize];

    let request = SmmReadRequest {
        process_id: 0,  // 0 = physical read
        address,
        buffer_address: buffer.as_mut_ptr() as u64,
        size: length,
    };

    let mut response = SmmReadWriteResponse::default();
    let result = send_ioctl(handle, IOCTL_SMM_READ_PHYS, &request, Some(&mut response));
    unsafe { let _ = CloseHandle(handle); }

    result.map_err(|_| SmmError::PhysReadFailed)?;

    if response.success != 0 {
        buffer.truncate(response.bytes_transferred as usize);
        Ok(buffer)
    } else {
        Err(SmmError::PhysReadFailed)
    }
}

/// Read virtual memory via SMM
pub fn smm_virtual_read(pid: u32, address: u64, length: u32) -> Result<Vec<u8>, SmmError> {
    if length == 0 || length > MAX_SMM_TRANSFER_SIZE {
        return Err(SmmError::ReadLengthExceeded);
    }
    if address == 0 || pid == 0 {
        return Err(SmmError::InvalidParameter("Address and PID cannot be 0".to_string()));
    }

    let handle = open_driver()?;
    let mut buffer: Vec<u8> = vec![0u8; length as usize];

    let request = SmmReadRequest {
        process_id: pid,
        address,
        buffer_address: buffer.as_mut_ptr() as u64,
        size: length,
    };

    let mut response = SmmReadWriteResponse::default();
    let result = send_ioctl(handle, IOCTL_SMM_READ_VIRTUAL, &request, Some(&mut response));
    unsafe { let _ = CloseHandle(handle); }

    result.map_err(|_| SmmError::VirtualReadFailed)?;

    if response.success != 0 {
        buffer.truncate(response.bytes_transferred as usize);
        Ok(buffer)
    } else {
        Err(SmmError::VirtualReadFailed)
    }
}

/// Write physical memory via SMM
pub fn smm_phys_write(address: u64, data: &[u8]) -> Result<u32, SmmError> {
    if data.is_empty() || data.len() > MAX_SMM_TRANSFER_SIZE as usize {
        return Err(SmmError::WriteLengthExceeded);
    }
    if address == 0 {
        return Err(SmmError::InvalidParameter("Address cannot be 0".to_string()));
    }

    let handle = open_driver()?;

    let request = SmmWriteRequest {
        process_id: 0,  // 0 = physical write
        address,
        buffer_address: data.as_ptr() as u64,
        size: data.len() as u32,
    };

    let mut response = SmmReadWriteResponse::default();
    let result = send_ioctl(handle, IOCTL_SMM_WRITE_PHYS, &request, Some(&mut response));
    unsafe { let _ = CloseHandle(handle); }

    result.map_err(|_| SmmError::PhysWriteFailed)?;

    if response.success != 0 {
        Ok(response.bytes_transferred)
    } else {
        Err(SmmError::PhysWriteFailed)
    }
}

/// Write virtual memory via SMM
pub fn smm_virtual_write(pid: u32, address: u64, data: &[u8]) -> Result<u32, SmmError> {
    if data.is_empty() || data.len() > MAX_SMM_TRANSFER_SIZE as usize {
        return Err(SmmError::WriteLengthExceeded);
    }
    if address == 0 || pid == 0 {
        return Err(SmmError::InvalidParameter("Address and PID cannot be 0".to_string()));
    }

    let handle = open_driver()?;

    let request = SmmWriteRequest {
        process_id: pid,
        address,
        buffer_address: data.as_ptr() as u64,
        size: data.len() as u32,
    };

    let mut response = SmmReadWriteResponse::default();
    let result = send_ioctl(handle, IOCTL_SMM_WRITE_VIRTUAL, &request, Some(&mut response));
    unsafe { let _ = CloseHandle(handle); }

    result.map_err(|_| SmmError::VirtualWriteFailed)?;

    if response.success != 0 {
        Ok(response.bytes_transferred)
    } else {
        Err(SmmError::VirtualWriteFailed)
    }
}

/// Translate virtual address to physical via SMM
pub fn smm_vtop(pid: u32, virtual_address: u64) -> Result<u64, SmmError> {
    if virtual_address == 0 || pid == 0 {
        return Err(SmmError::InvalidParameter("Address and PID cannot be 0".to_string()));
    }

    let handle = open_driver()?;

    let request = SmmVtopRequest {
        process_id: pid,
        virtual_address,
    };

    let mut response = SmmVtopResponse::default();
    let result = send_ioctl(handle, IOCTL_SMM_VIRT_TO_PHYS, &request, Some(&mut response));
    unsafe { let _ = CloseHandle(handle); }

    result.map_err(|_| SmmError::VtopFailed)?;

    if response.success != 0 && response.physical_address != 0 {
        Ok(response.physical_address)
    } else {
        Err(SmmError::VtopFailed)
    }
}

/// Escalate privileges via SMM (exchange token with SYSTEM)
pub fn smm_escalate_privileges() -> Result<(), SmmError> {
    let handle = open_driver()?;
    let dummy: u32 = 0;

    let result = send_ioctl(handle, IOCTL_SMM_PRIV_ESC, &dummy, None::<&mut u32>);
    unsafe { let _ = CloseHandle(handle); }

    result.map(|_| ()).map_err(|_| SmmError::PrivEscFailed)
}

/// SMM session with persistent handle
pub struct SmmSession {
    handle: HANDLE,
    session_cached: bool,
}

impl SmmSession {
    pub fn new() -> Result<Self, SmmError> {
        let handle = open_driver()?;
        Ok(Self {
            handle,
            session_cached: false,
        })
    }

    pub fn initialize(&mut self) -> Result<(), SmmError> {
        // Ping first to check SMM availability
        let dummy: u32 = 0;
        send_ioctl(self.handle, IOCTL_SMM_PING, &dummy, None::<&mut u32>)
            .map_err(|_| SmmError::SmiHandlerUnavailable)?;

        // Cache session
        let request = SmmCacheSessionRequest {
            controller_pid: get_current_pid(),
        };
        send_ioctl(self.handle, IOCTL_SMM_CACHE_SESSION, &request, None::<&mut u32>)
            .map_err(|_| SmmError::CacheSessionFailed)?;

        self.session_cached = true;
        Ok(())
    }

    pub fn ping(&self) -> Result<(), SmmError> {
        let dummy: u32 = 0;
        send_ioctl(self.handle, IOCTL_SMM_PING, &dummy, None::<&mut u32>)
            .map(|_| ())
            .map_err(|_| SmmError::SmiHandlerUnavailable)
    }

    pub fn is_session_cached(&self) -> bool {
        self.session_cached
    }

    pub fn phys_read(&self, address: u64, length: u32) -> Result<Vec<u8>, SmmError> {
        if length == 0 || length > MAX_SMM_TRANSFER_SIZE {
            return Err(SmmError::ReadLengthExceeded);
        }
        if address == 0 {
            return Err(SmmError::InvalidParameter("Address cannot be 0".to_string()));
        }

        let mut buffer: Vec<u8> = vec![0u8; length as usize];

        let request = SmmReadRequest {
            process_id: 0,
            address,
            buffer_address: buffer.as_mut_ptr() as u64,
            size: length,
        };

        let mut response = SmmReadWriteResponse::default();
        send_ioctl(self.handle, IOCTL_SMM_READ_PHYS, &request, Some(&mut response))
            .map_err(|_| SmmError::PhysReadFailed)?;

        if response.success != 0 {
            buffer.truncate(response.bytes_transferred as usize);
            Ok(buffer)
        } else {
            Err(SmmError::PhysReadFailed)
        }
    }

    pub fn virtual_read(&self, pid: u32, address: u64, length: u32) -> Result<Vec<u8>, SmmError> {
        if length == 0 || length > MAX_SMM_TRANSFER_SIZE {
            return Err(SmmError::ReadLengthExceeded);
        }
        if address == 0 || pid == 0 {
            return Err(SmmError::InvalidParameter("Address and PID cannot be 0".to_string()));
        }

        let mut buffer: Vec<u8> = vec![0u8; length as usize];

        let request = SmmReadRequest {
            process_id: pid,
            address,
            buffer_address: buffer.as_mut_ptr() as u64,
            size: length,
        };

        let mut response = SmmReadWriteResponse::default();
        send_ioctl(self.handle, IOCTL_SMM_READ_VIRTUAL, &request, Some(&mut response))
            .map_err(|_| SmmError::VirtualReadFailed)?;

        if response.success != 0 {
            buffer.truncate(response.bytes_transferred as usize);
            Ok(buffer)
        } else {
            Err(SmmError::VirtualReadFailed)
        }
    }

    pub fn phys_write(&self, address: u64, data: &[u8]) -> Result<u32, SmmError> {
        if data.is_empty() || data.len() > MAX_SMM_TRANSFER_SIZE as usize {
            return Err(SmmError::WriteLengthExceeded);
        }
        if address == 0 {
            return Err(SmmError::InvalidParameter("Address cannot be 0".to_string()));
        }

        let request = SmmWriteRequest {
            process_id: 0,
            address,
            buffer_address: data.as_ptr() as u64,
            size: data.len() as u32,
        };

        let mut response = SmmReadWriteResponse::default();
        send_ioctl(self.handle, IOCTL_SMM_WRITE_PHYS, &request, Some(&mut response))
            .map_err(|_| SmmError::PhysWriteFailed)?;

        if response.success != 0 {
            Ok(response.bytes_transferred)
        } else {
            Err(SmmError::PhysWriteFailed)
        }
    }

    pub fn virtual_write(&self, pid: u32, address: u64, data: &[u8]) -> Result<u32, SmmError> {
        if data.is_empty() || data.len() > MAX_SMM_TRANSFER_SIZE as usize {
            return Err(SmmError::WriteLengthExceeded);
        }
        if address == 0 || pid == 0 {
            return Err(SmmError::InvalidParameter("Address and PID cannot be 0".to_string()));
        }

        let request = SmmWriteRequest {
            process_id: pid,
            address,
            buffer_address: data.as_ptr() as u64,
            size: data.len() as u32,
        };

        let mut response = SmmReadWriteResponse::default();
        send_ioctl(self.handle, IOCTL_SMM_WRITE_VIRTUAL, &request, Some(&mut response))
            .map_err(|_| SmmError::VirtualWriteFailed)?;

        if response.success != 0 {
            Ok(response.bytes_transferred)
        } else {
            Err(SmmError::VirtualWriteFailed)
        }
    }

    pub fn vtop(&self, pid: u32, virtual_address: u64) -> Result<u64, SmmError> {
        if virtual_address == 0 || pid == 0 {
            return Err(SmmError::InvalidParameter("Address and PID cannot be 0".to_string()));
        }

        let request = SmmVtopRequest {
            process_id: pid,
            virtual_address,
        };

        let mut response = SmmVtopResponse::default();
        send_ioctl(self.handle, IOCTL_SMM_VIRT_TO_PHYS, &request, Some(&mut response))
            .map_err(|_| SmmError::VtopFailed)?;

        if response.success != 0 && response.physical_address != 0 {
            Ok(response.physical_address)
        } else {
            Err(SmmError::VtopFailed)
        }
    }

    pub fn escalate_privileges(&self) -> Result<(), SmmError> {
        let dummy: u32 = 0;
        send_ioctl(self.handle, IOCTL_SMM_PRIV_ESC, &dummy, None::<&mut u32>)
            .map(|_| ())
            .map_err(|_| SmmError::PrivEscFailed)
    }
}

impl Drop for SmmSession {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}
