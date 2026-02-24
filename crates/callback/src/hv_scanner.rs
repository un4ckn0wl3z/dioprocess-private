//! Hypervisor-level memory scanner operating via ring -1 hypercalls.
//!
//! Provides first scan, next scan, reset, and write-back operations.
//! All memory reads/writes go through the hypervisor's EPT-based
//! GVA→HVA translation — bypassing all ring 0 protections.

use crate::driver::open_device;
use crate::error::CallbackError;
use crate::scanner::{
    compare_bytes, compare_prev_current, compare_aob,
    AobPattern, ScanDataType, ScanRegion, ScanResult, ScanType,
};
use windows::Win32::Foundation::{CloseHandle, GetLastError};
use windows::Win32::System::IO::DeviceIoControl;

const IOCTL_DIOPROCESS_HV_READ_VM: u32 = 0x00222108;  // CTL_CODE(0x22, 0x842, 0, 0)
const IOCTL_DIOPROCESS_HV_WRITE_VM: u32 = 0x0022210C; // CTL_CODE(0x22, 0x843, 0, 0)

/// Maximum bytes per bulk HV read IOCTL call (64KB)
const HV_READ_VM_MAX_SIZE: usize = 64 * 1024;

/// Offset of Data field in HvWriteVmRequest (matches FIELD_OFFSET in C++)
/// Layout: ProcessId(4) + padding(4) + VirtualAddress(8) + Size(4) = 20
const HV_WRITE_REQUEST_DATA_OFFSET: usize = 20;

// ============== Wire structs matching kernel layout ==============

#[repr(C)]
struct HvReadVmRequest {
    process_id: u32,
    virtual_address: u64,
    size: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct HvReadVmResponse {
    bytes_read: u32,
    success: u8,
}

#[repr(C)]
struct HvWriteVmRequest {
    process_id: u32,
    virtual_address: u64,
    size: u32,
    // data follows
}

#[repr(C)]
#[derive(Clone, Copy)]
struct HvWriteVmResponse {
    bytes_written: u32,
    success: u8,
}

// ============== Public API ==============

/// Read virtual memory from a process via hypervisor (ring -1).
/// Returns the bytes read, or an error.
pub fn hv_read_virtual_memory(pid: u32, address: u64, size: usize) -> Result<Vec<u8>, CallbackError> {
    if size == 0 {
        return Ok(Vec::new());
    }

    let handle = open_device()?;

    let request = HvReadVmRequest {
        process_id: pid,
        virtual_address: address,
        size: size.min(HV_READ_VM_MAX_SIZE) as u32,
    };

    // Output buffer: response header + data
    let output_size = std::mem::size_of::<HvReadVmResponse>() + size.min(HV_READ_VM_MAX_SIZE);
    let mut output_buffer = vec![0u8; output_size];
    let mut bytes_returned: u32 = 0;

    let result = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_HV_READ_VM,
            Some(&request as *const _ as *const std::ffi::c_void),
            std::mem::size_of::<HvReadVmRequest>() as u32,
            Some(output_buffer.as_mut_ptr() as *mut std::ffi::c_void),
            output_size as u32,
            Some(&mut bytes_returned),
            None,
        )
    };

    unsafe { let _ = CloseHandle(handle); }

    if result.is_err() {
        let err = unsafe { GetLastError() };
        return Err(CallbackError::IoctlFailed(err.0));
    }

    // Parse response
    if bytes_returned < std::mem::size_of::<HvReadVmResponse>() as u32 {
        return Err(CallbackError::InvalidData);
    }

    let response: HvReadVmResponse = unsafe {
        std::ptr::read(output_buffer.as_ptr() as *const HvReadVmResponse)
    };

    if response.success == 0 || response.bytes_read == 0 {
        return Err(CallbackError::ReadFailed(0));
    }

    let data_start = std::mem::size_of::<HvReadVmResponse>();
    let data_end = data_start + response.bytes_read as usize;
    if data_end > output_buffer.len() {
        return Err(CallbackError::InvalidData);
    }

    Ok(output_buffer[data_start..data_end].to_vec())
}

/// Write virtual memory to a process via hypervisor (ring -1).
/// Returns the number of bytes written.
pub fn hv_write_virtual_memory(pid: u32, address: u64, data: &[u8]) -> Result<usize, CallbackError> {
    if data.is_empty() {
        return Ok(0);
    }

    let handle = open_device()?;

    // Build request with variable-length data
    // Use fixed offset for Data field to match C++ struct layout (not Rust struct size due to trailing padding)
    let header_size = HV_WRITE_REQUEST_DATA_OFFSET;
    let request_size = header_size + data.len();
    let mut request_buffer = vec![0u8; request_size];

    // Write header
    let header = HvWriteVmRequest {
        process_id: pid,
        virtual_address: address,
        size: data.len() as u32,
    };
    unsafe {
        std::ptr::write(request_buffer.as_mut_ptr() as *mut HvWriteVmRequest, header);
    }
    // Write data
    request_buffer[header_size..].copy_from_slice(data);

    let mut response = HvWriteVmResponse {
        bytes_written: 0,
        success: 0,
    };
    let mut bytes_returned: u32 = 0;

    let result = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_HV_WRITE_VM,
            Some(request_buffer.as_ptr() as *const std::ffi::c_void),
            request_size as u32,
            Some(&mut response as *mut _ as *mut std::ffi::c_void),
            std::mem::size_of::<HvWriteVmResponse>() as u32,
            Some(&mut bytes_returned),
            None,
        )
    };

    unsafe { let _ = CloseHandle(handle); }

    if result.is_err() {
        let err = unsafe { GetLastError() };
        return Err(CallbackError::IoctlFailed(err.0));
    }

    if response.success == 0 {
        return Err(CallbackError::IoctlFailed(0));
    }

    Ok(response.bytes_written as usize)
}

/// Write a scan value to a process via hypervisor (ring -1).
pub fn hv_write_scan_value(pid: u32, address: u64, bytes: &[u8]) -> Result<(), CallbackError> {
    let written = hv_write_virtual_memory(pid, address, bytes)?;
    if written != bytes.len() {
        return Err(CallbackError::IoctlFailed(0));
    }
    Ok(())
}

/// First scan via hypervisor: enumerate regions, read memory via ring -1, find matches.
pub fn hv_first_scan(
    pid: u32,
    regions: &[ScanRegion],
    target_value: &[u8],
    data_type: ScanDataType,
    scan_type: ScanType,
    aob_pattern: Option<&AobPattern>,
) -> Result<Vec<ScanResult>, CallbackError> {
    use crate::scanner::{MEM_COMMIT, PAGE_NOACCESS, PAGE_GUARD};

    let is_aob = data_type.is_aob();
    let scan_len = if is_aob {
        aob_pattern.map(|p| p.bytes.len()).unwrap_or(1)
    } else {
        data_type.byte_size()
    };
    let alignment = if is_aob { 1 } else { scan_len };
    let mut results = Vec::new();

    for region in regions {
        // Skip non-committed or protected regions
        if region.state != MEM_COMMIT {
            continue;
        }
        if region.protect == PAGE_NOACCESS || (region.protect & PAGE_GUARD) != 0 {
            continue;
        }

        let base = region.base_address;
        let size = region.region_size as usize;

        // Read in chunks
        let mut offset = 0usize;
        while offset < size {
            let chunk_size = (size - offset).min(HV_READ_VM_MAX_SIZE);
            let va = base + offset as u64;

            let data = match hv_read_virtual_memory(pid, va, chunk_size) {
                Ok(d) => d,
                Err(_) => {
                    offset += chunk_size;
                    continue;
                }
            };

            // Scan the chunk for matches
            if data.len() >= scan_len {
                let mut i = 0;
                while i + scan_len <= data.len() {
                    let matched = if is_aob {
                        if let Some(pattern) = aob_pattern {
                            compare_aob(&data[i..], pattern)
                        } else {
                            false
                        }
                    } else {
                        compare_bytes(&data[i..i + scan_len], target_value, data_type, scan_type)
                    };

                    if matched {
                        let slice = &data[i..i + scan_len];
                        results.push(ScanResult {
                            address: va + i as u64,
                            current_bytes: slice.to_vec(),
                            previous_bytes: slice.to_vec(),
                        });
                    }
                    i += alignment;
                }
            }

            offset += chunk_size;
        }
    }

    Ok(results)
}

/// Next scan via hypervisor: re-read only the addresses from previous results and filter.
pub fn hv_next_scan(
    pid: u32,
    previous_results: &[ScanResult],
    target_value: &[u8],
    data_type: ScanDataType,
    scan_type: ScanType,
    aob_pattern: Option<&AobPattern>,
) -> Result<Vec<ScanResult>, CallbackError> {
    let is_aob = data_type.is_aob();
    let value_size = if is_aob {
        aob_pattern.map(|p| p.bytes.len()).unwrap_or(1)
    } else {
        data_type.byte_size()
    };
    let mut new_results = Vec::new();

    // Batch nearby addresses into chunks for efficiency
    // Sort by address first
    let mut sorted: Vec<(usize, u64)> = previous_results
        .iter()
        .enumerate()
        .map(|(i, r)| (i, r.address))
        .collect();
    sorted.sort_by_key(|&(_, addr)| addr);

    // Read addresses in batches
    let mut batch_start = 0;
    while batch_start < sorted.len() {
        let start_addr = sorted[batch_start].1;
        let mut batch_end = batch_start + 1;

        // Group addresses within 64KB of the start
        while batch_end < sorted.len()
            && sorted[batch_end].1 - start_addr < HV_READ_VM_MAX_SIZE as u64
        {
            batch_end += 1;
        }

        let end_addr = sorted[batch_end - 1].1 + value_size as u64;
        let read_size = (end_addr - start_addr) as usize;

        match hv_read_virtual_memory(pid, start_addr, read_size.min(HV_READ_VM_MAX_SIZE)) {
            Ok(data) => {
                for &(idx, addr) in &sorted[batch_start..batch_end] {
                    let offset = (addr - start_addr) as usize;
                    if offset + value_size <= data.len() {
                        let current = &data[offset..offset + value_size];
                        let prev = &previous_results[idx].current_bytes;

                        let matched = if is_aob {
                            match scan_type {
                                ScanType::Exact => {
                                    if let Some(pattern) = aob_pattern {
                                        compare_aob(current, pattern)
                                    } else {
                                        false
                                    }
                                }
                                ScanType::Changed => current != prev.as_slice(),
                                ScanType::Unchanged => current == prev.as_slice(),
                                _ => false, // AOB doesn't support ordered comparisons
                            }
                        } else {
                            compare_prev_current(prev, current, target_value, data_type, scan_type)
                        };

                        if matched {
                            new_results.push(ScanResult {
                                address: addr,
                                current_bytes: current.to_vec(),
                                previous_bytes: prev.clone(),
                            });
                        }
                    }
                }
            }
            Err(_) => {
                // Skip addresses we can't read anymore
            }
        }

        batch_start = batch_end;
    }

    Ok(new_results)
}
