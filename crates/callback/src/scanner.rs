//! Cheat Engine-like memory scanner operating on raw physical memory via kernel CR3 walks.
//!
//! Provides first scan, next scan, reset, and write-back operations.
//! All memory reads go through the kernel driver's CR3 page table walk
//! and physical memory access — NOT through MmCopyVirtualMemory.

use crate::driver::open_device;
use crate::error::CallbackError;
use windows::Win32::Foundation::{CloseHandle, GetLastError};
use windows::Win32::System::IO::DeviceIoControl;

const IOCTL_DIOPROCESS_PHYS_READ_VM: u32 = 0x0022224C; // CTL_CODE(0x22, 0x893, 0, 0)

/// Maximum bytes per bulk read IOCTL call (64KB)
const PHYS_READ_VM_MAX_SIZE: usize = 64 * 1024;

// ============== Wire structs matching kernel layout ==============

#[repr(C)]
struct PhysReadVmRequest {
    process_id: u32,
    virtual_address: u64,
    size: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PhysReadVmResponse {
    bytes_read: u32,
    success: u8,
}

// ============== Public types ==============

/// Data type for scan/write operations
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ScanDataType {
    U8,
    I8,
    U16,
    I16,
    U32,
    I32,
    U64,
    I64,
    F32,
    F64,
    /// Array of Bytes — variable length hex pattern with `??` wildcards
    AOB,
}

impl ScanDataType {
    pub fn byte_size(&self) -> usize {
        match self {
            ScanDataType::U8 | ScanDataType::I8 => 1,
            ScanDataType::U16 | ScanDataType::I16 => 2,
            ScanDataType::U32 | ScanDataType::I32 => 4,
            ScanDataType::U64 | ScanDataType::I64 => 8,
            ScanDataType::F32 => 4,
            ScanDataType::F64 => 8,
            ScanDataType::AOB => 1, // AOB uses target length, not fixed size
        }
    }

    /// Whether this type is AOB (variable-length pattern)
    pub fn is_aob(&self) -> bool {
        matches!(self, ScanDataType::AOB)
    }

    pub fn label(&self) -> &'static str {
        match self {
            ScanDataType::U8 => "Byte (u8)",
            ScanDataType::I8 => "Byte (i8)",
            ScanDataType::U16 => "2 Bytes (u16)",
            ScanDataType::I16 => "2 Bytes (i16)",
            ScanDataType::U32 => "4 Bytes (u32)",
            ScanDataType::I32 => "4 Bytes (i32)",
            ScanDataType::U64 => "8 Bytes (u64)",
            ScanDataType::I64 => "8 Bytes (i64)",
            ScanDataType::F32 => "Float (f32)",
            ScanDataType::F64 => "Double (f64)",
            ScanDataType::AOB => "Array of Bytes",
        }
    }

    pub fn all() -> &'static [ScanDataType] {
        &[
            ScanDataType::U8,
            ScanDataType::I8,
            ScanDataType::U16,
            ScanDataType::I16,
            ScanDataType::U32,
            ScanDataType::I32,
            ScanDataType::U64,
            ScanDataType::I64,
            ScanDataType::F32,
            ScanDataType::F64,
            ScanDataType::AOB,
        ]
    }
}

/// Scan comparison type
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ScanType {
    Exact,
    GreaterThan,
    LessThan,
    Between,
    Changed,
    Unchanged,
    Increased,
    Decreased,
    UnknownInitial,
}

impl ScanType {
    pub fn label(&self) -> &'static str {
        match self {
            ScanType::Exact => "Exact Value",
            ScanType::GreaterThan => "Greater Than",
            ScanType::LessThan => "Less Than",
            ScanType::Between => "Between",
            ScanType::Changed => "Changed",
            ScanType::Unchanged => "Unchanged",
            ScanType::Increased => "Increased",
            ScanType::Decreased => "Decreased",
            ScanType::UnknownInitial => "Unknown Initial Value",
        }
    }

    /// Scan types available for first scan
    pub fn first_scan_types() -> &'static [ScanType] {
        &[
            ScanType::Exact,
            ScanType::GreaterThan,
            ScanType::LessThan,
            ScanType::Between,
            ScanType::UnknownInitial,
        ]
    }

    /// Scan types available for next scan
    pub fn next_scan_types() -> &'static [ScanType] {
        &[
            ScanType::Exact,
            ScanType::GreaterThan,
            ScanType::LessThan,
            ScanType::Between,
            ScanType::Changed,
            ScanType::Unchanged,
            ScanType::Increased,
            ScanType::Decreased,
        ]
    }

    /// Whether this scan type requires a value input
    pub fn needs_value(&self) -> bool {
        matches!(
            self,
            ScanType::Exact | ScanType::GreaterThan | ScanType::LessThan | ScanType::Between
        )
    }
}

/// Parsed AOB pattern with wildcard support
#[derive(Debug, Clone)]
pub struct AobPattern {
    /// The byte values (wildcard positions are 0)
    pub bytes: Vec<u8>,
    /// Mask: true = must match, false = wildcard
    pub mask: Vec<bool>,
}

/// Parse an AOB pattern string like "48 8B ?? 04" or "488B??04"
/// Returns pattern bytes and mask (true=match, false=wildcard)
pub fn parse_aob_pattern(input: &str) -> Result<AobPattern, String> {
    let cleaned = input.trim();
    if cleaned.is_empty() {
        return Err("Empty AOB pattern".to_string());
    }

    let mut bytes = Vec::new();
    let mut mask = Vec::new();

    // Split by spaces if present, otherwise parse as continuous hex pairs
    let parts: Vec<&str> = if cleaned.contains(' ') {
        cleaned.split_whitespace().collect()
    } else {
        // Split into 2-char chunks
        let mut chunks = Vec::new();
        let mut i = 0;
        while i + 1 < cleaned.len() {
            chunks.push(&cleaned[i..i + 2]);
            i += 2;
        }
        if i < cleaned.len() {
            return Err("AOB hex string must have even number of digits".to_string());
        }
        chunks
    };

    for part in &parts {
        if *part == "??" || *part == "?" {
            bytes.push(0);
            mask.push(false);
        } else {
            let hex = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")).unwrap_or(part);
            let val = u8::from_str_radix(hex, 16)
                .map_err(|_| format!("Invalid AOB byte: '{}'", part))?;
            bytes.push(val);
            mask.push(true);
        }
    }

    if bytes.is_empty() {
        return Err("AOB pattern is empty".to_string());
    }

    Ok(AobPattern { bytes, mask })
}

/// A single scan result entry
#[derive(Debug, Clone)]
pub struct ScanResult {
    /// Virtual address in target process
    pub address: u64,
    /// Current value as bytes (little-endian)
    pub current_bytes: Vec<u8>,
    /// Previous value as bytes (from last scan)
    pub previous_bytes: Vec<u8>,
}

impl ScanResult {
    pub fn format_value(&self, data_type: ScanDataType) -> String {
        format_bytes_as_value(&self.current_bytes, data_type)
    }

    pub fn format_previous(&self, data_type: ScanDataType) -> String {
        format_bytes_as_value(&self.previous_bytes, data_type)
    }
}

/// Progress information for ongoing scan
#[derive(Debug, Clone)]
pub struct ScanProgress {
    pub scanned_bytes: u64,
    pub total_bytes: u64,
    pub results_found: usize,
    pub done: bool,
}

// ============== Value parsing/formatting ==============

/// Parse a string value into bytes for the given data type (little-endian)
pub fn parse_scan_value(input: &str, data_type: ScanDataType) -> Result<Vec<u8>, String> {
    let s = input.trim();
    if s.is_empty() {
        return Err("Empty value".to_string());
    }

    match data_type {
        ScanDataType::U8 => {
            let v = parse_int_u64(s).map_err(|e| format!("Invalid u8: {}", e))?;
            if v > u8::MAX as u64 {
                return Err("Value out of range for u8".to_string());
            }
            Ok(vec![v as u8])
        }
        ScanDataType::I8 => {
            let v = parse_int_i64(s).map_err(|e| format!("Invalid i8: {}", e))?;
            if v < i8::MIN as i64 || v > i8::MAX as i64 {
                return Err("Value out of range for i8".to_string());
            }
            Ok((v as i8).to_le_bytes().to_vec())
        }
        ScanDataType::U16 => {
            let v = parse_int_u64(s).map_err(|e| format!("Invalid u16: {}", e))?;
            if v > u16::MAX as u64 {
                return Err("Value out of range for u16".to_string());
            }
            Ok((v as u16).to_le_bytes().to_vec())
        }
        ScanDataType::I16 => {
            let v = parse_int_i64(s).map_err(|e| format!("Invalid i16: {}", e))?;
            if v < i16::MIN as i64 || v > i16::MAX as i64 {
                return Err("Value out of range for i16".to_string());
            }
            Ok((v as i16).to_le_bytes().to_vec())
        }
        ScanDataType::U32 => {
            let v = parse_int_u64(s).map_err(|e| format!("Invalid u32: {}", e))?;
            if v > u32::MAX as u64 {
                return Err("Value out of range for u32".to_string());
            }
            Ok((v as u32).to_le_bytes().to_vec())
        }
        ScanDataType::I32 => {
            let v = parse_int_i64(s).map_err(|e| format!("Invalid i32: {}", e))?;
            if v < i32::MIN as i64 || v > i32::MAX as i64 {
                return Err("Value out of range for i32".to_string());
            }
            Ok((v as i32).to_le_bytes().to_vec())
        }
        ScanDataType::U64 => {
            let v = parse_int_u64(s).map_err(|e| format!("Invalid u64: {}", e))?;
            Ok(v.to_le_bytes().to_vec())
        }
        ScanDataType::I64 => {
            let v = parse_int_i64(s).map_err(|e| format!("Invalid i64: {}", e))?;
            Ok(v.to_le_bytes().to_vec())
        }
        ScanDataType::F32 => {
            let v: f32 = s.parse().map_err(|e| format!("Invalid f32: {}", e))?;
            Ok(v.to_le_bytes().to_vec())
        }
        ScanDataType::F64 => {
            let v: f64 = s.parse().map_err(|e| format!("Invalid f64: {}", e))?;
            Ok(v.to_le_bytes().to_vec())
        }
        ScanDataType::AOB => {
            // For AOB, parse_scan_value returns just the bytes (wildcards as 0x00).
            // The actual pattern+mask is parsed via parse_aob_pattern() separately.
            let pattern = parse_aob_pattern(s)?;
            Ok(pattern.bytes)
        }
    }
}

fn parse_int_u64(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|e| e.to_string())
    } else {
        s.parse::<u64>().map_err(|e| e.to_string())
    }
}

fn parse_int_i64(s: &str) -> Result<i64, String> {
    let s = s.trim();
    if s.starts_with('-') {
        s.parse::<i64>().map_err(|e| e.to_string())
    } else if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        i64::from_str_radix(hex, 16).map_err(|e| e.to_string())
    } else {
        s.parse::<i64>().map_err(|e| e.to_string())
    }
}

/// Format raw bytes as a typed value string
pub fn format_bytes_as_value(bytes: &[u8], data_type: ScanDataType) -> String {
    let size = data_type.byte_size();
    if bytes.len() < size {
        return "?".to_string();
    }

    match data_type {
        ScanDataType::U8 => format!("{}", bytes[0]),
        ScanDataType::I8 => format!("{}", bytes[0] as i8),
        ScanDataType::U16 => {
            let v = u16::from_le_bytes([bytes[0], bytes[1]]);
            format!("{}", v)
        }
        ScanDataType::I16 => {
            let v = i16::from_le_bytes([bytes[0], bytes[1]]);
            format!("{}", v)
        }
        ScanDataType::U32 => {
            let v = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            format!("{}", v)
        }
        ScanDataType::I32 => {
            let v = i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            format!("{}", v)
        }
        ScanDataType::U64 => {
            let v = u64::from_le_bytes(bytes[..8].try_into().unwrap());
            format!("{}", v)
        }
        ScanDataType::I64 => {
            let v = i64::from_le_bytes(bytes[..8].try_into().unwrap());
            format!("{}", v)
        }
        ScanDataType::F32 => {
            let v = f32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            format!("{:.6}", v)
        }
        ScanDataType::F64 => {
            let v = f64::from_le_bytes(bytes[..8].try_into().unwrap());
            format!("{:.6}", v)
        }
        ScanDataType::AOB => {
            // Display as hex bytes
            bytes
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<_>>()
                .join(" ")
        }
    }
}

/// Compare bytes as a typed value
fn compare_bytes(bytes: &[u8], target: &[u8], data_type: ScanDataType, scan_type: ScanType) -> bool {
    if data_type.is_aob() {
        // AOB comparison is handled by compare_aob() with mask — not here.
        // This function is called for non-AOB types only.
        return false;
    }

    let size = data_type.byte_size();
    if bytes.len() < size || (scan_type.needs_value() && target.len() < size) {
        return false;
    }

    match scan_type {
        ScanType::Exact => &bytes[..size] == &target[..size],
        ScanType::GreaterThan => cmp_typed(bytes, target, data_type) == std::cmp::Ordering::Greater,
        ScanType::LessThan => cmp_typed(bytes, target, data_type) == std::cmp::Ordering::Less,
        ScanType::UnknownInitial => true,
        _ => false, // Changed/Unchanged/Increased/Decreased handled separately
    }
}

/// Compare a byte slice against an AOB pattern with wildcard mask
fn compare_aob(bytes: &[u8], pattern: &AobPattern) -> bool {
    if bytes.len() < pattern.bytes.len() {
        return false;
    }
    for i in 0..pattern.bytes.len() {
        if pattern.mask[i] && bytes[i] != pattern.bytes[i] {
            return false;
        }
    }
    true
}

/// Compare bytes as previous vs current (for next scans)
fn compare_prev_current(
    prev: &[u8],
    current: &[u8],
    target: &[u8],
    data_type: ScanDataType,
    scan_type: ScanType,
) -> bool {
    let size = data_type.byte_size();
    if current.len() < size || prev.len() < size {
        return false;
    }

    match scan_type {
        ScanType::Exact => &current[..size] == &target[..size],
        ScanType::GreaterThan => cmp_typed(current, target, data_type) == std::cmp::Ordering::Greater,
        ScanType::LessThan => cmp_typed(current, target, data_type) == std::cmp::Ordering::Less,
        ScanType::Changed => &current[..size] != &prev[..size],
        ScanType::Unchanged => &current[..size] == &prev[..size],
        ScanType::Increased => cmp_typed(current, prev, data_type) == std::cmp::Ordering::Greater,
        ScanType::Decreased => cmp_typed(current, prev, data_type) == std::cmp::Ordering::Less,
        _ => false,
    }
}

fn cmp_typed(a: &[u8], b: &[u8], dt: ScanDataType) -> std::cmp::Ordering {
    macro_rules! cmp_as {
        ($ty:ty) => {{
            let s = std::mem::size_of::<$ty>();
            let va = <$ty>::from_le_bytes(a[..s].try_into().unwrap());
            let vb = <$ty>::from_le_bytes(b[..s].try_into().unwrap());
            va.partial_cmp(&vb).unwrap_or(std::cmp::Ordering::Equal)
        }};
    }
    match dt {
        ScanDataType::U8 => cmp_as!(u8),
        ScanDataType::I8 => cmp_as!(i8),
        ScanDataType::U16 => cmp_as!(u16),
        ScanDataType::I16 => cmp_as!(i16),
        ScanDataType::U32 => cmp_as!(u32),
        ScanDataType::I32 => cmp_as!(i32),
        ScanDataType::U64 => cmp_as!(u64),
        ScanDataType::I64 => cmp_as!(i64),
        ScanDataType::F32 => cmp_as!(f32),
        ScanDataType::F64 => cmp_as!(f64),
        ScanDataType::AOB => std::cmp::Ordering::Equal, // AOB doesn't support ordered comparison
    }
}

// ============== Physical VM Read ==============

/// Read virtual memory of target process via kernel CR3 page table walk.
/// Returns the bytes read. Maximum 64KB per call.
pub fn phys_read_virtual_memory(pid: u32, va: u64, size: usize) -> Result<Vec<u8>, CallbackError> {
    if size == 0 || size > PHYS_READ_VM_MAX_SIZE {
        return Err(CallbackError::InvalidParameter);
    }

    let handle = open_device()?;

    unsafe {
        let request = PhysReadVmRequest {
            process_id: pid,
            virtual_address: va,
            size: size as u32,
        };

        // Output buffer: response header + data
        let output_size = std::mem::size_of::<PhysReadVmResponse>() + size;
        let mut output_buf = vec![0u8; output_size];
        let mut bytes_returned: u32 = 0;

        let result = DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_PHYS_READ_VM,
            Some(&request as *const _ as *const _),
            std::mem::size_of::<PhysReadVmRequest>() as u32,
            Some(output_buf.as_mut_ptr() as *mut _),
            output_size as u32,
            Some(&mut bytes_returned),
            None,
        );

        let _ = CloseHandle(handle);

        if result.is_err() {
            let err = GetLastError();
            return Err(CallbackError::IoctlFailed(err.0));
        }

        let response = &*(output_buf.as_ptr() as *const PhysReadVmResponse);
        if response.success == 0 {
            return Err(CallbackError::IoctlFailed(0));
        }

        let data_start = std::mem::size_of::<PhysReadVmResponse>();
        let data_end = data_start + response.bytes_read as usize;
        if data_end > output_buf.len() {
            return Err(CallbackError::InvalidData);
        }

        Ok(output_buf[data_start..data_end].to_vec())
    }
}

// ============== Memory Region Info (for scanning) ==============

/// Memory region info for scanning — mirrors process crate's MemoryRegionInfo
#[derive(Debug, Clone)]
pub struct ScanRegion {
    pub base_address: u64,
    pub region_size: u64,
    pub state: u32,
    pub protect: u32,
}

/// Constants for memory state/protection
const MEM_COMMIT: u32 = 0x1000;
const PAGE_NOACCESS: u32 = 0x01;
const PAGE_GUARD: u32 = 0x100;

// ============== Scanner Core ==============

/// First scan: enumerate regions via process crate, read memory via CR3 walk, find matches.
/// Returns (results, total_bytes_scanned).
/// For AOB scans, pass `aob_pattern` with the parsed pattern (including wildcard mask).
pub fn first_scan(
    pid: u32,
    regions: &[ScanRegion],
    target_value: &[u8],
    data_type: ScanDataType,
    scan_type: ScanType,
    aob_pattern: Option<&AobPattern>,
) -> Result<Vec<ScanResult>, CallbackError> {
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
            let chunk_size = (size - offset).min(PHYS_READ_VM_MAX_SIZE);
            let va = base + offset as u64;

            let data = match phys_read_virtual_memory(pid, va, chunk_size) {
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

/// Next scan: re-read only the addresses from previous results and filter.
/// For AOB scans, pass `aob_pattern` with the parsed pattern (including wildcard mask).
pub fn next_scan(
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
            && sorted[batch_end].1 - start_addr < PHYS_READ_VM_MAX_SIZE as u64
        {
            batch_end += 1;
        }

        let end_addr = sorted[batch_end - 1].1 + value_size as u64;
        let read_size = (end_addr - start_addr) as usize;

        match phys_read_virtual_memory(pid, start_addr, read_size.min(PHYS_READ_VM_MAX_SIZE)) {
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

/// Write a value to a virtual address via physical memory
pub fn write_scan_value(
    pid: u32,
    address: u64,
    value_bytes: &[u8],
) -> Result<(), CallbackError> {
    // Translate VA → PA, then write physical
    let walk = crate::physical_memory::translate_virtual_address(pid, address)?;
    let pa = walk.physical_address;
    if pa == 0 {
        return Err(CallbackError::IoctlFailed(0));
    }
    crate::physical_memory::write_physical_memory(pa, value_bytes)?;
    Ok(())
}
