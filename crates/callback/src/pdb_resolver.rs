//! PDB Symbol Resolver for dynamic offset extraction
//!
//! Downloads ntoskrnl.pdb from Microsoft Symbol Server and extracts
//! required offsets for ETWTI patching at runtime.

use crate::error::CallbackError;
use cab::Cabinet;
use goblin::pe::PE;
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use pdb::{FallibleIterator, PDB};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Cursor, Read};
use std::path::PathBuf;

/// Microsoft Symbol Server URL
const SYMBOL_SERVER_URL: &str = "https://msdl.microsoft.com/download/symbols";

/// Cache directory for downloaded PDB files
fn get_cache_dir() -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push("dioprocess_pdb_cache");
    path
}

/// Resolved ETWTI offsets from PDB
#[derive(Debug, Clone)]
pub struct ResolvedEtwtiOffsets {
    /// Offset of EtwThreatIntProvRegHandle symbol in ntoskrnl.exe
    pub etw_threat_int_prov_reg_handle: u64,
    /// Offset of GuidEntry field in _ETW_REG_ENTRY structure
    pub etw_reg_entry_guid_entry: u64,
    /// Offset of ProviderEnableInfo field in _ETW_GUID_ENTRY structure
    pub etw_guid_entry_provider_enable_info: u64,
    /// Whether offsets were resolved from PDB (true) or hardcoded fallback (false)
    #[allow(dead_code)]
    pub from_pdb: bool,
    /// PDB signature/GUID used for resolution
    pub pdb_signature: String,
}

/// Global cache for resolved offsets
static OFFSET_CACHE: Lazy<RwLock<HashMap<String, ResolvedEtwtiOffsets>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

/// Resolved symbol info
#[derive(Debug, Clone)]
pub struct ResolvedSymbol {
    pub name: String,
    pub offset: u64,
}

/// Symbol table for address lookup
#[derive(Debug, Clone)]
pub struct SymbolTable {
    /// Sorted list of (address, symbol_name) for binary search
    symbols: Vec<(u64, String)>,
    /// Module base address
    pub base_address: u64,
}

impl SymbolTable {
    /// Look up the symbol containing an address
    pub fn lookup(&self, address: u64) -> Option<ResolvedSymbol> {
        if self.symbols.is_empty() {
            return None;
        }
        
        // Binary search for the largest address <= target
        let idx = match self.symbols.binary_search_by_key(&address, |&(addr, _)| addr) {
            Ok(i) => i,  // Exact match
            Err(i) => {
                if i == 0 {
                    return None;  // Address is before first symbol
                }
                i - 1  // Use previous symbol
            }
        };
        
        let (sym_addr, sym_name) = &self.symbols[idx];
        Some(ResolvedSymbol {
            name: sym_name.clone(),
            offset: address - sym_addr,
        })
    }
    
    /// Format address as "module!symbol+offset" or "module+offset"
    pub fn format_address(&self, address: u64, module_name: &str) -> String {
        if let Some(sym) = self.lookup(address) {
            if sym.offset == 0 {
                format!("{}!{}", module_name, sym.name)
            } else {
                format!("{}!{}+0x{:x}", module_name, sym.name, sym.offset)
            }
        } else {
            format!("{}+0x{:x}", module_name, address.saturating_sub(self.base_address))
        }
    }
}

/// Global cache for symbol tables
static SYMBOL_TABLE_CACHE: Lazy<RwLock<HashMap<String, SymbolTable>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

/// Debug info from PE file needed to download PDB
#[derive(Debug, Clone)]
pub struct PdbDebugInfo {
    pub pdb_name: String,
    pub guid: String,
    pub age: u32,
}

/// Extract PDB debug info from ntoskrnl.exe
pub fn get_ntoskrnl_pdb_info() -> Result<PdbDebugInfo, CallbackError> {
    let ntoskrnl_path = r"C:\Windows\System32\ntoskrnl.exe";
    
    let mut file = File::open(ntoskrnl_path)
        .map_err(|_| CallbackError::InvalidData)?;
    
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .map_err(|_| CallbackError::InvalidData)?;
    
    let pe = PE::parse(&buffer)
        .map_err(|_| CallbackError::InvalidData)?;
    
    // Find the debug directory
    if let Some(debug_data) = pe.debug_data {
        if let Some(codeview) = debug_data.codeview_pdb70_debug_info {
            // The signature is a raw [u8; 16] GUID in little-endian format
            // Format: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX but we need it as a continuous hex string
            let sig = &codeview.signature;
            let guid = format!(
                "{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
                sig[3], sig[2], sig[1], sig[0],  // data1 (little-endian u32)
                sig[5], sig[4],                   // data2 (little-endian u16)
                sig[7], sig[6],                   // data3 (little-endian u16)
                sig[8], sig[9], sig[10], sig[11], sig[12], sig[13], sig[14], sig[15]  // data4
            );
            
            let pdb_name = std::str::from_utf8(&codeview.filename)
                .map_err(|_| CallbackError::InvalidData)?
                .trim_end_matches('\0')
                .to_string();
            
            // Extract just the filename
            let pdb_name = pdb_name
                .rsplit('\\')
                .next()
                .unwrap_or(&pdb_name)
                .to_string();
            
            return Ok(PdbDebugInfo {
                pdb_name,
                guid,
                age: codeview.age,
            });
        }
    }
    
    Err(CallbackError::InvalidData)
}

/// Decompress a CAB file and extract the first file
fn decompress_cab(cab_data: &[u8]) -> Result<Vec<u8>, CallbackError> {
    let cursor = Cursor::new(cab_data);
    let mut cabinet = Cabinet::new(cursor)
        .map_err(|_| CallbackError::InvalidData)?;
    
    // Get the first file in the cabinet
    let folder = cabinet.folder_entries().next()
        .ok_or(CallbackError::InvalidData)?;
    let file = folder.file_entries().next()
        .ok_or(CallbackError::InvalidData)?;
    let file_name = file.name().to_string();
    
    // Read the file
    let mut reader = cabinet.read_file(&file_name)
        .map_err(|_| CallbackError::InvalidData)?;
    
    let mut decompressed = Vec::new();
    reader.read_to_end(&mut decompressed)
        .map_err(|_| CallbackError::InvalidData)?;
    
    Ok(decompressed)
}

/// Download PDB from Microsoft Symbol Server
pub fn download_pdb(info: &PdbDebugInfo) -> Result<Vec<u8>, CallbackError> {
    // Check cache first
    let cache_dir = get_cache_dir();
    let cache_file = cache_dir.join(format!("{}_{}{}", info.pdb_name, info.guid, info.age));
    
    if cache_file.exists() {
        let mut file = File::open(&cache_file)
            .map_err(|_| CallbackError::InvalidData)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)
            .map_err(|_| CallbackError::InvalidData)?;
        return Ok(buffer);
    }
    
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|_| CallbackError::IoctlFailed(0))?;
    
    // Try multiple URL formats - Microsoft Symbol Server can serve files in different ways
    let urls = [
        // Standard format: pdbname/GUID+Age/pdbname
        format!(
            "{}/{}/{}{}/{}",
            SYMBOL_SERVER_URL,
            info.pdb_name,
            info.guid,
            info.age,
            info.pdb_name
        ),
        // Compressed format: pdbname/GUID+Age/pdbname_ (underscore suffix)
        format!(
            "{}/{}/{}{}/{}",
            SYMBOL_SERVER_URL,
            info.pdb_name,
            info.guid,
            info.age,
            info.pdb_name.replace(".pdb", ".pd_")
        ),
        // Alternative: lowercase GUID
        format!(
            "{}/{}/{}{}/{}",
            SYMBOL_SERVER_URL,
            info.pdb_name,
            info.guid.to_lowercase(),
            info.age,
            info.pdb_name
        ),
    ];
    
    for url in &urls {
        let response = client
            .get(url)
            .header("User-Agent", "Microsoft-Symbol-Server/10.0.0.0")
            .send();
        
        if let Ok(resp) = response {
            if resp.status().is_success() {
                if let Ok(bytes) = resp.bytes() {
                    let pdb_data = bytes.to_vec();
                    
                    // Check if it's a CAB compressed file (starts with "MSCF")
                    if pdb_data.len() > 4 && &pdb_data[0..4] == b"MSCF" {
                        // Decompress CAB file
                        if let Ok(decompressed) = decompress_cab(&pdb_data) {
                            // Cache the decompressed PDB
                            let _ = fs::create_dir_all(&cache_dir);
                            let _ = fs::write(&cache_file, &decompressed);
                            return Ok(decompressed);
                        }
                        continue;
                    }
                    
                    // Verify it looks like a PDB (starts with "Microsoft C/C++ MSF 7.00")
                    if pdb_data.len() > 32 && pdb_data.starts_with(b"Microsoft C/C++") {
                        // Cache the downloaded PDB
                        let _ = fs::create_dir_all(&cache_dir);
                        let _ = fs::write(&cache_file, &pdb_data);
                        return Ok(pdb_data);
                    }
                }
            }
        }
    }
    
    Err(CallbackError::IoctlFailed(0))
}

/// Parse PDB and extract ETWTI offsets
pub fn parse_pdb_for_etwti_offsets(pdb_data: &[u8]) -> Result<ResolvedEtwtiOffsets, CallbackError> {
    let cursor = Cursor::new(pdb_data);
    let mut pdb = PDB::open(cursor)
        .map_err(|_| CallbackError::InvalidData)?;
    
    let mut etw_threat_int_prov_reg_handle: Option<u64> = None;
    let mut etw_reg_entry_guid_entry: Option<u64> = None;
    let mut etw_guid_entry_provider_enable_info: Option<u64> = None;
    
    // Get the global symbols
    let symbol_table = pdb.global_symbols()
        .map_err(|_| CallbackError::InvalidData)?;
    let address_map = pdb.address_map()
        .map_err(|_| CallbackError::InvalidData)?;
    
    // Search for EtwThreatIntProvRegHandle symbol
    let mut symbols = symbol_table.iter();
    while let Some(symbol) = symbols.next().map_err(|_| CallbackError::InvalidData)? {
        if let Ok(pdb::SymbolData::Public(public)) = symbol.parse() {
            let name = public.name.to_string();
            if name.to_string() == "EtwThreatIntProvRegHandle" {
                if let Some(rva) = public.offset.to_rva(&address_map) {
                    etw_threat_int_prov_reg_handle = Some(rva.0 as u64);
                }
            }
        }
    }
    
    // Get type information for structure field offsets
    let type_info = pdb.type_information()
        .map_err(|_| CallbackError::InvalidData)?;
    
    let mut type_finder = type_info.finder();
    let mut types = type_info.iter();
    
    while let Some(typ) = types.next().map_err(|_| CallbackError::InvalidData)? {
        let _ = type_finder.update(&types);
        
        if let Ok(pdb::TypeData::Class(class)) = typ.parse() {
            let class_name = class.name.to_string();
            
            // Look for _ETW_REG_ENTRY structure
            if class_name.to_string() == "_ETW_REG_ENTRY" {
                if let Some(fields) = class.fields {
                    if let Ok(field_type) = type_finder.find(fields) {
                        if let Ok(pdb::TypeData::FieldList(field_list)) = field_type.parse() {
                            for field in field_list.fields {
                                if let pdb::TypeData::Member(member) = field {
                                    if member.name.to_string().to_string() == "GuidEntry" {
                                        etw_reg_entry_guid_entry = Some(member.offset as u64);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            
            // Look for _ETW_GUID_ENTRY structure
            if class_name.to_string() == "_ETW_GUID_ENTRY" {
                if let Some(fields) = class.fields {
                    if let Ok(field_type) = type_finder.find(fields) {
                        if let Ok(pdb::TypeData::FieldList(field_list)) = field_type.parse() {
                            for field in field_list.fields {
                                if let pdb::TypeData::Member(member) = field {
                                    if member.name.to_string().to_string() == "ProviderEnableInfo" {
                                        etw_guid_entry_provider_enable_info = Some(member.offset as u64);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    // We need at least the main symbol offset
    let etw_threat_int_prov_reg_handle = etw_threat_int_prov_reg_handle
        .ok_or(CallbackError::InvalidData)?;
    
    // Use defaults for structure offsets if not found (they're typically stable)
    let etw_reg_entry_guid_entry = etw_reg_entry_guid_entry.unwrap_or(0x20);
    let etw_guid_entry_provider_enable_info = etw_guid_entry_provider_enable_info.unwrap_or(0x60);
    
    Ok(ResolvedEtwtiOffsets {
        etw_threat_int_prov_reg_handle,
        etw_reg_entry_guid_entry,
        etw_guid_entry_provider_enable_info,
        from_pdb: true,
        pdb_signature: String::new(),
    })
}

/// Resolve ETWTI offsets dynamically from PDB
/// Returns cached offsets if available, otherwise downloads and parses PDB
pub fn resolve_etwti_offsets() -> Result<ResolvedEtwtiOffsets, CallbackError> {
    // Get PDB info from ntoskrnl.exe
    let pdb_info = get_ntoskrnl_pdb_info()?;
    let cache_key = format!("{}{}", pdb_info.guid, pdb_info.age);
    
    // Check memory cache
    {
        let cache = OFFSET_CACHE.read();
        if let Some(offsets) = cache.get(&cache_key) {
            return Ok(offsets.clone());
        }
    }
    
    // Download and parse PDB
    let pdb_data = download_pdb(&pdb_info)?;
    let mut offsets = parse_pdb_for_etwti_offsets(&pdb_data)?;
    offsets.pdb_signature = cache_key.clone();
    
    // Cache the result
    {
        let mut cache = OFFSET_CACHE.write();
        cache.insert(cache_key, offsets.clone());
    }
    
    Ok(offsets)
}

/// Clear the offset cache (useful for testing or forcing re-resolution)
#[allow(dead_code)]
pub fn clear_offset_cache() {
    let mut cache = OFFSET_CACHE.write();
    cache.clear();
}

/// Resolved registry callback offsets from PDB
#[derive(Debug, Clone)]
pub struct ResolvedRegistryCallbackOffsets {
    /// Offset of Cookie field in _CM_CALLBACK_CONTEXT_BLOCK
    pub cookie_offset: u32,
    /// Offset of Function field in _CM_CALLBACK_CONTEXT_BLOCK
    pub function_offset: u32,
    /// Offset of CallerContext field in _CM_CALLBACK_CONTEXT_BLOCK
    pub context_offset: u32,
    /// Offset of Altitude field in _CM_CALLBACK_CONTEXT_BLOCK
    pub altitude_offset: u32,
    /// Whether offsets were resolved from PDB
    pub from_pdb: bool,
    /// PDB signature used for resolution
    pub pdb_signature: String,
}

/// Global cache for registry callback offsets
static REGISTRY_CALLBACK_OFFSET_CACHE: Lazy<RwLock<Option<ResolvedRegistryCallbackOffsets>>> =
    Lazy::new(|| RwLock::new(None));

/// Parse PDB and extract _CM_CALLBACK_CONTEXT_BLOCK offsets
fn parse_pdb_for_registry_callback_offsets(pdb_data: &[u8]) -> Result<ResolvedRegistryCallbackOffsets, CallbackError> {
    let cursor = Cursor::new(pdb_data);
    let mut pdb = PDB::open(cursor)
        .map_err(|_| CallbackError::InvalidData)?;
    
    let mut cookie_offset: Option<u32> = None;
    let mut function_offset: Option<u32> = None;
    let mut context_offset: Option<u32> = None;
    let mut altitude_offset: Option<u32> = None;
    
    // Get type information for structure field offsets
    let type_info = pdb.type_information()
        .map_err(|_| CallbackError::InvalidData)?;
    
    let mut type_finder = type_info.finder();
    let mut types = type_info.iter();
    
    while let Some(typ) = types.next().map_err(|_| CallbackError::InvalidData)? {
        let _ = type_finder.update(&types);
        
        if let Ok(pdb::TypeData::Class(class)) = typ.parse() {
            let class_name = class.name.to_string();
            
            // Look for _CM_CALLBACK_CONTEXT_BLOCK structure
            if class_name.to_string() == "_CM_CALLBACK_CONTEXT_BLOCK" {
                if let Some(fields) = class.fields {
                    if let Ok(field_type) = type_finder.find(fields) {
                        if let Ok(pdb::TypeData::FieldList(field_list)) = field_type.parse() {
                            for field in field_list.fields {
                                if let pdb::TypeData::Member(member) = field {
                                    let field_name = member.name.to_string().to_string();
                                    match field_name.as_str() {
                                        "Cookie" => cookie_offset = Some(member.offset as u32),
                                        "Function" => function_offset = Some(member.offset as u32),
                                        "CallerContext" => context_offset = Some(member.offset as u32),
                                        "Altitude" => altitude_offset = Some(member.offset as u32),
                                        _ => {}
                                    }
                                }
                            }
                        }
                    }
                }
                break; // Found the structure, no need to continue
            }
        }
    }
    
    // Use defaults if not found (based on Windows 10 22H2 typical layout)
    let cookie_offset = cookie_offset.unwrap_or(0x18);
    let function_offset = function_offset.unwrap_or(0x28);
    let context_offset = context_offset.unwrap_or(0x20);
    let altitude_offset = altitude_offset.unwrap_or(0x30);
    
    Ok(ResolvedRegistryCallbackOffsets {
        cookie_offset,
        function_offset,
        context_offset,
        altitude_offset,
        from_pdb: cookie_offset != 0x18 || function_offset != 0x28, // True if we found actual values
        pdb_signature: String::new(),
    })
}

/// Resolved ETHREAD offsets from PDB
#[derive(Debug, Clone)]
pub struct ResolvedEthreadOffsets {
    /// Offset of Win32StartAddress field in ETHREAD
    pub win32_start_address_offset: u32,
    /// Offset of State field in ETHREAD
    pub state_offset: u32,
    /// Offset of WaitReason field in ETHREAD
    pub wait_reason_offset: u32,
    /// Whether offsets were resolved from PDB
    pub from_pdb: bool,
    /// PDB signature used for resolution
    pub pdb_signature: String,
}

/// Global cache for ETHREAD offsets
static ETHREAD_OFFSET_CACHE: Lazy<RwLock<Option<ResolvedEthreadOffsets>>> =
    Lazy::new(|| RwLock::new(None));

/// Parse PDB and extract ETHREAD offsets
fn parse_pdb_for_ethread_offsets(pdb_data: &[u8]) -> Result<ResolvedEthreadOffsets, CallbackError> {
    let cursor = Cursor::new(pdb_data);
    let mut pdb = PDB::open(cursor)
        .map_err(|_| CallbackError::InvalidData)?;
    
    let mut win32_start_address_offset: Option<u32> = None;
    let mut state_offset: Option<u32> = None;
    let mut wait_reason_offset: Option<u32> = None;
    
    // Get type information for structure field offsets
    let type_info = pdb.type_information()
        .map_err(|_| CallbackError::InvalidData)?;
    
    let mut type_finder = type_info.finder();
    let mut types = type_info.iter();
    
    while let Some(typ) = types.next().map_err(|_| CallbackError::InvalidData)? {
        let _ = type_finder.update(&types);
        
        if let Ok(pdb::TypeData::Class(class)) = typ.parse() {
            let class_name = class.name.to_string();
            
            // Look for _ETHREAD structure
            if class_name.to_string() == "_ETHREAD" {
                if let Some(fields) = class.fields {
                    if let Ok(field_type) = type_finder.find(fields) {
                        if let Ok(pdb::TypeData::FieldList(field_list)) = field_type.parse() {
                            for field in field_list.fields {
                                if let pdb::TypeData::Member(member) = field {
                                    let field_name = member.name.to_string().to_string();
                                    match field_name.as_str() {
                                        "Win32StartAddress" => win32_start_address_offset = Some(member.offset as u32),
                                        "State" => state_offset = Some(member.offset as u32),
                                        "WaitReason" => wait_reason_offset = Some(member.offset as u32),
                                        _ => {}
                                    }
                                }
                            }
                        }
                    }
                }
                break; // Found the structure, no need to continue
            }
        }
    }
    
    // Use defaults if not found (based on Windows 10 22H2 typical layout)
    let win32_start_address_offset = win32_start_address_offset.unwrap_or(0x620);
    let state_offset = state_offset.unwrap_or(0x184);
    let wait_reason_offset = wait_reason_offset.unwrap_or(0x185);
    
    Ok(ResolvedEthreadOffsets {
        win32_start_address_offset,
        state_offset,
        wait_reason_offset,
        from_pdb: win32_start_address_offset != 0x620,
        pdb_signature: String::new(),
    })
}

/// Resolve ETHREAD offsets dynamically from PDB
/// Returns cached offsets if available, otherwise downloads and parses PDB
pub fn resolve_ethread_offsets() -> Result<ResolvedEthreadOffsets, CallbackError> {
    // Check memory cache first
    {
        let cache = ETHREAD_OFFSET_CACHE.read();
        if let Some(offsets) = cache.as_ref() {
            return Ok(offsets.clone());
        }
    }
    
    // Get PDB info from ntoskrnl.exe
    let pdb_info = get_ntoskrnl_pdb_info()?;
    let cache_key = format!("{}{}", pdb_info.guid, pdb_info.age);
    
    // Download and parse PDB
    let pdb_data = download_pdb(&pdb_info)?;
    let mut offsets = parse_pdb_for_ethread_offsets(&pdb_data)?;
    offsets.pdb_signature = cache_key;
    
    // Cache the result
    {
        let mut cache = ETHREAD_OFFSET_CACHE.write();
        *cache = Some(offsets.clone());
    }
    
    Ok(offsets)
}

/// Resolve registry callback offsets dynamically from PDB
/// Returns cached offsets if available, otherwise downloads and parses PDB
pub fn resolve_registry_callback_offsets() -> Result<ResolvedRegistryCallbackOffsets, CallbackError> {
    // Check memory cache first
    {
        let cache = REGISTRY_CALLBACK_OFFSET_CACHE.read();
        if let Some(offsets) = cache.as_ref() {
            return Ok(offsets.clone());
        }
    }
    
    // Get PDB info from ntoskrnl.exe
    let pdb_info = get_ntoskrnl_pdb_info()?;
    let cache_key = format!("{}{}", pdb_info.guid, pdb_info.age);
    
    // Download and parse PDB
    let pdb_data = download_pdb(&pdb_info)?;
    let mut offsets = parse_pdb_for_registry_callback_offsets(&pdb_data)?;
    offsets.pdb_signature = cache_key;
    
    // Cache the result
    {
        let mut cache = REGISTRY_CALLBACK_OFFSET_CACHE.write();
        *cache = Some(offsets.clone());
    }
    
    Ok(offsets)
}

/// Build a symbol table from PDB data for address lookup
fn build_symbol_table(pdb_data: &[u8]) -> Result<SymbolTable, CallbackError> {
    let cursor = Cursor::new(pdb_data);
    let mut pdb = PDB::open(cursor).map_err(|_| CallbackError::InvalidData)?;
    
    let symbol_table = pdb.global_symbols().map_err(|_| CallbackError::InvalidData)?;
    let address_map = pdb.address_map().map_err(|_| CallbackError::InvalidData)?;
    
    let mut symbols: Vec<(u64, String)> = Vec::new();
    
    let mut iter = symbol_table.iter();
    while let Some(symbol) = iter.next().map_err(|_| CallbackError::InvalidData)? {
        if let Ok(pdb::SymbolData::Public(data)) = symbol.parse() {
            if let Some(rva) = data.offset.to_rva(&address_map) {
                let name = data.name.to_string().to_string();
                // Skip compiler-generated symbols
                if !name.starts_with("__") && !name.starts_with("$") {
                    symbols.push((rva.0 as u64, name));
                }
            }
        }
    }
    
    // Sort by address for binary search
    symbols.sort_by_key(|&(addr, _)| addr);
    
    Ok(SymbolTable {
        symbols,
        base_address: 0,
    })
}

/// Get or build the ntoskrnl symbol table
pub fn get_ntoskrnl_symbols() -> Result<SymbolTable, CallbackError> {
    // Check cache first
    {
        let cache = SYMBOL_TABLE_CACHE.read();
        if let Some(table) = cache.get("ntoskrnl") {
            return Ok(table.clone());
        }
    }
    
    // Download and parse PDB
    let pdb_info = get_ntoskrnl_pdb_info()?;
    let pdb_data = download_pdb(&pdb_info)?;
    let table = build_symbol_table(&pdb_data)?;
    
    // Cache the result
    {
        let mut cache = SYMBOL_TABLE_CACHE.write();
        cache.insert("ntoskrnl".to_string(), table.clone());
    }
    
    Ok(table)
}

/// Resolve a kernel address to a symbol string like "ntoskrnl.exe!FunctionName+0x123"
pub fn resolve_kernel_symbol(address: u64, module_name: &str, module_base: u64) -> String {
    // Only resolve ntoskrnl symbols for now
    let module_lower = module_name.to_lowercase();
    if !module_lower.contains("ntoskrnl") && !module_lower.contains("ntkrnl") {
        return format!("{}+0x{:x}", module_name, address.saturating_sub(module_base));
    }
    
    // Calculate RVA
    let rva = address.saturating_sub(module_base);
    
    // Try to get symbol table
    match get_ntoskrnl_symbols() {
        Ok(table) => table.format_address(rva, module_name),
        Err(_) => format!("{}+0x{:x}", module_name, rva),
    }
}
