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
