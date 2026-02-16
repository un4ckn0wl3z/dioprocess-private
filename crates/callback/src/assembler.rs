//! x86/x64 assembler module using Keystone Engine
//!
//! This module provides assembly-to-machine-code conversion for EPT hooks.
//! Supports both 32-bit (x86) and 64-bit (x64) assembly.

use keystone_engine::{Arch, Keystone, Mode, OptionType, OptionValue};
use process::ProcessArch;
use std::fmt;

/// Assembler error type
#[derive(Debug, Clone)]
pub struct AssemblerError {
    pub message: String,
    pub line: Option<usize>,
}

impl fmt::Display for AssemblerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(line) = self.line {
            write!(f, "Line {}: {}", line, self.message)
        } else {
            write!(f, "{}", self.message)
        }
    }
}

impl std::error::Error for AssemblerError {}

/// Assemble x86 or x64 assembly code to machine code bytes
///
/// # Arguments
/// * `code` - Assembly code (e.g., "mov rax, 0x1234; ret" or "nop\nret")
/// * `arch` - Target architecture (x86 or x64)
/// * `base_address` - Base address for relative address calculations (default: 0)
///
/// # Returns
/// * `Ok(Vec<u8>)` - Assembled machine code bytes
/// * `Err(AssemblerError)` - Assembly error with optional line number
///
/// # Example
/// ```ignore
/// use callback::assembler::assemble;
/// use process::ProcessArch;
///
/// let bytes = assemble("nop; ret", ProcessArch::X64, 0)?;
/// assert_eq!(bytes, vec![0x90, 0xC3]);
/// ```
pub fn assemble(code: &str, arch: ProcessArch, base_address: u64) -> Result<Vec<u8>, AssemblerError> {
    if code.trim().is_empty() {
        return Err(AssemblerError {
            message: "No assembly code provided".to_string(),
            line: None,
        });
    }

    // Select Keystone mode based on architecture
    let mode = match arch {
        ProcessArch::X64 => Mode::MODE_64,
        ProcessArch::X86 => Mode::MODE_32,
        ProcessArch::Unknown => {
            return Err(AssemblerError {
                message: "Cannot assemble for unknown architecture".to_string(),
                line: None,
            });
        }
    };

    // Create Keystone engine instance
    let engine = Keystone::new(Arch::X86, mode).map_err(|e| AssemblerError {
        message: format!("Failed to initialize assembler: {:?}", e),
        line: None,
    })?;

    // Enable syntax flexibility (Intel syntax)
    let _ = engine.option(OptionType::SYNTAX, OptionValue::SYNTAX_INTEL);

    // Assemble the code
    let result = engine.asm(code.to_string(), base_address).map_err(|e| {
        // Try to extract line number from error
        let msg = format!("{:?}", e);
        AssemblerError {
            message: msg,
            line: None,
        }
    })?;

    if result.bytes.is_empty() {
        return Err(AssemblerError {
            message: "Assembly produced no output bytes".to_string(),
            line: None,
        });
    }

    Ok(result.bytes)
}

/// Assemble with auto-detected architecture from process
///
/// # Arguments
/// * `code` - Assembly code
/// * `pid` - Target process ID (used to detect architecture)
/// * `base_address` - Base address for relative calculations
pub fn assemble_for_process(code: &str, pid: u32, base_address: u64) -> Result<Vec<u8>, AssemblerError> {
    let arch = process::get_process_arch(pid);
    assemble(code, arch, base_address)
}

/// Format assembled bytes as a hex string for display
pub fn format_bytes_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ")
}

/// Validate assembly code without actually assembling
/// Returns Ok(()) if valid, Err with details if invalid
pub fn validate_assembly(code: &str, arch: ProcessArch) -> Result<(), AssemblerError> {
    assemble(code, arch, 0).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_assemble_nop_x64() {
        let result = assemble("nop", ProcessArch::X64, 0);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![0x90]);
    }

    #[test]
    fn test_assemble_ret_x64() {
        let result = assemble("ret", ProcessArch::X64, 0);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![0xC3]);
    }

    #[test]
    fn test_assemble_nop_x86() {
        let result = assemble("nop", ProcessArch::X86, 0);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![0x90]);
    }

    #[test]
    fn test_assemble_multiple_instructions() {
        let result = assemble("nop; nop; ret", ProcessArch::X64, 0);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![0x90, 0x90, 0xC3]);
    }

    #[test]
    fn test_assemble_mov_rax_x64() {
        let result = assemble("mov rax, 0x1234", ProcessArch::X64, 0);
        assert!(result.is_ok());
        // movabs rax, 0x1234 = 48 B8 34 12 00 00 00 00 00 00
        let bytes = result.unwrap();
        assert!(bytes.len() > 0);
    }

    #[test]
    fn test_assemble_empty_fails() {
        let result = assemble("", ProcessArch::X64, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_assemble_invalid_fails() {
        let result = assemble("invalid_instruction_xyz", ProcessArch::X64, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_format_bytes_hex() {
        assert_eq!(format_bytes_hex(&[0x90, 0xC3]), "90 C3");
        assert_eq!(format_bytes_hex(&[0x48, 0x89, 0xC0]), "48 89 C0");
    }
}
