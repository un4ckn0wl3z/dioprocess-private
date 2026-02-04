use std::fmt;

/// Errors that can occur during misc operations.
#[derive(Debug)]
pub enum MiscError {
    FileNotFound(String),
    OpenProcessFailed(u32),
    AllocFailed,
    WriteFailed,
    ReadFailed,
    GetModuleHandleFailed,
    GetProcAddressFailed,
    CreateRemoteThreadFailed,
    Timeout,
    UnloadFailed,
    ThreadEnumerationFailed,
    NoThreadFound(u32),
    OpenThreadFailed(u32),
    SuspendThreadFailed(u32),
    GetContextFailed,
    SetContextFailed,
    ResumeThreadFailed(u32),
    FileReadFailed(String),
    InvalidPE(String),
    CommitFailed(String),
    DecommitFailed(String),
    FreeFailed(String),
    QueueApcFailed,
    CreateProcessFailed(String),
    OpenTokenFailed(u32),
    DuplicateTokenFailed,
    AdjustPrivilegesFailed,
    ImpersonateFailed,
    CreateProcessAsUserFailed(String),
    NtQueryFailed,
    NtUnmapFailed,
    PebReadFailed,
    ArchMismatch(String),
    GhostFileFailed(String),
    GhostSectionFailed,
    GhostNtCreateProcessFailed,
    GhostSetupFailed(String),
    PPidSpoofFailed(String),
}

impl fmt::Display for MiscError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MiscError::FileNotFound(path) => write!(f, "File not found: {}", path),
            MiscError::OpenProcessFailed(pid) => write!(f, "Failed to open process {}", pid),
            MiscError::AllocFailed => write!(f, "Failed to allocate memory in target process"),
            MiscError::WriteFailed => write!(f, "Failed to write to target process memory"),
            MiscError::ReadFailed => write!(f, "Failed to read from target process memory"),
            MiscError::GetModuleHandleFailed => write!(f, "Failed to get kernel32.dll handle"),
            MiscError::GetProcAddressFailed => write!(f, "Failed to get LoadLibraryW address"),
            MiscError::CreateRemoteThreadFailed => write!(f, "Failed to create remote thread"),
            MiscError::Timeout => write!(f, "Remote thread timed out (10s)"),
            MiscError::UnloadFailed => write!(f, "Failed to unload module"),
            MiscError::ThreadEnumerationFailed => {
                write!(f, "Failed to enumerate threads (CreateToolhelp32Snapshot)")
            }
            MiscError::NoThreadFound(pid) => {
                write!(f, "No enumerable thread found for process {}", pid)
            }
            MiscError::OpenThreadFailed(tid) => write!(f, "Failed to open thread {}", tid),
            MiscError::SuspendThreadFailed(tid) => write!(f, "Failed to suspend thread {}", tid),
            MiscError::GetContextFailed => write!(f, "Failed to get thread context"),
            MiscError::SetContextFailed => write!(f, "Failed to set thread context"),
            MiscError::ResumeThreadFailed(tid) => write!(f, "Failed to resume thread {}", tid),
            MiscError::FileReadFailed(path) => write!(f, "Failed to read file: {}", path),
            MiscError::InvalidPE(msg) => write!(f, "Invalid PE file: {}", msg),
            MiscError::CommitFailed(msg) => write!(f, "Failed to commit memory: {}", msg),
            MiscError::DecommitFailed(msg) => write!(f, "Failed to decommit memory: {}", msg),
            MiscError::FreeFailed(msg) => write!(f, "Failed to free memory: {}", msg),
            MiscError::QueueApcFailed => {
                write!(f, "Failed to queue APC on any thread in target process")
            }
            MiscError::CreateProcessFailed(msg) => write!(f, "Failed to create process: {}", msg),
            MiscError::OpenTokenFailed(pid) => {
                write!(f, "Failed to open process token for PID {}", pid)
            }
            MiscError::DuplicateTokenFailed => write!(f, "Failed to duplicate token"),
            MiscError::AdjustPrivilegesFailed => write!(f, "Failed to adjust token privileges"),
            MiscError::ImpersonateFailed => write!(f, "Failed to impersonate logged on user"),
            MiscError::CreateProcessAsUserFailed(msg) => {
                write!(f, "Failed to create process as user: {}", msg)
            }
            MiscError::NtQueryFailed => write!(f, "NtQueryInformationProcess failed"),
            MiscError::NtUnmapFailed => write!(f, "NtUnmapViewOfSection failed"),
            MiscError::PebReadFailed => write!(f, "Failed to read/write PEB"),
            MiscError::ArchMismatch(msg) => write!(f, "Architecture mismatch: {}", msg),
            MiscError::GhostFileFailed(msg) => write!(f, "Ghost file operation failed: {}", msg),
            MiscError::GhostSectionFailed => write!(f, "Failed to create image section from ghost file"),
            MiscError::GhostNtCreateProcessFailed => write!(f, "NtCreateProcessEx failed"),
            MiscError::GhostSetupFailed(msg) => write!(f, "Ghost process setup failed: {}", msg),
            MiscError::PPidSpoofFailed(msg) => write!(f, "PPID spoofing failed: {}", msg),
        }
    }
}

impl std::error::Error for MiscError {}
