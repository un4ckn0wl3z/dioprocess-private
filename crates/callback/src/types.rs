//! Type definitions matching the kernel driver structures

/// Collection state from the kernel driver
#[derive(Clone, Copy, Debug)]
pub struct CollectionState {
    pub is_collecting: bool,
    pub item_count: u32,
}

/// Event types from the kernel driver
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventType {
    // Process/Thread callbacks
    ProcessCreate = 0,
    ProcessExit = 1,
    ThreadCreate = 2,
    ThreadExit = 3,

    // Image load callback
    ImageLoad = 4,

    // Object Manager callbacks (handle operations)
    ProcessHandleCreate = 5,
    ProcessHandleDuplicate = 6,
    ThreadHandleCreate = 7,
    ThreadHandleDuplicate = 8,

    // Registry callbacks
    RegistryCreate = 9,
    RegistryOpen = 10,
    RegistrySetValue = 11,
    RegistryDeleteKey = 12,
    RegistryDeleteValue = 13,
    RegistryRenameKey = 14,
    RegistryQueryValue = 15,
}

impl EventType {
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(EventType::ProcessCreate),
            1 => Some(EventType::ProcessExit),
            2 => Some(EventType::ThreadCreate),
            3 => Some(EventType::ThreadExit),
            4 => Some(EventType::ImageLoad),
            5 => Some(EventType::ProcessHandleCreate),
            6 => Some(EventType::ProcessHandleDuplicate),
            7 => Some(EventType::ThreadHandleCreate),
            8 => Some(EventType::ThreadHandleDuplicate),
            9 => Some(EventType::RegistryCreate),
            10 => Some(EventType::RegistryOpen),
            11 => Some(EventType::RegistrySetValue),
            12 => Some(EventType::RegistryDeleteKey),
            13 => Some(EventType::RegistryDeleteValue),
            14 => Some(EventType::RegistryRenameKey),
            15 => Some(EventType::RegistryQueryValue),
            _ => None,
        }
    }

    /// Get event category for filtering
    pub fn category(&self) -> EventCategory {
        match self {
            EventType::ProcessCreate | EventType::ProcessExit => EventCategory::Process,
            EventType::ThreadCreate | EventType::ThreadExit => EventCategory::Thread,
            EventType::ImageLoad => EventCategory::Image,
            EventType::ProcessHandleCreate
            | EventType::ProcessHandleDuplicate
            | EventType::ThreadHandleCreate
            | EventType::ThreadHandleDuplicate => EventCategory::Handle,
            EventType::RegistryCreate
            | EventType::RegistryOpen
            | EventType::RegistrySetValue
            | EventType::RegistryDeleteKey
            | EventType::RegistryDeleteValue
            | EventType::RegistryRenameKey
            | EventType::RegistryQueryValue => EventCategory::Registry,
        }
    }
}

impl std::fmt::Display for EventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EventType::ProcessCreate => write!(f, "Process Create"),
            EventType::ProcessExit => write!(f, "Process Exit"),
            EventType::ThreadCreate => write!(f, "Thread Create"),
            EventType::ThreadExit => write!(f, "Thread Exit"),
            EventType::ImageLoad => write!(f, "Image Load"),
            EventType::ProcessHandleCreate => write!(f, "Process Handle"),
            EventType::ProcessHandleDuplicate => write!(f, "Process Handle Dup"),
            EventType::ThreadHandleCreate => write!(f, "Thread Handle"),
            EventType::ThreadHandleDuplicate => write!(f, "Thread Handle Dup"),
            EventType::RegistryCreate => write!(f, "Reg Create"),
            EventType::RegistryOpen => write!(f, "Reg Open"),
            EventType::RegistrySetValue => write!(f, "Reg SetValue"),
            EventType::RegistryDeleteKey => write!(f, "Reg DeleteKey"),
            EventType::RegistryDeleteValue => write!(f, "Reg DeleteValue"),
            EventType::RegistryRenameKey => write!(f, "Reg Rename"),
            EventType::RegistryQueryValue => write!(f, "Reg Query"),
        }
    }
}

/// Event category for filtering
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventCategory {
    Process,
    Thread,
    Image,
    Handle,
    Registry,
}

impl std::fmt::Display for EventCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EventCategory::Process => write!(f, "Process"),
            EventCategory::Thread => write!(f, "Thread"),
            EventCategory::Image => write!(f, "Image"),
            EventCategory::Handle => write!(f, "Handle"),
            EventCategory::Registry => write!(f, "Registry"),
        }
    }
}

/// Registry operation type
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistryOperation {
    CreateKey = 0,
    OpenKey = 1,
    SetValue = 2,
    DeleteKey = 3,
    DeleteValue = 4,
    RenameKey = 5,
    QueryValue = 6,
}

/// Parsed callback event with all relevant information
#[derive(Clone, Debug)]
pub struct CallbackEvent {
    pub event_type: EventType,
    pub timestamp: u64, // FILETIME as u64
    pub process_id: u32,
    pub process_name: String,

    // Process create specific
    pub parent_process_id: Option<u32>,
    pub creating_process_id: Option<u32>,
    pub command_line: Option<String>,

    // Thread specific
    pub thread_id: Option<u32>,

    // Exit code (for process/thread exit)
    pub exit_code: Option<u32>,

    // Image load specific
    pub image_base: Option<u64>,
    pub image_size: Option<u64>,
    pub image_name: Option<String>,
    pub is_system_image: Option<bool>,
    pub is_kernel_image: Option<bool>,

    // Handle operation specific
    pub source_process_id: Option<u32>,
    pub source_thread_id: Option<u32>,
    pub target_process_id: Option<u32>,
    pub target_thread_id: Option<u32>,
    pub desired_access: Option<u32>,
    pub granted_access: Option<u32>,
    pub source_image_name: Option<String>,

    // Registry specific
    pub key_name: Option<String>,
    pub value_name: Option<String>,
    pub registry_operation: Option<RegistryOperation>,
}

impl CallbackEvent {
    /// Format timestamp as local time string
    pub fn format_timestamp(&self) -> String {
        // FILETIME is 100-nanosecond intervals since January 1, 1601 UTC
        // Convert to Unix timestamp (seconds since 1970)
        // Difference between 1601 and 1970 in 100-ns intervals: 116444736000000000
        const FILETIME_UNIX_DIFF: u64 = 116_444_736_000_000_000;

        if self.timestamp < FILETIME_UNIX_DIFF {
            return "Invalid timestamp".to_string();
        }

        let unix_100ns = self.timestamp - FILETIME_UNIX_DIFF;
        let unix_secs = unix_100ns / 10_000_000;
        let subsec_100ns = unix_100ns % 10_000_000;
        let millis = subsec_100ns / 10_000;

        // Convert to local time using Windows API would be ideal,
        // but for simplicity we'll display as UTC with milliseconds
        let secs_in_day = unix_secs % 86400;
        let hours = secs_in_day / 3600;
        let minutes = (secs_in_day % 3600) / 60;
        let seconds = secs_in_day % 60;

        format!("{:02}:{:02}:{:02}.{:03}", hours, minutes, seconds, millis)
    }

    /// Get a short description of the event details
    pub fn get_details(&self) -> String {
        match self.event_type {
            EventType::ProcessCreate => {
                let mut details = Vec::new();
                if let Some(ppid) = self.parent_process_id {
                    details.push(format!("PPID: {}", ppid));
                }
                if let Some(ref cmd) = self.command_line {
                    if !cmd.is_empty() {
                        let truncated = if cmd.len() > 60 {
                            format!("{}...", &cmd[..57])
                        } else {
                            cmd.clone()
                        };
                        details.push(truncated);
                    }
                }
                details.join(" | ")
            }
            EventType::ProcessExit => {
                if let Some(code) = self.exit_code {
                    format!("Exit: 0x{:X}", code)
                } else {
                    String::new()
                }
            }
            EventType::ThreadCreate => {
                if let Some(tid) = self.thread_id {
                    format!("TID: {}", tid)
                } else {
                    String::new()
                }
            }
            EventType::ThreadExit => {
                let mut details = Vec::new();
                if let Some(tid) = self.thread_id {
                    details.push(format!("TID: {}", tid));
                }
                if let Some(code) = self.exit_code {
                    details.push(format!("Exit: 0x{:X}", code));
                }
                details.join(" | ")
            }
            EventType::ImageLoad => {
                let mut details = Vec::new();
                if let Some(ref name) = self.image_name {
                    let short_name = name
                        .rsplit('\\')
                        .next()
                        .unwrap_or(name);
                    details.push(short_name.to_string());
                }
                if let Some(base) = self.image_base {
                    details.push(format!("0x{:X}", base));
                }
                if self.is_kernel_image == Some(true) {
                    details.push("Kernel".to_string());
                }
                details.join(" | ")
            }
            EventType::ProcessHandleCreate | EventType::ProcessHandleDuplicate => {
                let mut details = Vec::new();
                if let Some(ref src) = self.source_image_name {
                    details.push(src.clone());
                }
                details.push("->".to_string());
                if let Some(tpid) = self.target_process_id {
                    details.push(format!("PID {}", tpid));
                }
                if let Some(access) = self.desired_access {
                    details.push(format!("0x{:X}", access));
                }
                details.join(" ")
            }
            EventType::ThreadHandleCreate | EventType::ThreadHandleDuplicate => {
                let mut details = Vec::new();
                if let Some(ref src) = self.source_image_name {
                    details.push(src.clone());
                }
                details.push("->".to_string());
                if let Some(ttid) = self.target_thread_id {
                    details.push(format!("TID {}", ttid));
                }
                if let Some(access) = self.desired_access {
                    details.push(format!("0x{:X}", access));
                }
                details.join(" ")
            }
            EventType::RegistryCreate
            | EventType::RegistryOpen
            | EventType::RegistrySetValue
            | EventType::RegistryDeleteKey
            | EventType::RegistryDeleteValue
            | EventType::RegistryRenameKey
            | EventType::RegistryQueryValue => {
                let mut details = Vec::new();
                if let Some(ref key) = self.key_name {
                    let truncated = if key.len() > 50 {
                        format!("...{}", &key[key.len() - 47..])
                    } else {
                        key.clone()
                    };
                    details.push(truncated);
                }
                if let Some(ref val) = self.value_name {
                    if !val.is_empty() {
                        details.push(format!("Value: {}", val));
                    }
                }
                details.join(" | ")
            }
        }
    }
}

impl Default for CallbackEvent {
    fn default() -> Self {
        Self {
            event_type: EventType::ProcessCreate,
            timestamp: 0,
            process_id: 0,
            process_name: String::new(),
            parent_process_id: None,
            creating_process_id: None,
            command_line: None,
            thread_id: None,
            exit_code: None,
            image_base: None,
            image_size: None,
            image_name: None,
            is_system_image: None,
            is_kernel_image: None,
            source_process_id: None,
            source_thread_id: None,
            target_process_id: None,
            target_thread_id: None,
            desired_access: None,
            granted_access: None,
            source_image_name: None,
            key_name: None,
            value_name: None,
            registry_operation: None,
        }
    }
}
