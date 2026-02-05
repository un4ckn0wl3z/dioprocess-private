//! Type definitions matching the kernel driver structures

/// Event types from the kernel driver
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventType {
    ProcessCreate = 0,
    ProcessExit = 1,
    ThreadCreate = 2,
    ThreadExit = 3,
}

impl EventType {
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(EventType::ProcessCreate),
            1 => Some(EventType::ProcessExit),
            2 => Some(EventType::ThreadCreate),
            3 => Some(EventType::ThreadExit),
            _ => None,
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
        }
    }
}

/// Parsed callback event with all relevant information
#[derive(Clone, Debug)]
pub struct CallbackEvent {
    pub event_type: EventType,
    pub timestamp: u64, // FILETIME as u64
    pub process_id: u32,
    pub parent_process_id: Option<u32>,
    pub creating_process_id: Option<u32>,
    pub thread_id: Option<u32>,
    pub exit_code: Option<u32>,
    pub command_line: Option<String>,
    pub process_name: String,
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
                    details.push(format!("ParentPID: {}", ppid));
                }
                if let Some(cpid) = self.creating_process_id {
                    details.push(format!("CreatorPID: {}", cpid));
                }
                if let Some(ref cmd) = self.command_line {
                    if !cmd.is_empty() {
                        let truncated = if cmd.len() > 80 {
                            format!("{}...", &cmd[..77])
                        } else {
                            cmd.clone()
                        };
                        details.push(format!("Cmd: {}", truncated));
                    }
                }
                details.join(" | ")
            }
            EventType::ProcessExit => {
                if let Some(code) = self.exit_code {
                    format!("ExitCode: {} (0x{:X})", code, code)
                } else {
                    String::new()
                }
            }
            EventType::ThreadCreate => {
                if let Some(tid) = self.thread_id {
                    format!("ThreadID: {}", tid)
                } else {
                    String::new()
                }
            }
            EventType::ThreadExit => {
                let mut details = Vec::new();
                if let Some(tid) = self.thread_id {
                    details.push(format!("ThreadID: {}", tid));
                }
                if let Some(code) = self.exit_code {
                    details.push(format!("ExitCode: {} (0x{:X})", code, code));
                }
                details.join(" | ")
            }
        }
    }
}
