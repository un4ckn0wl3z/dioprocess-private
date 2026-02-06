//! Windows service enumeration and management module
//! Contains Windows API calls for Service Control Manager operations

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;

use windows::core::PCWSTR;
use windows::Win32::System::Services::*;

/// Service status states
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceStatus {
    Running,
    Stopped,
    StartPending,
    StopPending,
    Paused,
    PausePending,
    ContinuePending,
    Unknown,
}

impl std::fmt::Display for ServiceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceStatus::Running => write!(f, "Running"),
            ServiceStatus::Stopped => write!(f, "Stopped"),
            ServiceStatus::StartPending => write!(f, "Start Pending"),
            ServiceStatus::StopPending => write!(f, "Stop Pending"),
            ServiceStatus::Paused => write!(f, "Paused"),
            ServiceStatus::PausePending => write!(f, "Pause Pending"),
            ServiceStatus::ContinuePending => write!(f, "Continue Pending"),
            ServiceStatus::Unknown => write!(f, "Unknown"),
        }
    }
}

impl From<SERVICE_STATUS_CURRENT_STATE> for ServiceStatus {
    fn from(state: SERVICE_STATUS_CURRENT_STATE) -> Self {
        if state == SERVICE_RUNNING {
            ServiceStatus::Running
        } else if state == SERVICE_STOPPED {
            ServiceStatus::Stopped
        } else if state == SERVICE_START_PENDING {
            ServiceStatus::StartPending
        } else if state == SERVICE_STOP_PENDING {
            ServiceStatus::StopPending
        } else if state == SERVICE_PAUSED {
            ServiceStatus::Paused
        } else if state == SERVICE_PAUSE_PENDING {
            ServiceStatus::PausePending
        } else if state == SERVICE_CONTINUE_PENDING {
            ServiceStatus::ContinuePending
        } else {
            ServiceStatus::Unknown
        }
    }
}

/// Service start type
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceStartType {
    Auto,
    Manual,
    Disabled,
    Boot,
    System,
    Unknown,
}

impl std::fmt::Display for ServiceStartType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceStartType::Auto => write!(f, "Automatic"),
            ServiceStartType::Manual => write!(f, "Manual"),
            ServiceStartType::Disabled => write!(f, "Disabled"),
            ServiceStartType::Boot => write!(f, "Boot"),
            ServiceStartType::System => write!(f, "System"),
            ServiceStartType::Unknown => write!(f, "Unknown"),
        }
    }
}

impl From<SERVICE_START_TYPE> for ServiceStartType {
    fn from(st: SERVICE_START_TYPE) -> Self {
        if st == SERVICE_AUTO_START {
            ServiceStartType::Auto
        } else if st == SERVICE_DEMAND_START {
            ServiceStartType::Manual
        } else if st == SERVICE_DISABLED {
            ServiceStartType::Disabled
        } else if st == SERVICE_BOOT_START {
            ServiceStartType::Boot
        } else if st == SERVICE_SYSTEM_START {
            ServiceStartType::System
        } else {
            ServiceStartType::Unknown
        }
    }
}

/// Information about a Windows service
#[derive(Clone, Debug, PartialEq)]
pub struct ServiceInfo {
    pub name: String,
    pub display_name: String,
    pub status: ServiceStatus,
    pub start_type: ServiceStartType,
    pub binary_path: String,
    pub description: String,
    pub pid: u32,
}

/// Read a PWSTR into a Rust String (empty string if null)
unsafe fn pwstr_to_string(ptr: windows::core::PWSTR) -> String {
    if ptr.0.is_null() {
        return String::new();
    }
    let mut len = 0;
    while *ptr.0.add(len) != 0 {
        len += 1;
    }
    let slice = std::slice::from_raw_parts(ptr.0, len);
    OsString::from_wide(slice).to_string_lossy().into_owned()
}

/// Read a PCWSTR into a Rust String (empty string if null)
unsafe fn pcwstr_to_string(ptr: PCWSTR) -> String {
    if ptr.0.is_null() {
        return String::new();
    }
    let mut len = 0;
    while *ptr.0.add(len) != 0 {
        len += 1;
    }
    let slice = std::slice::from_raw_parts(ptr.0, len);
    OsString::from_wide(slice).to_string_lossy().into_owned()
}

/// Encode a Rust string as a null-terminated wide string
fn to_wide(s: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Enumerate all Win32 services
pub fn get_services() -> Vec<ServiceInfo> {
    let mut services = Vec::new();

    unsafe {
        let sc_manager = OpenSCManagerW(
            PCWSTR::null(),
            PCWSTR::null(),
            SC_MANAGER_ENUMERATE_SERVICE,
        );
        let sc_manager = match sc_manager {
            Ok(h) => h,
            Err(_) => return services,
        };

        // First call to get required buffer size
        let mut bytes_needed: u32 = 0;
        let mut services_returned: u32 = 0;
        let mut resume_handle: u32 = 0;

        let _ = EnumServicesStatusExW(
            sc_manager,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            None,
            &mut bytes_needed,
            &mut services_returned,
            Some(&mut resume_handle),
            PCWSTR::null(),
        );

        if bytes_needed == 0 {
            let _ = CloseServiceHandle(sc_manager);
            return services;
        }

        let mut buffer: Vec<u8> = vec![0u8; bytes_needed as usize];
        resume_handle = 0;

        let result = EnumServicesStatusExW(
            sc_manager,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            Some(&mut buffer),
            &mut bytes_needed,
            &mut services_returned,
            Some(&mut resume_handle),
            PCWSTR::null(),
        );

        if result.is_err() {
            let _ = CloseServiceHandle(sc_manager);
            return services;
        }

        let entries = std::slice::from_raw_parts(
            buffer.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW,
            services_returned as usize,
        );

        for entry in entries {
            let name = pwstr_to_string(entry.lpServiceName);
            let display_name = pwstr_to_string(entry.lpDisplayName);
            let status = ServiceStatus::from(entry.ServiceStatusProcess.dwCurrentState);
            let pid = entry.ServiceStatusProcess.dwProcessId;

            // Query config for start type and binary path
            let (start_type, binary_path, description) =
                query_service_config(sc_manager, &name);

            services.push(ServiceInfo {
                name,
                display_name,
                status,
                start_type,
                binary_path,
                description,
                pid,
            });
        }

        let _ = CloseServiceHandle(sc_manager);
    }

    services
}

/// Query service configuration (start type, binary path, description)
unsafe fn query_service_config(
    sc_manager: SC_HANDLE,
    service_name: &str,
) -> (ServiceStartType, String, String) {
    let wide_name = to_wide(service_name);
    let svc_handle = OpenServiceW(
        sc_manager,
        PCWSTR(wide_name.as_ptr()),
        SERVICE_QUERY_CONFIG,
    );
    let svc_handle = match svc_handle {
        Ok(h) => h,
        Err(_) => return (ServiceStartType::Unknown, String::new(), String::new()),
    };

    let mut start_type = ServiceStartType::Unknown;
    let mut binary_path = String::new();

    // Query basic config
    let mut bytes_needed: u32 = 0;
    let _ = QueryServiceConfigW(svc_handle, None, 0, &mut bytes_needed);

    if bytes_needed > 0 {
        let mut buf: Vec<u8> = vec![0u8; bytes_needed as usize];
        let config_ptr = buf.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW;
        if QueryServiceConfigW(svc_handle, Some(config_ptr), bytes_needed, &mut bytes_needed)
            .is_ok()
        {
            let config = &*config_ptr;
            start_type = ServiceStartType::from(config.dwStartType);
            binary_path = pwstr_to_string(config.lpBinaryPathName);
        }
    }

    // Query description
    let description = query_service_description(svc_handle);

    let _ = CloseServiceHandle(svc_handle);
    (start_type, binary_path, description)
}

/// Query service description via QueryServiceConfig2W
unsafe fn query_service_description(svc_handle: SC_HANDLE) -> String {
    let mut bytes_needed: u32 = 0;
    let _ = QueryServiceConfig2W(
        svc_handle,
        SERVICE_CONFIG_DESCRIPTION,
        None,
        &mut bytes_needed,
    );

    if bytes_needed == 0 {
        return String::new();
    }

    let mut buf: Vec<u8> = vec![0u8; bytes_needed as usize];
    if QueryServiceConfig2W(
        svc_handle,
        SERVICE_CONFIG_DESCRIPTION,
        Some(&mut buf),
        &mut bytes_needed,
    )
    .is_ok()
    {
        let desc = &*(buf.as_ptr() as *const SERVICE_DESCRIPTIONW);
        pcwstr_to_string(PCWSTR(desc.lpDescription.0 as *const u16))
    } else {
        String::new()
    }
}

/// Start a service by name
pub fn start_service(name: &str) -> bool {
    unsafe {
        let sc_manager = match OpenSCManagerW(
            PCWSTR::null(),
            PCWSTR::null(),
            SC_MANAGER_CONNECT,
        ) {
            Ok(h) => h,
            Err(_) => return false,
        };

        let wide_name = to_wide(name);
        let svc_handle = match OpenServiceW(
            sc_manager,
            PCWSTR(wide_name.as_ptr()),
            SERVICE_START,
        ) {
            Ok(h) => h,
            Err(_) => {
                let _ = CloseServiceHandle(sc_manager);
                return false;
            }
        };

        let result = StartServiceW(svc_handle, None).is_ok();

        let _ = CloseServiceHandle(svc_handle);
        let _ = CloseServiceHandle(sc_manager);
        result
    }
}

/// Stop a service by name
pub fn stop_service(name: &str) -> bool {
    unsafe {
        let sc_manager = match OpenSCManagerW(
            PCWSTR::null(),
            PCWSTR::null(),
            SC_MANAGER_CONNECT,
        ) {
            Ok(h) => h,
            Err(_) => return false,
        };

        let wide_name = to_wide(name);
        let svc_handle = match OpenServiceW(
            sc_manager,
            PCWSTR(wide_name.as_ptr()),
            SERVICE_STOP,
        ) {
            Ok(h) => h,
            Err(_) => {
                let _ = CloseServiceHandle(sc_manager);
                return false;
            }
        };

        let mut status = SERVICE_STATUS::default();
        let result =
            ControlService(svc_handle, SERVICE_CONTROL_STOP, &mut status).is_ok();

        let _ = CloseServiceHandle(svc_handle);
        let _ = CloseServiceHandle(sc_manager);
        result
    }
}

/// Delete a service by name
pub fn delete_service(name: &str) -> bool {
    unsafe {
        let sc_manager = match OpenSCManagerW(
            PCWSTR::null(),
            PCWSTR::null(),
            SC_MANAGER_CONNECT,
        ) {
            Ok(h) => h,
            Err(_) => return false,
        };

        let wide_name = to_wide(name);
        let svc_handle = match OpenServiceW(
            sc_manager,
            PCWSTR(wide_name.as_ptr()),
            SERVICE_ALL_ACCESS,
        ) {
            Ok(h) => h,
            Err(_) => {
                let _ = CloseServiceHandle(sc_manager);
                return false;
            }
        };

        let result = DeleteService(svc_handle).is_ok();

        let _ = CloseServiceHandle(svc_handle);
        let _ = CloseServiceHandle(sc_manager);
        result
    }
}

/// Create a new service
pub fn create_service(
    name: &str,
    display_name: &str,
    binary_path: &str,
    start_type: ServiceStartType,
) -> bool {
    unsafe {
        let sc_manager = match OpenSCManagerW(
            PCWSTR::null(),
            PCWSTR::null(),
            SC_MANAGER_CREATE_SERVICE,
        ) {
            Ok(h) => h,
            Err(_) => return false,
        };

        let wide_name = to_wide(name);
        let wide_display = to_wide(display_name);
        let wide_path = to_wide(binary_path);

        let is_kernel_driver = matches!(start_type, ServiceStartType::Boot | ServiceStartType::System);

        let win_start_type = match start_type {
            ServiceStartType::Auto => SERVICE_AUTO_START,
            ServiceStartType::Manual => SERVICE_DEMAND_START,
            ServiceStartType::Disabled => SERVICE_DISABLED,
            ServiceStartType::Boot => SERVICE_BOOT_START,
            ServiceStartType::System => SERVICE_SYSTEM_START,
            _ => SERVICE_DEMAND_START,
        };

        let service_type = if is_kernel_driver {
            SERVICE_KERNEL_DRIVER
        } else {
            SERVICE_WIN32_OWN_PROCESS
        };

        let result = CreateServiceW(
            sc_manager,
            PCWSTR(wide_name.as_ptr()),
            PCWSTR(wide_display.as_ptr()),
            SERVICE_ALL_ACCESS,
            service_type,
            win_start_type,
            SERVICE_ERROR_NORMAL,
            PCWSTR(wide_path.as_ptr()),
            PCWSTR::null(),
            None,
            PCWSTR::null(),
            PCWSTR::null(),
            PCWSTR::null(),
        );

        match result {
            Ok(svc_handle) => {
                let _ = CloseServiceHandle(svc_handle);
                let _ = CloseServiceHandle(sc_manager);
                true
            }
            Err(_) => {
                let _ = CloseServiceHandle(sc_manager);
                false
            }
        }
    }
}
