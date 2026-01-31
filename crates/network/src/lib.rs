//! Windows network connection enumeration module
//! Contains Windows API calls for TCP/UDP connection listing

use std::collections::HashMap;
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCPROW_OWNER_PID, MIB_TCP_STATE,
    MIB_UDPROW_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows::Win32::Networking::WinSock::AF_INET;

/// Network connection protocol
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "TCP"),
            Protocol::Udp => write!(f, "UDP"),
        }
    }
}

/// TCP connection state
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    DeleteTcb,
    Unknown,
}

impl std::fmt::Display for TcpState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TcpState::Closed => write!(f, "CLOSED"),
            TcpState::Listen => write!(f, "LISTEN"),
            TcpState::SynSent => write!(f, "SYN_SENT"),
            TcpState::SynReceived => write!(f, "SYN_RECV"),
            TcpState::Established => write!(f, "ESTABLISHED"),
            TcpState::FinWait1 => write!(f, "FIN_WAIT1"),
            TcpState::FinWait2 => write!(f, "FIN_WAIT2"),
            TcpState::CloseWait => write!(f, "CLOSE_WAIT"),
            TcpState::Closing => write!(f, "CLOSING"),
            TcpState::LastAck => write!(f, "LAST_ACK"),
            TcpState::TimeWait => write!(f, "TIME_WAIT"),
            TcpState::DeleteTcb => write!(f, "DELETE_TCB"),
            TcpState::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

impl From<MIB_TCP_STATE> for TcpState {
    fn from(state: MIB_TCP_STATE) -> Self {
        match state {
            MIB_TCP_STATE(1) => TcpState::Closed,
            MIB_TCP_STATE(2) => TcpState::Listen,
            MIB_TCP_STATE(3) => TcpState::SynSent,
            MIB_TCP_STATE(4) => TcpState::SynReceived,
            MIB_TCP_STATE(5) => TcpState::Established,
            MIB_TCP_STATE(6) => TcpState::FinWait1,
            MIB_TCP_STATE(7) => TcpState::FinWait2,
            MIB_TCP_STATE(8) => TcpState::CloseWait,
            MIB_TCP_STATE(9) => TcpState::Closing,
            MIB_TCP_STATE(10) => TcpState::LastAck,
            MIB_TCP_STATE(11) => TcpState::TimeWait,
            MIB_TCP_STATE(12) => TcpState::DeleteTcb,
            _ => TcpState::Unknown,
        }
    }
}

/// Network connection information
#[derive(Clone, Debug, PartialEq)]
pub struct NetworkConnection {
    pub protocol: Protocol,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: Option<TcpState>,
    pub pid: u32,
    pub process_name: String,
    pub exe_path: String,
}

/// Convert u32 IP address to string
fn ip_to_string(ip: u32) -> String {
    let bytes = ip.to_ne_bytes();
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}

/// Convert network byte order port to host byte order
fn port_from_network(port: u32) -> u16 {
    ((port & 0xFF) << 8 | (port >> 8) & 0xFF) as u16
}

/// Get all network connections (TCP and UDP)
pub fn get_network_connections() -> Vec<NetworkConnection> {
    let mut connections = Vec::new();

    // Get process info map for name/path lookup
    let process_map: HashMap<u32, (String, String)> = process::get_processes()
        .into_iter()
        .map(|p| (p.pid, (p.name, p.exe_path)))
        .collect();

    // Get TCP connections
    connections.extend(get_tcp_connections(&process_map));

    // Get UDP connections
    connections.extend(get_udp_connections(&process_map));

    connections
}

/// Get TCP connections
fn get_tcp_connections(process_map: &HashMap<u32, (String, String)>) -> Vec<NetworkConnection> {
    let mut connections = Vec::new();

    unsafe {
        let mut size: u32 = 0;

        // First call to get required buffer size
        let _ = GetExtendedTcpTable(
            None,
            &mut size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );

        if size == 0 {
            return connections;
        }

        let mut buffer: Vec<u8> = vec![0; size as usize];

        let result = GetExtendedTcpTable(
            Some(buffer.as_mut_ptr() as *mut _),
            &mut size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );

        if result != 0 {
            return connections;
        }

        // Parse the table
        // Structure: DWORD dwNumEntries, MIB_TCPROW_OWNER_PID table[]
        let num_entries = u32::from_ne_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;
        let entry_size = std::mem::size_of::<MIB_TCPROW_OWNER_PID>();

        for i in 0..num_entries {
            let offset = 4 + i * entry_size;
            if offset + entry_size > buffer.len() {
                break;
            }

            let entry_ptr = buffer.as_ptr().add(offset) as *const MIB_TCPROW_OWNER_PID;
            let entry = &*entry_ptr;

            let pid = entry.dwOwningPid;
            let (process_name, exe_path) = process_map
                .get(&pid)
                .cloned()
                .unwrap_or_else(|| (format!("PID {}", pid), String::new()));

            connections.push(NetworkConnection {
                protocol: Protocol::Tcp,
                local_addr: ip_to_string(entry.dwLocalAddr),
                local_port: port_from_network(entry.dwLocalPort),
                remote_addr: ip_to_string(entry.dwRemoteAddr),
                remote_port: port_from_network(entry.dwRemotePort),
                state: Some(TcpState::from(MIB_TCP_STATE(entry.dwState as i32))),
                pid,
                process_name,
                exe_path,
            });
        }
    }

    connections
}

/// Get UDP connections
fn get_udp_connections(process_map: &HashMap<u32, (String, String)>) -> Vec<NetworkConnection> {
    let mut connections = Vec::new();

    unsafe {
        let mut size: u32 = 0;

        // First call to get required buffer size
        let _ = GetExtendedUdpTable(
            None,
            &mut size,
            false,
            AF_INET.0 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        );

        if size == 0 {
            return connections;
        }

        let mut buffer: Vec<u8> = vec![0; size as usize];

        let result = GetExtendedUdpTable(
            Some(buffer.as_mut_ptr() as *mut _),
            &mut size,
            false,
            AF_INET.0 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        );

        if result != 0 {
            return connections;
        }

        // Parse the table
        // Structure: DWORD dwNumEntries, MIB_UDPROW_OWNER_PID table[]
        let num_entries = u32::from_ne_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;
        let entry_size = std::mem::size_of::<MIB_UDPROW_OWNER_PID>();

        for i in 0..num_entries {
            let offset = 4 + i * entry_size;
            if offset + entry_size > buffer.len() {
                break;
            }

            let entry_ptr = buffer.as_ptr().add(offset) as *const MIB_UDPROW_OWNER_PID;
            let entry = &*entry_ptr;

            let pid = entry.dwOwningPid;
            let (process_name, exe_path) = process_map
                .get(&pid)
                .cloned()
                .unwrap_or_else(|| (format!("PID {}", pid), String::new()));

            connections.push(NetworkConnection {
                protocol: Protocol::Udp,
                local_addr: ip_to_string(entry.dwLocalAddr),
                local_port: port_from_network(entry.dwLocalPort),
                remote_addr: String::new(),
                remote_port: 0,
                state: None,
                pid,
                process_name,
                exe_path,
            });
        }
    }

    connections
}
