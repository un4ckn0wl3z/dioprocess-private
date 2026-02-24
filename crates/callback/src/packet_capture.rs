//! Packet Capture functionality via WFP (Windows Filtering Platform)
//!
//! Provides per-process TCP/UDP packet capture, filtering, and injection.

use crate::driver::open_device;
use crate::error::CallbackError;
use std::net::Ipv4Addr;
use windows::Win32::Foundation::{CloseHandle, GetLastError};
use windows::Win32::System::IO::DeviceIoControl;

// IOCTL codes matching DioProcessCommon.h
// CTL_CODE(DeviceType, Function, Method, Access) = (DeviceType << 16) | (Access << 14) | (Function << 2) | Method
const IOCTL_DIOPROCESS_PACKET_START_CAPTURE: u32 = 0x00222400; // CTL_CODE(0x22, 0x900, 0, 0)
const IOCTL_DIOPROCESS_PACKET_STOP_CAPTURE: u32 = 0x00222404;  // CTL_CODE(0x22, 0x901, 0, 0)
const IOCTL_DIOPROCESS_PACKET_GET_PACKETS: u32 = 0x00222408;   // CTL_CODE(0x22, 0x902, 0, 0)
#[allow(dead_code)]
const IOCTL_DIOPROCESS_PACKET_INJECT: u32 = 0x0022240C;        // CTL_CODE(0x22, 0x903, 0, 0)
const IOCTL_DIOPROCESS_PACKET_ADD_FILTER: u32 = 0x00222410;    // CTL_CODE(0x22, 0x904, 0, 0)
const IOCTL_DIOPROCESS_PACKET_REMOVE_FILTER: u32 = 0x00222414; // CTL_CODE(0x22, 0x905, 0, 0)
const IOCTL_DIOPROCESS_PACKET_CLEAR_FILTERS: u32 = 0x00222418; // CTL_CODE(0x22, 0x906, 0, 0)
const IOCTL_DIOPROCESS_PACKET_CLEAR_BUFFER: u32 = 0x0022241C;  // CTL_CODE(0x22, 0x907, 0, 0)
const IOCTL_DIOPROCESS_PACKET_GET_STATE: u32 = 0x00222420;     // CTL_CODE(0x22, 0x908, 0, 0)

const MAX_PACKET_PAYLOAD: usize = 1500;

/// Packet direction
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum PacketDirection {
    Outbound = 0,
    Inbound = 1,
}

impl From<u8> for PacketDirection {
    fn from(val: u8) -> Self {
        match val {
            0 => PacketDirection::Outbound,
            _ => PacketDirection::Inbound,
        }
    }
}

/// Packet protocol
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum PacketProtocol {
    Tcp = 6,
    Udp = 17,
}

impl From<u8> for PacketProtocol {
    fn from(val: u8) -> Self {
        match val {
            6 => PacketProtocol::Tcp,
            _ => PacketProtocol::Udp,
        }
    }
}

impl std::fmt::Display for PacketProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PacketProtocol::Tcp => write!(f, "TCP"),
            PacketProtocol::Udp => write!(f, "UDP"),
        }
    }
}

/// Filter action
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum FilterAction {
    Allow = 0,
    Block = 1,
}

/// Captured packet data
#[derive(Clone, Debug)]
pub struct CapturedPacket {
    pub id: u64,
    pub timestamp: u64,
    pub pid: u32,
    pub direction: PacketDirection,
    pub protocol: PacketProtocol,
    pub local_addr: Ipv4Addr,
    pub local_port: u16,
    pub remote_addr: Ipv4Addr,
    pub remote_port: u16,
    pub payload: Vec<u8>,
}

/// Packet filter rule
#[derive(Clone, Debug)]
pub struct PacketFilterRule {
    pub enabled: bool,
    pub action: FilterAction,
    pub port: u16,           // 0 = any port
    pub ip_address: u32,     // 0 = any IP
    pub protocol: PacketProtocol,
}

/// Capture state
#[derive(Clone, Debug)]
pub struct CaptureState {
    pub is_capturing: bool,
    pub target_pid: u32,
    pub packet_count: u32,
    pub dropped_count: u32,
}

// Raw structures matching kernel driver (packed)
#[repr(C, packed)]
struct RawCapturedPacket {
    id: u64,
    timestamp: u64,
    process_id: u32,
    direction: u8,
    protocol: u8,
    local_addr: u32,
    local_port: u16,
    remote_addr: u32,
    remote_port: u16,
    payload_size: u16,
    payload: [u8; MAX_PACKET_PAYLOAD],
}

#[repr(C)]
struct PacketCaptureStartRequest {
    target_pid: u32,
}

#[repr(C)]
struct PacketCaptureStateResponse {
    is_capturing: u8,
    target_pid: u32,
    packet_count: u32,
    dropped_count: u32,
}

#[repr(C, packed)]
struct RawPacketFilterRule {
    enabled: u8,
    action: u8,
    port: u16,
    ip_address: u32,
    protocol: u8,
}

#[repr(C)]
struct PacketFilterRemoveRequest {
    index: u32,
}

/// Start packet capture for a specific process
pub fn start_packet_capture(pid: u32) -> Result<(), CallbackError> {
    let handle = open_device()?;

    let request = PacketCaptureStartRequest { target_pid: pid };
    let mut bytes_returned: u32 = 0;

    unsafe {
        let result = DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_PACKET_START_CAPTURE,
            Some(&request as *const _ as *const _),
            std::mem::size_of::<PacketCaptureStartRequest>() as u32,
            None,
            0,
            Some(&mut bytes_returned),
            None,
        );

        let _ = CloseHandle(handle);

        if result.is_err() {
            let err = GetLastError();
            return Err(CallbackError::IoctlFailed(err.0));
        }
    }

    Ok(())
}

/// Stop packet capture
pub fn stop_packet_capture() -> Result<(), CallbackError> {
    let handle = open_device()?;
    let mut bytes_returned: u32 = 0;

    unsafe {
        let result = DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_PACKET_STOP_CAPTURE,
            None,
            0,
            None,
            0,
            Some(&mut bytes_returned),
            None,
        );

        let _ = CloseHandle(handle);

        if result.is_err() {
            let err = GetLastError();
            return Err(CallbackError::IoctlFailed(err.0));
        }
    }

    Ok(())
}

/// Get captured packets from the kernel buffer
pub fn get_captured_packets() -> Result<Vec<CapturedPacket>, CallbackError> {
    let handle = open_device()?;

    // Allocate buffer for up to 100 packets at a time
    const MAX_PACKETS_PER_CALL: usize = 100;
    let buffer_size = std::mem::size_of::<RawCapturedPacket>() * MAX_PACKETS_PER_CALL;
    let mut buffer: Vec<u8> = vec![0; buffer_size];
    let mut bytes_returned: u32 = 0;

    unsafe {
        let result = DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_PACKET_GET_PACKETS,
            None,
            0,
            Some(buffer.as_mut_ptr() as *mut _),
            buffer_size as u32,
            Some(&mut bytes_returned),
            None,
        );

        let _ = CloseHandle(handle);

        if result.is_err() {
            let err = GetLastError();
            return Err(CallbackError::IoctlFailed(err.0));
        }
    }

    // Parse packets from buffer
    let packet_size = std::mem::size_of::<RawCapturedPacket>();
    let num_packets = bytes_returned as usize / packet_size;
    let mut packets = Vec::with_capacity(num_packets);

    for i in 0..num_packets {
        let offset = i * packet_size;
        let raw = unsafe { &*(buffer.as_ptr().add(offset) as *const RawCapturedPacket) };

        let payload_size = raw.payload_size as usize;
        let payload = raw.payload[..payload_size.min(MAX_PACKET_PAYLOAD)].to_vec();

        // WFP stores IP addresses in host byte order with MSB first
        // e.g., 127.0.0.1 = 0x7F000001
        // Ipv4Addr::from(u32) expects the same format (big-endian interpretation)
        packets.push(CapturedPacket {
            id: raw.id,
            timestamp: raw.timestamp,
            pid: raw.process_id,
            direction: PacketDirection::from(raw.direction),
            protocol: PacketProtocol::from(raw.protocol),
            local_addr: Ipv4Addr::from(raw.local_addr.to_be_bytes()),
            local_port: raw.local_port,
            remote_addr: Ipv4Addr::from(raw.remote_addr.to_be_bytes()),
            remote_port: raw.remote_port,
            payload,
        });
    }

    Ok(packets)
}

/// Inject (resend) a packet using usermode sockets
/// For UDP: sends the payload to the destination
/// For TCP: attempts to send but may fail due to connection state
pub fn inject_packet(packet: &CapturedPacket) -> Result<(), CallbackError> {
    use std::net::{SocketAddr, UdpSocket, TcpStream};
    use std::io::Write;
    use std::time::Duration;
    
    if packet.payload.is_empty() {
        return Err(CallbackError::InvalidParameter);
    }
    
    // Determine destination based on packet direction
    // If outbound packet: send to remote (original destination)
    // If inbound packet: send to local (simulate re-receiving)
    let (dest_addr, dest_port) = if packet.direction == PacketDirection::Outbound {
        (packet.remote_addr, packet.remote_port)
    } else {
        (packet.local_addr, packet.local_port)
    };
    
    let dest = SocketAddr::new(dest_addr.into(), dest_port);
    
    // Log for debugging
    #[cfg(debug_assertions)]
    eprintln!("[inject_packet] Sending {} bytes to {} via {:?}", 
        packet.payload.len(), dest, packet.protocol);
    
    match packet.protocol {
        PacketProtocol::Udp => {
            // UDP injection - simple and stateless
            let socket = UdpSocket::bind("0.0.0.0:0")
                .map_err(|e| {
                    eprintln!("[inject_packet] UDP bind failed: {}", e);
                    CallbackError::IoctlFailed(1)
                })?;
            socket.send_to(&packet.payload, dest)
                .map_err(|e| {
                    eprintln!("[inject_packet] UDP send_to failed: {}", e);
                    CallbackError::IoctlFailed(2)
                })?;
            Ok(())
        }
        PacketProtocol::Tcp => {
            // TCP injection - requires existing connection or new connection
            // This will attempt to connect and send, but may fail if no listener
            let mut stream = TcpStream::connect_timeout(&dest, Duration::from_secs(2))
                .map_err(|e| {
                    eprintln!("[inject_packet] TCP connect failed: {}", e);
                    CallbackError::IoctlFailed(3)
                })?;
            stream.write_all(&packet.payload)
                .map_err(|e| {
                    eprintln!("[inject_packet] TCP write failed: {}", e);
                    CallbackError::IoctlFailed(4)
                })?;
            Ok(())
        }
    }
}

/// Add a packet filter rule
pub fn add_packet_filter(rule: &PacketFilterRule) -> Result<(), CallbackError> {
    let handle = open_device()?;

    let raw = RawPacketFilterRule {
        enabled: if rule.enabled { 1 } else { 0 },
        action: rule.action as u8,
        port: rule.port,
        ip_address: rule.ip_address,
        protocol: rule.protocol as u8,
    };

    let mut bytes_returned: u32 = 0;

    unsafe {
        let result = DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_PACKET_ADD_FILTER,
            Some(&raw as *const _ as *const _),
            std::mem::size_of::<RawPacketFilterRule>() as u32,
            None,
            0,
            Some(&mut bytes_returned),
            None,
        );

        let _ = CloseHandle(handle);

        if result.is_err() {
            let err = GetLastError();
            return Err(CallbackError::IoctlFailed(err.0));
        }
    }

    Ok(())
}

/// Remove a packet filter rule by index
pub fn remove_packet_filter(index: u32) -> Result<(), CallbackError> {
    let handle = open_device()?;

    let request = PacketFilterRemoveRequest { index };
    let mut bytes_returned: u32 = 0;

    unsafe {
        let result = DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_PACKET_REMOVE_FILTER,
            Some(&request as *const _ as *const _),
            std::mem::size_of::<PacketFilterRemoveRequest>() as u32,
            None,
            0,
            Some(&mut bytes_returned),
            None,
        );

        let _ = CloseHandle(handle);

        if result.is_err() {
            let err = GetLastError();
            return Err(CallbackError::IoctlFailed(err.0));
        }
    }

    Ok(())
}

/// Clear all packet filter rules
pub fn clear_packet_filters() -> Result<(), CallbackError> {
    let handle = open_device()?;
    let mut bytes_returned: u32 = 0;

    unsafe {
        let result = DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_PACKET_CLEAR_FILTERS,
            None,
            0,
            None,
            0,
            Some(&mut bytes_returned),
            None,
        );

        let _ = CloseHandle(handle);

        if result.is_err() {
            let err = GetLastError();
            return Err(CallbackError::IoctlFailed(err.0));
        }
    }

    Ok(())
}

/// Clear the packet capture buffer
pub fn clear_packet_buffer() -> Result<(), CallbackError> {
    let handle = open_device()?;
    let mut bytes_returned: u32 = 0;

    unsafe {
        let result = DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_PACKET_CLEAR_BUFFER,
            None,
            0,
            None,
            0,
            Some(&mut bytes_returned),
            None,
        );

        let _ = CloseHandle(handle);

        if result.is_err() {
            let err = GetLastError();
            return Err(CallbackError::IoctlFailed(err.0));
        }
    }

    Ok(())
}

/// Get the current capture state
pub fn get_capture_state() -> Result<CaptureState, CallbackError> {
    let handle = open_device()?;

    let mut response = PacketCaptureStateResponse {
        is_capturing: 0,
        target_pid: 0,
        packet_count: 0,
        dropped_count: 0,
    };
    let mut bytes_returned: u32 = 0;

    unsafe {
        let result = DeviceIoControl(
            handle,
            IOCTL_DIOPROCESS_PACKET_GET_STATE,
            None,
            0,
            Some(&mut response as *mut _ as *mut _),
            std::mem::size_of::<PacketCaptureStateResponse>() as u32,
            Some(&mut bytes_returned),
            None,
        );

        let _ = CloseHandle(handle);

        if result.is_err() {
            let err = GetLastError();
            return Err(CallbackError::IoctlFailed(err.0));
        }
    }

    Ok(CaptureState {
        is_capturing: response.is_capturing != 0,
        target_pid: response.target_pid,
        packet_count: response.packet_count,
        dropped_count: response.dropped_count,
    })
}

/// Format timestamp as HH:MM:SS.mmm
pub fn format_timestamp(timestamp: u64) -> String {
    // Windows FILETIME is 100-nanosecond intervals since 1601
    // Convert to seconds and extract time components
    let seconds = timestamp / 10_000_000;
    let millis = (timestamp / 10_000) % 1000;
    
    let total_seconds = seconds % 86400; // Seconds in a day
    let hours = total_seconds / 3600;
    let minutes = (total_seconds % 3600) / 60;
    let secs = total_seconds % 60;
    
    format!("{:02}:{:02}:{:02}.{:03}", hours, minutes, secs, millis)
}

/// Export packets to PCAP format
pub fn export_to_pcap(packets: &[CapturedPacket], path: &std::path::Path) -> std::io::Result<()> {
    use std::io::Write;
    
    let mut file = std::fs::File::create(path)?;
    
    // PCAP global header
    let magic: u32 = 0xa1b2c3d4;
    let version_major: u16 = 2;
    let version_minor: u16 = 4;
    let thiszone: i32 = 0;
    let sigfigs: u32 = 0;
    let snaplen: u32 = 65535;
    let network: u32 = 101; // LINKTYPE_RAW (raw IP)
    
    file.write_all(&magic.to_le_bytes())?;
    file.write_all(&version_major.to_le_bytes())?;
    file.write_all(&version_minor.to_le_bytes())?;
    file.write_all(&thiszone.to_le_bytes())?;
    file.write_all(&sigfigs.to_le_bytes())?;
    file.write_all(&snaplen.to_le_bytes())?;
    file.write_all(&network.to_le_bytes())?;
    
    for packet in packets {
        // Convert timestamp to seconds and microseconds
        let ts_sec = (packet.timestamp / 10_000_000) as u32;
        let ts_usec = ((packet.timestamp / 10) % 1_000_000) as u32;
        
        // Build a minimal IP header + transport header + payload
        let mut ip_packet = Vec::new();
        
        // IP header (20 bytes minimum)
        let ip_version_ihl: u8 = 0x45; // IPv4, 5 words
        let ip_tos: u8 = 0;
        let total_len: u16 = 20 + 8 + packet.payload.len() as u16; // IP + UDP/TCP min + payload
        let ip_id: u16 = 0;
        let ip_flags_frag: u16 = 0;
        let ip_ttl: u8 = 64;
        let ip_proto: u8 = packet.protocol as u8;
        let ip_checksum: u16 = 0; // Simplified, not calculated
        
        let (src_ip, dst_ip) = if packet.direction == PacketDirection::Outbound {
            (packet.local_addr, packet.remote_addr)
        } else {
            (packet.remote_addr, packet.local_addr)
        };
        
        ip_packet.push(ip_version_ihl);
        ip_packet.push(ip_tos);
        ip_packet.extend_from_slice(&total_len.to_be_bytes());
        ip_packet.extend_from_slice(&ip_id.to_be_bytes());
        ip_packet.extend_from_slice(&ip_flags_frag.to_be_bytes());
        ip_packet.push(ip_ttl);
        ip_packet.push(ip_proto);
        ip_packet.extend_from_slice(&ip_checksum.to_be_bytes());
        ip_packet.extend_from_slice(&src_ip.octets());
        ip_packet.extend_from_slice(&dst_ip.octets());
        
        // Transport header (simplified UDP header - 8 bytes)
        let (src_port, dst_port) = if packet.direction == PacketDirection::Outbound {
            (packet.local_port, packet.remote_port)
        } else {
            (packet.remote_port, packet.local_port)
        };
        
        ip_packet.extend_from_slice(&src_port.to_be_bytes());
        ip_packet.extend_from_slice(&dst_port.to_be_bytes());
        let udp_len: u16 = 8 + packet.payload.len() as u16;
        ip_packet.extend_from_slice(&udp_len.to_be_bytes());
        ip_packet.extend_from_slice(&0u16.to_be_bytes()); // checksum
        
        // Payload
        ip_packet.extend_from_slice(&packet.payload);
        
        // PCAP packet header
        let incl_len = ip_packet.len() as u32;
        let orig_len = incl_len;
        
        file.write_all(&ts_sec.to_le_bytes())?;
        file.write_all(&ts_usec.to_le_bytes())?;
        file.write_all(&incl_len.to_le_bytes())?;
        file.write_all(&orig_len.to_le_bytes())?;
        file.write_all(&ip_packet)?;
    }
    
    Ok(())
}
