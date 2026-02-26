import Link from "next/link";
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { WarningBox } from "@/components/warning-box";
import { CodeBlock } from "@/components/code-block";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Network,
  Shield,
  Filter,
  Download,
  Play,
  Square,
  Edit,
  Save,
  Upload,
  Database,
  Cpu,
  Layers,
  ArrowRight,
  CheckCircle,
  XCircle,
  Clock,
  Package,
} from "lucide-react";

const features = [
  {
    title: "Real-time Capture",
    description: "Live TCP/UDP packet interception per process",
    icon: Network,
  },
  {
    title: "Packet Filtering",
    description: "Allow/block rules by port, IP, and protocol",
    icon: Filter,
  },
  {
    title: "Packet Injection",
    description: "Edit and resend captured packets with loop support",
    icon: Upload,
  },
  {
    title: "Export Support",
    description: "PCAP export for Wireshark analysis",
    icon: Download,
  },
  {
    title: "Packet Library",
    description: "SQLite storage with .dpp format and tagging",
    icon: Database,
  },
  {
    title: "WFP Integration",
    description: "Windows Filtering Platform kernel callouts",
    icon: Shield,
  },
];

export default function PacketCapturePage() {
  return (
    <div className="space-y-8">
      <div>
        <div className="flex items-center gap-3 mb-4">
          <h1 className="text-4xl font-bold">Packet Capture</h1>
          <Badge variant="outline">WFP</Badge>
          <Badge variant="outline">Ring 0</Badge>
        </div>
        <p className="text-lg text-muted-foreground">
          Windows Filtering Platform (WFP) based packet capture with per-process filtering, 
          real-time monitoring, and packet injection capabilities.
        </p>
      </div>

      <WarningBox variant="danger" title="Kernel Component Required">
        Packet capture requires the DioProcess kernel driver to be loaded. The feature uses 
        WFP callouts operating at kernel level for network packet interception.
      </WarningBox>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Overview</h2>
        <p className="text-muted-foreground">
          The packet capture system provides comprehensive network monitoring capabilities through 
          Windows Filtering Platform integration. It captures TCP/UDP packets for specific processes, 
          applies filtering rules, and enables packet analysis and manipulation.
        </p>
        
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
          {features.map((feature) => (
            <Card key={feature.title}>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <feature.icon className="w-5 h-5" />
                  {feature.title}
                </CardTitle>
                <CardDescription>{feature.description}</CardDescription>
              </CardHeader>
            </Card>
          ))}
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Architecture</h2>
        <div className="space-y-6">
          <div className="p-6 rounded-lg border bg-muted/20">
            <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <Layers className="w-5 h-5" />
              System Components
            </h3>
            <div className="space-y-4">
              <div className="flex items-start gap-3">
                <div className="w-8 h-8 rounded-full bg-blue-500/20 flex items-center justify-center flex-shrink-0">
                  <Cpu className="w-4 h-4 text-blue-500" />
                </div>
                <div>
                  <h4 className="font-semibold">Kernel Layer (WFP)</h4>
                  <p className="text-sm text-muted-foreground">
                    WFP callouts intercept packets at the network stack. Implements filtering logic 
                    and manages a 10,000 packet ring buffer for high-performance capture.
                  </p>
                </div>
              </div>
              <div className="flex items-start gap-3">
                <div className="w-8 h-8 rounded-full bg-green-500/20 flex items-center justify-center flex-shrink-0">
                  <Package className="w-4 h-4 text-green-500" />
                </div>
                <div>
                  <h4 className="font-semibold">Usermode Layer (Rust)</h4>
                  <p className="text-sm text-muted-foreground">
                    IOCTL interface communicates with the driver. Provides packet storage, 
                    PCAP export, and packet injection capabilities.
                  </p>
                </div>
              </div>
              <div className="flex items-start gap-3">
                <div className="w-8 h-8 rounded-full bg-purple-500/20 flex items-center justify-center flex-shrink-0">
                  <Network className="w-4 h-4 text-purple-500" />
                </div>
                <div>
                  <h4 className="font-semibold">UI Layer (Dioxus)</h4>
                  <p className="text-sm text-muted-foreground">
                    Real-time packet display with filtering, editing, and management features. 
                    Includes packet library with search and tagging.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      <Tabs defaultValue="kernel" className="space-y-4">
        <TabsList>
          <TabsTrigger value="kernel">Kernel Implementation</TabsTrigger>
          <TabsTrigger value="usermode">Usermode API</TabsTrigger>
          <TabsTrigger value="usage">Usage Examples</TabsTrigger>
          <TabsTrigger value="storage">Storage & Export</TabsTrigger>
        </TabsList>

        <TabsContent value="kernel" className="space-y-4">
          <div className="space-y-6">
            <div>
              <h3 className="text-lg font-semibold mb-3">WFP Callout Registration</h3>
              <p className="text-muted-foreground mb-4">
                The kernel driver registers WFP callouts for inbound and outbound traffic at 
                the FWPM_LAYER_ALE_AUTH_CONNECT_V4 and FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 layers.
              </p>
              <CodeBlock language="cpp" code={"// WFP Callout Functions\nvoid NTAPI WfpClassifyOutbound(\n    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,\n    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,\n    _Inout_opt_ void* layerData,\n    _In_opt_ const void* classifyContext,\n    _In_ const FWPS_FILTER0* filter,\n    _In_ UINT64 flowContext,\n    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut\n);\n\nvoid NTAPI WfpClassifyInbound(\n    // Same parameters as outbound\n);"} />
            </div>

            <div>
              <h3 className="text-lg font-semibold mb-3">Packet Processing Pipeline</h3>
              <div className="space-y-2 text-sm text-muted-foreground">
                <p>1. Packet intercepted by WFP callout</p>
                <p>2. Process ID verification against target PID</p>
                <p>3. Filter rule evaluation (allow/block)</p>
                <p>4. Packet metadata extraction</p>
                <p>5. Storage in ring buffer (FIFO, 10K capacity)</p>
                <p>6. Drop counting when buffer overflow occurs</p>
              </div>
            </div>

            <div>
              <h3 className="text-lg font-semibold mb-3">Data Structures</h3>
              <CodeBlock language="cpp" code={"// Captured Packet Structure\n#pragma pack(push, 1)\nstruct CapturedPacket\n{\n    UINT64 Id;                    // Unique packet identifier\n    UINT64 Timestamp;             // Windows FILETIME\n    UINT32 ProcessId;             // Target process ID\n    PacketDirection Direction;    // Inbound/Outbound\n    PacketProtocol Protocol;      // TCP/UDP\n    UINT32 LocalAddr;             // Local IP address\n    UINT16 LocalPort;             // Local port\n    UINT32 RemoteAddr;            // Remote IP address\n    UINT16 RemotePort;            // Remote port\n    UINT16 PayloadSize;           // Payload data size\n    UINT8 Payload[MAX_PACKET_PAYLOAD_SIZE]; // Packet data (1500 bytes)\n};\n#pragma pack(pop)\n\n// Filter Rule Structure\nstruct PacketFilterRule\n{\n    BOOLEAN Enabled;\n    PacketFilterAction Action;    // Allow/Block\n    UINT16 Port;                  // 0 = any port\n    UINT32 IpAddress;            // 0 = any IP\n    PacketProtocol Protocol;      // TCP/UDP\n};"} />
            </div>

            <div>
              <h3 className="text-lg font-semibold mb-3">IOCTL Interface</h3>
              <CodeBlock language="cpp" code={"// Packet Capture IOCTLs\n#define IOCTL_DIOPROCESS_PACKET_START_CAPTURE     0x00222400\n#define IOCTL_DIOPROCESS_PACKET_STOP_CAPTURE      0x00222404\n#define IOCTL_DIOPROCESS_PACKET_GET_PACKETS       0x00222408\n#define IOCTL_DIOPROCESS_PACKET_INJECT            0x0022240C\n#define IOCTL_DIOPROCESS_PACKET_ADD_FILTER        0x00222410\n#define IOCTL_DIOPROCESS_PACKET_REMOVE_FILTER     0x00222414\n#define IOCTL_DIOPROCESS_PACKET_CLEAR_FILTERS     0x00222418\n#define IOCTL_DIOPROCESS_PACKET_CLEAR_BUFFER      0x0022241C\n#define IOCTL_DIOPROCESS_PACKET_GET_STATE         0x00222420"} />
            </div>
          </div>
        </TabsContent>

        <TabsContent value="usermode" className="space-y-4">
          <div className="space-y-6">
            <div>
              <h3 className="text-lg font-semibold mb-3">Rust Callback API</h3>
              <p className="text-muted-foreground mb-4">
                The usermode library provides safe Rust wrappers for all packet capture operations.
              </p>
              <CodeBlock language="rust" code={"// Core packet capture functions\npub fn start_packet_capture(pid: u32) -> Result<(), CallbackError>\npub fn stop_packet_capture() -> Result<(), CallbackError>\npub fn get_captured_packets() -> Result<Vec<CapturedPacket>, CallbackError>\npub fn get_capture_state() -> Result<CaptureState, CallbackError>\n\n// Filter management\npub fn add_packet_filter(rule: &PacketFilterRule) -> Result<(), CallbackError>\npub fn remove_packet_filter(index: u32) -> Result<(), CallbackError>\npub fn clear_packet_filters() -> Result<(), CallbackError>\n\n// Packet operations\npub fn inject_packet(packet: &CapturedPacket) -> Result<(), CallbackError>\npub fn clear_packet_buffer() -> Result<(), CallbackError>\n\n// Export functionality\npub fn export_to_pcap(packets: &[CapturedPacket], path: &Path) -> std::io::Result<()>"} />
            </div>

            <div>
              <h3 className="text-lg font-semibold mb-3">Data Types</h3>
              <CodeBlock language="rust" code={"// Packet metadata\n#[derive(Clone, Debug, PartialEq, Eq)]\npub enum PacketDirection { Outbound = 0, Inbound = 1 }\n\n#[derive(Clone, Debug, PartialEq, Eq)]\npub enum PacketProtocol { Tcp = 6, Udp = 17 }\n\n#[derive(Clone, Debug)]\npub struct CapturedPacket {\n    pub id: u64,\n    pub timestamp: u64,\n    pub pid: u32,\n    pub direction: PacketDirection,\n    pub protocol: PacketProtocol,\n    pub local_addr: Ipv4Addr,\n    pub local_port: u16,\n    pub remote_addr: Ipv4Addr,\n    pub remote_port: u16,\n    pub payload: Vec<u8>,\n}\n\n// Filter configuration\n#[derive(Clone, Debug)]\npub struct PacketFilterRule {\n    pub enabled: bool,\n    pub action: FilterAction,\n    pub port: u16,           // 0 = any port\n    pub ip_address: u32,     // 0 = any IP\n    pub protocol: PacketProtocol,\n"} />
            </div>

            <div>
              <h3 className="text-lg font-semibold mb-3">Packet Injection</h3>
              <p className="text-muted-foreground mb-4">
                Packet injection uses usermode sockets to resend captured packets. 
                UDP packets are sent directly, while TCP packets attempt to establish connections.
              </p>
              <CodeBlock language="rust" code={"pub fn inject_packet(packet: &CapturedPacket) -> Result<(), CallbackError> {\n    let dest = if packet.direction == PacketDirection::Outbound {\n        (packet.remote_addr, packet.remote_port)\n    } else {\n        (packet.local_addr, packet.local_port)\n    };\n    \n    match packet.protocol {\n        PacketProtocol::Udp => {\n            let socket = UdpSocket::bind(\"0.0.0.0:0\")?;\n            socket.send_to(&packet.payload, dest)?;\n        }\n        PacketProtocol::Tcp => {\n            let mut stream = TcpStream::connect_timeout(&dest, Duration::from_secs(2))?;\n            stream.write_all(&packet.payload)?;\n        }\n    }\n    Ok(())\n"} />
            </div>
          </div>
        </TabsContent>

        <TabsContent value="usage" className="space-y-4">
          <div className="space-y-6">
            <div>
              <h3 className="text-lg font-semibold mb-3">Basic Capture Setup</h3>
              <div className="space-y-4">
                <div>
                  <h4 className="font-medium mb-2">1. Start Capture</h4>
                  <CodeBlock language="rust" code={"use callback::packet_capture::*;\n\n// Start capturing packets for process ID 1234\nlet pid = 1234;\nmatch start_packet_capture(pid) {\n    Ok(()) => println!(\"Capture started for PID {}\", pid),\n    Err(e) => eprintln!(\"Failed to start capture: {:?}\", e),\n}"}/>
                </div>
                
                <div>
                  <h4 className="font-medium mb-2">2. Monitor Packets</h4>
                  <CodeBlock language="rust" code={"// Get captured packets in a loop\nloop {\n    match get_captured_packets() {\n        Ok(packets) => {\n            for packet in packets {\n                println!(\"{} {}:{} -> {}:{} ({} bytes)\",\n                    packet.protocol,\n                    packet.local_addr, packet.local_port,\n                    packet.remote_addr, packet.remote_port,\n                    packet.payload.len()\n                );\n            }\n        }\n        Err(e) => eprintln!(\"Failed to get packets: {:?}\", e),\n    }\n    \n    std::thread::sleep(std::time::Duration::from_millis(500));\n}"}/>
                </div>
                
                <div>
                  <h4 className="font-medium mb-2">3. Stop Capture</h4>
                  <CodeBlock language="rust" code={"match stop_packet_capture() {\n    Ok(()) => println!(\"Capture stopped\"),\n    Err(e) => eprintln!(\"Failed to stop capture: {:?}\", e),\n}"}/>
                </div>
              </div>
            </div>

            <div>
              <h3 className="text-lg font-semibold mb-3">Filter Configuration</h3>
              <CodeBlock language="rust" code={"use callback::packet_capture::*;\n\n// Block all outbound traffic on port 80\nlet http_filter = PacketFilterRule {\n    enabled: true,\n    action: FilterAction::Block,\n    port: 80,\n    ip_address: 0,  // Any IP\n    protocol: PacketProtocol::Tcp,\n};\n\nadd_packet_filter(&http_filter)?;\n\n// Allow DNS traffic (port 53 UDP)\nlet dns_filter = PacketFilterRule {\n    enabled: true,\n    action: FilterAction::Allow,\n    port: 53,\n    ip_address: 0,\n    protocol: PacketProtocol::Udp,\n};\n\nadd_packet_filter(&dns_filter)?;"}/>
            </div>

            <div>
              <h3 className="text-lg font-semibold mb-3">Packet Replay</h3>
              <CodeBlock language="rust" code={"// Capture a packet and resend it 10 times\nlet packets = get_captured_packets()?;\nif let Some(packet) = packets.first() {\n    for i in 0..10 {\n        match inject_packet(packet) {\n            Ok(()) => println!(\"Packet {} sent successfully\", i + 1),\n            Err(e) => eprintln!(\"Packet {} failed: {:?}\", i + 1, e),\n        }\n        \n        // Wait 100ms between sends\n        std::thread::sleep(std::time::Duration::from_millis(100));\n    }\n}"}/>
            </div>

            <div>
              <h3 className="text-lg font-semibold mb-3">PCAP Export</h3>
              <CodeBlock language="rust" code={"use std::path::Path;\n\n// Export captured packets to PCAP format\nlet packets = get_captured_packets()?;\nlet pcap_path = Path::new(\"capture.pcap\");\n\nmatch export_to_pcap(&packets, pcap_path) {\n    Ok(()) => println!(\"PCAP exported to {:?}\", pcap_path),\n    Err(e) => eprintln!(\"Export failed: {:?}\", e),\n}\n\n// Export can be opened in Wireshark for analysis\n// The PCAP format includes reconstructed IP and transport headers"}/>
            </div>
          </div>
        </TabsContent>

        <TabsContent value="storage" className="space-y-4">
          <div className="space-y-6">
            <div>
              <h3 className="text-lg font-semibold mb-3">.dpp File Format</h3>
              <p className="text-muted-foreground mb-4">
                DioProcess Packet (.dpp) files store captured packets with metadata in JSON format 
                for easy sharing and replay.
              </p>
              <CodeBlock language="json" code={"{\n  \"version\": 1,\n  \"name\": \"HTTP Request Example\",\n  \"description\": \"GET request to example.com\",\n  \"tags\": [\"http\", \"get\", \"example\"],\n  \"protocol\": \"Tcp\",\n  \"direction\": \"Outbound\",\n  \"local_addr\": \"192.168.1.100\",\n  \"local_port\": 54321,\n  \"remote_addr\": \"93.184.216.34\",\n  \"remote_port\": 80,\n  \"payload_hex\": \"47 45 54 20 2F 20 48 54 54 50 2F 31 2E 31 0D 0A 48 6F 73 74 3A 20 65 78 61 6D 70 6C 65 2E 63 6F 6D 0D 0A 55 73 65 72 2D 41 67 65 6E 74 3A 20 44 69 6F 50 72 6F 63 65 73 73 2F 31 2E 30 0D 0A 0D 0A\"\n}"} />
            </div>

            <div>
              <h3 className="text-lg font-semibold mb-3">SQLite Storage</h3>
              <p className="text-muted-foreground mb-4">
                Packets are stored in a SQLite database at <code>%LOCALAPPDATA%\DioProcess\packets.db</code> 
                with full-text search and tagging capabilities.
              </p>
              <CodeBlock language="rust" code={"use callback::packet_storage::*;\n\n// Open the default packet storage\nlet storage = PacketStorage::open_default()?;\n\n// Save a packet with metadata\nlet packet_id = storage.save_packet(\n    \"HTTP GET Request\",\n    \"Request to example.com\",\n    &[\"http\", \"get\", \"example\"],\n    &captured_packet\n)?;\n\n// Search for packets\nlet results = storage.search_packets(\"http\");\n\n// Export to .dpp file\nstorage.export_dpp(packet_id, Path::new(\"packet.dpp\"))?"} />
            </div>

            <div>
              <h3 className="text-lg font-semibold mb-3">Performance Considerations</h3>
              <div className="space-y-2 text-sm text-muted-foreground">
                <p>• <strong>Ring Buffer:</strong> 10,000 packet capacity with FIFO overflow</p>
                <p>• <strong>Memory Usage:</strong> ~15MB for full buffer (1500 bytes/packet)</p>
                <p>• <strong>Query Interval:</strong> 500ms refresh cycle for real-time updates</p>
                <p>• <strong>Storage:</strong> SQLite WAL mode for concurrent access</p>
                <p>• <strong>Export:</strong> PCAP format with reconstructed headers</p>
              </div>
            </div>
          </div>
        </TabsContent>
      </Tabs>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">UI Features</h2>
        <div className="grid md:grid-cols-2 gap-6">
          <div className="p-4 rounded-lg border">
            <h3 className="font-semibold mb-2 flex items-center gap-2">
              <Play className="w-4 h-4" />
              Capture Controls
            </h3>
            <ul className="text-sm text-muted-foreground space-y-1">
              <li>• Start/stop capture by PID</li>
              <li>• Real-time packet counter</li>
              <li>• Auto-scroll toggle</li>
              <li>• Clear buffer option</li>
            </ul>
          </div>
          
          <div className="p-4 rounded-lg border">
            <h3 className="font-semibold mb-2 flex items-center gap-2">
              <Filter className="w-4 h-4" />
              Filter Management
            </h3>
            <ul className="text-sm text-muted-foreground space-y-1">
              <li>• Add port-based filters</li>
              <li>• Allow/block actions</li>
              <li>• Visual filter tags</li>
              <li>• Clear all filters</li>
            </ul>
          </div>
          
          <div className="p-4 rounded-lg border">
            <h3 className="font-semibold mb-2 flex items-center gap-2">
              <Edit className="w-4 h-4" />
              Packet Operations
            </h3>
            <ul className="text-sm text-muted-foreground space-y-1">
              <li>• Hex/ASCII editing</li>
              <li>• Single/loop resend</li>
              <li>• Configurable intervals</li>
              <li>• Send status feedback</li>
            </ul>
          </div>
          
          <div className="p-4 rounded-lg border">
            <h3 className="font-semibold mb-2 flex items-center gap-2">
              <Database className="w-4 h-4" />
              Packet Library
            </h3>
            <ul className="text-sm text-muted-foreground space-y-1">
              <li>• Save with metadata</li>
              <li>• Tag-based organization</li>
              <li>• Full-text search</li>
              <li>• .dpp import/export</li>
            </ul>
          </div>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Security Considerations</h2>
        <WarningBox variant="warning" title="Network Interception">
          Packet capture operates at the kernel level and can intercept all network traffic 
          for the target process. This includes sensitive data such as passwords, tokens, 
          and private communications.
        </WarningBox>
        
        <div className="space-y-3 text-sm text-muted-foreground">
          <p><strong>Privacy:</strong> Captured packets contain unencrypted network data.</p>
          <p><strong>Permissions:</strong> Requires administrator privileges for kernel driver access.</p>
          <p><strong>Storage:</strong> Packet data is stored in plaintext in SQLite database.</p>
          <p><strong>Network:</strong> Packet injection can generate network traffic from the host.</p>
        </div>
      </section>
    </div>
  );
}
