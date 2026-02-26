import { Badge } from "@/components/ui/badge";
import { CodeBlock } from "@/components/code-block";

export default function NetworkMonitoringPage() {
  return (
    <div className="space-y-8">
      <div>
        <div className="flex items-center gap-3 mb-4">
          <h1 className="text-4xl font-bold">Network Monitoring</h1>
          <Badge variant="outline">Ring 3</Badge>
        </div>
        <p className="text-lg text-muted-foreground">
          Enumerate active TCP and UDP connections with process correlation via the Windows IP Helper API.
        </p>
      </div>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Overview</h2>
        <p className="text-muted-foreground">
          The Network tab provides a real-time view of all network connections on the system, 
          similar to <code>netstat</code> but with a graphical interface and process information. 
          This is implemented in the <code className="text-violet">network</code> crate.
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">NetworkConnection Structure</h2>
        <p className="text-muted-foreground">
          Each connection is represented by the following structure:
        </p>
        <CodeBlock
          language="rust"
          filename="crates/network/src/lib.rs"
          code={`pub struct NetworkConnection {
    pub protocol: Protocol,      // TCP or UDP
    pub local_addr: IpAddr,      // Local IP address
    pub local_port: u16,         // Local port number
    pub remote_addr: IpAddr,     // Remote IP address (0.0.0.0 for listening)
    pub remote_port: u16,        // Remote port number (0 for listening)
    pub state: TcpState,         // Connection state (TCP only)
    pub pid: u32,                // Owning process ID
    pub process_name: String,    // Process name (resolved)
}

pub enum Protocol {
    Tcp,
    Udp,
}

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
}`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Implementation</h2>
        <p className="text-muted-foreground">
          Network enumeration uses the Windows IP Helper API for efficient and reliable connection listing:
        </p>
        <CodeBlock
          language="rust"
          filename="Algorithm"
          code={`// TCP Connections (IPv4)
1. GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL)
2. Allocate buffer of returned size
3. GetExtendedTcpTable(buffer, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL)
4. Parse MIB_TCPTABLE_OWNER_PID structure
5. For each MIB_TCPROW_OWNER_PID:
   - Convert dwLocalAddr/dwRemoteAddr to IpAddr
   - Convert dwLocalPort/dwRemotePort (network byte order)
   - Map dwState to TcpState enum
   - Record dwOwningPid

// TCP Connections (IPv6)
1. GetExtendedTcpTable(..., AF_INET6, TCP_TABLE_OWNER_PID_ALL)
2. Parse MIB_TCP6TABLE_OWNER_PID structure

// UDP Endpoints (IPv4 + IPv6)
1. GetExtendedUdpTable(..., UDP_TABLE_OWNER_PID)
2. Parse MIB_UDPTABLE_OWNER_PID / MIB_UDP6TABLE_OWNER_PID

// Process name resolution
1. OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, pid)
2. QueryFullProcessImageNameW()
3. Extract filename from path`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">API Functions</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-2 px-3 font-semibold">Function</th>
                <th className="text-left py-2 px-3 font-semibold">Description</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet">enumerate_connections()</td>
                <td className="py-2 px-3 text-muted-foreground">
                  Returns <code>Vec&lt;NetworkConnection&gt;</code> of all TCP/UDP connections
                </td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet">enumerate_tcp_connections()</td>
                <td className="py-2 px-3 text-muted-foreground">
                  Returns only TCP connections (IPv4 + IPv6)
                </td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet">enumerate_udp_endpoints()</td>
                <td className="py-2 px-3 text-muted-foreground">
                  Returns only UDP endpoints (IPv4 + IPv6)
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">UI Features</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <strong>Protocol filter</strong> — Show All, TCP only, or UDP only</li>
          <li>• <strong>State filter</strong> — Filter by connection state (Established, Listen, etc.)</li>
          <li>• <strong>Search filter</strong> — Filter by IP address, port, or process name</li>
          <li>• <strong>Sorting</strong> — Click column headers to sort by any field</li>
          <li>• <strong>Process correlation</strong> — PID and process name shown for each connection</li>
          <li>• <strong>Context menu</strong> — Copy local/remote address, copy PID, filter by process</li>
          <li>• <strong>CSV export</strong> — Export filtered results to CSV file</li>
          <li>• <strong>Auto-refresh</strong> — Updates every 3 seconds</li>
          <li>• <strong>IPv6 support</strong> — Full IPv4 and IPv6 address display</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Connection States</h2>
        <p className="text-muted-foreground">
          TCP connections can be in various states during their lifecycle:
        </p>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-2 px-3 font-semibold">State</th>
                <th className="text-left py-2 px-3 font-semibold">Description</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-green-400">LISTEN</td>
                <td className="py-2 px-3 text-muted-foreground">Server socket waiting for connections</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-blue-400">ESTABLISHED</td>
                <td className="py-2 px-3 text-muted-foreground">Active connection with data transfer</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-yellow-400">TIME_WAIT</td>
                <td className="py-2 px-3 text-muted-foreground">Connection closed, waiting for network cleanup</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-orange-400">CLOSE_WAIT</td>
                <td className="py-2 px-3 text-muted-foreground">Remote side closed, local close pending</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-red-400">SYN_SENT</td>
                <td className="py-2 px-3 text-muted-foreground">Connection attempt in progress</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Use Cases</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• Identify processes with active network connections</li>
          <li>• Find which process is using a specific port</li>
          <li>• Monitor outbound connections for suspicious activity</li>
          <li>• Identify listening services and their associated processes</li>
          <li>• Debug network connectivity issues</li>
          <li>• Audit network activity for security analysis</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Port Hiding</h2>
        <p className="text-muted-foreground">
          The kernel driver can hide specific ports from network enumeration. See{" "}
          <a href="/docs/kernel-hiding/port-hiding" className="text-violet hover:underline">
            Kernel Hiding &gt; Port Hiding
          </a>{" "}
          for details on hiding connections from this tab.
        </p>
      </section>
    </div>
  );
}
