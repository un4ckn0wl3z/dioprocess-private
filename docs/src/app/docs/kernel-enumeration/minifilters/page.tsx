import { Badge } from "@/components/ui/badge";
import { CodeBlock } from "@/components/code-block";
import { WarningBox } from "@/components/warning-box";

export default function MinifitersPage() {
  return (
    <div className="space-y-8">
      <div>
        <div className="flex items-center gap-3 mb-4">
          <h1 className="text-4xl font-bold">Minifilter Enumeration</h1>
          <Badge variant="outline">Ring 0</Badge>
        </div>
        <p className="text-lg text-muted-foreground">
          Enumerate and unlink filesystem minifilter drivers registered with the Filter Manager.
        </p>
      </div>

      <WarningBox variant="danger" title="Stability Warning">
        Unlinking minifilter callbacks can destabilize security products and the system. 
        Use only on test systems for security research.
      </WarningBox>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Overview</h2>
        <p className="text-muted-foreground">
          Minifilters are the modern Windows filesystem filtering mechanism, replacing legacy 
          filter drivers. EDR/AV products use minifilters to monitor file operations. This 
          feature allows enumeration and selective callback unlinking.
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">MinifilterInfo Structure</h2>
        <CodeBlock
          language="rust"
          filename="crates/callback/src/types.rs"
          code={`pub struct MinifilterInfo {
    pub filter_name: String,        // Filter driver name (e.g., "WdFilter")
    pub altitude: String,           // Filter altitude (load order priority)
    pub filter_address: u64,        // Address of FLT_FILTER structure
    pub frame_id: u64,              // Filter frame ID
    pub num_instances: u32,         // Number of active instances
    pub flags: u32,                 // Filter flags
    pub callbacks: MinifilterCallbacks,  // Pre/Post callbacks
    pub owner_module: String,       // Driver module that owns this filter
    pub index: u32,
}

pub struct MinifilterCallbacks {
    pub pre_create: u64,
    pub post_create: u64,
    pub pre_read: u64,
    pub post_read: u64,
    pub pre_write: u64,
    pub post_write: u64,
    // ... more operations
}`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Altitude System</h2>
        <p className="text-muted-foreground">
          Minifilters are loaded in a specific order based on their altitude (a numeric string). 
          Higher altitudes load first and see I/O requests before lower altitudes:
        </p>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-2 px-3 font-semibold">Altitude Range</th>
                <th className="text-left py-2 px-3 font-semibold">Category</th>
                <th className="text-left py-2 px-3 font-semibold">Examples</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3">420000-429999</td>
                <td className="py-2 px-3 text-muted-foreground">Filter</td>
                <td className="py-2 px-3 text-muted-foreground">General filtering</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3">320000-329999</td>
                <td className="py-2 px-3 text-muted-foreground">Anti-Virus</td>
                <td className="py-2 px-3 text-muted-foreground">WdFilter (328010)</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3">260000-269999</td>
                <td className="py-2 px-3 text-muted-foreground">Activity Monitor</td>
                <td className="py-2 px-3 text-muted-foreground">SentinelMonitor (264000)</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3">140000-149999</td>
                <td className="py-2 px-3 text-muted-foreground">Encryption</td>
                <td className="py-2 px-3 text-muted-foreground">EFS, BitLocker</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Implementation</h2>
        <CodeBlock
          language="cpp"
          filename="Algorithm"
          code={`// Enumeration using documented Filter Manager API
NTSTATUS EnumerateMinifilters(PMINIFILTER_INFO* Filters, PULONG Count) {
    PFLT_FILTER FilterList[256];
    ULONG FilterCount;
    
    // 1. Use FltEnumerateFilters to get all registered filters
    status = FltEnumerateFilters(FilterList, 256, &FilterCount);
    
    for (ULONG i = 0; i < FilterCount; i++) {
        PFLT_FILTER Filter = FilterList[i];
        
        // 2. Get filter information
        status = FltGetFilterInformation(
            Filter,
            FilterFullInformation,
            Buffer,
            BufferSize,
            &BytesReturned
        );
        
        // 3. Extract filter name and altitude from FILTER_FULL_INFORMATION
        Info->FilterName = FullInfo->FilterNameBuffer;
        Info->Altitude = ParseAltitude(FullInfo);
        
        // 4. Get instance count
        Info->NumInstances = FullInfo->NumberOfInstances;
        
        // 5. Resolve owner module from filter address
        Info->OwnerModule = GetModuleFromAddress(Filter);
    }
    
    return STATUS_SUCCESS;
}

// Unlink callbacks (dangerous operation)
NTSTATUS UnlinkMinifilter(PCWSTR FilterName) {
    // 1. Find filter by name
    // 2. Locate callback node list in FLT_FILTER structure
    // 3. Unlink Pre/Post operation callbacks from linked list
    // Note: Does not unload the filter, just disables monitoring
}`}
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
                <td className="py-2 px-3 font-mono text-xs">ENUM_MINIFILTERS</td>
                <td className="py-2 px-3">0x00222044</td>
                <td className="py-2 px-3 text-muted-foreground">Enumerate all registered minifilters</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">UNLINK_MINIFILTER</td>
                <td className="py-2 px-3">0x0022205C</td>
                <td className="py-2 px-3 text-muted-foreground">Unlink minifilter callbacks by name</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Known EDR/AV Minifilters</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-2 px-3 font-semibold">Filter Name</th>
                <th className="text-left py-2 px-3 font-semibold">Product</th>
                <th className="text-left py-2 px-3 font-semibold">Altitude</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">WdFilter</td>
                <td className="py-2 px-3 text-muted-foreground">Windows Defender</td>
                <td className="py-2 px-3">328010</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">SentinelMonitor</td>
                <td className="py-2 px-3 text-muted-foreground">SentinelOne</td>
                <td className="py-2 px-3">264000</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">CarbonBlackK</td>
                <td className="py-2 px-3 text-muted-foreground">Carbon Black</td>
                <td className="py-2 px-3">264000</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">csagent</td>
                <td className="py-2 px-3 text-muted-foreground">CrowdStrike Falcon</td>
                <td className="py-2 px-3">264000</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">mfeaskm</td>
                <td className="py-2 px-3 text-muted-foreground">McAfee</td>
                <td className="py-2 px-3">323100</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">symefasi</td>
                <td className="py-2 px-3 text-muted-foreground">Symantec/Broadcom</td>
                <td className="py-2 px-3">311050</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">UI Features</h2>
        <p className="text-muted-foreground">
          Access via Kernel Utilities tab → Minifilters sub-tab:
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <strong>Minifilter table</strong> — Name, Altitude, Address, Instances, Pre/Post callbacks</li>
          <li>• <strong>Sorting</strong> — Default descending by altitude (highest first)</li>
          <li>• <strong>Search filter</strong> — Filter by name, altitude, or owner module</li>
          <li>• <strong>CSV export</strong> — Export to minifilters.csv</li>
          <li>• <strong>Context menu</strong> — Copy Filter Name, Altitude, Address, <strong>Unlink Callbacks</strong></li>
          <li>• <strong>Altitude highlighting</strong> — Yellow highlight for visibility</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Use Cases</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• Identify EDR/AV minifilters monitoring file operations</li>
          <li>• Disable specific minifilter callbacks for security research</li>
          <li>• Analyze minifilter load order via altitude values</li>
          <li>• Test minifilter bypass techniques in controlled environments</li>
          <li>• Forensic analysis of installed filesystem filters</li>
        </ul>
      </section>
    </div>
  );
}
