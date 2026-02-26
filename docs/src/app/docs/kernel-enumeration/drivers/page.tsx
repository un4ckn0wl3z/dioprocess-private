import { Badge } from "@/components/ui/badge";
import { CodeBlock } from "@/components/code-block";

export default function DriversPage() {
  return (
    <div className="space-y-8">
      <div>
        <div className="flex items-center gap-3 mb-4">
          <h1 className="text-4xl font-bold">Driver Enumeration</h1>
          <Badge variant="outline">Ring 0</Badge>
        </div>
        <p className="text-lg text-muted-foreground">
          Enumerate all loaded kernel drivers with their base addresses, sizes, entry points, 
          and file paths.
        </p>
      </div>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Overview</h2>
        <p className="text-muted-foreground">
          Driver enumeration provides a comprehensive view of all kernel-mode drivers loaded 
          in the system. This is useful for identifying security products, rootkits, and 
          understanding the kernel environment.
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">DriverInfo Structure</h2>
        <CodeBlock
          language="rust"
          filename="crates/callback/src/types.rs"
          code={`pub struct DriverInfo {
    pub base_address: u64,      // Driver image base in kernel memory
    pub size: u64,              // Size of driver image
    pub entry_point: u64,       // DriverEntry address
    pub driver_object: u64,     // DRIVER_OBJECT address
    pub driver_name: String,    // Driver name (e.g., "\\Driver\\DioProcess")
    pub path: String,           // File path (e.g., "C:\\Windows\\System32\\drivers\\...")
    pub service_name: String,   // Service registry key name
}`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Implementation</h2>
        <CodeBlock
          language="cpp"
          filename="Algorithm"
          code={`NTSTATUS EnumerateKernelDrivers(PDRIVER_INFO* Drivers, PULONG Count) {
    // Method 1: Walk PsLoadedModuleList (kernel's module list)
    PLIST_ENTRY ModuleList = PsLoadedModuleList;
    PLIST_ENTRY Entry = ModuleList->Flink;
    
    while (Entry != ModuleList) {
        PLDR_DATA_TABLE_ENTRY LdrEntry = CONTAINING_RECORD(
            Entry, 
            LDR_DATA_TABLE_ENTRY, 
            InLoadOrderLinks
        );
        
        Info->BaseAddress = (ULONG64)LdrEntry->DllBase;
        Info->Size = LdrEntry->SizeOfImage;
        Info->EntryPoint = (ULONG64)LdrEntry->EntryPoint;
        Info->Path = LdrEntry->FullDllName.Buffer;
        Info->DriverName = LdrEntry->BaseDllName.Buffer;
        
        Entry = Entry->Flink;
    }
    
    // Method 2: IoDriverObjectType enumeration
    // Walks the driver object directory for DRIVER_OBJECT pointers
    
    return STATUS_SUCCESS;
}`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">API</h2>
        <CodeBlock
          language="rust"
          filename="Usage"
          code={`use callback::enumerate_kernel_drivers;

// Get all loaded drivers
let drivers: Vec<DriverInfo> = enumerate_kernel_drivers()?;

// Find security product drivers
let security_drivers: Vec<_> = drivers.iter()
    .filter(|d| {
        d.path.to_lowercase().contains("symantec") ||
        d.path.to_lowercase().contains("crowdstrike") ||
        d.path.to_lowercase().contains("defender")
    })
    .collect();

// Find drivers loaded from non-standard paths
let suspicious: Vec<_> = drivers.iter()
    .filter(|d| !d.path.to_lowercase().contains("windows\\system32\\drivers"))
    .collect();`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">IOCTL</h2>
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
                <td className="py-2 px-3 font-mono text-xs">ENUM_DRIVERS</td>
                <td className="py-2 px-3">0x00222048</td>
                <td className="py-2 px-3 text-muted-foreground">Enumerate all loaded kernel drivers</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">UI Features</h2>
        <p className="text-muted-foreground">
          Access via Kernel Utilities tab → Drivers sub-tab:
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <strong>Driver table</strong> — Name, Base Address, Size, Entry Point, Path</li>
          <li>• <strong>Sorting</strong> — Click column headers (default: by base address)</li>
          <li>• <strong>Search filter</strong> — Filter by name, path, or address</li>
          <li>• <strong>CSV export</strong> — Export to drivers.csv</li>
          <li>• <strong>Context menu</strong> — Copy Name, Address, Path, Size</li>
          <li>• <strong>Size formatting</strong> — Human-readable (KB/MB)</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Common System Drivers</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-2 px-3 font-semibold">Driver</th>
                <th className="text-left py-2 px-3 font-semibold">Purpose</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">ntoskrnl.exe</td>
                <td className="py-2 px-3 text-muted-foreground">Windows kernel executive</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">FLTMGR.SYS</td>
                <td className="py-2 px-3 text-muted-foreground">Filesystem Filter Manager</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">CI.dll</td>
                <td className="py-2 px-3 text-muted-foreground">Code Integrity (DSE)</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">tcpip.sys</td>
                <td className="py-2 px-3 text-muted-foreground">TCP/IP network stack</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">ksecdd.sys</td>
                <td className="py-2 px-3 text-muted-foreground">Kernel security support</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Detecting Suspicious Drivers</h2>
        <p className="text-muted-foreground">
          Signs of potentially malicious drivers:
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>• Loaded from non-standard paths (not <code>%SYSTEMROOT%\System32\drivers</code>)</li>
          <li>• No corresponding service registry key</li>
          <li>• Unusually small or large size</li>
          <li>• Obfuscated or random-looking names</li>
          <li>• Missing or invalid file path</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Driver Hiding</h2>
        <p className="text-muted-foreground">
          The DioProcess hypervisor can hide drivers from this enumeration. See{" "}
          <a href="/docs/hypervisor/process-hiding" className="text-violet hover:underline">
            Hypervisor &gt; Process &amp; Driver Hiding
          </a>
          {" "}for details.
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Use Cases</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• Inventory all loaded kernel drivers</li>
          <li>• Identify security product drivers</li>
          <li>• Detect potentially malicious or unauthorized drivers</li>
          <li>• Verify driver addresses for kernel debugging</li>
          <li>• Compare loaded drivers against known-good baseline</li>
        </ul>
      </section>
    </div>
  );
}
