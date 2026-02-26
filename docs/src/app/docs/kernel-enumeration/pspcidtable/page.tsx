import { Badge } from "@/components/ui/badge";
import { CodeBlock } from "@/components/code-block";
import { WarningBox } from "@/components/warning-box";

export default function PspCidTablePage() {
  return (
    <div className="space-y-8">
      <div>
        <div className="flex items-center gap-3 mb-4">
          <h1 className="text-4xl font-bold">PspCidTable Enumeration</h1>
          <Badge variant="outline">Ring 0</Badge>
        </div>
        <p className="text-lg text-muted-foreground">
          Enumerate all processes and threads via the kernel&apos;s CID (Client ID) handle table, 
          bypassing usermode hiding techniques.
        </p>
      </div>

      <WarningBox variant="info" title="Hidden Process Detection">
        PspCidTable enumeration can detect processes hidden via DKOM (Direct Kernel Object 
        Manipulation) because it uses a different data structure than the ActiveProcessLinks list.
      </WarningBox>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Overview</h2>
        <p className="text-muted-foreground">
          The <code className="text-violet">PspCidTable</code> is a kernel handle table that 
          maintains references to all processes and threads by their Client ID (PID/TID). 
          Unlike the ActiveProcessLinks list, which is commonly manipulated by rootkits, 
          the CID table is harder to tamper with and provides a more complete view.
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">CidEntry Structure</h2>
        <CodeBlock
          language="rust"
          filename="crates/callback/src/pspcidtable.rs"
          code={`pub struct CidEntry {
    pub id: u32,                    // PID (for processes) or TID (for threads)
    pub object_address: u64,        // EPROCESS or ETHREAD kernel address
    pub object_type: CidObjectType, // Process or Thread
    pub parent_pid: u32,            // Parent PID (processes) or owning PID (threads)
    pub process_name: [u8; 16],     // ImageFileName from EPROCESS (15 chars + null)
}

pub enum CidObjectType {
    Process,
    Thread,
}`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Implementation</h2>
        <p className="text-muted-foreground">
          The driver uses signature scanning to dynamically locate PspCidTable, avoiding 
          hardcoded offsets that break across Windows versions:
        </p>
        <CodeBlock
          language="cpp"
          filename="Algorithm"
          code={`// 1. Find PspCidTable via signature scanning
//    Search ntoskrnl.exe for pattern that references PspCidTable
PVOID PspCidTable = FindPattern(ntoskrnl, pattern, mask);

// 2. Walk the handle table
//    PspCidTable is an HANDLE_TABLE structure
for (each handle in table) {
    // 3. Decode handle entry to get EPROCESS/ETHREAD pointer
    PVOID Object = DecodeHandleEntry(entry);
    
    // 4. Determine object type
    POBJECT_TYPE ObjectType = ObGetObjectType(Object);
    
    if (ObjectType == *PsProcessType) {
        // 5. Read EPROCESS fields
        entry.id = PsGetProcessId(Object);
        entry.parent_pid = PsGetProcessInheritedFromUniqueProcessId(Object);
        memcpy(entry.process_name, Object + ImageFileNameOffset, 16);
        entry.object_address = (ULONG64)Object;
        entry.object_type = Process;
    }
    else if (ObjectType == *PsThreadType) {
        // 6. Read ETHREAD fields
        entry.id = PsGetThreadId(Object);
        entry.parent_pid = PsGetProcessId(PsGetThreadProcess(Object));
        entry.object_address = (ULONG64)Object;
        entry.object_type = Thread;
    }
}`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">API</h2>
        <CodeBlock
          language="rust"
          filename="Usage"
          code={`use callback::enumerate_pspcidtable;

// Enumerate all CID entries
let entries: Vec<CidEntry> = enumerate_pspcidtable()?;

// Filter processes only
let processes: Vec<_> = entries.iter()
    .filter(|e| e.object_type == CidObjectType::Process)
    .collect();

// Find hidden processes (compare to ToolHelp32 enumeration)
let toolhelp_pids: HashSet<u32> = get_toolhelp_processes();
let hidden: Vec<_> = processes.iter()
    .filter(|p| !toolhelp_pids.contains(&p.id))
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
                <th className="text-left py-2 px-3 font-semibold">Input</th>
                <th className="text-left py-2 px-3 font-semibold">Output</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">ENUM_PSPCIDTABLE</td>
                <td className="py-2 px-3">0x0022203C</td>
                <td className="py-2 px-3 text-muted-foreground">None</td>
                <td className="py-2 px-3 text-muted-foreground">Array of CidEntry</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">UI Features</h2>
        <p className="text-muted-foreground">
          Access via Kernel Utilities tab → PspCidTable sub-tab:
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <strong>Type filter</strong> — All, Processes, or Threads buttons</li>
          <li>• <strong>Columns</strong> — Type, ID, Process Name, Object Address, Parent/Owner PID</li>
          <li>• <strong>Sorting</strong> — Click column headers to sort</li>
          <li>• <strong>Search filter</strong> — Filter by name, ID, address, or parent PID</li>
          <li>• <strong>CSV export</strong> — Export to pspcidtable.csv</li>
          <li>• <strong>Context menu</strong> — Copy ID, Copy Process Name, Copy Object Address</li>
          <li>• <strong>Color coding</strong> — Green &quot;Process&quot; label, blue &quot;Thread&quot; label</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Detecting Hidden Processes</h2>
        <p className="text-muted-foreground">
          To detect DKOM-hidden processes, compare results with standard enumeration:
        </p>
        <ol className="space-y-2 text-muted-foreground list-decimal list-inside">
          <li>Enumerate processes via ToolHelp32 (CreateToolhelp32Snapshot)</li>
          <li>Enumerate processes via PspCidTable</li>
          <li>Processes in PspCidTable but NOT in ToolHelp32 are likely hidden via DKOM</li>
        </ol>
        <p className="text-muted-foreground mt-4">
          Note: The DioProcess UI shows both enumerations for easy comparison.
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Use Cases</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• Detect rootkits hiding processes via ActiveProcessLinks unlinking</li>
          <li>• View raw EPROCESS/ETHREAD kernel addresses</li>
          <li>• Forensic analysis of running system</li>
          <li>• Security research on process hiding techniques</li>
          <li>• Enumerate system threads (PID 4)</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Limitations</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• Cannot detect processes hidden via PspCidTable manipulation (very rare)</li>
          <li>• Signature scanning may need updates for new Windows versions</li>
          <li>• Read-only: cannot unhide or manipulate entries</li>
        </ul>
      </section>
    </div>
  );
}
