import { Badge } from "@/components/ui/badge";
import { CodeBlock } from "@/components/code-block";
import { WarningBox } from "@/components/warning-box";

export default function ProcessHidingPage() {
  return (
    <div className="space-y-8">
      <div>
        <div className="flex items-center gap-3 mb-4">
          <h1 className="text-4xl font-bold">Process Hiding</h1>
          <Badge variant="outline">Ring -1</Badge>
        </div>
        <p className="text-lg text-muted-foreground">
          Hide processes from ring 0 enumeration using hypervisor EPT manipulation.
        </p>
      </div>

      <WarningBox variant="danger" title="Advanced Feature">
        Process hiding at Ring -1 is extremely powerful. Hidden processes cannot be 
        seen by the kernel, security products, or standard tools. Use responsibly.
      </WarningBox>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Overview</h2>
        <p className="text-muted-foreground">
          The hypervisor intercepts kernel enumeration by hooking the memory pages that 
          contain process-related data structures. When the kernel or any ring 0 code 
          attempts to walk the process list, the hypervisor presents a modified view 
          that excludes hidden processes.
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">What Gets Hidden</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <strong>ActiveProcessLinks</strong> — The main doubly-linked list in EPROCESS</li>
          <li>• <strong>PspCidTable</strong> — Client ID handle table entries</li>
          <li>• <strong>Process handles</strong> — Obfuscated from handle table enumeration</li>
          <li>• <strong>Thread enumeration</strong> — Threads of hidden processes</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Implementation</h2>
        <CodeBlock
          language="cpp"
          filename="Algorithm"
          code={`// Hide process via EPT hooking
NTSTATUS HvHideProcess(ULONG ProcessId) {
    // 1. Get EPROCESS pointer for target process
    PEPROCESS Process;
    PsLookupProcessByProcessId(ProcessId, &Process);
    
    // 2. Get physical address of EPROCESS.ActiveProcessLinks
    PHYSICAL_ADDRESS PhysAddr = MmGetPhysicalAddress(
        &Process->ActiveProcessLinks
    );
    
    // 3. Set up EPT hook for read operations
    EptSetupHook(
        PhysAddr,
        EPT_HOOK_TYPE_READ,
        HiddenProcessReadHandler
    );
    
    // 4. Store original link values for restoration
    SaveOriginalLinks(ProcessId, Process);
    
    return STATUS_SUCCESS;
}

// EPT violation handler - called when kernel reads ActiveProcessLinks
VOID HiddenProcessReadHandler(PVOID Address, ULONG Size) {
    PLIST_ENTRY Links = (PLIST_ENTRY)Address;
    
    // Present modified links that skip the hidden process
    // Effectively: Prev->Flink = Hidden->Flink
    //              Next->Blink = Hidden->Blink
    ModifyLinksToSkipHidden(Links);
}`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">API</h2>
        <CodeBlock
          language="rust"
          filename="Usage"
          code={`use callback::{hv_hide_process, hv_unhide_process, hv_list_hidden_processes};

// Hide a process
let pid: u32 = 1234;
hv_hide_process(pid)?;

// List all hidden processes
let hidden: Vec<u32> = hv_list_hidden_processes()?;
println!("Hidden PIDs: {:?}", hidden);

// Unhide a process
hv_unhide_process(pid)?;`}
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
                <td className="py-2 px-3 font-mono text-xs">HV_HIDE_PROCESS</td>
                <td className="py-2 px-3">0x850</td>
                <td className="py-2 px-3 text-muted-foreground">Hide process by PID</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">HV_UNHIDE_PROCESS</td>
                <td className="py-2 px-3">0x851</td>
                <td className="py-2 px-3 text-muted-foreground">Unhide process by PID</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">HV_LIST_HIDDEN</td>
                <td className="py-2 px-3">0x852</td>
                <td className="py-2 px-3 text-muted-foreground">List all hidden PIDs</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Detection Evasion</h2>
        <p className="text-muted-foreground">
          Process hiding at Ring -1 evades:
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>✓ Task Manager</li>
          <li>✓ Process Explorer / Process Hacker</li>
          <li>✓ CreateToolhelp32Snapshot (ring 3)</li>
          <li>✓ NtQuerySystemInformation (ring 0)</li>
          <li>✓ PspCidTable enumeration (ring 0)</li>
          <li>✓ EDR/AV process scanning</li>
          <li>✓ Kernel debugger !process command</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Limitations</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• Process must be running when hide is applied</li>
          <li>• Does not persist across reboots</li>
          <li>• Resource usage (CPU, memory) may still be observable indirectly</li>
          <li>• Another hypervisor could detect the manipulation</li>
          <li>• Network connections from hidden process are still visible (use port hiding)</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">UI Access</h2>
        <p className="text-muted-foreground">
          Two ways to hide processes:
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>1. <strong>Process context menu</strong> → Miscellaneous → <strong>Hide Process (Ring -1)</strong></li>
          <li>2. <strong>Hypervisor tab</strong> → Enter PID → Hide</li>
        </ul>
        <p className="text-muted-foreground mt-4">
          Hidden processes show in the Hypervisor tab&apos;s &quot;Hidden Processes&quot; list with unhide option.
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Use Cases</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• Red team operations requiring process stealth</li>
          <li>• Testing security product visibility</li>
          <li>• Research on process hiding detection</li>
          <li>• Demonstrating hypervisor capabilities</li>
        </ul>
      </section>
    </div>
  );
}
