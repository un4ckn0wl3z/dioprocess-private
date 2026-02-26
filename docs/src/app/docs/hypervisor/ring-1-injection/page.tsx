import { WarningBox } from "@/components/warning-box";
import { Badge } from "@/components/ui/badge";

export default function Ring1InjectionPage() {
  return (
    <div className="space-y-8">
      <div>
        <div className="flex items-center gap-3 mb-4">
          <h1 className="text-4xl font-bold">Ring -1 Injection</h1>
          <Badge variant="destructive">Hypervisor</Badge>
        </div>
        <p className="text-lg text-muted-foreground">
          Inject shellcode and DLLs via hypervisor physical memory access, bypassing Ring 0 protections.
        </p>
      </div>

      <WarningBox variant="danger" title="Bypasses Ring 0 Protections">
        Ring -1 injection writes directly to physical memory via EPT, making it invisible 
        to Ring 0 monitoring tools.
      </WarningBox>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Methods</h2>
        
        <div className="space-y-4">
          <div className="p-4 rounded-lg border border-red-500/30 bg-red-500/10">
            <div className="flex items-center gap-2 mb-2">
              <h3 className="font-semibold text-red-400">HV Shellcode Injection</h3>
            </div>
            <p className="text-sm text-muted-foreground mb-3">
              Allocate RWX memory from Ring 0, write shellcode via hypervisor physical memory access.
            </p>
            <ol className="list-decimal list-inside text-sm text-muted-foreground space-y-1">
              <li>Open target process, allocate RWX memory via <code>ZwAllocateVirtualMemory</code></li>
              <li><strong>Touch memory</strong> via <code>RtlZeroMemory</code> while attached — creates physical backing</li>
              <li>Detach from process context</li>
              <li>VMCALL to hypervisor: EPT translate virtual → physical, write shellcode</li>
              <li>Create thread via <code>RtlCreateUserThread</code> at shellcode address</li>
            </ol>
          </div>

          <div className="p-4 rounded-lg border border-red-500/30 bg-red-500/10">
            <div className="flex items-center gap-2 mb-2">
              <h3 className="font-semibold text-red-400">HV DLL Injection</h3>
            </div>
            <p className="text-sm text-muted-foreground mb-3">
              Same physical memory approach for LoadLibraryW-based DLL injection.
            </p>
            <ol className="list-decimal list-inside text-sm text-muted-foreground space-y-1">
              <li>Allocate memory for DLL path, touch to page in</li>
              <li>VMCALL to write DLL path via physical memory</li>
              <li>Resolve <code>LoadLibraryW</code> via <code>GetLoadLibraryWAddress()</code></li>
              <li>Create thread with <code>RtlCreateUserThread(LoadLibraryW, path_addr)</code></li>
            </ol>
          </div>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Key Advantages</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <strong>Physical memory writes</strong> — Bypasses Ring 0 memory protections</li>
          <li>• <strong>Invisible to Ring 0</strong> — Monitoring tools can&apos;t see the writes</li>
          <li>• <strong>EPT translation</strong> — Direct virtual → physical address conversion</li>
          <li>• <strong>No usermode API calls</strong> — Bypasses all usermode hooks</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Memory Paging Requirement</h2>
        <WarningBox variant="info" title="Important">
          Memory must be &quot;paged in&quot; before the hypervisor can write. Allocated virtual memory 
          has no physical backing until accessed. The driver touches memory with <code>RtlZeroMemory</code> 
          while attached to the process context to force page-in.
        </WarningBox>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Usage</h2>
        <p className="text-muted-foreground">Access via two methods:</p>
        
        <div className="space-y-4">
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2">From Process Context Menu</h3>
            <p className="text-sm text-muted-foreground">
              Right-click process → Miscellaneous → <strong>HV Inject Shellcode (Ring -1)</strong> or 
              <strong>HV Inject DLL (Ring -1)</strong>
            </p>
          </div>

          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2">From Hypervisor Tab</h3>
            <p className="text-sm text-muted-foreground">
              Hypervisor tab → Injection section → Select process, browse for shellcode/DLL
            </p>
          </div>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Return Values</h2>
        
        <div className="grid sm:grid-cols-2 gap-4">
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2">HvInjectResult (Shellcode)</h3>
            <ul className="text-sm text-muted-foreground space-y-1">
              <li>• <code>bytes_written</code> — Bytes written via VMCALL</li>
              <li>• <code>thread_handle</code> — Handle to created thread</li>
              <li>• <code>shellcode_address</code> — Where shellcode was written</li>
              <li>• <code>success</code> — Operation result</li>
            </ul>
          </div>
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2">HvInjectDllResult (DLL)</h3>
            <ul className="text-sm text-muted-foreground space-y-1">
              <li>• <code>module_base</code> — Base address of loaded DLL</li>
              <li>• <code>path_address</code> — Where DLL path was written</li>
              <li>• <code>success</code> — Operation result</li>
            </ul>
          </div>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">IOCTLs</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-3 px-4 font-semibold">IOCTL</th>
                <th className="text-left py-3 px-4 font-semibold">Code</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4 font-mono">HV_INJECT_SHELLCODE</td>
                <td className="py-3 px-4">0x840</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4 font-mono">HV_INJECT_DLL</td>
                <td className="py-3 px-4">0x841</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
