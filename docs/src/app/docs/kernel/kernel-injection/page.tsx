import { WarningBox } from "@/components/warning-box";
import { Badge } from "@/components/ui/badge";

export default function KernelInjectionPage() {
  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-4xl font-bold mb-4">Kernel Injection</h1>
        <p className="text-lg text-muted-foreground">
          Inject shellcode and DLLs from kernel mode via <code className="text-violet">RtlCreateUserThread</code>, 
          bypassing usermode hooks.
        </p>
      </div>

      <WarningBox variant="danger" title="Bypasses Usermode Security">
        Kernel injection bypasses usermode hooks and monitoring. Use only for authorized security research.
      </WarningBox>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Methods</h2>
        
        <div className="space-y-4">
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <div className="flex items-center gap-2 mb-2">
              <h3 className="font-semibold">Kernel Shellcode Injection</h3>
              <Badge variant="outline">Ring 0</Badge>
            </div>
            <p className="text-sm text-muted-foreground mb-3">
              Allocate RWX memory in target process, write shellcode, create thread from kernel mode.
            </p>
            <ol className="list-decimal list-inside text-sm text-muted-foreground space-y-1">
              <li>Resolve <code>RtlCreateUserThread</code> via <code>MmGetSystemRoutineAddress</code></li>
              <li><code>PsLookupProcessByProcessId()</code> to get EPROCESS</li>
              <li><code>KeStackAttachProcess()</code> to attach to target</li>
              <li><code>ZwAllocateVirtualMemory()</code> to allocate RWX memory</li>
              <li><code>RtlCopyMemory()</code> to write shellcode</li>
              <li><code>RtlCreateUserThread()</code> at shellcode address</li>
              <li>Cleanup: <code>ZwClose</code>, <code>KeUnstackDetachProcess</code>, <code>ObDereferenceObject</code></li>
            </ol>
          </div>

          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <div className="flex items-center gap-2 mb-2">
              <h3 className="font-semibold">Kernel DLL Injection</h3>
              <Badge variant="outline">Ring 0</Badge>
            </div>
            <p className="text-sm text-muted-foreground mb-3">
              Resolve LoadLibraryW in target process via PEB walking, create thread with DLL path.
            </p>
            <ol className="list-decimal list-inside text-sm text-muted-foreground space-y-1">
              <li>Resolve <code>RtlCreateUserThread</code> dynamically</li>
              <li>Get <code>LoadLibraryW</code> address in target:
                <ul className="ml-6 mt-1 space-y-1">
                  <li>• Get PEB via <code>PROCESS_PEB_OFFSET[version]</code></li>
                  <li>• Walk <code>PEB→Ldr→InLoadOrderModuleList</code> to find kernel32.dll</li>
                  <li>• Parse PE export directory to find LoadLibraryW</li>
                </ul>
              </li>
              <li>Attach to target process</li>
              <li>Allocate memory for wide-char DLL path</li>
              <li>Write DLL path via <code>RtlCopyMemory</code></li>
              <li><code>RtlCreateUserThread(LoadLibraryW, dll_path_addr)</code></li>
            </ol>
          </div>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Advantages over Usermode Injection</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <strong>Bypasses usermode hooks</strong> — No ntdll.dll syscall interception</li>
          <li>• <strong>No CreateRemoteThread</strong> — Uses kernel-only RtlCreateUserThread</li>
          <li>• <strong>Direct memory access</strong> — No WriteProcessMemory API calls</li>
          <li>• <strong>Harder to detect</strong> — No usermode API call traces</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Usage</h2>
        <ol className="list-decimal list-inside space-y-2 text-muted-foreground">
          <li>Ensure the kernel driver is loaded</li>
          <li>Right-click on a process in the Process tab</li>
          <li>Navigate to <strong>Miscellaneous → Kernel Injection</strong></li>
          <li>Select <strong>Shellcode Injection</strong> or <strong>DLL Injection</strong></li>
          <li>Browse for shellcode file (.bin) or DLL file</li>
        </ol>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Implementation</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-3 px-4 font-semibold">Item</th>
                <th className="text-left py-3 px-4 font-semibold">Location</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4">Rust bindings</td>
                <td className="py-3 px-4 font-mono text-violet">crates/misc/src/kernel_inject.rs</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4">Kernel code</td>
                <td className="py-3 px-4 font-mono text-violet">kernelmode/.../DioProcessDriver.cpp</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4">IOCTL (Shellcode)</td>
                <td className="py-3 px-4 font-mono">0x80C</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4">IOCTL (DLL)</td>
                <td className="py-3 px-4 font-mono">0x80D</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
