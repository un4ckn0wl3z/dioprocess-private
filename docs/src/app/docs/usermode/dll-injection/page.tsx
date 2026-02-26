import { CodeBlock } from "@/components/code-block";
import { WarningBox } from "@/components/warning-box";
import { Badge } from "@/components/ui/badge";

export default function DllInjectionPage() {
  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-4xl font-bold mb-4">DLL Injection</h1>
        <p className="text-lg text-muted-foreground">
          DioProcess provides 7 different DLL injection methods, each with unique characteristics 
          and evasion capabilities.
        </p>
      </div>

      <WarningBox variant="warning" title="Security Research Only">
        DLL injection techniques should only be used for authorized security research, 
        malware analysis, and testing on systems you own or have permission to test.
      </WarningBox>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Available Methods</h2>
        <p className="text-muted-foreground">
          Each method is implemented in its own file under <code className="text-violet">crates/misc/src/injection/</code>
        </p>
      </section>

      <section className="space-y-6">
        <div className="p-6 rounded-lg border border-border/50 bg-card/50">
          <div className="flex items-center gap-3 mb-3">
            <h3 className="text-xl font-semibold">1. LoadLibrary</h3>
            <Badge variant="outline">Classic</Badge>
          </div>
          <p className="text-muted-foreground mb-4">
            The classic injection method using <code>CreateRemoteThread</code> + <code>WriteProcessMemory</code> + <code>LoadLibraryW</code>.
          </p>
          <div className="text-sm text-muted-foreground">
            <strong>File:</strong> <code className="text-violet">loadlibrary.rs</code><br />
            <strong>Function:</strong> <code className="text-violet">inject_dll()</code>
          </div>
        </div>

        <div className="p-6 rounded-lg border border-border/50 bg-card/50">
          <div className="flex items-center gap-3 mb-3">
            <h3 className="text-xl font-semibold">2. Thread Hijack</h3>
            <Badge variant="outline">Stealthy</Badge>
          </div>
          <p className="text-muted-foreground mb-4">
            Suspend an existing thread, alter its RIP/PC to point to shellcode, then resume. 
            No new thread creation required.
          </p>
          <div className="text-sm text-muted-foreground">
            <strong>File:</strong> <code className="text-violet">thread_hijack.rs</code><br />
            <strong>Function:</strong> <code className="text-violet">inject_dll_thread_hijack()</code>
          </div>
        </div>

        <div className="p-6 rounded-lg border border-border/50 bg-card/50">
          <div className="flex items-center gap-3 mb-3">
            <h3 className="text-xl font-semibold">3. APC Queue</h3>
            <Badge variant="outline">Alertable Wait</Badge>
          </div>
          <p className="text-muted-foreground mb-4">
            Queue an APC (Asynchronous Procedure Call) with <code>LoadLibraryW</code> on all threads. 
            Fires when a thread enters an alertable wait state.
          </p>
          <div className="text-sm text-muted-foreground">
            <strong>File:</strong> <code className="text-violet">apc_queue.rs</code><br />
            <strong>Function:</strong> <code className="text-violet">inject_dll_apc_queue()</code>
          </div>
        </div>

        <div className="p-6 rounded-lg border border-border/50 bg-card/50">
          <div className="flex items-center gap-3 mb-3">
            <h3 className="text-xl font-semibold">4. EarlyBird</h3>
            <Badge variant="outline">Guaranteed Execution</Badge>
          </div>
          <p className="text-muted-foreground mb-4">
            Create a suspended remote thread, queue an APC before the thread runs. 
            APC fires during <code>LdrInitializeThunk</code>, guaranteeing execution.
          </p>
          <div className="text-sm text-muted-foreground">
            <strong>File:</strong> <code className="text-violet">earlybird.rs</code><br />
            <strong>Function:</strong> <code className="text-violet">inject_dll_earlybird()</code>
          </div>
        </div>

        <div className="p-6 rounded-lg border border-border/50 bg-card/50">
          <div className="flex items-center gap-3 mb-3">
            <h3 className="text-xl font-semibold">5. Remote Mapping</h3>
            <Badge variant="outline">No VirtualAllocEx</Badge>
          </div>
          <p className="text-muted-foreground mb-4">
            Use <code>CreateFileMappingW</code> + <code>MapViewOfFile</code> locally, 
            then <code>NtMapViewOfSection</code> remotely. Avoids <code>VirtualAllocEx</code>/<code>WriteProcessMemory</code> entirely.
          </p>
          <div className="text-sm text-muted-foreground">
            <strong>File:</strong> <code className="text-violet">remote_mapping.rs</code><br />
            <strong>Function:</strong> <code className="text-violet">inject_dll_remote_mapping()</code>
          </div>
        </div>

        <div className="p-6 rounded-lg border border-border/50 bg-card/50">
          <div className="flex items-center gap-3 mb-3">
            <h3 className="text-xl font-semibold">6. Function Stomping</h3>
            <Badge variant="outline">No New Memory</Badge>
          </div>
          <p className="text-muted-foreground mb-4">
            Overwrite a sacrificial function (default: <code>setupapi.dll!SetupScanFileQueueA</code>) 
            in the remote process with LoadLibraryW shellcode. Avoids new executable memory allocation.
          </p>
          <div className="text-sm text-muted-foreground">
            <strong>File:</strong> <code className="text-violet">function_stomping.rs</code><br />
            <strong>Function:</strong> <code className="text-violet">inject_dll_function_stomping()</code>
          </div>
        </div>

        <div className="p-6 rounded-lg border border-border/50 bg-card/50">
          <div className="flex items-center gap-3 mb-3">
            <h3 className="text-xl font-semibold">7. Manual Mapping</h3>
            <Badge variant="destructive">Advanced</Badge>
          </div>
          <p className="text-muted-foreground mb-4">
            Full PE parsing, section mapping, import resolution, per-section memory protections, 
            <code>FlushInstructionCache</code>, and call <code>DllMain</code>. No <code>LoadLibrary</code> call — 
            DLL won&apos;t appear in module lists.
          </p>
          <div className="text-sm text-muted-foreground">
            <strong>File:</strong> <code className="text-violet">manual_map.rs</code><br />
            <strong>Function:</strong> <code className="text-violet">inject_dll_manual_map()</code>
          </div>
          <div className="mt-4 p-3 bg-secondary/50 rounded text-sm">
            <strong>Features:</strong>
            <ul className="mt-2 space-y-1 text-muted-foreground">
              <li>• PE header parsing (DOS → NT → Section Headers)</li>
              <li>• Section-by-section memory mapping</li>
              <li>• Import resolution with LoadLibraryA fallback</li>
              <li>• Per-section protections (PAGE_EXECUTE_READ for .text, PAGE_READWRITE for .data)</li>
              <li>• Base relocation processing</li>
            </ul>
          </div>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Usage</h2>
        <p className="text-muted-foreground">
          Access DLL injection via the UI:
        </p>
        <ol className="list-decimal list-inside space-y-2 text-muted-foreground">
          <li>Right-click on a process in the Process tab</li>
          <li>Navigate to <strong>Miscellaneous → DLL Injection</strong></li>
          <li>Select the injection method</li>
          <li>Browse for the DLL file to inject</li>
          <li>Click Inject</li>
        </ol>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Method Comparison</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-3 px-4 font-semibold">Method</th>
                <th className="text-left py-3 px-4 font-semibold">New Thread</th>
                <th className="text-left py-3 px-4 font-semibold">VirtualAllocEx</th>
                <th className="text-left py-3 px-4 font-semibold">In Module List</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4">LoadLibrary</td>
                <td className="py-3 px-4 text-red-400">Yes</td>
                <td className="py-3 px-4 text-red-400">Yes</td>
                <td className="py-3 px-4 text-red-400">Yes</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4">Thread Hijack</td>
                <td className="py-3 px-4 text-green-400">No</td>
                <td className="py-3 px-4 text-red-400">Yes</td>
                <td className="py-3 px-4 text-red-400">Yes</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4">APC Queue</td>
                <td className="py-3 px-4 text-green-400">No</td>
                <td className="py-3 px-4 text-red-400">Yes</td>
                <td className="py-3 px-4 text-red-400">Yes</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4">EarlyBird</td>
                <td className="py-3 px-4 text-red-400">Yes</td>
                <td className="py-3 px-4 text-red-400">Yes</td>
                <td className="py-3 px-4 text-red-400">Yes</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4">Remote Mapping</td>
                <td className="py-3 px-4 text-red-400">Yes</td>
                <td className="py-3 px-4 text-green-400">No</td>
                <td className="py-3 px-4 text-red-400">Yes</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4">Function Stomping</td>
                <td className="py-3 px-4 text-red-400">Yes</td>
                <td className="py-3 px-4 text-green-400">No</td>
                <td className="py-3 px-4 text-red-400">Yes</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4 font-semibold">Manual Mapping</td>
                <td className="py-3 px-4 text-red-400">Yes</td>
                <td className="py-3 px-4 text-red-400">Yes</td>
                <td className="py-3 px-4 text-green-400">No</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
