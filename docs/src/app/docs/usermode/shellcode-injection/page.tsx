import { CodeBlock } from "@/components/code-block";
import { WarningBox } from "@/components/warning-box";
import { Badge } from "@/components/ui/badge";

export default function ShellcodeInjectionPage() {
  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-4xl font-bold mb-4">Shellcode Injection</h1>
        <p className="text-lg text-muted-foreground">
          DioProcess provides 3 shellcode injection methods for executing raw machine code 
          in remote processes.
        </p>
      </div>

      <WarningBox variant="danger" title="Dangerous Operation">
        Shellcode injection can execute arbitrary code in remote processes. Only use on 
        systems you own or have explicit permission to test.
      </WarningBox>

      <section className="space-y-6">
        <h2 className="text-2xl font-bold">Available Methods</h2>

        <div className="p-6 rounded-lg border border-border/50 bg-card/50">
          <div className="flex items-center gap-3 mb-3">
            <h3 className="text-xl font-semibold">1. Classic</h3>
            <Badge variant="outline">File-based</Badge>
          </div>
          <p className="text-muted-foreground mb-4">
            Read raw shellcode from a <code>.bin</code> file and inject using the standard technique.
          </p>
          <div className="p-3 bg-secondary/50 rounded text-sm mb-4">
            <strong>Algorithm:</strong>
            <ol className="mt-2 space-y-1 text-muted-foreground list-decimal list-inside">
              <li><code>OpenProcess</code> with PROCESS_ALL_ACCESS</li>
              <li><code>VirtualAllocEx(PAGE_READWRITE)</code> — allocate RW memory</li>
              <li><code>WriteProcessMemory</code> — write shellcode bytes</li>
              <li><code>VirtualProtectEx(PAGE_EXECUTE_READWRITE)</code> — make executable</li>
              <li><code>CreateRemoteThread</code> at shellcode address</li>
            </ol>
          </div>
          <div className="text-sm text-muted-foreground">
            <strong>File:</strong> <code className="text-violet">classic.rs</code><br />
            <strong>Functions:</strong> <code className="text-violet">inject_shellcode_classic()</code>, <code className="text-violet">inject_shellcode_bytes()</code>
          </div>
        </div>

        <div className="p-6 rounded-lg border border-border/50 bg-card/50">
          <div className="flex items-center gap-3 mb-3">
            <h3 className="text-xl font-semibold">2. Web Staging</h3>
            <Badge variant="outline">URL Download</Badge>
          </div>
          <p className="text-muted-foreground mb-4">
            Download shellcode from a URL via WinInet, then inject using the classic technique. 
            Useful for staged payloads.
          </p>
          <div className="p-3 bg-secondary/50 rounded text-sm mb-4">
            <strong>Algorithm:</strong>
            <ol className="mt-2 space-y-1 text-muted-foreground list-decimal list-inside">
              <li><code>InternetOpenW</code> — initialize WinInet</li>
              <li><code>InternetOpenUrlW</code> — open HTTP/HTTPS URL</li>
              <li><code>InternetReadFile</code> — read in 1024-byte chunks</li>
              <li>Inject using classic technique</li>
            </ol>
          </div>
          <div className="text-sm text-muted-foreground">
            <strong>File:</strong> <code className="text-violet">web_staging.rs</code><br />
            <strong>Function:</strong> <code className="text-violet">inject_shellcode_url()</code>
          </div>
        </div>

        <div className="p-6 rounded-lg border border-border/50 bg-card/50">
          <div className="flex items-center gap-3 mb-3">
            <h3 className="text-xl font-semibold">3. Threadless</h3>
            <Badge variant="destructive">Advanced</Badge>
          </div>
          <p className="text-muted-foreground mb-4">
            No <code>CreateRemoteThread</code>. Hooks an exported function with a CALL trampoline. 
            Payload fires when the target process naturally calls the hooked function.
          </p>
          <div className="p-3 bg-secondary/50 rounded text-sm mb-4">
            <strong>Algorithm:</strong>
            <ol className="mt-2 space-y-1 text-muted-foreground list-decimal list-inside">
              <li>Find target function (e.g., <code>USER32!MessageBoxW</code>)</li>
              <li>Allocate &quot;memory hole&quot; within ±1.75 GB of target function</li>
              <li>Write 63-byte hook stub (saves registers, restores original bytes, calls payload, jumps back)</li>
              <li>Write main shellcode payload after stub</li>
              <li>Patch target function with 5-byte CALL trampoline</li>
              <li>Self-healing: hook restores original bytes after first execution</li>
            </ol>
          </div>
          <div className="text-sm text-muted-foreground">
            <strong>File:</strong> <code className="text-violet">threadless.rs</code><br />
            <strong>Function:</strong> <code className="text-violet">inject_shellcode_threadless()</code>
          </div>
          <WarningBox variant="info" title="Default Target" className="mt-4">
            Default hook target is <code>USER32!MessageBoxW</code>. This can be customized 
            in the UI to any exported function.
          </WarningBox>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Usage</h2>
        <p className="text-muted-foreground">
          Access shellcode injection via the UI:
        </p>
        <ol className="list-decimal list-inside space-y-2 text-muted-foreground">
          <li>Right-click on a process in the Process tab</li>
          <li>Navigate to <strong>Miscellaneous → Shellcode Injection</strong></li>
          <li>Select the injection method:
            <ul className="ml-6 mt-1 space-y-1">
              <li>• <strong>Classic</strong> — file picker for <code>.bin</code> shellcode files</li>
              <li>• <strong>Web Staging</strong> — opens modal with URL input field</li>
              <li>• <strong>Threadless</strong> — opens modal with shellcode file picker + target DLL/function inputs</li>
            </ul>
          </li>
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
                <th className="text-left py-3 px-4 font-semibold">Network</th>
                <th className="text-left py-3 px-4 font-semibold">Execution</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4">Classic</td>
                <td className="py-3 px-4 text-red-400">Yes</td>
                <td className="py-3 px-4 text-green-400">No</td>
                <td className="py-3 px-4">Immediate</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4">Web Staging</td>
                <td className="py-3 px-4 text-red-400">Yes</td>
                <td className="py-3 px-4 text-red-400">Yes</td>
                <td className="py-3 px-4">Immediate</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4 font-semibold">Threadless</td>
                <td className="py-3 px-4 text-green-400">No</td>
                <td className="py-3 px-4 text-green-400">No</td>
                <td className="py-3 px-4">On function call</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
