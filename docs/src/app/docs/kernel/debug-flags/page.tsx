import { Badge } from "@/components/ui/badge";
import { CodeBlock } from "@/components/code-block";
import { WarningBox } from "@/components/warning-box";

export default function DebugFlagsPage() {
  return (
    <div className="space-y-8">
      <div>
        <div className="flex items-center gap-3 mb-4">
          <h1 className="text-4xl font-bold">Clear Debug Flags</h1>
          <Badge variant="outline">Ring 0</Badge>
        </div>
        <p className="text-lg text-muted-foreground">
          Remove debugging indicators from a process to bypass anti-debugging checks.
        </p>
      </div>

      <WarningBox variant="info" title="Anti-Anti-Debugging">
        This feature clears common debug detection indicators that software uses to 
        detect if it&apos;s being analyzed. Useful for malware analysis and reverse engineering.
      </WarningBox>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Overview</h2>
        <p className="text-muted-foreground">
          Many applications (especially malware and protected software) check for debuggers 
          and refuse to run or behave differently when detected. The <code className="text-violet">
          clear_debug_flags</code> function removes these indicators directly in kernel 
          memory, bypassing usermode anti-debug checks.
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Flags Cleared</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-2 px-3 font-semibold">Structure</th>
                <th className="text-left py-2 px-3 font-semibold">Field</th>
                <th className="text-left py-2 px-3 font-semibold">Bypass</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">EPROCESS</td>
                <td className="py-2 px-3">DebugPort</td>
                <td className="py-2 px-3 text-muted-foreground">NtQueryInformationProcess(ProcessDebugPort)</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">PEB</td>
                <td className="py-2 px-3">BeingDebugged</td>
                <td className="py-2 px-3 text-muted-foreground">IsDebuggerPresent()</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">PEB</td>
                <td className="py-2 px-3">NtGlobalFlag</td>
                <td className="py-2 px-3 text-muted-foreground">Heap debug flags (FLG_HEAP_*)</td>
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
          code={`NTSTATUS ClearDebugFlags(ULONG ProcessId) {
    PEPROCESS Process;
    PPEB Peb;
    
    // 1. Get EPROCESS pointer from PID
    NTSTATUS Status = PsLookupProcessByProcessId(
        (HANDLE)ProcessId, 
        &Process
    );
    if (!NT_SUCCESS(Status)) return Status;
    
    // 2. Clear EPROCESS.DebugPort (removes kernel debugger detection)
    ULONG64 DebugPortOffset = GetDebugPortOffset(GetWindowsVersion());
    *(PVOID*)((PUCHAR)Process + DebugPortOffset) = NULL;
    
    // 3. Get PEB address
    ULONG64 PebOffset = GetPebOffset(GetWindowsVersion());
    Peb = *(PPEB*)((PUCHAR)Process + PebOffset);
    
    // 4. Attach to process context to access PEB
    KAPC_STATE ApcState;
    KeStackAttachProcess(Process, &ApcState);
    
    __try {
        // 5. Clear PEB.BeingDebugged (bypasses IsDebuggerPresent)
        Peb->BeingDebugged = FALSE;
        
        // 6. Clear PEB.NtGlobalFlag (removes heap debug flags)
        Peb->NtGlobalFlag = 0;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
    }
    
    // 7. Detach and cleanup
    KeUnstackDetachProcess(&ApcState);
    ObDereferenceObject(Process);
    
    return Status;
}`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Anti-Debug Checks Bypassed</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>✓ <code className="text-violet">IsDebuggerPresent()</code></li>
          <li>✓ <code className="text-violet">CheckRemoteDebuggerPresent()</code></li>
          <li>✓ <code className="text-violet">NtQueryInformationProcess(ProcessDebugPort)</code></li>
          <li>✓ <code className="text-violet">NtQueryInformationProcess(ProcessDebugFlags)</code></li>
          <li>✓ Heap flag detection via <code className="text-violet">PEB.NtGlobalFlag</code></li>
          <li>✓ HeapWalk checks (FLG_HEAP_ENABLE_TAIL_CHECK, etc.)</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">API</h2>
        <CodeBlock
          language="rust"
          filename="Usage"
          code={`use callback::clear_debug_flags;

// Clear debug flags from process PID 1234
let pid: u32 = 1234;
clear_debug_flags(pid)?;

// Now the process won't detect debugger presence via:
// - IsDebuggerPresent()
// - CheckRemoteDebuggerPresent()
// - NtQueryInformationProcess(ProcessDebugPort)
// - PEB.NtGlobalFlag heap checks`}
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
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">CLEAR_DEBUG_FLAGS</td>
                <td className="py-2 px-3">0x00222020</td>
                <td className="py-2 px-3 text-muted-foreground">TargetProcessRequest (PID)</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">UI Access</h2>
        <p className="text-muted-foreground">
          Right-click process → Miscellaneous → <strong>🔍 Clear Debug Flags</strong>
        </p>
        <p className="text-muted-foreground">
          Button is disabled/grayed when driver is not loaded.
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Limitations</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• Does not bypass timing-based checks (RDTSC, QueryPerformanceCounter)</li>
          <li>• Does not hide hardware breakpoints (DR0-DR7)</li>
          <li>• Does not bypass exception-based checks (INT 3, EXCEPTION_BREAKPOINT)</li>
          <li>• Application may re-check flags; may need to clear repeatedly</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Use Cases</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• Malware analysis with debugger attached</li>
          <li>• Reverse engineering protected software</li>
          <li>• Game hacking / anti-cheat research</li>
          <li>• Security research and testing</li>
        </ul>
      </section>
    </div>
  );
}
