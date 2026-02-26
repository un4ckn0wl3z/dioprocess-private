import { Badge } from "@/components/ui/badge";
import { CodeBlock } from "@/components/code-block";
import { WarningBox } from "@/components/warning-box";

export default function KillMethodsPage() {
  return (
    <div className="space-y-8">
      <div>
        <div className="flex items-center gap-3 mb-4">
          <h1 className="text-4xl font-bold">Process Kill Methods</h1>
          <Badge variant="outline">Ring 0</Badge>
        </div>
        <p className="text-lg text-muted-foreground">
          Terminate processes using various kernel-level methods to bypass protection.
        </p>
      </div>

      <WarningBox variant="danger" title="Use With Caution">
        Kernel-level process termination bypasses normal protections. Terminating 
        critical system processes can cause BSOD or data loss.
      </WarningBox>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Overview</h2>
        <p className="text-muted-foreground">
          DioProcess provides multiple process termination methods, escalating from 
          usermode APIs to kernel-level termination that can kill protected processes.
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Kill Methods</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-2 px-3 font-semibold">Method</th>
                <th className="text-left py-2 px-3 font-semibold">Level</th>
                <th className="text-left py-2 px-3 font-semibold">Bypasses</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">TerminateProcess</td>
                <td className="py-2 px-3">Ring 3</td>
                <td className="py-2 px-3 text-muted-foreground">Nothing (standard)</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">NtTerminateProcess</td>
                <td className="py-2 px-3">Ring 3</td>
                <td className="py-2 px-3 text-muted-foreground">TerminateProcess hooks</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">Kernel Kill</td>
                <td className="py-2 px-3">Ring 0</td>
                <td className="py-2 px-3 text-muted-foreground">Handle access restrictions, EDR</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">HV Kill</td>
                <td className="py-2 px-3">Ring -1</td>
                <td className="py-2 px-3 text-muted-foreground">PPL, kernel callbacks, everything</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Kernel Kill Implementation</h2>
        <CodeBlock
          language="cpp"
          filename="Algorithm"
          code={`NTSTATUS KernelTerminateProcess(ULONG ProcessId) {
    PEPROCESS Process;
    
    // 1. Get EPROCESS pointer
    NTSTATUS Status = PsLookupProcessByProcessId(
        (HANDLE)ProcessId,
        &Process
    );
    if (!NT_SUCCESS(Status)) return Status;
    
    // 2. Method 1: ZwTerminateProcess (uses kernel handle)
    HANDLE ProcessHandle;
    Status = ObOpenObjectByPointer(
        Process,
        OBJ_KERNEL_HANDLE,
        NULL,
        PROCESS_TERMINATE,
        *PsProcessType,
        KernelMode,
        &ProcessHandle
    );
    
    if (NT_SUCCESS(Status)) {
        // Bypasses usermode access checks
        Status = ZwTerminateProcess(ProcessHandle, 0);
        ZwClose(ProcessHandle);
    }
    
    ObDereferenceObject(Process);
    return Status;
}

// Alternative: Direct thread termination
NTSTATUS KernelTerminateProcessAlt(ULONG ProcessId) {
    // For each thread in process:
    //   PsLookupThreadByThreadId(ThreadId, &Thread);
    //   PsTerminateSystemThread(STATUS_SUCCESS);
    // This terminates all threads, killing the process
}`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Hypervisor Kill</h2>
        <p className="text-muted-foreground">
          The most powerful termination method operates from Ring -1:
        </p>
        <CodeBlock
          language="cpp"
          filename="HV Kill Algorithm"
          code={`NTSTATUS HvTerminateProcess(ULONG ProcessId) {
    // 1. From hypervisor, directly manipulate EPROCESS
    PEPROCESS Process = GetEprocessFromPid(ProcessId);
    
    // 2. Set process exit flags
    Process->Flags |= PS_PROCESS_FLAGS_PROCESS_DELETE;
    Process->ExitStatus = STATUS_SUCCESS;
    
    // 3. Terminate all threads by clearing their context
    for (each thread in process) {
        Thread->Terminated = TRUE;
        // Clear thread context, causing exception on resume
    }
    
    // 4. Signal process termination
    KeSetEvent(&Process->ExitEvent);
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
                <td className="py-2 px-3 font-mono text-xs">KERNEL_TERMINATE</td>
                <td className="py-2 px-3">0x00222060</td>
                <td className="py-2 px-3 text-muted-foreground">Ring 0 termination</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">HV_TERMINATE</td>
                <td className="py-2 px-3">0x880</td>
                <td className="py-2 px-3 text-muted-foreground">Ring -1 termination</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">UI Access</h2>
        <p className="text-muted-foreground">
          Multiple ways to terminate processes:
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <strong>Delete key</strong> — Standard termination (default)</li>
          <li>• <strong>Right-click → Terminate</strong> — Shows method selector</li>
          <li>• <strong>Terminate dropdown</strong> — Choose specific method</li>
        </ul>
        <p className="text-muted-foreground mt-4">
          Kernel and HV methods are only available when the driver is loaded.
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">What Each Method Kills</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-2 px-3 font-semibold">Process Type</th>
                <th className="text-left py-2 px-3 font-semibold">Ring 3</th>
                <th className="text-left py-2 px-3 font-semibold">Ring 0</th>
                <th className="text-left py-2 px-3 font-semibold">Ring -1</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3">Normal processes</td>
                <td className="py-2 px-3 text-green-500">✓</td>
                <td className="py-2 px-3 text-green-500">✓</td>
                <td className="py-2 px-3 text-green-500">✓</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3">EDR-protected</td>
                <td className="py-2 px-3 text-red-500">✗</td>
                <td className="py-2 px-3 text-green-500">✓</td>
                <td className="py-2 px-3 text-green-500">✓</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3">PPL (Protected)</td>
                <td className="py-2 px-3 text-red-500">✗</td>
                <td className="py-2 px-3 text-yellow-500">~</td>
                <td className="py-2 px-3 text-green-500">✓</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3">System (PID 4)</td>
                <td className="py-2 px-3 text-red-500">✗</td>
                <td className="py-2 px-3 text-red-500">✗</td>
                <td className="py-2 px-3 text-yellow-500">~BSOD</td>
              </tr>
            </tbody>
          </table>
        </div>
        <p className="text-xs text-muted-foreground mt-2">
          ✓ = Works, ✗ = Blocked, ~ = May work with side effects
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Use Cases</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• Kill stubborn processes that refuse to terminate</li>
          <li>• Terminate EDR/AV processes for testing</li>
          <li>• Kill processes protected by ObRegisterCallbacks</li>
          <li>• Security research on process protection mechanisms</li>
        </ul>
      </section>
    </div>
  );
}
