import { Badge } from "@/components/ui/badge";
import { CodeBlock } from "@/components/code-block";
import { WarningBox } from "@/components/warning-box";

export default function MemoryDumpPage() {
  return (
    <div className="space-y-8">
      <div>
        <div className="flex items-center gap-3 mb-4">
          <h1 className="text-4xl font-bold">Kernel Memory Dump</h1>
          <Badge variant="outline">Ring 0</Badge>
        </div>
        <p className="text-lg text-muted-foreground">
          Dump process memory using kernel-level APIs to bypass usermode protections.
        </p>
      </div>

      <WarningBox variant="info" title="KsDumper-style">
        This feature uses MmCopyVirtualMemory for direct kernel-to-kernel memory 
        transfer, similar to the KsDumper tool.
      </WarningBox>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Overview</h2>
        <p className="text-muted-foreground">
          Protected processes (PPL, AV, EDR) often prevent memory reading via standard 
          APIs like <code className="text-violet">ReadProcessMemory</code>. The kernel 
          memory dump feature bypasses these restrictions by using{" "}
          <code className="text-violet">MmCopyVirtualMemory</code> directly from Ring 0.
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Implementation</h2>
        <CodeBlock
          language="cpp"
          filename="Kernel Copy Memory"
          code={`NTSTATUS KernelCopyMemory(
    ULONG TargetProcessId,
    ULONG64 SourceAddress,
    ULONG64 DestinationAddress,  // In caller's process
    ULONG Size,
    PULONG BytesCopied
) {
    PEPROCESS SourceProcess;
    PEPROCESS CurrentProcess = PsGetCurrentProcess();
    SIZE_T NumberOfBytes = 0;
    
    // 1. Get target process EPROCESS
    NTSTATUS Status = PsLookupProcessByProcessId(
        (HANDLE)TargetProcessId,
        &SourceProcess
    );
    if (!NT_SUCCESS(Status)) return Status;
    
    // 2. Use MmCopyVirtualMemory for direct transfer
    // This function is undocumented but widely used
    Status = MmCopyVirtualMemory(
        SourceProcess,                      // Source process
        (PVOID)SourceAddress,               // Source address
        CurrentProcess,                     // Destination process (caller)
        (PVOID)DestinationAddress,          // Destination address
        (SIZE_T)Size,                       // Size to copy
        KernelMode,                         // Previous mode
        &NumberOfBytes                      // Bytes copied
    );
    
    *BytesCopied = (ULONG)NumberOfBytes;
    ObDereferenceObject(SourceProcess);
    
    return Status;
}`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">API</h2>
        <CodeBlock
          language="rust"
          filename="Usage"
          code={`use callback::kernel_copy_memory;
use process::get_process_modules;

// Get main module info
let modules = get_process_modules(pid)?;
let main_module = &modules[0];  // First module is usually the main exe

// Allocate buffer for dump
let mut buffer = vec![0u8; main_module.size as usize];

// Read memory via kernel
let bytes_copied = kernel_copy_memory(
    pid,
    main_module.base_address,
    buffer.as_mut_ptr() as u64,
    buffer.len() as u32
)?;

// Save dump to file
std::fs::write("dump.bin", &buffer[..bytes_copied as usize])?;`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Request Structures</h2>
        <CodeBlock
          language="cpp"
          filename="Structures"
          code={`struct KernelCopyMemoryRequest {
    ULONG TargetProcessId;      // Target process PID
    ULONG64 SourceAddress;      // Address in target to read
    ULONG64 DestinationAddress; // Address in caller's buffer
    ULONG Size;                 // Bytes to copy (max 64MB)
};

struct KernelCopyMemoryResponse {
    ULONG BytesCopied;
    BOOLEAN Success;
};`}
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
                <td className="py-2 px-3 font-mono text-xs">COPY_MEMORY</td>
                <td className="py-2 px-3">0x00222180</td>
                <td className="py-2 px-3 text-muted-foreground">Copy memory from target process</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">What Can Be Dumped</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>✓ Protected processes (AV, EDR)</li>
          <li>✓ PPL (Protected Process Light)</li>
          <li>✓ LSASS (credential dumping)</li>
          <li>✓ Processes with ObRegisterCallbacks protection</li>
          <li>✓ Any committed memory regions</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">UI Access</h2>
        <p className="text-muted-foreground">
          Right-click process → Miscellaneous → Kernel (Ring 0) → <strong>📦 Dump Process</strong>
        </p>
        <p className="text-muted-foreground mt-4">
          The dump operation:
        </p>
        <ol className="list-decimal list-inside space-y-2 text-muted-foreground">
          <li>Gets the main module base address and size</li>
          <li>Allocates a buffer and calls <code className="text-violet">kernel_copy_memory()</code></li>
          <li>Opens a save dialog for destination file</li>
          <li>Saves the raw memory dump to disk</li>
        </ol>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">PE Reconstruction</h2>
        <p className="text-muted-foreground">
          The dumped file is a raw memory dump, not a valid PE file. For static analysis:
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <strong>IAT may need reconstruction</strong> — Imports are resolved to runtime addresses</li>
          <li>• <strong>Use PE-bear or Scylla</strong> — Tools to rebuild IAT from memory dump</li>
          <li>• <strong>Section alignment</strong> — Memory dump has section alignment, not file alignment</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Limitations</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• Maximum 64MB per request (larger dumps need multiple calls)</li>
          <li>• Cannot dump non-committed memory</li>
          <li>• PAGE_GUARD pages may cause issues</li>
          <li>• Some kernel-protected memory still inaccessible</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Use Cases</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• Dump protected PE files from memory</li>
          <li>• Credential extraction from LSASS</li>
          <li>• Malware analysis of packed/protected samples</li>
          <li>• Forensic collection of running process memory</li>
        </ul>
      </section>
    </div>
  );
}
