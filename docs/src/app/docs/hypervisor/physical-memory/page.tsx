import { Badge } from "@/components/ui/badge";
import { CodeBlock } from "@/components/code-block";
import { WarningBox } from "@/components/warning-box";

export default function PhysicalMemoryPage() {
  return (
    <div className="space-y-8">
      <div>
        <div className="flex items-center gap-3 mb-4">
          <h1 className="text-4xl font-bold">Physical Memory Access</h1>
          <Badge variant="outline">Ring -1</Badge>
        </div>
        <p className="text-muted-foreground">
          Read and write physical RAM directly via hypervisor Virtual Machine eXit (VMCALL) 
          operations, bypassing all kernel protections.
        </p>
      </div>

      <WarningBox variant="danger" title="Extreme Caution">
        Direct physical memory access can corrupt system data, cause BSODs, or permanently 
        damage the system. Only use on test systems with full backups.
      </WarningBox>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Overview</h2>
        <p className="text-muted-foreground">
          The DioProcess hypervisor provides direct physical memory access via VMCALL 
          instructions. This bypasses all kernel-level protections including:
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>• Memory protection (PAGE_GUARD, etc.)</li>
          <li>• Kernel-mode address validation</li>
          <li>• Memory access callbacks</li>
          <li>• Secure kernel isolation</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">CR3 Page Table Walk</h2>
        <p className="text-muted-foreground">
          To access process memory physically, the hypervisor walks page tables using the 
          target process&apos;s CR3 register value:
        </p>
        <CodeBlock
          language="cpp"
          filename="Virtual to Physical Translation"
          code={`PHYSICAL_ADDRESS TranslateVirtualToPhysical(
    ULONG64 Cr3,           // Target process CR3
    ULONG64 VirtualAddress
) {
    // 4-level paging: PML4 -> PDPT -> PD -> PT -> Physical
    
    // 1. Get PML4 entry (bits 47:39 of VA)
    ULONG64 Pml4Index = (VirtualAddress >> 39) & 0x1FF;
    ULONG64 Pml4Entry = ReadPhysical(Cr3 + Pml4Index * 8);
    if (!(Pml4Entry & 1)) return 0;  // Not present
    
    // 2. Get PDPT entry (bits 38:30)
    ULONG64 PdptBase = Pml4Entry & PHYS_ADDR_MASK;
    ULONG64 PdptIndex = (VirtualAddress >> 30) & 0x1FF;
    ULONG64 PdptEntry = ReadPhysical(PdptBase + PdptIndex * 8);
    if (!(PdptEntry & 1)) return 0;
    
    // Check for 1GB huge page
    if (PdptEntry & (1 << 7)) {
        return (PdptEntry & HUGE_PAGE_MASK) + (VirtualAddress & 0x3FFFFFFF);
    }
    
    // 3. Get PD entry (bits 29:21)
    ULONG64 PdBase = PdptEntry & PHYS_ADDR_MASK;
    ULONG64 PdIndex = (VirtualAddress >> 21) & 0x1FF;
    ULONG64 PdEntry = ReadPhysical(PdBase + PdIndex * 8);
    if (!(PdEntry & 1)) return 0;
    
    // Check for 2MB large page
    if (PdEntry & (1 << 7)) {
        return (PdEntry & LARGE_PAGE_MASK) + (VirtualAddress & 0x1FFFFF);
    }
    
    // 4. Get PT entry (bits 20:12)
    ULONG64 PtBase = PdEntry & PHYS_ADDR_MASK;
    ULONG64 PtIndex = (VirtualAddress >> 12) & 0x1FF;
    ULONG64 PtEntry = ReadPhysical(PtBase + PtIndex * 8);
    if (!(PtEntry & 1)) return 0;
    
    // 5. Final physical address
    return (PtEntry & PHYS_ADDR_MASK) + (VirtualAddress & 0xFFF);
}`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">VMCALL Interface</h2>
        <CodeBlock
          language="cpp"
          filename="Hypervisor VMCALL Handling"
          code={`// VMCALL from ring 0 driver to hypervisor
NTSTATUS HvReadPhysical(
    PHYSICAL_ADDRESS PhysAddr,
    PVOID Buffer,
    SIZE_T Size
) {
    VMCALL_DATA Data = {
        .Operation = HV_READ_PHYSICAL,
        .PhysicalAddress = PhysAddr.QuadPart,
        .Buffer = Buffer,
        .Size = Size
    };
    
    // Execute VMCALL with hypercall key
    __vmcall(HYPERCALL_KEY, &Data);
    
    return Data.Status;
}

// Hypervisor side: handle VMCALL in VM Exit handler
VOID VmExitHandler_Vmcall(PVCPU_CONTEXT Vcpu) {
    PVMCALL_DATA Data = (PVMCALL_DATA)Vcpu->Rdi;
    
    if (Vcpu->Rax != HYPERCALL_KEY) {
        InjectException(Vcpu, INVALID_OPCODE);
        return;
    }
    
    switch (Data->Operation) {
        case HV_READ_PHYSICAL:
            // Direct physical memory copy
            memcpy(
                Data->Buffer,
                PhysToVirt(Data->PhysicalAddress),
                Data->Size
            );
            Data->Status = STATUS_SUCCESS;
            break;
            
        case HV_WRITE_PHYSICAL:
            memcpy(
                PhysToVirt(Data->PhysicalAddress),
                Data->Buffer,
                Data->Size
            );
            Data->Status = STATUS_SUCCESS;
            break;
    }
}`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">API</h2>
        <CodeBlock
          language="rust"
          filename="Usage"
          code={`use callback::{hv_read_physical, hv_write_physical, hv_translate_virtual};

// Translate virtual address to physical
let cr3 = get_process_cr3(pid)?;
let phys_addr = hv_translate_virtual(cr3, virtual_addr)?;

// Read physical memory
let mut buffer = [0u8; 4096];
hv_read_physical(phys_addr, &mut buffer)?;

// Write physical memory
let data = [0x90u8; 5];  // 5 NOPs
hv_write_physical(phys_addr, &data)?;

// Combined: read process memory via physical
let mut value: u64 = 0;
hv_read_process_memory(pid, virtual_addr, &mut value)?;`}
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
                <td className="py-2 px-3 font-mono text-xs">HV_READ_PHYSICAL</td>
                <td className="py-2 px-3">0x810</td>
                <td className="py-2 px-3 text-muted-foreground">Read physical memory</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">HV_WRITE_PHYSICAL</td>
                <td className="py-2 px-3">0x811</td>
                <td className="py-2 px-3 text-muted-foreground">Write physical memory</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">HV_TRANSLATE_VA</td>
                <td className="py-2 px-3">0x812</td>
                <td className="py-2 px-3 text-muted-foreground">Translate VA to PA with CR3</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">HV_GET_CR3</td>
                <td className="py-2 px-3">0x813</td>
                <td className="py-2 px-3 text-muted-foreground">Get process CR3 from PID</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">What Can Be Accessed</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>✓ Any user-mode process memory</li>
          <li>✓ Kernel memory (ntoskrnl, drivers)</li>
          <li>✓ Secure kernel (VSM/VBS) memory</li>
          <li>✓ UEFI runtime services memory</li>
          <li>✓ MMIO device memory</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Memory Scanner Integration</h2>
        <p className="text-muted-foreground">
          The Memory Scanner tab uses physical memory access for scanning:
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>• CR3 walk to enumerate all valid VA ranges</li>
          <li>• Physical reads for value scanning</li>
          <li>• Physical writes for memory editing</li>
          <li>• Support for large pages (2MB, 1GB)</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Use Cases</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• Memory forensics without kernel assistance</li>
          <li>• Bypassing anti-cheat memory protection</li>
          <li>• Kernel rootkit detection via physical comparison</li>
          <li>• Secure kernel research</li>
          <li>• UEFI runtime memory analysis</li>
        </ul>
      </section>
    </div>
  );
}
