import { CodeBlock } from "@/components/code-block";
import { WarningBox } from "@/components/warning-box";

export default function SmmPhysicalMemoryPage() {
  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-4xl font-bold mb-4">Physical Memory Operations</h1>
        <p className="text-lg text-muted-foreground">
          Read and write arbitrary physical memory from within SMM. Because SMM runs below the
          hypervisor and the kernel, this bypasses EPT hooks, PatchGuard, and any usermode/kernel
          memory protection.
        </p>
      </div>

      <WarningBox variant="danger" title="Physical Memory Is Not a Toy">
        Writing to the wrong physical page can corrupt kernel state, page tables, firmware
        variables, or MMIO registers. Always verify the target address, and prefer read-only
        operations for research.
      </WarningBox>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Read Physical Memory</h2>
        <p className="text-muted-foreground">
          Copies <code>size</code> bytes from physical address <code>src</code> into the SMM
          communication buffer. The kernel driver then copies the result back to usermode.
        </p>
        <CodeBlock
          language="rust"
          code={`use smm::{read_physical, SmmError};

let bytes: Vec<u8> = read_physical(0x1000, 4096)?;
println!("{:02X?}", &bytes[..16]);`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Write Physical Memory</h2>
        <CodeBlock
          language="rust"
          code={`use smm::write_physical;

let patch: [u8; 8] = [0x90; 8];      // 8 NOPs
write_physical(0xFFFFF80012340000, &patch)?;`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Translate Virtual → Physical</h2>
        <p className="text-muted-foreground">
          SMM walks the target process&apos;s CR3 page tables to translate a virtual address into
          its physical page. Combines with <code>read_physical</code>/<code>write_physical</code>{" "}
          to reach usermode memory that the OS would otherwise mediate.
        </p>
        <CodeBlock
          language="rust"
          code={`use smm::{translate_virtual, read_physical};

let phys = translate_virtual(target_pid, 0x7FF612340000)?;
let bytes = read_physical(phys, 256)?;`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">CR3 Page Table Walk</h2>
        <p className="text-muted-foreground">
          The SMM handler walks the standard 4-level x86-64 paging hierarchy — PML4 → PDPT → PD →
          PT — reading each level directly from physical memory.
        </p>
        <CodeBlock
          language="c"
          code={`// efi/DioProcessSmm/Memory.c (simplified)
UINT64 TranslateVa(UINT64 Cr3, UINT64 Va) {
    UINT64 Pml4e = ReadPhys(Cr3 + ((Va >> 39) & 0x1FF) * 8);
    if (!(Pml4e & 1)) return 0;
    UINT64 Pdpte = ReadPhys((Pml4e & PA_MASK) + ((Va >> 30) & 0x1FF) * 8);
    if (!(Pdpte & 1)) return 0;
    if (Pdpte & PS_BIT) return (Pdpte & PA_MASK) + (Va & 0x3FFFFFFF); // 1GB
    UINT64 Pde = ReadPhys((Pdpte & PA_MASK) + ((Va >> 21) & 0x1FF) * 8);
    if (!(Pde & 1)) return 0;
    if (Pde & PS_BIT) return (Pde & PA_MASK) + (Va & 0x1FFFFF); // 2MB
    UINT64 Pte = ReadPhys((Pde & PA_MASK) + ((Va >> 12) & 0x1FF) * 8);
    if (!(Pte & 1)) return 0;
    return (Pte & PA_MASK) + (Va & 0xFFF); // 4KB
}`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Why Not Just Use the Hypervisor?</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>
            • <strong className="text-foreground">Deeper isolation</strong> — SMRAM is chipset-
            locked and invisible to both Ring 0 and Ring -1 EPT tables
          </li>
          <li>
            • <strong className="text-foreground">Survives HV takedown</strong> — even if a
            security product unloads the DioProcess hypervisor, the SMM handler remains resident
          </li>
          <li>
            • <strong className="text-foreground">Firmware-persistent</strong> — SMM code is loaded
            from platform firmware, not a driver — it activates before Windows even boots
          </li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Limitations</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>
            • SMI latency is measurable (µs–ms) — not suitable for high-frequency polling
          </li>
          <li>
            • All CPU cores stall while SMM executes — long handlers cause visible system pauses
          </li>
          <li>
            • Communication buffer is bounded (4 KB per request) — large reads require chunking
          </li>
          <li>
            • SMM cannot call OS functions — everything must be self-contained
          </li>
        </ul>
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
                <td className="py-3 px-4">SMM memory ops</td>
                <td className="py-3 px-4 font-mono text-violet">efi/DioProcessSmm/Memory.c</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4">Command dispatcher</td>
                <td className="py-3 px-4 font-mono text-violet">efi/DioProcessSmm/Commands.c</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4">Rust bindings</td>
                <td className="py-3 px-4 font-mono text-violet">crates/smm/src/driver.rs</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
