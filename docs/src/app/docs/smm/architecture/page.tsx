import { CodeBlock } from "@/components/code-block";
import { WarningBox } from "@/components/warning-box";

export default function SmmArchitecturePage() {
  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-4xl font-bold mb-4">SMM Architecture</h1>
        <p className="text-lg text-muted-foreground">
          The Ring -2 stack is split between a DXE runtime driver (
          <code className="text-violet mx-1">DioProcessDxe.efi</code>) and an SMM driver (
          <code className="text-violet mx-1">DioProcessSmm.efi</code>). They coordinate via a
          shared communication buffer whose address is published to NVRAM at boot.
        </p>
      </div>

      <WarningBox variant="info" title="Two-driver split is not optional">
        The OS/kernel cannot invoke SMM code directly — an SMI is the only entry point. The DXE
        driver acts as a mailbox setup layer, and the kernel side reads its published NVRAM entry
        to know where to write commands.
      </WarningBox>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Boot Flow</h2>
        <ol className="list-decimal list-inside space-y-2 text-muted-foreground">
          <li>Firmware loads DXE phase drivers, including <code>DioProcessDxe.efi</code></li>
          <li>
            DXE allocates a communication buffer using
            <code className="mx-1">EFI_MM_COMMUNICATION2_PROTOCOL</code>
          </li>
          <li>DXE publishes the buffer&apos;s physical address to a UEFI NVRAM variable</li>
          <li>SMM driver <code>DioProcessSmm.efi</code> is dispatched into SMRAM by the SMM IPL</li>
          <li>SMM driver registers an SMI handler with a unique handler GUID</li>
          <li>OS boots — buffer address and handler GUID remain accessible via NVRAM</li>
        </ol>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Runtime Flow</h2>
        <div className="p-4 rounded-lg border border-border/50 bg-card/50 font-mono text-sm overflow-x-auto">
          <pre className="text-muted-foreground">{`Usermode (dioprocess.exe)
        │  DeviceIoControl(IOCTL_SMM_*)
        ▼
Kernel (DioProcess.sys · SmmCommunication.cpp)
  1. Read NVRAM: buffer address + handler GUID
  2. Map communication buffer into kernel virtual space
  3. Write command struct into buffer
  4. Trigger software SMI (OUT 0xB2, cmd)
        │
        ▼    (all cores enter SMM)
SMRAM (DioProcessSmm.efi)
  1. SMI handler fires — matches handler GUID
  2. Reads command from buffer
  3. Executes: read/write phys memory, walk CR3, etc.
  4. Writes response back to buffer
  5. Returns (RSM instruction — resumes OS)
        │
        ▼
Kernel reads response from buffer → returns to usermode`}</pre>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Communication Buffer Layout</h2>
        <CodeBlock
          language="c"
          code={`// Shared struct between kernel and SMM
typedef struct _SMM_COMM_BUFFER {
    UINT32   Signature;      // 'DPSM' magic
    UINT32   Command;        // Command opcode
    UINT64   Arg1;           // Command-specific
    UINT64   Arg2;           // Command-specific
    UINT64   Arg3;           // Command-specific
    UINT32   Size;           // Data length
    UINT32   Status;         // Response status
    UINT8    Data[4096];     // Inline data buffer
} SMM_COMM_BUFFER;`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Command Opcodes</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-3 px-4 font-semibold">Opcode</th>
                <th className="text-left py-3 px-4 font-semibold">Name</th>
                <th className="text-left py-3 px-4 font-semibold">Description</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4 font-mono text-violet">0x01</td>
                <td className="py-3 px-4">READ_PHYS</td>
                <td className="py-3 px-4 text-muted-foreground">
                  Read N bytes from a physical address
                </td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4 font-mono text-violet">0x02</td>
                <td className="py-3 px-4">WRITE_PHYS</td>
                <td className="py-3 px-4 text-muted-foreground">
                  Write N bytes to a physical address
                </td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4 font-mono text-violet">0x03</td>
                <td className="py-3 px-4">TRANSLATE_VA</td>
                <td className="py-3 px-4 text-muted-foreground">
                  Walk CR3 to translate a virtual address to physical
                </td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4 font-mono text-violet">0x04</td>
                <td className="py-3 px-4">PING</td>
                <td className="py-3 px-4 text-muted-foreground">
                  Sanity-check that the SMM handler is reachable
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Implementation</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-3 px-4 font-semibold">Layer</th>
                <th className="text-left py-3 px-4 font-semibold">Location</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4">SMM driver (SMRAM)</td>
                <td className="py-3 px-4 font-mono text-violet">efi/DioProcessSmm/SmmMain.c</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4">SMI handler</td>
                <td className="py-3 px-4 font-mono text-violet">efi/DioProcessSmm/Smi.c</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4">Command dispatcher</td>
                <td className="py-3 px-4 font-mono text-violet">efi/DioProcessSmm/Commands.c</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4">DXE bridge</td>
                <td className="py-3 px-4 font-mono text-violet">efi/DioProcessDxe/DxeMain.c</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4">Kernel-side SMI trigger</td>
                <td className="py-3 px-4 font-mono text-violet">
                  kernelmode/DioProcess/DioProcessDriver/SMM/SmmCommunication.cpp
                </td>
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
