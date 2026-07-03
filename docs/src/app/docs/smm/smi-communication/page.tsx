import { CodeBlock } from "@/components/code-block";
import { WarningBox } from "@/components/warning-box";

export default function SmmSmiCommunicationPage() {
  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-4xl font-bold mb-4">SMI Communication</h1>
        <p className="text-lg text-muted-foreground">
          The kernel driver communicates with the SMM handler via a shared buffer + software SMI.
          The buffer&apos;s physical address is published to NVRAM at boot time by{" "}
          <code className="text-violet">DioProcessDxe.efi</code>.
        </p>
      </div>

      <WarningBox variant="warning" title="Software SMI is Platform-Specific">
        Software SMI is typically triggered by writing to I/O port 0xB2 (Intel APM_CNT). The exact
        behavior depends on the chipset; QEMU/OVMF emulates the standard PIIX4/ICH9 behavior.
      </WarningBox>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">NVRAM Variable</h2>
        <p className="text-muted-foreground">
          At DXE phase, <code>DioProcessDxe.efi</code> allocates a communication buffer and
          publishes its physical address to a runtime-accessible NVRAM variable so the OS can find
          it.
        </p>
        <div className="p-4 rounded-lg border border-border/50 bg-card/50">
          <ul className="text-sm text-muted-foreground space-y-1">
            <li>
              • <strong>GUID:</strong>{" "}
              <code>{`{D10PR0C5-1337-4242-BEEF-CAFEBABE0002}`}</code>
            </li>
            <li>
              • <strong>Name:</strong> <code>DioProcessSmmBuffer</code>
            </li>
            <li>
              • <strong>Value:</strong> 64-bit physical address of the communication buffer
            </li>
            <li>
              • <strong>Attributes:</strong> BS+RT (Boot Service + Runtime Access)
            </li>
          </ul>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Kernel-Side SMI Trigger</h2>
        <CodeBlock
          language="cpp"
          code={`// kernelmode/DioProcess/DioProcessDriver/SMM/SmmCommunication.cpp
NTSTATUS TriggerSmi(SMM_COMM_BUFFER* Cmd) {
    // 1. Read buffer address from NVRAM
    ULONG64 BufferPa = ReadNvramU64(&kSmmBufferGuid, L"DioProcessSmmBuffer");
    if (!BufferPa) return STATUS_NOT_FOUND;

    // 2. Map buffer into kernel VA
    PHYSICAL_ADDRESS Pa = { .QuadPart = BufferPa };
    PVOID BufferVa = MmMapIoSpace(Pa, sizeof(*Cmd), MmNonCached);
    if (!BufferVa) return STATUS_INSUFFICIENT_RESOURCES;

    // 3. Copy command into shared buffer
    RtlCopyMemory(BufferVa, Cmd, sizeof(*Cmd));

    // 4. Trigger software SMI (OUT 0xB2, cmd)
    __outbyte(0xB2, 0x00);   // SMI command byte — SMM handler ignores value

    // 5. Read response back
    RtlCopyMemory(Cmd, BufferVa, sizeof(*Cmd));

    // 6. Unmap
    MmUnmapIoSpace(BufferVa, sizeof(*Cmd));
    return STATUS_SUCCESS;
}`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">SMM-Side Handler</h2>
        <CodeBlock
          language="c"
          code={`// efi/DioProcessSmm/Smi.c
EFI_STATUS EFIAPI SmiHandler(
    IN EFI_HANDLE  DispatchHandle,
    IN CONST VOID *Context OPTIONAL,
    IN OUT VOID  *CommBuffer OPTIONAL,
    IN OUT UINTN *CommBufferSize OPTIONAL
) {
    SMM_COMM_BUFFER *Cmd = (SMM_COMM_BUFFER *)CommBuffer;
    if (Cmd->Signature != SIGNATURE_32('D','P','S','M')) {
        return EFI_INVALID_PARAMETER;
    }

    switch (Cmd->Command) {
        case CMD_READ_PHYS:  Cmd->Status = HandleReadPhys(Cmd);  break;
        case CMD_WRITE_PHYS: Cmd->Status = HandleWritePhys(Cmd); break;
        case CMD_TRANSLATE:  Cmd->Status = HandleTranslate(Cmd); break;
        case CMD_PING:       Cmd->Status = STATUS_OK;            break;
        default:             Cmd->Status = STATUS_INVALID_CMD;   break;
    }
    return EFI_SUCCESS;
}`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Handler Registration (DXE Side)</h2>
        <p className="text-muted-foreground">
          The SMM driver registers itself with the SMM IPL when dispatched into SMRAM. It uses{" "}
          <code>gSmst-&gt;SmiHandlerRegister</code> with a unique GUID so the kernel side can
          target this specific handler if multiple SMM drivers coexist.
        </p>
        <CodeBlock
          language="c"
          code={`// efi/DioProcessSmm/SmmMain.c
EFI_STATUS EFIAPI DioProcessSmmEntry(
    IN EFI_HANDLE        ImageHandle,
    IN EFI_SYSTEM_TABLE *SystemTable
) {
    EFI_HANDLE Handle = NULL;
    return gSmst->SmiHandlerRegister(
        SmiHandler,
        &gDioProcessSmiHandlerGuid,
        &Handle
    );
}`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Serial Debug Output</h2>
        <p className="text-muted-foreground">
          When running under QEMU with OVMF, SMM debug prints appear on the serial console. This is
          the primary way to trace SMM initialization and command dispatch.
        </p>
        <CodeBlock
          language="text"
          code={`=[ DioProcess DXE ]=
[ DXE ] EFI_MM_COMMUNICATION2_PROTOCOL discovered
[ DXE ] Buffer allocated @ 0x7EFB1000
[ DXE ] NVRAM variable DioProcessSmmBuffer set
=[ DioProcess SMM ]=
=[ Ring -2 Memory Operations ]=
[ SMM ] SMM driver invoked by SMM IPL, initializing...
[ SMM ] SMI handler registered (GUID: D10PR0C5-...-0002)
[ SMM ] SMM driver has been initialized
[ SMM ] SMI fired — cmd=0x01 (READ_PHYS)
[ SMM ] ReadPhys 0x1000, 4096 bytes — OK`}
        />
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
                <td className="py-3 px-4">Kernel SMI trigger</td>
                <td className="py-3 px-4 font-mono text-violet">
                  kernelmode/.../SMM/SmmCommunication.cpp
                </td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4">SMM handler</td>
                <td className="py-3 px-4 font-mono text-violet">efi/DioProcessSmm/Smi.c</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4">DXE buffer publisher</td>
                <td className="py-3 px-4 font-mono text-violet">efi/DioProcessDxe/DxeMain.c</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
