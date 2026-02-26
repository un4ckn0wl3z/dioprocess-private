import { CodeBlock } from "@/components/code-block";
import { WarningBox } from "@/components/warning-box";

export default function DseBypassPage() {
  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-4xl font-bold mb-4">DSE Bypass</h1>
        <p className="text-lg text-muted-foreground">
          Disable Driver Signature Enforcement (DSE) at boot time by patching 
          <code className="text-violet mx-1">g_CiOptions</code> in winload.efi.
        </p>
      </div>

      <WarningBox variant="danger" title="Security Implications">
        Disabling DSE allows loading of unsigned kernel drivers. This significantly 
        reduces system security and should only be used on test systems.
      </WarningBox>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">What is DSE?</h2>
        <p className="text-muted-foreground">
          Driver Signature Enforcement (DSE) is a Windows security feature that requires 
          all kernel-mode drivers to be digitally signed by Microsoft or a trusted certificate 
          authority. Without a valid signature, Windows refuses to load the driver.
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Bypass Strategy</h2>
        <p className="text-muted-foreground">
          The EFI driver scans <code>winload.efi</code>&apos;s .text section for the 
          <code>MOV [rip+imm32], ecx</code> instruction that initializes <code>g_CiOptions</code>, 
          then NOPs out the 6-byte instruction to leave <code>g_CiOptions</code> at 0.
        </p>
        <CodeBlock
          language="asm"
          code={`; Original instruction in winload.efi
mov [rip+0x12345], ecx    ; Sets g_CiOptions

; After patching (6 bytes of NOP)
nop
nop
nop
nop
nop
nop                        ; g_CiOptions remains 0`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">How It Works</h2>
        <ol className="list-decimal list-inside space-y-2 text-muted-foreground">
          <li>EFI driver hooks <code>gBS-&gt;ExitBootServices</code></li>
          <li>When hook fires, read <code>DioProcessDseBypass</code> NVRAM variable</li>
          <li>If enabled, scan winload.efi .text section for target pattern</li>
          <li>Pattern: <code>89 0D ?? ?? ?? ??</code> (MOV [rip+imm32], ecx)</li>
          <li>Replace 6 bytes with NOPs (<code>90 90 90 90 90 90</code>)</li>
          <li>Restore original <code>ExitBootServices</code> and continue boot</li>
        </ol>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Usage</h2>
        <ol className="list-decimal list-inside space-y-2 text-muted-foreground">
          <li>Install the EFI driver via title bar &quot;Install EFI&quot; button</li>
          <li>Navigate to <strong>UEFI Bootkit</strong> tab</li>
          <li>In Boot Patches section, toggle <strong>DSE Bypass</strong> ON</li>
          <li>Click <strong>Save to NVRAM</strong></li>
          <li>Reboot — DSE will be disabled</li>
        </ol>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">NVRAM Variable</h2>
        <div className="p-4 rounded-lg border border-border/50 bg-card/50">
          <ul className="text-sm text-muted-foreground space-y-1">
            <li>• <strong>GUID:</strong> <code>{`{D10PR0C5-1337-4242-BEEF-CAFEBABE0001}`}</code></li>
            <li>• <strong>Name:</strong> <code>DioProcessDseBypass</code></li>
            <li>• <strong>Value:</strong> 0 (disabled) or 1 (enabled)</li>
          </ul>
        </div>
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
                <td className="py-3 px-4">EFI implementation</td>
                <td className="py-3 px-4 font-mono text-violet">efi/DioProcessEfi/PatchDse.c</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4">Rust bindings</td>
                <td className="py-3 px-4 font-mono text-violet">crates/uefi/src/nvram.rs</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
