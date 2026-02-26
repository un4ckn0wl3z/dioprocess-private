import { CodeBlock } from "@/components/code-block";
import { WarningBox } from "@/components/warning-box";

export default function KppBypassPage() {
  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-4xl font-bold mb-4">KPP Bypass</h1>
        <p className="text-lg text-muted-foreground">
          Disable PatchGuard (Kernel Patch Protection) at boot time by patching 
          initialization functions in ntoskrnl.exe.
        </p>
      </div>

      <WarningBox variant="danger" title="System Stability Risk">
        Disabling PatchGuard allows kernel code modifications but may cause system 
        instability. Use only on test systems.
      </WarningBox>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">What is PatchGuard?</h2>
        <p className="text-muted-foreground">
          Kernel Patch Protection (KPP), commonly known as PatchGuard, is a Windows security 
          feature that monitors critical kernel structures and code for unauthorized modifications. 
          If tampering is detected, Windows triggers a BSOD (CRITICAL_STRUCTURE_CORRUPTION).
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Bypass Strategy</h2>
        <p className="text-muted-foreground">
          The EFI driver scans <code>ntoskrnl.exe</code>&apos;s .text section for PatchGuard 
          initialization function prologues and patches them with <code>RET (0xC3)</code> to 
          prevent initialization.
        </p>
        
        <div className="grid sm:grid-cols-2 gap-4">
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2">KiFilterFiberContext</h3>
            <p className="text-sm text-muted-foreground">
              Main PatchGuard initialization routine. Patched with RET to skip entirely.
            </p>
          </div>
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2">ExpLicenseWatchInitWorker</h3>
            <p className="text-sm text-muted-foreground">
              Secondary PatchGuard component. Also patched with RET.
            </p>
          </div>
        </div>

        <CodeBlock
          language="asm"
          code={`; Original function prologue
push rbp
mov rbp, rsp
sub rsp, 0x40
...

; After patching
ret                ; Immediately returns, skipping initialization`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">How It Works</h2>
        <ol className="list-decimal list-inside space-y-2 text-muted-foreground">
          <li>EFI driver hooks <code>gBS-&gt;ExitBootServices</code></li>
          <li>When hook fires, read <code>DioProcessKppBypass</code> NVRAM variable</li>
          <li>If enabled, scan ntoskrnl.exe .text section for target patterns</li>
          <li>Locate <code>KiFilterFiberContext</code> and <code>ExpLicenseWatchInitWorker</code></li>
          <li>Replace first byte with <code>0xC3</code> (RET instruction)</li>
          <li>Restore original <code>ExitBootServices</code> and continue boot</li>
        </ol>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Usage</h2>
        <ol className="list-decimal list-inside space-y-2 text-muted-foreground">
          <li>Install the EFI driver via title bar &quot;Install EFI&quot; button</li>
          <li>Navigate to <strong>UEFI Bootkit</strong> tab</li>
          <li>In Boot Patches section, toggle <strong>PatchGuard Bypass</strong> ON</li>
          <li>Click <strong>Save to NVRAM</strong></li>
          <li>Reboot — PatchGuard will be disabled</li>
        </ol>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">NVRAM Variable</h2>
        <div className="p-4 rounded-lg border border-border/50 bg-card/50">
          <ul className="text-sm text-muted-foreground space-y-1">
            <li>• <strong>GUID:</strong> <code>{`{D10PR0C5-1337-4242-BEEF-CAFEBABE0001}`}</code></li>
            <li>• <strong>Name:</strong> <code>DioProcessKppBypass</code></li>
            <li>• <strong>Value:</strong> 0 (disabled) or 1 (enabled)</li>
          </ul>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">What You Can Do Without PatchGuard</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• Modify SSDT (System Service Descriptor Table)</li>
          <li>• Hook kernel functions directly</li>
          <li>• Modify IDT (Interrupt Descriptor Table)</li>
          <li>• Patch kernel code without triggering BSOD</li>
          <li>• Implement custom kernel-level monitoring</li>
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
                <td className="py-3 px-4">EFI implementation</td>
                <td className="py-3 px-4 font-mono text-violet">efi/DioProcessEfi/PatchKpp.c</td>
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
