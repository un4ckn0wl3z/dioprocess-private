import { CodeBlock } from "@/components/code-block";
import { WarningBox } from "@/components/warning-box";
import { Badge } from "@/components/ui/badge";

export default function ProcessProtectionPage() {
  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-4xl font-bold mb-4">Process Protection</h1>
        <p className="text-lg text-muted-foreground">
          Apply or remove Protected Process Light (PPL) protection via direct 
          <code className="text-violet mx-1">_EPROCESS</code> structure modification.
        </p>
      </div>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Overview</h2>
        <p className="text-muted-foreground">
          Windows Protected Process Light (PPL) prevents unauthorized access to protected processes. 
          DioProcess can manipulate these protection flags directly in kernel memory.
        </p>
        
        <div className="grid sm:grid-cols-2 gap-4">
          <div className="p-4 rounded-lg border border-green-500/30 bg-green-500/10">
            <h3 className="font-semibold text-green-400 mb-2">🛡️ Protect Process</h3>
            <p className="text-sm text-muted-foreground">
              Apply WinTcb-Light protection (highest PPL level) to any process
            </p>
          </div>
          <div className="p-4 rounded-lg border border-red-500/30 bg-red-500/10">
            <h3 className="font-semibold text-red-400 mb-2">🔓 Unprotect Process</h3>
            <p className="text-sm text-muted-foreground">
              Remove PPL protection from protected processes (lsass.exe, AV, etc.)
            </p>
          </div>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Protection Levels</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-3 px-4 font-semibold">Level</th>
                <th className="text-left py-3 px-4 font-semibold">Value</th>
                <th className="text-left py-3 px-4 font-semibold">Description</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4 font-mono">PS_PROTECTED_WINTCB_LIGHT</td>
                <td className="py-3 px-4">0x61</td>
                <td className="py-3 px-4 text-muted-foreground">WinTcb + Light (default for protect)</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4 font-mono">PS_PROTECTED_WINDOWS_LIGHT</td>
                <td className="py-3 px-4">0x51</td>
                <td className="py-3 px-4 text-muted-foreground">Windows + Light</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4 font-mono">PS_PROTECTED_LSA_LIGHT</td>
                <td className="py-3 px-4">0x41</td>
                <td className="py-3 px-4 text-muted-foreground">LSA + Light (lsass.exe)</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4 font-mono">PS_PROTECTED_ANTIMALWARE_LIGHT</td>
                <td className="py-3 px-4">0x31</td>
                <td className="py-3 px-4 text-muted-foreground">Antimalware + Light (AV processes)</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Algorithm</h2>
        
        <div className="p-4 rounded-lg border border-border/50 bg-card/50">
          <h3 className="font-semibold mb-3">Protect Process</h3>
          <ol className="list-decimal list-inside space-y-1 text-sm text-muted-foreground">
            <li>Call <code>GetWindowsVersion()</code> to detect current Windows build</li>
            <li><code>PsLookupProcessByProcessId()</code> to get EPROCESS pointer</li>
            <li>Calculate protection address: <code>EPROCESS + PROCESS_PROTECTION_OFFSET[version]</code></li>
            <li>Write protection values:
              <ul className="ml-6 mt-1 space-y-1">
                <li>• <code>SignatureLevel = 0x3E</code> (SE_SIGNING_LEVEL_WINDOWS_TCB)</li>
                <li>• <code>SectionSignatureLevel = 0x3C</code> (SE_SIGNING_LEVEL_WINDOWS)</li>
                <li>• <code>Protection.Type = 2</code> (PsProtectedTypeProtectedLight)</li>
                <li>• <code>Protection.Signer = 6</code> (PsProtectedSignerWinTcb)</li>
              </ul>
            </li>
            <li><code>ObDereferenceObject(eProcess)</code></li>
          </ol>
        </div>

        <div className="p-4 rounded-lg border border-border/50 bg-card/50">
          <h3 className="font-semibold mb-3">Unprotect Process</h3>
          <p className="text-sm text-muted-foreground">
            Same algorithm, but zero out all protection fields instead of setting them.
          </p>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Structure Offsets</h2>
        <p className="text-muted-foreground">
          The <code>PROCESS_PROTECTION_OFFSET</code> varies by Windows version:
        </p>
        <CodeBlock
          language="cpp"
          code={`// PROCESS_PROTECTION_OFFSET array (indexed by WINDOWS_VERSION)
Win 10 1809 (17763):  0x6ca
Win 10 2004 (19041):  0x87a
Win 11 21H2 (22000):  0x87a
Win 11 22H2 (22621):  0x87a
Win 11 23H2 (22631):  0x87a
Win 11 24H2 (26100):  0x87a`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Usage</h2>
        <ol className="list-decimal list-inside space-y-2 text-muted-foreground">
          <li>Ensure the kernel driver is loaded</li>
          <li>Right-click on a process in the Process tab</li>
          <li>Navigate to <strong>Miscellaneous</strong></li>
          <li>Select <strong>🛡️ Protect Process</strong> or <strong>🔓 Unprotect Process</strong></li>
        </ol>
        <WarningBox variant="info" title="Note">
          These options are grayed out when the driver is not loaded.
        </WarningBox>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Use Cases</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <strong>Protect benign processes</strong> — Prevent termination or injection</li>
          <li>• <strong>Unprotect lsass.exe</strong> — Enable credential dumping for research</li>
          <li>• <strong>Unprotect AV processes</strong> — Analyze security product behavior</li>
          <li>• <strong>Test PPL bypass techniques</strong> — Security research and red teaming</li>
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
                <td className="py-3 px-4">Rust binding</td>
                <td className="py-3 px-4 font-mono text-violet">crates/callback/src/driver.rs</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4">Kernel code</td>
                <td className="py-3 px-4 font-mono text-violet">kernelmode/.../DioProcessDriver.cpp</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4">IOCTL (Protect)</td>
                <td className="py-3 px-4 font-mono">IOCTL_DIOPROCESS_PROTECT_PROCESS (0x805)</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4">IOCTL (Unprotect)</td>
                <td className="py-3 px-4 font-mono">IOCTL_DIOPROCESS_UNPROTECT_PROCESS (0x806)</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
