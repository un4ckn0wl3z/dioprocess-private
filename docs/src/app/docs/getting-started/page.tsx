import { CodeBlock } from "@/components/code-block";
import { WarningBox } from "@/components/warning-box";
import { Badge } from "@/components/ui/badge";

export default function GettingStartedPage() {
  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-4xl font-bold mb-4">Getting Started</h1>
        <p className="text-lg text-muted-foreground">
          Learn how to install and run DioProcess on your Windows system.
        </p>
      </div>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">System Requirements</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li className="flex items-center gap-2">
            <Badge variant="outline">OS</Badge>
            Windows 10 (1507-22H2) or Windows 11 (21H2-24H2)
          </li>
          <li className="flex items-center gap-2">
            <Badge variant="outline">Arch</Badge>
            64-bit (x64) only
          </li>
          <li className="flex items-center gap-2">
            <Badge variant="outline">Privileges</Badge>
            Administrator (UAC elevation required)
          </li>
          <li className="flex items-center gap-2">
            <Badge variant="outline">CPU</Badge>
            Intel VT-x support (for hypervisor features)
          </li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Download Prebuilt</h2>
        <p className="text-muted-foreground">
          Join our Discord server to download prebuilt binaries:
        </p>
        <a 
          href="https://discord.gg/ugYeeJRf5S" 
          target="_blank" 
          rel="noopener noreferrer"
          className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-indigo-500/10 border border-indigo-500/30 text-indigo-400 hover:bg-indigo-500/20 transition-colors"
        >
          <svg className="w-5 h-5" viewBox="0 0 24 24" fill="currentColor">
            <path d="M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028 14.09 14.09 0 0 0 1.226-1.994.076.076 0 0 0-.041-.106 13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z"/>
          </svg>
          Join Discord Server
        </a>
      </section>

      
      <section className="space-y-4">
        <h2 className="text-2xl font-bold">CLI Flags</h2>
        <p className="text-muted-foreground">
          DioProcess supports optional command-line flags to enable additional features.
        </p>

        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-3 px-4 font-semibold">Flag</th>
                <th className="text-left py-3 px-4 font-semibold">Description</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4 font-mono text-violet">-debug</td>
                <td className="py-3 px-4 text-muted-foreground">
                  Enables local file browsing for EFI installation
                </td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4 font-mono text-violet">-alldrv</td>
                <td className="py-3 px-4 text-muted-foreground">
                  Enables all driver installation methods (KDU, KDMapper) in addition to signed driver
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <CodeBlock
          language="bash"
          code={`# Normal launch — signed driver install only
.\\dioprocess.exe

# Enable local EFI file install + all driver methods
.\\dioprocess.exe -debug -alldrv`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Driver Installation Requirements</h2>
        
        <WarningBox variant="danger" title="Important Prerequisites">
          <p>Before installing the kernel driver, you MUST complete these steps:</p>
        </WarningBox>

        <div className="space-y-4 mt-4">
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2">1. Disable Hyper-V</h3>
            <CodeBlock
              language="powershell"
              code={`bcdedit /set hypervisorlaunchtype off
# Reboot required`}
            />
          </div>

          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2">2. Disable Secure Boot</h3>
            <p className="text-sm text-muted-foreground">
              Access your BIOS/UEFI settings and disable Secure Boot.
            </p>
          </div>

          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2">3. Disable Windows Driver Protections</h3>
            <ul className="text-sm text-muted-foreground space-y-1">
              <li>• Disable Driver Signature Enforcement (test mode or boot options)</li>
              <li>• Disable Vulnerable Driver Blocklist (Windows Security → Device Security → Core Isolation)</li>
              <li>• Disable Memory Integrity / HVCI if enabled</li>
            </ul>
          </div>
        </div>

        <WarningBox variant="warning" title="Test Systems Only">
          Use DioProcess ONLY on test systems. You are responsible for any damage caused by 
          improper use of these security research tools.
        </WarningBox>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Keyboard Shortcuts</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-3 px-4 font-semibold">Key</th>
                <th className="text-left py-3 px-4 font-semibold">Action</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4"><kbd className="px-2 py-1 bg-secondary rounded text-xs">F5</kbd></td>
                <td className="py-3 px-4 text-muted-foreground">Refresh current list</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4"><kbd className="px-2 py-1 bg-secondary rounded text-xs">Delete</kbd></td>
                <td className="py-3 px-4 text-muted-foreground">Kill selected process</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4"><kbd className="px-2 py-1 bg-secondary rounded text-xs">Escape</kbd></td>
                <td className="py-3 px-4 text-muted-foreground">Close modal / context menu</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Next Steps</h2>
        <p className="text-muted-foreground">
          Now that you have DioProcess running, explore the different feature categories:
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>
            • <a href="/docs/usermode" className="text-violet hover:underline">Usermode Features</a> — Process monitoring, DLL injection, shellcode injection
          </li>
          <li>
            • <a href="/docs/kernel" className="text-violet hover:underline">Kernel Driver</a> — Process protection, privilege escalation, callback enumeration
          </li>
          <li>
            • <a href="/docs/hypervisor" className="text-violet hover:underline">Hypervisor</a> — EPT hooks, memory scanner, Ring -1 injection
          </li>
          <li>
            • <a href="/docs/uefi" className="text-violet hover:underline">UEFI Bootkit</a> — DSE bypass, PatchGuard bypass
          </li>
        </ul>
      </section>
    </div>
  );
}
