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
        <h2 className="text-2xl font-bold">Build from Source</h2>
        <p className="text-muted-foreground">
          DioProcess is built with Rust. Make sure you have the Rust toolchain installed.
        </p>
        
        <CodeBlock
          filename="Terminal"
          language="bash"
          code={`# Clone the repository
git clone https://github.com/your-repo/dioprocess.git
cd dioprocess

# Debug build + run (must run as administrator)
cargo run

# Optimized release binary
cargo build --release
.\\target\\release\\dioprocess.exe`}
        />
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
                  Enables local file browsing for EFI installation (bypass GitHub download)
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
