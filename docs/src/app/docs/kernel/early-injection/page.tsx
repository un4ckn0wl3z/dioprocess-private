import { WarningBox } from "@/components/warning-box";
import { Badge } from "@/components/ui/badge";

export default function EarlyInjectionPage() {
  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-4xl font-bold mb-4">Early Injection</h1>
        <p className="text-lg text-muted-foreground">
          Inject DLLs into processes <strong>before any user code executes</strong> — 
          triggered by kernel callbacks at process creation time.
        </p>
      </div>

      <WarningBox variant="info" title="APC Method Only">
        Only the APC Callback method is supported. The Trampoline method was removed due to 
        stability issues (PEB.Ldr not initialized at process creation time).
      </WarningBox>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">How It Works</h2>
        <ol className="list-decimal list-inside space-y-2 text-muted-foreground">
          <li>User arms injection with target process name (e.g., &quot;notepad.exe&quot;) and DLL path</li>
          <li>Kernel&apos;s <code>PsSetLoadImageNotifyRoutine</code> callback monitors DLL loads</li>
          <li>When <code>kernel32.dll</code> loads in a matching target process:
            <ul className="ml-6 mt-1 space-y-1">
              <li>• Allocate memory, write DLL path</li>
              <li>• Resolve <code>LoadLibraryW</code> via PEB walking</li>
              <li>• Queue kernel APC targeting the main thread</li>
            </ul>
          </li>
          <li>APC fires during process initialization, calling <code>LoadLibraryW(dll_path)</code></li>
          <li>One-shot mode: auto-disarm after first successful injection</li>
        </ol>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Why APC Method</h2>
        <p className="text-muted-foreground">
          The APC method triggers when <code>kernel32.dll</code> loads — at this point:
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>• ✓ PEB.Ldr is fully initialized</li>
          <li>• ✓ <code>LoadLibraryW</code> is available and callable</li>
          <li>• ✓ Process initialization is far enough along for DLL loading</li>
          <li>• ✓ Still before any application code runs</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Usage</h2>
        <ol className="list-decimal list-inside space-y-2 text-muted-foreground">
          <li>Ensure the kernel driver is loaded</li>
          <li>Click <strong>Early Injection</strong> button in Process tab toolbar</li>
          <li>In the modal:
            <ul className="ml-6 mt-1 space-y-1">
              <li>• Enter target process name (e.g., &quot;notepad.exe&quot;)</li>
              <li>• Browse for DLL to inject</li>
              <li>• Toggle one-shot mode if desired</li>
            </ul>
          </li>
          <li>Click <strong>Arm</strong> to enable injection</li>
          <li>Launch the target process — DLL will be injected automatically</li>
          <li>Click <strong>Disarm</strong> to disable injection</li>
        </ol>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Status Information</h2>
        <p className="text-muted-foreground">
          The modal displays live status:
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <strong>Armed State</strong> — Whether injection is active</li>
          <li>• <strong>Target Process</strong> — Name being monitored</li>
          <li>• <strong>DLL Path</strong> — Path to inject</li>
          <li>• <strong>Injection Count</strong> — Number of successful injections</li>
          <li>• <strong>Last Injected PID</strong> — Most recent target PID</li>
          <li>• <strong>Last Status</strong> — Success or error message</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Use Cases</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <strong>Inject monitoring DLLs</strong> — Before application code runs</li>
          <li>• <strong>Bypass DLL load order restrictions</strong> — Load before dependencies</li>
          <li>• <strong>Security research</strong> — Analyze early-stage process behavior</li>
          <li>• <strong>Anti-cheat research</strong> — Inject before protection initializes</li>
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
                <td className="py-3 px-4">Rust bindings</td>
                <td className="py-3 px-4 font-mono text-violet">crates/callback/src/early_injection.rs</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4">Kernel code</td>
                <td className="py-3 px-4 font-mono text-violet">kernelmode/.../Injection/EarlyInjection.cpp</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4">UI component</td>
                <td className="py-3 px-4 font-mono text-violet">early_injection_window.rs</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4">IOCTL (Arm)</td>
                <td className="py-3 px-4 font-mono">0x140</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4">IOCTL (Disarm)</td>
                <td className="py-3 px-4 font-mono">0x144</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4">IOCTL (Status)</td>
                <td className="py-3 px-4 font-mono">0x148</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
