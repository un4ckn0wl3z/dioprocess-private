import { CodeBlock } from "@/components/code-block";
import { Badge } from "@/components/ui/badge";

export default function EptHooksPage() {
  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-4xl font-bold mb-4">EPT Hooks</h1>
        <p className="text-lg text-muted-foreground">
          Install execution-page hooks via hypervisor EPT (Extended Page Tables). 
          The read-page shows original bytes while the execute-page shows patched bytes.
        </p>
      </div>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Input Modes</h2>
        
        <div className="space-y-4">
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <div className="flex items-center gap-2 mb-2">
              <h3 className="font-semibold">Hex Mode</h3>
              <Badge variant="outline">Simple</Badge>
            </div>
            <p className="text-sm text-muted-foreground">
              Patch execution page with raw hex bytes. Supports formats: <code>90 90 90</code>, 
              <code>0x90</code>, <code>909090</code>. Max 256 bytes.
            </p>
          </div>

          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <div className="flex items-center gap-2 mb-2">
              <h3 className="font-semibold">Assembly Mode</h3>
              <Badge variant="outline">Intel Syntax</Badge>
            </div>
            <p className="text-sm text-muted-foreground">
              Write Intel syntax assembly, assembled at target address with live byte preview. 
              Save/load <code>.aa</code> assembly script files.
            </p>
          </div>

          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <div className="flex items-center gap-2 mb-2">
              <h3 className="font-semibold">Detour Mode</h3>
              <Badge variant="destructive">Advanced</Badge>
            </div>
            <p className="text-sm text-muted-foreground mb-3">
              Allocate RWX cave near hook point (±2GB for JMP rel32), assemble detour code there, 
              EPT hook redirects execution via JMP.
            </p>
            <ul className="text-sm text-muted-foreground space-y-1">
              <li>• Return jump auto-appended: <code>FF 25 00 00 00 00 [8-byte abs addr]</code></li>
              <li>• Stolen bytes minimum: 5 (for E9 JMP rel32 + NOP padding)</li>
              <li>• Default stolen bytes: 6</li>
            </ul>
          </div>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">.dph Hook Script System</h2>
        <p className="text-muted-foreground">
          Save EPT hook configurations to <code>.dph</code> (DioProcess Hook) files for portable, 
          repeatable hook application. Scripts survive process restarts via <code>module+offset</code> addressing.
        </p>

        <CodeBlock
          filename="example.dph"
          language="ini"
          code={`# DioProcess Hook Script
[hook]
name = My Hook
target = Tutorial-x86_64.exe+45D7D
mode = detour
stolen_bytes = 6

[code]
add [rbx+0x7F8], edx`}
        />

        <div className="mt-4">
          <h3 className="font-semibold mb-2">Fields</h3>
          <ul className="text-sm text-muted-foreground space-y-1">
            <li>• <code className="text-violet">name</code> — Display name (optional, defaults to filename)</li>
            <li>• <code className="text-violet">target</code> — <code>module+offset</code> or absolute hex <code>0x7FF645D7D</code></li>
            <li>• <code className="text-violet">mode</code> — <code>hex</code>, <code>assembly</code> (or <code>asm</code>), or <code>detour</code></li>
            <li>• <code className="text-violet">stolen_bytes</code> — Only for detour mode (default 6, minimum 5)</li>
            <li>• <code className="text-violet">[code]</code> — Everything after this line is the hook payload</li>
          </ul>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Usage</h2>
        
        <div className="space-y-4">
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2">Install EPT Hook</h3>
            <ol className="list-decimal list-inside text-sm text-muted-foreground space-y-1">
              <li>Navigate to <strong>Memory Scanner</strong> tab</li>
              <li>Select a process and scan for values</li>
              <li>Right-click a result → <strong>Install EPT Hook</strong></li>
              <li>Choose input mode (Hex/Assembly/Detour)</li>
              <li>Enter hook code</li>
              <li>Click <strong>Install</strong></li>
            </ol>
          </div>

          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2">Save .dph Script</h3>
            <p className="text-sm text-muted-foreground">
              Click &quot;Save .dph&quot; on any active EPT hook row. Address is reverse-resolved to 
              <code>module+offset</code> format.
            </p>
          </div>

          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2">Load .dph Script</h3>
            <ol className="list-decimal list-inside text-sm text-muted-foreground space-y-1">
              <li>Memory Scanner → Scripts sub-tab</li>
              <li>Click <strong>Load .dph</strong></li>
              <li>Script appears in table with &quot;Pending&quot; status</li>
              <li>Click <strong>Apply</strong> or <strong>Apply All</strong></li>
            </ol>
          </div>

          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2">Apply from Process Context Menu</h3>
            <p className="text-sm text-muted-foreground">
              Right-click process → Miscellaneous → <strong>Apply .dph Script</strong> → browse file
            </p>
          </div>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Active Hooks Table</h2>
        <p className="text-muted-foreground">
          Shows all installed EPT hooks with:
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>• Hook index</li>
          <li>• Target PID</li>
          <li>• Target address</li>
          <li>• Patch size</li>
          <li>• Actions: Save .dph, Remove</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Functions</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-3 px-4 font-semibold">Function</th>
                <th className="text-left py-3 px-4 font-semibold">Description</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4 font-mono text-violet">install_ept_hook()</td>
                <td className="py-3 px-4 text-muted-foreground">Install EPT hook, returns hook index</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4 font-mono text-violet">remove_ept_hook()</td>
                <td className="py-3 px-4 text-muted-foreground">Remove EPT hook by index</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4 font-mono text-violet">list_ept_hooks()</td>
                <td className="py-3 px-4 text-muted-foreground">List all active hooks</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4 font-mono text-violet">assemble()</td>
                <td className="py-3 px-4 text-muted-foreground">Assemble Intel syntax to bytes</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
