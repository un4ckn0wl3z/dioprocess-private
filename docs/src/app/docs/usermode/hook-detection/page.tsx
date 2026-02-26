import { Badge } from "@/components/ui/badge";
import { WarningBox } from "@/components/warning-box";

export default function HookDetectionPage() {
  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-4xl font-bold mb-4">Hook Detection & Unhooking</h1>
        <p className="text-lg text-muted-foreground">
          Scan process IAT for inline hooks and restore hooked DLLs by replacing 
          the .text section from disk.
        </p>
      </div>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Hook Detection</h2>
        <p className="text-muted-foreground">
          The hook scanner parses the Import Address Table (IAT) and compares imported 
          function bytes with the original DLL from disk.
        </p>

        <div className="p-4 rounded-lg border border-border/50 bg-card/50">
          <h3 className="font-semibold mb-3">Detected Hook Patterns</h3>
          <div className="grid sm:grid-cols-2 gap-4">
            <div>
              <Badge variant="outline" className="mb-2">E9 JMP</Badge>
              <p className="text-sm text-muted-foreground">Near jump (5-byte inline hook)</p>
            </div>
            <div>
              <Badge variant="outline" className="mb-2">E8 CALL</Badge>
              <p className="text-sm text-muted-foreground">Near call hook</p>
            </div>
            <div>
              <Badge variant="outline" className="mb-2">EB Short JMP</Badge>
              <p className="text-sm text-muted-foreground">Short jump (2-byte hook)</p>
            </div>
            <div>
              <Badge variant="outline" className="mb-2">FF25 Indirect JMP</Badge>
              <p className="text-sm text-muted-foreground">Indirect jump via memory</p>
            </div>
            <div className="sm:col-span-2">
              <Badge variant="outline" className="mb-2">MOV+JMP x64</Badge>
              <p className="text-sm text-muted-foreground">
                <code>48 B8 [addr] FF E0</code> or <code>48 B8 [addr] 50 C3</code> patterns
              </p>
            </div>
          </div>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Algorithm</h2>
        <ol className="list-decimal list-inside space-y-2 text-muted-foreground">
          <li>Parse PE Import Directory to enumerate all imported DLLs and functions</li>
          <li>Read first 16 bytes of each imported function from process memory</li>
          <li>Detect hook patterns via <code>detect_hook_type()</code> function</li>
          <li>Read original DLL from System32 and compare function bytes</li>
          <li>Display results with hook location, memory vs disk bytes, and target module</li>
        </ol>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Supported DLLs</h2>
        <p className="text-muted-foreground">
          Hook detection works for <strong>all</strong> imported DLLs, including:
        </p>
        <div className="flex flex-wrap gap-2">
          {["ntdll.dll", "kernel32.dll", "kernelbase.dll", "user32.dll", "advapi32.dll", "ws2_32.dll"].map((dll) => (
            <Badge key={dll} variant="secondary">{dll}</Badge>
          ))}
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">DLL Unhooking</h2>
        <p className="text-muted-foreground">
          Restore hooked DLLs by reading a clean copy from System32 and replacing 
          the in-memory .text section.
        </p>

        <div className="p-4 rounded-lg border border-border/50 bg-card/50">
          <h3 className="font-semibold mb-3">Remote Unhooking Algorithm</h3>
          <ol className="list-decimal list-inside space-y-1 text-sm text-muted-foreground">
            <li>Read clean DLL from System32 via <code>GetSystemDirectoryA</code></li>
            <li>Open target process with VM_OPERATION | VM_READ | VM_WRITE</li>
            <li>Parse PE headers to find .text section (RVA + raw offset)</li>
            <li>Make remote .text writable via <code>VirtualProtectEx(PAGE_EXECUTE_WRITECOPY)</code></li>
            <li>Write clean .text bytes via <code>WriteProcessMemory</code></li>
            <li>Restore original memory protection</li>
          </ol>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Usage</h2>
        
        <div className="space-y-4">
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2">Hook Scan</h3>
            <p className="text-sm text-muted-foreground">
              Right-click process → <strong>Inspect → Hook Scan</strong>
            </p>
            <ul className="mt-2 text-sm text-muted-foreground space-y-1">
              <li>• Results table shows module, address, hook type, bytes comparison</li>
              <li>• Filter by address or region name</li>
              <li>• Status shows hook count or clean status</li>
            </ul>
          </div>

          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2">Unhook from Scan Results</h3>
            <p className="text-sm text-muted-foreground">
              Right-click detected hook → <strong>&quot;Unhook Module&quot;</strong> to restore original bytes
            </p>
          </div>

          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2">Direct DLL Unhook</h3>
            <p className="text-sm text-muted-foreground">
              Right-click process → <strong>Miscellaneous → DLL Unhook</strong> → select DLL
            </p>
          </div>
        </div>
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
                <td className="py-3 px-4 font-mono text-violet">scan_process_hooks()</td>
                <td className="py-3 px-4 text-muted-foreground">Scan IAT for hooks</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4 font-mono text-violet">unhook_dll_remote()</td>
                <td className="py-3 px-4 text-muted-foreground">Unhook DLL in remote process</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4 font-mono text-violet">unhook_dll()</td>
                <td className="py-3 px-4 text-muted-foreground">Unhook DLL in current process</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4 font-mono text-violet">is_function_hooked()</td>
                <td className="py-3 px-4 text-muted-foreground">Check if function bytes match syscall stub</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <WarningBox variant="info" title="Test Suite">
        A test suite is included in <code>assets/unhook_test/</code> with a MinHook-based 
        DLL that hooks <code>NtProtectVirtualMemory</code> for testing the unhooking functionality.
      </WarningBox>
    </div>
  );
}
