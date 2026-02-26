import { WarningBox } from "@/components/warning-box";
import { Badge } from "@/components/ui/badge";

export default function ProcessCreationPage() {
  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-4xl font-bold mb-4">Process Creation</h1>
        <p className="text-lg text-muted-foreground">
          DioProcess provides 7 process creation techniques for security research, 
          from simple CreateProcess to advanced fileless execution methods.
        </p>
      </div>

      <section className="space-y-6">
        <h2 className="text-2xl font-bold">Available Methods</h2>

        <div className="p-6 rounded-lg border border-border/50 bg-card/50">
          <div className="flex items-center gap-3 mb-3">
            <h3 className="text-xl font-semibold">1. Normal CreateProcess</h3>
            <Badge variant="outline">Basic</Badge>
          </div>
          <p className="text-muted-foreground mb-4">
            Standard process creation via <code>CreateProcessW</code>. Optionally create suspended 
            or with Block DLL Policy.
          </p>
          <div className="text-sm text-muted-foreground">
            <strong>File:</strong> <code className="text-violet">create.rs</code><br />
            <strong>Function:</strong> <code className="text-violet">create_process()</code>
          </div>
        </div>

        <div className="p-6 rounded-lg border border-border/50 bg-card/50">
          <div className="flex items-center gap-3 mb-3">
            <h3 className="text-xl font-semibold">2. PPID Spoofing</h3>
            <Badge variant="outline">Evasion</Badge>
          </div>
          <p className="text-muted-foreground mb-4">
            Create a process that appears as a child of a different parent process using 
            <code>PROC_THREAD_ATTRIBUTE_PARENT_PROCESS</code>.
          </p>
          <div className="text-sm text-muted-foreground">
            <strong>File:</strong> <code className="text-violet">ppid_spoof.rs</code><br />
            <strong>Function:</strong> <code className="text-violet">create_ppid_spoofed_process()</code>
          </div>
        </div>

        <div className="p-6 rounded-lg border border-border/50 bg-card/50">
          <div className="flex items-center gap-3 mb-3">
            <h3 className="text-xl font-semibold">3. Process Hollowing</h3>
            <Badge variant="destructive">Advanced</Badge>
          </div>
          <p className="text-muted-foreground mb-4">
            Create a legitimate process suspended, unmap its image, map payload PE, 
            fix relocations, patch PEB, and hijack thread execution.
          </p>
          <div className="p-3 bg-secondary/50 rounded text-sm mb-4">
            <strong>Algorithm:</strong>
            <ol className="mt-2 space-y-1 text-muted-foreground list-decimal list-inside">
              <li>Create host process SUSPENDED</li>
              <li>Get PEB address via thread context (Rdx)</li>
              <li>Unmap original image via <code>NtUnmapViewOfSection</code></li>
              <li>Allocate memory at payload&apos;s preferred base</li>
              <li>Write PE headers and sections individually</li>
              <li>Apply base relocations if needed</li>
              <li>Patch PEB.ImageBaseAddress</li>
              <li>Fix per-section memory permissions</li>
              <li>Hijack thread entry point (RCX)</li>
              <li>Resume thread</li>
            </ol>
          </div>
          <div className="text-sm text-muted-foreground">
            <strong>File:</strong> <code className="text-violet">hollow.rs</code><br />
            <strong>Function:</strong> <code className="text-violet">hollow_process()</code>
          </div>
        </div>

        <div className="p-6 rounded-lg border border-border/50 bg-card/50">
          <div className="flex items-center gap-3 mb-3">
            <h3 className="text-xl font-semibold">4. Process Ghosting</h3>
            <Badge variant="destructive">Fileless</Badge>
          </div>
          <p className="text-muted-foreground mb-4">
            Create a process whose backing file no longer exists on disk. Uses delete-pending 
            file state to create an orphaned image section.
          </p>
          <div className="p-3 bg-secondary/50 rounded text-sm mb-4">
            <strong>Algorithm:</strong>
            <ol className="mt-2 space-y-1 text-muted-foreground list-decimal list-inside">
              <li>Create temp file, open with DELETE permission</li>
              <li>Mark for deletion via <code>NtSetInformationFile(FileDispositionInformation)</code></li>
              <li>Write payload via <code>NtWriteFile</code></li>
              <li>Create <code>SEC_IMAGE</code> section via <code>NtCreateSection</code></li>
              <li>Close file handle (file deleted, section survives)</li>
              <li>Create process via <code>NtCreateProcessEx</code></li>
              <li>Set up PEB, process parameters, environment</li>
              <li>Create initial thread via <code>NtCreateThreadEx</code></li>
            </ol>
          </div>
          <div className="text-sm text-muted-foreground">
            <strong>File:</strong> <code className="text-violet">ghost.rs</code><br />
            <strong>Function:</strong> <code className="text-violet">ghost_process()</code>
          </div>
        </div>

        <div className="p-6 rounded-lg border border-border/50 bg-card/50">
          <div className="flex items-center gap-3 mb-3">
            <h3 className="text-xl font-semibold">5. Ghostly Hollowing</h3>
            <Badge variant="destructive">Combined</Badge>
          </div>
          <p className="text-muted-foreground mb-4">
            Combines process ghosting with hollowing. Ghost section mapped into a suspended 
            legitimate process, then thread hijacked.
          </p>
          <div className="text-sm text-muted-foreground">
            <strong>File:</strong> <code className="text-violet">ghostly_hollow.rs</code><br />
            <strong>Function:</strong> <code className="text-violet">ghostly_hollow_process()</code>
          </div>
        </div>

        <div className="p-6 rounded-lg border border-border/50 bg-card/50">
          <div className="flex items-center gap-3 mb-3">
            <h3 className="text-xl font-semibold">6. Process Herpaderping</h3>
            <Badge variant="destructive">AV Evasion</Badge>
          </div>
          <p className="text-muted-foreground mb-4">
            Write payload to temp file, create image section, create process, then overwrite 
            temp file with legitimate PE. AV sees legit PE on disk, but payload runs in memory.
          </p>
          <div className="text-sm text-muted-foreground">
            <strong>File:</strong> <code className="text-violet">herpaderp.rs</code><br />
            <strong>Function:</strong> <code className="text-violet">herpaderp_process()</code>
          </div>
          <WarningBox variant="info" title="Note" className="mt-4">
            The legitimate image file should be larger than the payload PE.
          </WarningBox>
        </div>

        <div className="p-6 rounded-lg border border-border/50 bg-card/50">
          <div className="flex items-center gap-3 mb-3">
            <h3 className="text-xl font-semibold">7. Herpaderping Hollowing</h3>
            <Badge variant="destructive">Combined</Badge>
          </div>
          <p className="text-muted-foreground mb-4">
            Combines herpaderping with hollowing. Payload section mapped into suspended legit 
            process, temp file overwritten with legit PE, thread hijacked.
          </p>
          <div className="text-sm text-muted-foreground">
            <strong>File:</strong> <code className="text-violet">herpaderp_hollow.rs</code><br />
            <strong>Function:</strong> <code className="text-violet">herpaderp_hollow_process()</code>
          </div>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Usage</h2>
        <p className="text-muted-foreground">
          Access process creation via the UI:
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <strong>Normal/PPID Spoofing/Hollowing</strong> — &quot;Create Process&quot; button in Process tab toolbar</li>
          <li>• <strong>Ghosting</strong> — &quot;Ghost Process&quot; button in Process tab toolbar</li>
          <li>• <strong>Ghostly Hollowing/Herpaderping</strong> — Utilities tab</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Method Comparison</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-3 px-4 font-semibold">Method</th>
                <th className="text-left py-3 px-4 font-semibold">File on Disk</th>
                <th className="text-left py-3 px-4 font-semibold">Host Process</th>
                <th className="text-left py-3 px-4 font-semibold">Evasion Level</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4">Normal</td>
                <td className="py-3 px-4 text-red-400">Required</td>
                <td className="py-3 px-4">Own process</td>
                <td className="py-3 px-4">Low</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4">PPID Spoofing</td>
                <td className="py-3 px-4 text-red-400">Required</td>
                <td className="py-3 px-4">Own process</td>
                <td className="py-3 px-4">Medium</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4">Hollowing</td>
                <td className="py-3 px-4 text-red-400">Required</td>
                <td className="py-3 px-4">Legit process</td>
                <td className="py-3 px-4">Medium</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4">Ghosting</td>
                <td className="py-3 px-4 text-green-400">Deleted</td>
                <td className="py-3 px-4">Own process</td>
                <td className="py-3 px-4">High</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4">Ghostly Hollowing</td>
                <td className="py-3 px-4 text-green-400">Deleted</td>
                <td className="py-3 px-4">Legit process</td>
                <td className="py-3 px-4">Very High</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4">Herpaderping</td>
                <td className="py-3 px-4 text-yellow-400">Overwritten</td>
                <td className="py-3 px-4">Own process</td>
                <td className="py-3 px-4">High</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4">Herpaderping Hollowing</td>
                <td className="py-3 px-4 text-yellow-400">Overwritten</td>
                <td className="py-3 px-4">Legit process</td>
                <td className="py-3 px-4">Very High</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
