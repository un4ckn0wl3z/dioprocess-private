import { Badge } from "@/components/ui/badge";
import { CodeBlock } from "@/components/code-block";

export default function StringScanningPage() {
  return (
    <div className="space-y-8">
      <div>
        <div className="flex items-center gap-3 mb-4">
          <h1 className="text-4xl font-bold">String Scanning</h1>
          <Badge variant="outline">Ring 3</Badge>
        </div>
        <p className="text-lg text-muted-foreground">
          Extract printable strings from process memory, supporting ASCII and UTF-16 encoding 
          with configurable length filters.
        </p>
      </div>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Overview</h2>
        <p className="text-muted-foreground">
          The String Scan feature scans all committed memory regions of a target process to 
          find printable strings. This is useful for malware analysis, debugging, and 
          reverse engineering. Implemented in the <code className="text-violet">process</code> crate.
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Data Structures</h2>
        <CodeBlock
          language="rust"
          filename="crates/process/src/lib.rs"
          code={`pub struct StringResult {
    pub address: u64,           // Memory address where string was found
    pub value: String,          // The extracted string content
    pub encoding: StringEncoding,  // ASCII or UTF-16
    pub length: usize,          // Character count
    pub region_type: String,    // Private, Mapped, or Image
}

pub enum StringEncoding {
    Ascii,
    Utf16,
}

pub struct StringScanConfig {
    pub min_length: usize,      // Minimum string length (default: 4)
    pub scan_ascii: bool,       // Scan for ASCII strings
    pub scan_utf16: bool,       // Scan for UTF-16 strings
    pub max_string_length: usize,  // Maximum capture length (default: 512)
}`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Algorithm</h2>
        <CodeBlock
          language="rust"
          filename="Algorithm"
          code={`pub fn scan_process_strings(
    pid: u32, 
    config: StringScanConfig
) -> Result<Vec<StringResult>, ProcessError> {
    // 1. Open process with PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
    let handle = OpenProcess(..., pid)?;
    
    // 2. Enumerate all memory regions via VirtualQueryEx
    let mut address = 0usize;
    loop {
        let info = VirtualQueryEx(handle, address)?;
        
        // 3. Skip uncommitted, reserved, or guarded regions
        if info.State != MEM_COMMIT || info.Protect & PAGE_GUARD != 0 {
            address += info.RegionSize;
            continue;
        }
        
        // 4. Read region contents
        let mut buffer = vec![0u8; info.RegionSize];
        ReadProcessMemory(handle, info.BaseAddress, &mut buffer)?;
        
        // 5. Scan for ASCII strings
        if config.scan_ascii {
            scan_ascii_strings(&buffer, info.BaseAddress, &config, &mut results);
        }
        
        // 6. Scan for UTF-16 strings
        if config.scan_utf16 {
            scan_utf16_strings(&buffer, info.BaseAddress, &config, &mut results);
        }
        
        address += info.RegionSize;
    }
    
    Ok(results)
}

fn scan_ascii_strings(buffer: &[u8], base: u64, config: &StringScanConfig, results: &mut Vec<StringResult>) {
    // Find runs of printable ASCII characters (0x20-0x7E)
    // Minimum length from config, null terminator optional
    // Record address as base + offset
}

fn scan_utf16_strings(buffer: &[u8], base: u64, config: &StringScanConfig, results: &mut Vec<StringResult>) {
    // Find runs of valid UTF-16 code units (pairs of bytes)
    // Filter by printable characters
    // Handle both little-endian (Windows standard) and BOM
}`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Printable Character Detection</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-2 px-3 font-semibold">Encoding</th>
                <th className="text-left py-2 px-3 font-semibold">Range</th>
                <th className="text-left py-2 px-3 font-semibold">Description</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet">ASCII</td>
                <td className="py-2 px-3 text-muted-foreground">0x20 - 0x7E</td>
                <td className="py-2 px-3 text-muted-foreground">Printable ASCII + space</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet">ASCII</td>
                <td className="py-2 px-3 text-muted-foreground">0x09, 0x0A, 0x0D</td>
                <td className="py-2 px-3 text-muted-foreground">Tab, newline, carriage return</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet">UTF-16</td>
                <td className="py-2 px-3 text-muted-foreground">0x0020 - 0xFFFF</td>
                <td className="py-2 px-3 text-muted-foreground">BMP printable characters</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">UI Features</h2>
        <p className="text-muted-foreground">
          Access via right-click process → Inspect → String Scan. The modal provides:
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <strong>Minimum length slider</strong> — 1-100 characters (default: 4)</li>
          <li>• <strong>Encoding filter</strong> — All, ASCII Only, UTF-16 Only</li>
          <li>• <strong>Search filter</strong> — Real-time text search across results</li>
          <li>• <strong>Pagination</strong> — 1000 results per page with navigation controls</li>
          <li>• <strong>Export</strong> — Export all filtered results to .txt file</li>
          <li>• <strong>Context menu</strong> — Copy String, Copy Address, Copy Row</li>
          <li>• <strong>Region type column</strong> — Shows Private, Mapped, or Image</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Region Types</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-2 px-3 font-semibold">Type</th>
                <th className="text-left py-2 px-3 font-semibold">Source</th>
                <th className="text-left py-2 px-3 font-semibold">Typical Contents</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-green-400">Private</td>
                <td className="py-2 px-3 text-muted-foreground">VirtualAlloc, heap</td>
                <td className="py-2 px-3 text-muted-foreground">Dynamic data, buffers, objects</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-blue-400">Image</td>
                <td className="py-2 px-3 text-muted-foreground">PE file mapping</td>
                <td className="py-2 px-3 text-muted-foreground">Module strings, resources, exports</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-yellow-400">Mapped</td>
                <td className="py-2 px-3 text-muted-foreground">Memory-mapped file</td>
                <td className="py-2 px-3 text-muted-foreground">File contents, shared memory</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Performance</h2>
        <p className="text-muted-foreground">
          String scanning is performed on a background thread (<code>tokio::task::spawn_blocking</code>) 
          to keep the UI responsive. Large processes may take several seconds to scan completely.
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>• Results are paginated (1000 per page) to prevent UI lag</li>
          <li>• Maximum string length (512 chars) prevents memory bloat</li>
          <li>• Progress indicator shows scan status</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Use Cases</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <strong>Malware analysis</strong> — Extract C2 URLs, encryption keys, API names</li>
          <li>• <strong>Debugging</strong> — Find error messages, log strings, config values</li>
          <li>• <strong>Reverse engineering</strong> — Identify function names, library versions</li>
          <li>• <strong>Credential hunting</strong> — Search for plaintext passwords in memory</li>
          <li>• <strong>CTF challenges</strong> — Find flags or clues in process memory</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Example Output</h2>
        <CodeBlock
          language="text"
          filename="results.txt"
          code={`Address          | Encoding | Length | Region  | String
-----------------+----------+--------+---------+----------------------------------
0x7FF6A1234560   | ASCII    | 12     | Image   | kernel32.dll
0x7FF6A1234580   | UTF-16   | 24     | Image   | LoadLibraryW
0x000001A23456   | ASCII    | 47     | Private | https://api.example.com/callback
0x000001A23490   | UTF-16   | 15     | Private | ACCESS_DENIED
0x7FFE12340000   | ASCII    | 8      | Mapped  | password`}
        />
      </section>
    </div>
  );
}
