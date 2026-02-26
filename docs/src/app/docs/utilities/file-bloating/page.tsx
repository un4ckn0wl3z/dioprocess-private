import { Badge } from "@/components/ui/badge";
import { CodeBlock } from "@/components/code-block";
import { WarningBox } from "@/components/warning-box";

export default function FileBloatingPage() {
  return (
    <div className="space-y-8">
      <div>
        <div className="flex items-center gap-3 mb-4">
          <h1 className="text-4xl font-bold">File Bloating</h1>
          <Badge variant="outline">Ring 3</Badge>
        </div>
        <p className="text-lg text-muted-foreground">
          Inflate file size by appending null bytes or random data to bypass AV/EDR scanner 
          file size limits.
        </p>
      </div>

      <WarningBox variant="warning" title="AV Evasion Technique">
        File bloating is used to evade antivirus scanners that skip files above certain size 
        thresholds. Use only for authorized security testing.
      </WarningBox>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Overview</h2>
        <p className="text-muted-foreground">
          Many antivirus and EDR products have file size limits for performance reasons. Files 
          above a certain size (often 100-500MB) are skipped or only partially scanned. File 
          bloating exploits this by appending data to make the file exceed these limits while 
          keeping the executable functional.
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Methods</h2>
        <div className="grid gap-4">
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2 flex items-center gap-2">
              Append Null Bytes (0x00)
              <Badge variant="secondary">Default</Badge>
            </h3>
            <p className="text-sm text-muted-foreground">
              Appends zero bytes to the end of the file. Most compressible and fastest to 
              generate. Some scanners may detect patterns of null bytes.
            </p>
          </div>
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2">Random Data (0xFF)</h3>
            <p className="text-sm text-muted-foreground">
              Appends 0xFF bytes which simulate embedded binary resources. Less compressible 
              and harder to detect as padding. Takes slightly longer to generate.
            </p>
          </div>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Algorithm</h2>
        <CodeBlock
          language="rust"
          filename="crates/ui/src/components/utilities_tab.rs"
          code={`async fn bloat_file(
    source: &Path,
    output: &Path,
    size_mb: usize,
    use_null_bytes: bool,
) -> Result<(), std::io::Error> {
    // 1. Copy source file to output location
    std::fs::copy(source, output)?;
    
    // 2. Open output file in append mode
    let mut file = OpenOptions::new()
        .write(true)
        .append(true)
        .open(output)?;
    
    // 3. Create 1MB buffer of chosen byte
    let fill_byte = if use_null_bytes { 0x00 } else { 0xFF };
    let chunk = vec![fill_byte; 1024 * 1024]; // 1 MB
    
    // 4. Write chunks until target size reached
    for _ in 0..size_mb {
        file.write_all(&chunk)?;
    }
    
    // 5. Flush and close
    file.flush()?;
    Ok(())
}`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">UI Controls</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <strong>Source file picker</strong> — Browse for any file (typically .exe or .dll)</li>
          <li>• <strong>Output file picker</strong> — Save As dialog for destination path</li>
          <li>• <strong>Method selector</strong> — Dropdown: &quot;Null Bytes (0x00)&quot; or &quot;Random Data (0xFF)&quot;</li>
          <li>• <strong>Size input</strong> — 1-2000 MB (default: 200)</li>
          <li>• <strong>Bloat File button</strong> — Disabled with &quot;Bloating...&quot; while processing</li>
          <li>• <strong>Status feedback</strong> — Success/error with auto-dismiss</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Known Scanner Limits</h2>
        <p className="text-muted-foreground">
          Common file size limits observed in various security products:
        </p>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-2 px-3 font-semibold">Product Type</th>
                <th className="text-left py-2 px-3 font-semibold">Typical Limit</th>
                <th className="text-left py-2 px-3 font-semibold">Recommended Bloat</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3">Consumer AV</td>
                <td className="py-2 px-3 text-muted-foreground">100-200 MB</td>
                <td className="py-2 px-3 text-muted-foreground">250 MB</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3">Enterprise EDR</td>
                <td className="py-2 px-3 text-muted-foreground">200-500 MB</td>
                <td className="py-2 px-3 text-muted-foreground">600 MB</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3">Cloud Sandbox</td>
                <td className="py-2 px-3 text-muted-foreground">50-100 MB upload</td>
                <td className="py-2 px-3 text-muted-foreground">150 MB</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3">Email Gateway</td>
                <td className="py-2 px-3 text-muted-foreground">25-50 MB attachment</td>
                <td className="py-2 px-3 text-muted-foreground">75 MB</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Why It Works</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <strong>PE/ELF structure</strong> — Executable headers define section boundaries; appended data is ignored by loaders</li>
          <li>• <strong>Performance trade-off</strong> — Scanning large files impacts system performance</li>
          <li>• <strong>Memory limits</strong> — Some scanners load entire files into memory</li>
          <li>• <strong>Cloud upload</strong> — Large files exceed upload bandwidth limits</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Detection</h2>
        <p className="text-muted-foreground">
          File bloating can be detected by:
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>• Comparing PE section sizes to actual file size</li>
          <li>• High entropy analysis (null bytes = very low entropy at end)</li>
          <li>• Overlay detection in PE parsing</li>
          <li>• YARA rules matching trailing zero/0xFF patterns</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Use Cases</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• Testing AV/EDR file size handling</li>
          <li>• Red team payload delivery</li>
          <li>• Security research on scanner behavior</li>
          <li>• Bypass cloud sandbox upload limits</li>
        </ul>
      </section>
    </div>
  );
}
