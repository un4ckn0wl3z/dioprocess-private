import { Badge } from "@/components/ui/badge";

export default function MemoryScannerPage() {
  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-4xl font-bold mb-4">Memory Scanner</h1>
        <p className="text-lg text-muted-foreground">
          Physical memory scanning via hypervisor CR3 page table walk. Scan process memory 
          for values and modify them in real-time.
        </p>
      </div>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Scan Types</h2>
        
        <div className="grid sm:grid-cols-2 gap-4">
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2">First Scan</h3>
            <ul className="text-sm text-muted-foreground space-y-1">
              <li>• Exact value</li>
              <li>• Greater than</li>
              <li>• Less than</li>
              <li>• Between (range)</li>
              <li>• Array of Bytes (AOB)</li>
            </ul>
          </div>
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2">Next Scan</h3>
            <ul className="text-sm text-muted-foreground space-y-1">
              <li>• Changed</li>
              <li>• Unchanged</li>
              <li>• Increased</li>
              <li>• Decreased</li>
              <li>• Exact value</li>
            </ul>
          </div>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Data Types</h2>
        <div className="flex flex-wrap gap-2">
          {["Byte", "2-byte (Int16)", "4-byte (Int32)", "8-byte (Int64)", "Float", "Double", "Array of Bytes"].map((type) => (
            <Badge key={type} variant="secondary">{type}</Badge>
          ))}
        </div>
        <p className="text-sm text-muted-foreground mt-2">
          AOB supports wildcards with <code>??</code> (e.g., <code>48 8B ?? 90</code>)
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Scan Regions</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <strong>All</strong> — Scan all committed memory</li>
          <li>• <strong>Heap</strong> — Private memory regions</li>
          <li>• <strong>Stack</strong> — Thread stack regions</li>
          <li>• <strong>Image</strong> — Loaded modules (.exe, .dll)</li>
          <li>• <strong>Mapped</strong> — Memory-mapped files</li>
          <li>• <strong>Private</strong> — Private allocations only</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Features</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <strong>Value writing</strong> — Select a result and write a new value</li>
          <li>• <strong>Inline editing</strong> — Double-click to edit values directly</li>
          <li>• <strong>Pagination</strong> — 500 results per page</li>
          <li>• <strong>Context menu</strong> — Edit Value, Copy Address/Value, Install EPT Hook</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">How It Works</h2>
        <p className="text-muted-foreground">
          The memory scanner uses the hypervisor to perform physical memory access:
        </p>
        <ol className="list-decimal list-inside space-y-2 text-muted-foreground">
          <li>Get target process CR3 (page table base)</li>
          <li>Walk page tables to translate virtual → physical addresses</li>
          <li>Read/write physical memory via EPT</li>
          <li>Bypasses Ring 0 memory protections</li>
        </ol>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Usage</h2>
        <ol className="list-decimal list-inside space-y-2 text-muted-foreground">
          <li>Navigate to <strong>Memory Scanner</strong> tab</li>
          <li>Select a process from the dropdown</li>
          <li>Choose data type and scan type</li>
          <li>Enter value to search for</li>
          <li>Click <strong>First Scan</strong></li>
          <li>Use <strong>Next Scan</strong> to refine results</li>
          <li>Double-click or right-click results to modify values</li>
        </ol>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">IOCTLs</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-3 px-4 font-semibold">IOCTL</th>
                <th className="text-left py-3 px-4 font-semibold">Code</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4 font-mono">HV_READ_VM</td>
                <td className="py-3 px-4">0x842</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4 font-mono">HV_WRITE_VM</td>
                <td className="py-3 px-4">0x843</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
