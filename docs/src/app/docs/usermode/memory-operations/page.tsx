export default function MemoryOperationsPage() {
  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-4xl font-bold mb-4">Memory Operations</h1>
        <p className="text-lg text-muted-foreground">
          Commit, decommit, and free virtual memory regions with hex dump viewing 
          and memory dump export capabilities.
        </p>
      </div>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Memory Region Enumeration</h2>
        <p className="text-muted-foreground">
          The Memory window displays all virtual memory regions via <code>VirtualQueryEx</code>:
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <strong>Base Address</strong> — Starting address of the region</li>
          <li>• <strong>Allocation Base</strong> — Base address of the allocation</li>
          <li>• <strong>Region Size</strong> — Size in bytes</li>
          <li>• <strong>State</strong> — Commit, Reserve, or Free</li>
          <li>• <strong>Type</strong> — Private, Mapped, or Image</li>
          <li>• <strong>Protection</strong> — Memory protection flags (R/W/X combinations)</li>
          <li>• <strong>Module</strong> — Associated module name for MEM_IMAGE regions</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Available Operations</h2>
        
        <div className="space-y-4">
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2">Commit Memory</h3>
            <p className="text-sm text-muted-foreground">
              Commit reserved memory regions to make them usable. Uses <code>VirtualAllocEx</code> 
              with <code>MEM_COMMIT</code>.
            </p>
          </div>

          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2">Decommit Memory</h3>
            <p className="text-sm text-muted-foreground">
              Decommit committed memory regions, returning them to reserved state. 
              Uses <code>VirtualFreeEx</code> with <code>MEM_DECOMMIT</code>.
            </p>
          </div>

          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2">Free Memory</h3>
            <p className="text-sm text-muted-foreground">
              Free entire allocations, releasing the virtual address space. 
              Uses <code>VirtualFreeEx</code> with <code>MEM_RELEASE</code>.
            </p>
          </div>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Hex Dump Viewer</h2>
        <p className="text-muted-foreground">
          View the raw bytes of any committed memory region:
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>• Paginated display (4KB pages)</li>
          <li>• Hex column with byte values</li>
          <li>• ASCII column showing printable characters</li>
          <li>• Navigation controls for large regions</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Memory Dump Export</h2>
        <p className="text-muted-foreground">
          Export any committed memory region to a .bin file:
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>• Available from action button in memory table</li>
          <li>• Available from context menu</li>
          <li>• Available from hex dump view</li>
          <li>• Native save dialog for file location</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Functions</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-3 px-4 font-semibold">Function</th>
                <th className="text-left py-3 px-4 font-semibold">File</th>
                <th className="text-left py-3 px-4 font-semibold">Description</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4 font-mono text-violet">commit_memory()</td>
                <td className="py-3 px-4">memory.rs</td>
                <td className="py-3 px-4 text-muted-foreground">Commit reserved memory</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4 font-mono text-violet">decommit_memory()</td>
                <td className="py-3 px-4">memory.rs</td>
                <td className="py-3 px-4 text-muted-foreground">Decommit committed memory</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4 font-mono text-violet">free_memory()</td>
                <td className="py-3 px-4">memory.rs</td>
                <td className="py-3 px-4 text-muted-foreground">Free entire allocation</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Usage</h2>
        <ol className="list-decimal list-inside space-y-2 text-muted-foreground">
          <li>Right-click a process → <strong>Inspect → Memory</strong></li>
          <li>Browse memory regions in the table</li>
          <li>Use filter to search by address, state, type, or module</li>
          <li>Click a region to view hex dump</li>
          <li>Use context menu or action buttons for operations</li>
        </ol>
      </section>
    </div>
  );
}
