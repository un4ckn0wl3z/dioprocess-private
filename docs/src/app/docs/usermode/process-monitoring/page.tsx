import { Badge } from "@/components/ui/badge";

export default function ProcessMonitoringPage() {
  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-4xl font-bold mb-4">Process Monitoring</h1>
        <p className="text-lg text-muted-foreground">
          Real-time enumeration and inspection of processes, threads, handles, modules, 
          and memory regions using Windows APIs.
        </p>
      </div>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Process Enumeration</h2>
        <p className="text-muted-foreground">
          The Process tab displays all running processes with the following information:
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <strong>PID</strong> — Process ID</li>
          <li>• <strong>Name</strong> — Process name (executable filename)</li>
          <li>• <strong>Parent PID</strong> — Parent process ID</li>
          <li>• <strong>CPU %</strong> — Current CPU usage percentage</li>
          <li>• <strong>Memory</strong> — Working set memory usage</li>
          <li>• <strong>Threads</strong> — Number of threads</li>
          <li>• <strong>Path</strong> — Full executable path</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Tree View</h2>
        <p className="text-muted-foreground">
          Toggle between flat list and hierarchical tree view showing parent-child relationships.
        </p>
        <div className="grid sm:grid-cols-2 gap-4">
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2">Features</h3>
            <ul className="text-sm text-muted-foreground space-y-1">
              <li>• Unicode box-drawing connectors (│ ├ └ ─)</li>
              <li>• Expand/collapse per node (▶/▼)</li>
              <li>• &quot;Expand All&quot; / &quot;Collapse All&quot; buttons</li>
              <li>• State survives auto-refresh</li>
            </ul>
          </div>
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2">Search in Tree Mode</h3>
            <ul className="text-sm text-muted-foreground space-y-1">
              <li>• Shows matching processes + all ancestors</li>
              <li>• Preserves hierarchy context</li>
              <li>• Auto-expands children of matches</li>
            </ul>
          </div>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Inspection Windows</h2>
        <p className="text-muted-foreground">
          Right-click a process and select &quot;Inspect&quot; to open detailed views:
        </p>

        <div className="space-y-4">
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <div className="flex items-center gap-2 mb-2">
              <h3 className="font-semibold">Threads</h3>
              <Badge variant="outline">NtQueryInformationThread</Badge>
            </div>
            <p className="text-sm text-muted-foreground">
              View all threads with ID, base priority, current priority, start address, and state.
            </p>
          </div>

          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <div className="flex items-center gap-2 mb-2">
              <h3 className="font-semibold">Handles</h3>
              <Badge variant="outline">NtQuerySystemInformation</Badge>
            </div>
            <p className="text-sm text-muted-foreground">
              View all open handles with value, type (File, Key, Event, etc.), and name.
            </p>
          </div>

          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <div className="flex items-center gap-2 mb-2">
              <h3 className="font-semibold">Modules</h3>
              <Badge variant="outline">ToolHelp32</Badge>
            </div>
            <p className="text-sm text-muted-foreground">
              View loaded DLLs with base address, size, entry point, and full path.
            </p>
          </div>

          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <div className="flex items-center gap-2 mb-2">
              <h3 className="font-semibold">Memory</h3>
              <Badge variant="outline">VirtualQueryEx</Badge>
            </div>
            <p className="text-sm text-muted-foreground">
              View virtual memory regions with base address, size, state (Commit/Reserve/Free), 
              type (Private/Mapped/Image), and protection flags.
            </p>
          </div>

          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <div className="flex items-center gap-2 mb-2">
              <h3 className="font-semibold">Performance</h3>
              <Badge variant="outline">Real-time</Badge>
            </div>
            <p className="text-sm text-muted-foreground">
              Real-time CPU and memory graphs with 60-second rolling history. SVG-based with 
              fill area, auto-scaling, and pause/resume controls.
            </p>
          </div>

          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <div className="flex items-center gap-2 mb-2">
              <h3 className="font-semibold">String Scan</h3>
              <Badge variant="outline">Memory Scan</Badge>
            </div>
            <p className="text-sm text-muted-foreground">
              Extract ASCII and UTF-16 strings from process memory. Configurable minimum length 
              (1-100), encoding filter, paginated results (1000/page), and export to .txt.
            </p>
          </div>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Memory Window Features</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <strong>Module correlation</strong> — MEM_IMAGE regions display associated module name</li>
          <li>• <strong>Hex dump viewer</strong> — Paginated hex dump (4KB pages) with ASCII column</li>
          <li>• <strong>Memory dump</strong> — Export any committed region to .bin file</li>
          <li>• <strong>Memory operations</strong> — Commit reserved regions, decommit, free allocations</li>
          <li>• <strong>Filtering</strong> — Filter by address, state, type, protection, or module name</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Network Tab</h2>
        <p className="text-muted-foreground">
          View TCP and UDP connections with owning process information via IP Helper API 
          (<code>GetExtendedTcpTable</code> / <code>GetUdpTable</code>).
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>• Protocol (TCP/UDP)</li>
          <li>• Local address and port</li>
          <li>• Remote address and port (TCP only)</li>
          <li>• Connection state (TCP only)</li>
          <li>• Owning process PID and name</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Services Tab</h2>
        <p className="text-muted-foreground">
          Windows Service enumeration and management via Service Control Manager.
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <strong>Enumerate</strong> — List all services with name, display name, status, start type</li>
          <li>• <strong>Start/Stop</strong> — Control service state</li>
          <li>• <strong>Create/Delete</strong> — Manage service entries</li>
          <li>• <strong>Details</strong> — Binary path, description, PID (if running)</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Data Types</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-3 px-4 font-semibold">Struct</th>
                <th className="text-left py-3 px-4 font-semibold">Crate</th>
                <th className="text-left py-3 px-4 font-semibold">Key Fields</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4 font-mono text-violet">ProcessInfo</td>
                <td className="py-3 px-4">process</td>
                <td className="py-3 px-4 text-muted-foreground">pid, parent_pid, name, memory, threads, cpu, exe_path</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4 font-mono text-violet">ThreadInfo</td>
                <td className="py-3 px-4">process</td>
                <td className="py-3 px-4 text-muted-foreground">thread_id, owner_pid, base_priority, priority</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4 font-mono text-violet">HandleInfo</td>
                <td className="py-3 px-4">process</td>
                <td className="py-3 px-4 text-muted-foreground">handle_value, type, name</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4 font-mono text-violet">ModuleInfo</td>
                <td className="py-3 px-4">process</td>
                <td className="py-3 px-4 text-muted-foreground">base_address, size, path, entry_point</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4 font-mono text-violet">MemoryRegionInfo</td>
                <td className="py-3 px-4">process</td>
                <td className="py-3 px-4 text-muted-foreground">base_address, region_size, state, mem_type, protect</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4 font-mono text-violet">NetworkConnection</td>
                <td className="py-3 px-4">network</td>
                <td className="py-3 px-4 text-muted-foreground">protocol, local/remote addr:port, state, pid</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4 font-mono text-violet">ServiceInfo</td>
                <td className="py-3 px-4">service</td>
                <td className="py-3 px-4 text-muted-foreground">name, display_name, status, start_type, binary_path</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
